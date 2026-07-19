use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::thread;

use super::contract::Contract;
use super::error::{InitError, InitResult};
use super::log;
use super::mount::create_dir;

const MARKER_GUEST_PROXY_READY: &str = "FIRMA_GUEST_PROXY_READY";
const MARKER_GUEST_DNS_READY: &str = "FIRMA_GUEST_DNS_READY";
const RESOLV_CONF: &str = "/etc/resolv.conf";
const AF_VSOCK: libc::c_int = 40;
const VMADDR_CID_HOST: u32 = 2;
const DNS_REFUSED_RCODE: u8 = 5;
const IFNAMSIZ: usize = 16;
const NO_PROXY_ENV_KEYS: [&str; 2] = ["NO_PROXY", "no_proxy"];
const NO_PROXY_VALUE: &str = "127.0.0.1,localhost,::1";
const PROXY_ENV_KEYS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// Accepted guest network service plan derived from the launch contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkServicesPlan {
    proxy: ProxyPlan,
    dns: DnsPlan,
    env: CommandNetworkEnv,
}

impl NetworkServicesPlan {
    /// Returns the accepted command environment for guest network services.
    pub const fn command_env(&self) -> &CommandNetworkEnv {
        &self.env
    }
}

impl TryFrom<&Contract> for NetworkServicesPlan {
    type Error = InitError;

    /// Accepts guest network service inputs from the already accepted contract.
    fn try_from(contract: &Contract) -> Result<Self, Self::Error> {
        let network = contract.network();
        let proxy = ProxyPlan {
            guest_http_proxy_addr: network.guest_http_proxy_addr(),
            vsock_sidecar_port: network.vsock_sidecar_port(),
            attribution_headers: network.attribution_headers().clone(),
        };
        let dns = DnsPlan {
            guest_dns_stub_addr: network.guest_dns_stub_addr(),
        };
        let env = CommandNetworkEnv::from_contract(contract);

        Ok(Self { proxy, dns, env })
    }
}

/// Accepted guest proxy service configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProxyPlan {
    guest_http_proxy_addr: SocketAddr,
    vsock_sidecar_port: std::num::NonZeroU32,
    attribution_headers: BTreeMap<String, String>,
}

/// Accepted guest DNS service configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DnsPlan {
    guest_dns_stub_addr: SocketAddr,
}

/// Accepted command environment with guest-local network endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandNetworkEnv {
    values: BTreeMap<String, String>,
}

impl CommandNetworkEnv {
    /// Returns the accepted command environment map.
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.values
    }

    /// Builds command environment from the accepted launch contract.
    fn from_contract(contract: &Contract) -> Self {
        let mut values = contract.command().env.clone();
        let network = contract.network();
        let proxy_url = format!("http://{}", network.guest_http_proxy_addr());

        for key in PROXY_ENV_KEYS {
            values.insert(key.to_string(), proxy_url.clone());
        }

        for key in NO_PROXY_ENV_KEYS {
            values.insert(key.to_string(), NO_PROXY_VALUE.to_string());
        }
        values.insert(
            "FIRMA_DNS_STUB_ADDR".to_string(),
            network.guest_dns_stub_addr().to_string(),
        );
        values.insert(
            "FIRMA_VSOCK_SIDECAR_PORT".to_string(),
            network.vsock_sidecar_port().to_string(),
        );
        if let Some(term) = contract.terminal().term() {
            values.insert("TERM".to_string(), term.to_string());
        }

        if let Some(port) = contract.terminal().pty_vsock_port() {
            values.insert("FIRMA_VSOCK_COMMAND_PTY_PORT".to_string(), port.to_string());
        }

        if let Some(port) = contract.terminal().pty_control_vsock_port() {
            values.insert(
                "FIRMA_VSOCK_COMMAND_PTY_CONTROL_PORT".to_string(),
                port.to_string(),
            );
        }

        Self { values }
    }
}

/// Running guest-local network services owned by the current command launch.
///
/// Keeping this handle alive makes the service lifetime explicit: sockets are
/// prepared before command spawn, then the listener threads live until command
/// execution finishes and the init process powers off the guest.
pub struct GuestNetworkServices {
    threads: Vec<thread::JoinHandle<()>>,
}

impl GuestNetworkServices {
    /// Returns how many service listener threads are owned by this handle.
    #[cfg(test)]
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    /// Returns the prepared service thread names for tests.
    #[cfg(test)]
    fn thread_names(&self) -> impl Iterator<Item = Option<&str>> {
        self.threads.iter().map(|thread| thread.thread().name())
    }
}

impl Drop for GuestNetworkServices {
    /// Releases guest network listener handles when command execution ends.
    fn drop(&mut self) {
        self.threads.clear();
    }
}

/// Bound guest network sockets that have not started serving traffic yet.
struct GuestNetworkListeners {
    proxy: GuestProxyListener,
    dns: GuestDnsListeners,
}

impl GuestNetworkListeners {
    /// Binds every guest network socket before any service thread is spawned.
    fn bind(plan: &NetworkServicesPlan) -> InitResult<Self> {
        let proxy = GuestProxyListener::bind(&plan.proxy)?;
        let dns = GuestDnsListeners::bind(&plan.dns)?;

        Ok(Self { proxy, dns })
    }

    /// Starts all prepared guest network listeners.
    fn start(self) -> InitResult<GuestNetworkServices> {
        let mut threads = Vec::with_capacity(self.dns.listener_count() + 1);
        threads.push(start_guest_http_proxy(self.proxy)?);
        threads.extend(self.dns.start()?);

        Ok(GuestNetworkServices { threads })
    }
}

/// Prepared guest HTTP proxy listener.
struct GuestProxyListener {
    addr: SocketAddr,
    listener: TcpListener,
    vsock_sidecar_port: u32,
    attribution_headers: BTreeMap<String, String>,
}

impl GuestProxyListener {
    /// Binds the guest HTTP proxy socket without accepting clients yet.
    fn bind(plan: &ProxyPlan) -> InitResult<Self> {
        let addr = plan.guest_http_proxy_addr;
        let listener =
            TcpListener::bind(addr).map_err(|source| InitError::ProxyBind { addr, source })?;

        Ok(Self {
            addr,
            listener,
            vsock_sidecar_port: plan.vsock_sidecar_port.get(),
            attribution_headers: plan.attribution_headers.clone(),
        })
    }
}

/// Prepared guest DNS refusal listeners.
struct GuestDnsListeners {
    stub_addr: SocketAddr,
    resolver_addr: SocketAddr,
    listeners: Vec<GuestDnsListener>,
}

impl GuestDnsListeners {
    /// Binds UDP and TCP DNS listeners for both the configured and resolver ports.
    fn bind(plan: &DnsPlan) -> InitResult<Self> {
        let stub_addr = plan.guest_dns_stub_addr;
        let resolver_addr = SocketAddr::new(stub_addr.ip(), 53);
        let mut listeners = Vec::new();

        for addr in dns_listener_addrs(stub_addr) {
            listeners.push(GuestDnsListener::bind_udp(addr)?);
            listeners.push(GuestDnsListener::bind_tcp(addr)?);
        }

        Ok(Self {
            stub_addr,
            resolver_addr,
            listeners,
        })
    }

    /// Returns the number of prepared DNS listener threads.
    fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Starts the prepared DNS listeners.
    fn start(self) -> InitResult<Vec<thread::JoinHandle<()>>> {
        let mut threads = Vec::with_capacity(self.listeners.len());
        for listener in self.listeners {
            threads.push(listener.start()?);
        }

        log(&format!(
            "guest DNS refusal stub listening at {} and resolver port {}",
            self.stub_addr, self.resolver_addr
        ));

        log(MARKER_GUEST_DNS_READY);

        Ok(threads)
    }
}

/// Prepared UDP or TCP DNS refusal socket.
enum GuestDnsListener {
    Udp {
        addr: SocketAddr,
        socket: UdpSocket,
    },
    Tcp {
        addr: SocketAddr,
        listener: TcpListener,
    },
}

impl GuestDnsListener {
    /// Binds a UDP DNS refusal listener without serving requests yet.
    fn bind_udp(addr: SocketAddr) -> InitResult<Self> {
        let socket =
            UdpSocket::bind(addr).map_err(|source| InitError::DnsUdpBind { addr, source })?;

        Ok(Self::Udp { addr, socket })
    }

    /// Binds a TCP DNS refusal listener without accepting clients yet.
    fn bind_tcp(addr: SocketAddr) -> InitResult<Self> {
        let listener =
            TcpListener::bind(addr).map_err(|source| InitError::DnsTcpBind { addr, source })?;

        Ok(Self::Tcp { addr, listener })
    }

    /// Starts serving DNS refusal responses on this prepared listener.
    fn start(self) -> InitResult<thread::JoinHandle<()>> {
        match self {
            Self::Udp { addr, socket } => thread::Builder::new()
                .name(format!("firma-guest-dns-udp-{addr}"))
                .spawn(move || udp_dns_stub_loop(&socket))
                .map_err(|source| InitError::DnsUdpThreadSpawn { addr, source }),
            Self::Tcp { addr, listener } => thread::Builder::new()
                .name(format!("firma-guest-dns-tcp-{addr}"))
                .spawn(move || tcp_dns_stub_loop(&listener))
                .map_err(|source| InitError::DnsTcpThreadSpawn { addr, source }),
        }
    }
}

/// Starts guest-local network services required before command spawn.
pub fn start_guest_network_services(
    plan: &NetworkServicesPlan,
) -> InitResult<GuestNetworkServices> {
    bring_loopback_up()?;
    let listeners = GuestNetworkListeners::bind(plan)?;
    write_resolv_conf(plan.dns.guest_dns_stub_addr)?;

    listeners.start()
}

/// Brings up the guest loopback interface used by the local proxy and DNS stub.
fn bring_loopback_up() -> InitResult<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(InitError::LoopbackControlOpen {
            source: io::Error::last_os_error(),
        });
    }

    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut request = IfReq::named("lo")?;
    let read_flags = libc::Ioctl::try_from(libc::SIOCGIFFLAGS)
        .map_err(|_| network_setup("SIOCGIFFLAGS ioctl request out of range"))?;

    let result = unsafe { libc::ioctl(socket.as_raw_fd(), read_flags, &mut request) };
    if result != 0 {
        return Err(InitError::LoopbackReadFlags {
            source: io::Error::last_os_error(),
        });
    }

    let enabled_flags = libc::c_short::try_from(libc::IFF_UP | libc::IFF_RUNNING)
        .map_err(|_| network_setup("loopback interface flags out of range"))?;

    unsafe {
        request.value.flags |= enabled_flags;
    }

    let write_flags = libc::Ioctl::try_from(libc::SIOCSIFFLAGS)
        .map_err(|_| network_setup("SIOCSIFFLAGS ioctl request out of range"))?;

    let result = unsafe { libc::ioctl(socket.as_raw_fd(), write_flags, &request) };
    if result != 0 {
        return Err(InitError::LoopbackEnable {
            source: io::Error::last_os_error(),
        });
    }

    log("guest loopback interface is up");

    Ok(())
}

/// Starts the prepared guest HTTP proxy listener.
fn start_guest_http_proxy(proxy: GuestProxyListener) -> InitResult<thread::JoinHandle<()>> {
    let GuestProxyListener {
        addr,
        listener,
        vsock_sidecar_port,
        attribution_headers,
    } = proxy;

    let thread = thread::Builder::new()
        .name("firma-guest-http-proxy".to_string())
        .spawn(move || guest_http_proxy_loop(&listener, vsock_sidecar_port, &attribution_headers))
        .map_err(|source| InitError::ProxyThreadSpawn { source })?;

    log(&format!(
        "guest HTTP proxy listening at {addr} forwarding to host VSOCK port {vsock_sidecar_port}"
    ));

    log(MARKER_GUEST_PROXY_READY);

    Ok(thread)
}

/// Accepts guest proxy clients and forwards each connection through VSOCK.
fn guest_http_proxy_loop(
    listener: &TcpListener,
    vsock_sidecar_port: u32,
    attribution_headers: &BTreeMap<String, String>,
) {
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let attribution_headers = attribution_headers.clone();
                let _ = thread::Builder::new()
                    .name("firma-guest-http-proxy-conn".to_string())
                    .spawn(move || {
                        if let Err(error) = handle_guest_proxy_connection(
                            stream,
                            vsock_sidecar_port,
                            &attribution_headers,
                        ) {
                            log(&format!("guest HTTP proxy connection failed: {error}"));
                        }
                    });
            }
            Err(error) => log(&format!("guest HTTP proxy accept failed: {error}")),
        }
    }
}

/// Proxies a single guest TCP connection to the host Sidecar VSOCK port.
fn handle_guest_proxy_connection(
    client_stream: TcpStream,
    vsock_sidecar_port: u32,
    attribution_headers: &BTreeMap<String, String>,
) -> InitResult<()> {
    client_stream
        .set_nodelay(true)
        .map_err(|source| InitError::ProxyClientNoDelay { source })?;
    let mut client_reader = client_stream
        .try_clone()
        .map_err(|source| InitError::ProxyClientClone { source })?;

    let mut client_writer = client_stream;
    let vsock_stream = connect_vsock_host(vsock_sidecar_port)
        .map_err(|source| InitError::VsockConnect { source })?;

    let mut vsock_reader = vsock_stream
        .try_clone()
        .map_err(|source| InitError::ProxyVsockClone { source })?;

    let mut vsock_writer = vsock_stream;
    let attribution_headers = attribution_headers.clone();
    let upstream = thread::spawn(move || {
        let result = forward_requests_with_header_injection(
            &mut client_reader,
            &mut vsock_writer,
            &attribution_headers,
        );
        let _ = vsock_writer.flush();
        result
    });

    let downstream = io::copy(&mut vsock_reader, &mut client_writer);
    let _ = client_writer.shutdown(Shutdown::Write);
    downstream.map_err(|source| InitError::ProxyCopyResponse { source })?;

    match upstream.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(source)) => Err(InitError::ProxyCopyRequest { source }),
        Err(_) => Err(network_setup("guest proxy request thread panicked")),
    }
}

/// Forwards HTTP requests while adding missing Firma attribution headers.
fn forward_requests_with_header_injection<W>(
    client: &mut TcpStream,
    upstream: &mut W,
    attribution_headers: &BTreeMap<String, String>,
) -> io::Result<()>
where
    W: Write,
{
    let mut buffer = Vec::new();
    loop {
        let Some(header_end) = read_until_header_block(client, &mut buffer)? else {
            return Ok(());
        };

        let mut request = std::mem::take(&mut buffer);
        let mut remaining = request.split_off(header_end + 4);
        request.truncate(header_end);

        let meta = parse_request_metadata(&request)?;
        replace_attribution_headers(&mut request, attribution_headers)?;

        upstream.write_all(&request)?;
        upstream.write_all(b"\r\n")?;

        match meta.body {
            BodyKind::None => {}
            BodyKind::ContentLength(mut bytes_left) => {
                if !remaining.is_empty() {
                    let take = remaining.len().min(bytes_left);
                    upstream.write_all(&remaining[..take])?;
                    remaining.drain(..take);
                    bytes_left -= take;
                }
                copy_exact_bytes(client, upstream, bytes_left)?;
            }
            BodyKind::Chunked => {
                forward_chunked_body(client, upstream, &mut remaining)?;
            }
        }

        if !remaining.is_empty() {
            buffer.extend_from_slice(&remaining);
        }

        if meta.method.eq_ignore_ascii_case("CONNECT") {
            if !buffer.is_empty() {
                upstream.write_all(&buffer)?;
                buffer.clear();
            }
            io::copy(client, upstream)?;
            return Ok(());
        }
    }
}

/// Replaces untrusted attribution headers with the contract-bound values.
fn replace_attribution_headers(
    header_block: &mut Vec<u8>,
    attribution_headers: &BTreeMap<String, String>,
) -> io::Result<()> {
    let head_str = std::str::from_utf8(header_block).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "request headers are not valid utf-8",
        )
    })?;
    let mut lines = head_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Ok(());
    };

    let authoritative_names = attribution_headers
        .keys()
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();

    let mut rebuilt = String::new();
    rebuilt.push_str(request_line);
    rebuilt.push_str("\r\n");
    for line in head_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        if line.split_once(':').is_some_and(|(name, _)| {
            authoritative_names.contains(&name.trim().to_ascii_lowercase())
        }) {
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }

    for (name, value) in attribution_headers {
        rebuilt.push_str(name);
        rebuilt.push_str(": ");
        rebuilt.push_str(value);
        rebuilt.push_str("\r\n");
    }

    *header_block = rebuilt.into_bytes();

    Ok(())
}

/// Reads bytes until an HTTP header block terminator is available.
fn read_until_header_block(
    client: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<usize>> {
    if let Some(pos) = find_header_terminator(buffer) {
        return Ok(Some(pos));
    }

    let mut chunk = [0_u8; 4096];

    loop {
        let read = client.read(&mut chunk)?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-request headers",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_header_terminator(buffer) {
            return Ok(Some(pos));
        }
        if buffer.len() > 1024 * 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceed 128KiB",
            ));
        }
    }
}

/// Finds the end of an HTTP header block.
fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Request body forwarding mode inferred from the request headers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyKind {
    None,
    ContentLength(usize),
    Chunked,
}

/// HTTP request metadata needed while forwarding through the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestMetadata {
    method: String,
    body: BodyKind,
}

/// Parses the request method and body framing from an HTTP header block.
fn parse_request_metadata(header_block: &[u8]) -> io::Result<RequestMetadata> {
    let head_str = std::str::from_utf8(header_block).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "request headers are not valid utf-8",
        )
    })?;

    let mut lines = head_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();

    let mut transfer_chunked = false;
    let mut content_length = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name_lc = name.trim().to_ascii_lowercase();
            let value_trim = value.trim();
            if name_lc == "transfer-encoding" && value_trim.to_ascii_lowercase().contains("chunked")
            {
                transfer_chunked = true;
            } else if name_lc == "content-length" {
                content_length = value_trim.parse::<usize>().ok();
            }
        }
    }

    let body = if transfer_chunked {
        BodyKind::Chunked
    } else if let Some(length) = content_length {
        if length == 0 {
            BodyKind::None
        } else {
            BodyKind::ContentLength(length)
        }
    } else {
        BodyKind::None
    };

    Ok(RequestMetadata { method, body })
}

/// Copies a known number of request body bytes.
fn copy_exact_bytes<W>(client: &mut TcpStream, upstream: &mut W, mut left: usize) -> io::Result<()>
where
    W: Write,
{
    let mut chunk = [0_u8; 8192];
    while left > 0 {
        let to_read = chunk.len().min(left);
        let read = client.read(&mut chunk[..to_read])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-request body",
            ));
        }
        upstream.write_all(&chunk[..read])?;
        left -= read;
    }
    Ok(())
}

/// Forwards an HTTP chunked request body.
fn forward_chunked_body<W>(
    client: &mut TcpStream,
    upstream: &mut W,
    buffer: &mut Vec<u8>,
) -> io::Result<()>
where
    W: Write,
{
    loop {
        let line_end = read_until_crlf(client, buffer)?;
        let line = &buffer[..line_end];
        let size_hex = std::str::from_utf8(line)
            .ok()
            .and_then(|line| line.split(';').next())
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size line"))?;
        upstream.write_all(&buffer[..line_end + 2])?;
        buffer.drain(..line_end + 2);

        let needed = chunk_size + 2;
        ensure_buffered(client, buffer, needed)?;
        upstream.write_all(&buffer[..needed])?;
        buffer.drain(..needed);

        if chunk_size == 0 {
            loop {
                let tail_end = read_until_crlf(client, buffer)?;
                upstream.write_all(&buffer[..tail_end + 2])?;
                let is_blank = tail_end == 0;
                buffer.drain(..tail_end + 2);
                if is_blank {
                    return Ok(());
                }
            }
        }
    }
}

/// Ensures the provided buffer contains at least `needed` bytes.
fn ensure_buffered(client: &mut TcpStream, buffer: &mut Vec<u8>, needed: usize) -> io::Result<()> {
    let mut chunk = [0_u8; 4096];
    while buffer.len() < needed {
        let read = client.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed while buffering body",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

/// Reads until a CRLF line terminator is present in the buffer.
fn read_until_crlf(client: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<usize> {
    if let Some(pos) = find_crlf(buffer) {
        return Ok(pos);
    }
    let mut chunk = [0_u8; 1024];
    loop {
        let read = client.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed while reading chunk line",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_crlf(buffer) {
            return Ok(pos);
        }
    }
}

/// Finds the next CRLF line terminator.
fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

/// Returns the configured DNS stub address and the resolver port address.
fn dns_listener_addrs(stub_addr: SocketAddr) -> Vec<SocketAddr> {
    let resolver_addr = SocketAddr::new(stub_addr.ip(), 53);
    if resolver_addr == stub_addr {
        vec![stub_addr]
    } else {
        vec![stub_addr, resolver_addr]
    }
}

/// Serves DNS refusal responses over UDP.
fn udp_dns_stub_loop(socket: &UdpSocket) {
    let mut buffer = [0_u8; 512];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((len, peer)) => {
                if let Some(response) = dns_refused_response(&buffer[..len]) {
                    let _ = socket.send_to(&response, peer);
                }
            }
            Err(error) => log(&format!("guest UDP DNS refusal stub failed: {error}")),
        }
    }
}

/// Serves DNS refusal responses over TCP.
fn tcp_dns_stub_loop(listener: &TcpListener) {
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let _ = thread::Builder::new()
                    .name("firma-guest-dns-tcp-conn".to_string())
                    .spawn(move || {
                        if let Err(error) = handle_tcp_dns_stub_connection(stream) {
                            log(&format!("guest TCP DNS refusal stub failed: {error}"));
                        }
                    });
            }
            Err(error) => log(&format!(
                "guest TCP DNS refusal stub accept failed: {error}"
            )),
        }
    }
}

/// Reads one TCP DNS query at a time and responds with RCODE=REFUSED.
fn handle_tcp_dns_stub_connection(mut stream: TcpStream) -> InitResult<()> {
    loop {
        let mut length = [0_u8; 2];
        if let Err(error) = stream.read_exact(&mut length) {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                Ok(())
            } else {
                Err(InitError::DnsTcpReadLength { source: error })
            };
        }
        let query_len = usize::from(u16::from_be_bytes(length));
        let mut query = vec![0_u8; query_len];
        stream
            .read_exact(&mut query)
            .map_err(|source| InitError::DnsTcpReadBody { source })?;
        let Some(response) = dns_refused_response(&query) else {
            continue;
        };
        let response_len = u16::try_from(response.len()).map_err(|_| {
            network_setup(format!(
                "TCP DNS response too large: {} bytes",
                response.len()
            ))
        })?;
        stream
            .write_all(&response_len.to_be_bytes())
            .map_err(|source| InitError::DnsTcpWriteLength { source })?;
        stream
            .write_all(&response)
            .map_err(|source| InitError::DnsTcpWriteBody { source })?;
    }
}

/// Builds a DNS response that refuses the original query.
fn dns_refused_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let refused_flags = 0x8000 | (request_flags & 0x0100) | u16::from(DNS_REFUSED_RCODE);

    let mut response = Vec::with_capacity(query.len());
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&refused_flags.to_be_bytes());
    response.extend_from_slice(&query[4..6]);
    response.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    response.extend_from_slice(&query[12..]);
    Some(response)
}

/// Points guest resolver configuration at the local DNS refusal stub.
fn write_resolv_conf(dns_stub_addr: SocketAddr) -> InitResult<()> {
    create_dir("/etc")?;
    let content = format!(
        "nameserver {}\noptions attempts:1 timeout:1\n",
        dns_stub_addr.ip()
    );
    fs::write(RESOLV_CONF, content).map_err(|source| InitError::ResolvConfWrite { source })?;
    log(&format!(
        "wrote {RESOLV_CONF} for guest DNS stub {}",
        dns_stub_addr.ip()
    ));
    Ok(())
}

/// Connects to a host service using the Linux `AF_VSOCK` host CID.
pub fn connect_vsock_host(port: u32) -> io::Result<File> {
    let socket = open_vsock_socket()?;
    let family = libc::sa_family_t::try_from(AF_VSOCK)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "AF_VSOCK out of range"))?;
    let addr = SockAddrVm {
        family,
        reserved1: 0,
        port,
        cid: VMADDR_CID_HOST,
        zero: [0; 4],
    };
    let len = libc::socklen_t::try_from(std::mem::size_of::<SockAddrVm>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "sockaddr_vm length does not fit socklen_t",
        )
    })?;
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            len,
        )
    };
    if result == 0 {
        Ok(File::from(socket))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Opens a raw Linux `AF_VSOCK` stream socket.
fn open_vsock_socket() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

/// Converts a static setup failure into an init error.
fn network_setup(detail: impl Into<String>) -> InitError {
    InitError::GuestNetworkSetup {
        detail: detail.into(),
    }
}

/// Linux `sockaddr_vm` layout used for raw `AF_VSOCK` connects.
#[repr(C)]
struct SockAddrVm {
    family: libc::sa_family_t,
    reserved1: libc::c_ushort,
    port: libc::c_uint,
    cid: libc::c_uint,
    zero: [u8; 4],
}

/// Linux `ifreq` layout for reading and setting interface flags.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    value: IfReqValue,
}

impl IfReq {
    /// Builds an `ifreq` for an ASCII interface name.
    fn named(name: &str) -> InitResult<Self> {
        let bytes = name.as_bytes();
        if bytes.len() >= IFNAMSIZ {
            return Err(network_setup(format!("interface name too long: {name}")));
        }
        let mut request = Self {
            name: [0; IFNAMSIZ],
            value: IfReqValue { flags: 0 },
        };
        for (target, source) in request.name.iter_mut().zip(bytes.iter().copied()) {
            *target = libc::c_char::try_from(source)
                .map_err(|_| network_setup(format!("interface name is not ASCII: {name}")))?;
        }
        Ok(request)
    }
}

/// Value union for the `ifreq` calls used in this file.
#[repr(C)]
union IfReqValue {
    flags: libc::c_short,
    addr: libc::sockaddr,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::num::NonZeroU32;
    use std::thread;

    use super::super::contract::{Contract, LaunchContract};
    use super::super::error::InitError;
    use super::{
        BodyKind, CommandNetworkEnv, DnsPlan, GuestDnsListener, GuestDnsListeners,
        GuestNetworkListeners, GuestProxyListener, IfReq, NetworkServicesPlan, ProxyPlan,
        copy_exact_bytes, dns_refused_response, ensure_buffered, find_crlf, find_header_terminator,
        forward_requests_with_header_injection, handle_guest_proxy_connection,
        handle_tcp_dns_stub_connection, parse_request_metadata, read_until_crlf,
        read_until_header_block, replace_attribution_headers, start_guest_http_proxy,
        tcp_dns_stub_loop, udp_dns_stub_loop,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    const VALID_CONTRACT_JSON: &str = include_str!("fixtures/valid-contract.json");

    #[test]
    fn network_services_plan_accepts_proxy_dns_and_command_env() -> TestResult {
        let mut launch = valid_launch_contract()?;
        launch
            .command
            .env
            .insert("HTTP_PROXY".to_string(), "http://host-proxy".to_string());
        launch
            .command
            .env
            .insert("http_proxy".to_string(), "http://host-proxy".to_string());
        launch
            .command
            .env
            .insert("FIRMA_VSOCK_SIDECAR_PORT".to_string(), "1".to_string());
        launch
            .command
            .env
            .insert("CUSTOM_ENV".to_string(), "kept".to_string());
        let contract: Contract = launch.try_into()?;

        let plan = NetworkServicesPlan::try_from(&contract)?;
        let env = plan.command_env().as_map();

        assert_eq!(
            plan.proxy.guest_http_proxy_addr.to_string(),
            "127.0.0.1:18080"
        );
        assert_eq!(plan.proxy.vsock_sidecar_port.get(), 18080);
        assert_eq!(plan.dns.guest_dns_stub_addr.to_string(), "127.0.0.1:1053");
        assert_eq!(
            env.get("HTTP_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18080")
        );
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18080")
        );
        assert_eq!(
            env.get("ALL_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18080")
        );
        assert_eq!(
            env.get("http_proxy").map(String::as_str),
            Some("http://127.0.0.1:18080")
        );
        assert_eq!(
            env.get("https_proxy").map(String::as_str),
            Some("http://127.0.0.1:18080")
        );
        assert_eq!(
            env.get("all_proxy").map(String::as_str),
            Some("http://127.0.0.1:18080")
        );
        assert_eq!(
            env.get("NO_PROXY").map(String::as_str),
            Some("127.0.0.1,localhost,::1")
        );
        assert_eq!(
            env.get("no_proxy").map(String::as_str),
            Some("127.0.0.1,localhost,::1")
        );
        assert_eq!(
            env.get("FIRMA_DNS_STUB_ADDR").map(String::as_str),
            Some("127.0.0.1:1053")
        );
        assert_eq!(
            env.get("FIRMA_VSOCK_SIDECAR_PORT").map(String::as_str),
            Some("18080")
        );
        assert_eq!(env.get("CUSTOM_ENV").map(String::as_str), Some("kept"));

        Ok(())
    }

    #[test]
    fn command_env_exports_terminal_pty_ports_when_accepted() -> TestResult {
        let mut launch = valid_launch_contract()?;
        launch.terminal.interactive = true;
        launch.terminal.pty = true;
        launch.terminal.pty_vsock_port = Some(18_081);
        launch.terminal.pty_control_vsock_port = Some(18_082);
        launch.terminal.term = Some("xterm-256color".to_string());
        let contract: Contract = launch.try_into()?;

        let plan = NetworkServicesPlan::try_from(&contract)?;
        let env = plan.command_env().as_map();

        assert_eq!(env.get("TERM").map(String::as_str), Some("xterm-256color"));
        assert_eq!(
            env.get("FIRMA_VSOCK_COMMAND_PTY_PORT").map(String::as_str),
            Some("18081")
        );
        assert_eq!(
            env.get("FIRMA_VSOCK_COMMAND_PTY_CONTROL_PORT")
                .map(String::as_str),
            Some("18082")
        );

        Ok(())
    }

    #[test]
    fn dns_listener_addrs_include_resolver_port_once() -> TestResult {
        let stub_addr: SocketAddr = "127.0.0.1:1053".parse()?;
        let resolver_addr: SocketAddr = "127.0.0.1:53".parse()?;

        assert_eq!(
            super::dns_listener_addrs(stub_addr),
            vec![stub_addr, resolver_addr]
        );
        assert_eq!(
            super::dns_listener_addrs(resolver_addr),
            vec![resolver_addr]
        );

        Ok(())
    }

    #[test]
    fn network_listeners_report_proxy_bind_conflicts_before_dns() -> TestResult {
        let existing = TcpListener::bind("127.0.0.1:0")?;
        let addr = existing.local_addr()?;
        let Some(vsock_sidecar_port) = NonZeroU32::new(18080) else {
            return Err(io::Error::other("test VSOCK port must be non-zero").into());
        };

        let plan = NetworkServicesPlan {
            proxy: ProxyPlan {
                guest_http_proxy_addr: addr,
                vsock_sidecar_port,
                attribution_headers: BTreeMap::new(),
            },
            dns: DnsPlan {
                guest_dns_stub_addr: "127.0.0.1:1053".parse()?,
            },
            env: CommandNetworkEnv {
                values: BTreeMap::new(),
            },
        };

        let error = expect_init_error(
            GuestNetworkListeners::bind(&plan),
            "network listeners should bind proxy before DNS",
        )?;

        assert!(matches!(
            error,
            InitError::ProxyBind { addr: error_addr, source: _ } if error_addr == addr
        ));

        Ok(())
    }

    #[test]
    fn dns_listener_binds_ephemeral_udp_and_tcp_sockets() -> TestResult {
        let udp = GuestDnsListener::bind_udp("127.0.0.1:0".parse()?)?;
        let tcp = GuestDnsListener::bind_tcp("127.0.0.1:0".parse()?)?;

        match udp {
            GuestDnsListener::Udp { socket, .. } => {
                assert_ne!(socket.local_addr()?.port(), 0);
            }
            GuestDnsListener::Tcp { .. } => {
                return Err(io::Error::other("UDP listener fixture returned TCP").into());
            }
        }

        match tcp {
            GuestDnsListener::Tcp { listener, .. } => {
                assert_ne!(listener.local_addr()?.port(), 0);
            }
            GuestDnsListener::Udp { .. } => {
                return Err(io::Error::other("TCP listener fixture returned UDP").into());
            }
        }

        Ok(())
    }

    #[test]
    fn prepared_dns_listener_start_returns_lifetime_handle() -> TestResult {
        let listener = GuestDnsListener::bind_udp("127.0.0.1:0".parse()?)?;
        let handle = listener.start()?;

        assert_eq!(
            handle.thread().name(),
            Some("firma-guest-dns-udp-127.0.0.1:0")
        );
        assert!(!handle.is_finished());

        drop(handle);

        Ok(())
    }

    #[test]
    fn prepared_proxy_listener_start_returns_lifetime_handle() -> TestResult {
        let Some(vsock_sidecar_port) = NonZeroU32::new(18080) else {
            return Err(io::Error::other("test VSOCK port must be non-zero").into());
        };

        let proxy = GuestProxyListener::bind(&ProxyPlan {
            guest_http_proxy_addr: "127.0.0.1:0".parse()?,
            vsock_sidecar_port,
            attribution_headers: BTreeMap::new(),
        })?;

        let handle = start_guest_http_proxy(proxy)?;

        assert_eq!(handle.thread().name(), Some("firma-guest-http-proxy"));
        assert!(!handle.is_finished());

        drop(handle);

        Ok(())
    }

    #[test]
    fn prepared_network_listeners_start_all_service_threads() -> TestResult {
        let Some(vsock_sidecar_port) = NonZeroU32::new(18080) else {
            return Err(io::Error::other("test VSOCK port must be non-zero").into());
        };

        let proxy = GuestProxyListener::bind(&ProxyPlan {
            guest_http_proxy_addr: "127.0.0.1:0".parse()?,
            vsock_sidecar_port,
            attribution_headers: BTreeMap::new(),
        })?;

        let dns = GuestDnsListeners {
            stub_addr: "127.0.0.1:1053".parse()?,
            resolver_addr: "127.0.0.1:53".parse()?,
            listeners: vec![
                GuestDnsListener::bind_udp("127.0.0.1:0".parse()?)?,
                GuestDnsListener::bind_tcp("127.0.0.1:0".parse()?)?,
            ],
        };

        let listeners = GuestNetworkListeners { proxy, dns };
        let services = listeners.start()?;

        assert_eq!(services.thread_count(), 3);
        let thread_names = services.thread_names().collect::<Vec<_>>();
        assert!(thread_names.contains(&Some("firma-guest-http-proxy")));
        assert!(
            thread_names
                .iter()
                .any(|name| name.is_some_and(|name| name.starts_with("firma-guest-dns-udp-")))
        );
        assert!(
            thread_names
                .iter()
                .any(|name| name.is_some_and(|name| name.starts_with("firma-guest-dns-tcp-")))
        );

        Ok(())
    }

    #[test]
    fn proxy_connection_reports_vsock_connect_failure() -> TestResult {
        let (_client, server) = connected_tcp_pair()?;
        let headers = BTreeMap::new();

        let error = expect_init_error(
            handle_guest_proxy_connection(server, 18080, &headers),
            "proxy connection should fail before request forwarding when VSOCK is unavailable",
        )?;

        assert!(matches!(error, InitError::VsockConnect { .. }));

        Ok(())
    }

    #[test]
    fn proxy_listener_reports_bind_conflicts_before_serving() -> TestResult {
        let existing = TcpListener::bind("127.0.0.1:0")?;
        let addr = existing.local_addr()?;
        let Some(vsock_sidecar_port) = NonZeroU32::new(18080) else {
            return Err(io::Error::other("test VSOCK port must be non-zero").into());
        };
        let plan = ProxyPlan {
            guest_http_proxy_addr: addr,
            vsock_sidecar_port,
            attribution_headers: BTreeMap::new(),
        };

        let error = expect_init_error(
            GuestProxyListener::bind(&plan),
            "proxy bind should fail while the address is already held",
        )?;

        assert!(matches!(
            error,
            InitError::ProxyBind { addr: error_addr, source: _ } if error_addr == addr
        ));

        Ok(())
    }

    #[test]
    fn dns_listener_reports_udp_bind_conflicts_before_serving() -> TestResult {
        let existing = UdpSocket::bind("127.0.0.1:0")?;
        let addr = existing.local_addr()?;
        let plan = DnsPlan {
            guest_dns_stub_addr: addr,
        };

        let error = expect_init_error(
            GuestDnsListeners::bind(&plan),
            "DNS UDP bind should fail while the address is already held",
        )?;

        assert!(matches!(
            error,
            InitError::DnsUdpBind { addr: error_addr, source: _ } if error_addr == addr
        ));

        Ok(())
    }

    #[test]
    fn dns_listener_reports_tcp_bind_conflicts_before_serving() -> TestResult {
        let existing = TcpListener::bind("127.0.0.1:0")?;
        let addr = existing.local_addr()?;
        let plan = DnsPlan {
            guest_dns_stub_addr: addr,
        };

        let error = expect_init_error(
            GuestDnsListeners::bind(&plan),
            "DNS TCP bind should fail while the address is already held",
        )?;

        assert!(matches!(
            error,
            InitError::DnsTcpBind { addr: error_addr, source: _ } if error_addr == addr
        ));

        Ok(())
    }

    #[test]
    fn ifreq_rejects_interface_names_that_do_not_fit() -> TestResult {
        let name = "x".repeat(super::IFNAMSIZ);

        let error = expect_init_error(
            IfReq::named(&name),
            "Linux ifreq names reserve one byte for the terminator",
        )?;

        assert!(matches!(
            error,
            InitError::GuestNetworkSetup { detail }
                if detail == format!("interface name too long: {name}")
        ));

        Ok(())
    }

    #[test]
    fn ifreq_accepts_short_ascii_interface_names() -> TestResult {
        let request = IfReq::named("lo")?;

        assert_eq!(request.name[0], libc::c_char::try_from(b'l')?);
        assert_eq!(request.name[1], libc::c_char::try_from(b'o')?);
        assert_eq!(request.name[2], 0);

        Ok(())
    }

    #[test]
    fn replaces_untrusted_attribution_headers_case_insensitively() -> TestResult {
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Firma-Sandbox-Id: spoofed\r\nx-firma-session: spoofed\r\nX-Firma-Agent: spoofed\r\nX-Unrelated: retained\r\n".to_vec();
        let headers = BTreeMap::from([
            (
                "x-firma-sandbox-id".to_string(),
                "01900000-0000-7000-8000-000000000001".to_string(),
            ),
            ("X-Firma-Agent".to_string(), "guest".to_string()),
            ("X-Firma-Session".to_string(), "new".to_string()),
        ]);

        replace_attribution_headers(&mut request, &headers)?;

        let request = String::from_utf8(request)?;
        assert!(request.contains("\r\nX-Firma-Agent: guest\r\n"));
        assert!(request.contains("\r\nX-Firma-Session: new\r\n"));
        assert!(
            request.contains("\r\nx-firma-sandbox-id: 01900000-0000-7000-8000-000000000001\r\n")
        );
        assert!(request.contains("\r\nX-Unrelated: retained\r\n"));
        assert!(!request.contains("spoofed"));

        Ok(())
    }

    #[test]
    fn forwards_content_length_request_with_attribution_headers() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        let headers = BTreeMap::from([("X-Firma-Session".to_string(), "session-test".to_string())]);
        server.write_all(
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
        )?;
        server.shutdown(Shutdown::Write)?;
        let mut upstream = Vec::new();

        forward_requests_with_header_injection(&mut client, &mut upstream, &headers)?;

        let forwarded = String::from_utf8(upstream)?;
        assert!(forwarded.contains("\r\nX-Firma-Session: session-test\r\n"));
        assert!(forwarded.ends_with("\r\n\r\nhello"));

        Ok(())
    }

    #[test]
    fn forwards_chunked_request_with_trailers() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        let headers = BTreeMap::from([("X-Firma-Session".to_string(), "session-test".to_string())]);
        server.write_all(
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\nX-Firma-Trailer: yes\r\n\r\n",
        )?;
        server.shutdown(Shutdown::Write)?;
        let mut upstream = Vec::new();

        forward_requests_with_header_injection(&mut client, &mut upstream, &headers)?;

        let forwarded = String::from_utf8(upstream)?;
        assert!(forwarded.contains("\r\nX-Firma-Session: session-test\r\n"));
        assert!(forwarded.ends_with("4\r\nWiki\r\n0\r\nX-Firma-Trailer: yes\r\n\r\n"));

        Ok(())
    }

    #[test]
    fn forwards_connect_tunnel_bytes_after_headers() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        let headers = BTreeMap::from([("X-Firma-Session".to_string(), "session-test".to_string())]);
        server.write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\ntunnel-bytes",
        )?;
        server.shutdown(Shutdown::Write)?;
        let mut upstream = Vec::new();

        forward_requests_with_header_injection(&mut client, &mut upstream, &headers)?;

        let forwarded = String::from_utf8(upstream)?;
        assert!(forwarded.contains("\r\nX-Firma-Session: session-test\r\n"));
        assert!(forwarded.ends_with("\r\n\r\ntunnel-bytes"));

        Ok(())
    }

    #[test]
    fn forwards_pipelined_requests_from_buffered_remaining_bytes() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        let headers = BTreeMap::from([("X-Firma-Session".to_string(), "session-test".to_string())]);
        server.write_all(
            b"GET http://example.com/one HTTP/1.1\r\nHost: example.com\r\n\r\n\
              GET http://example.com/two HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )?;
        server.shutdown(Shutdown::Write)?;
        let mut upstream = Vec::new();

        forward_requests_with_header_injection(&mut client, &mut upstream, &headers)?;

        let forwarded = String::from_utf8(upstream)?;
        assert!(forwarded.contains("GET http://example.com/one HTTP/1.1\r\n"));
        assert!(forwarded.contains("GET http://example.com/two HTTP/1.1\r\n"));
        assert_eq!(
            forwarded
                .matches("\r\nX-Firma-Session: session-test\r\n")
                .count(),
            2
        );

        Ok(())
    }

    #[test]
    fn forwarding_rejects_invalid_chunk_size_lines() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        let headers = BTreeMap::new();
        server.write_all(
            b"POST http://example.com/ HTTP/1.1\r\n\
              Host: example.com\r\n\
              Transfer-Encoding: chunked\r\n\r\n\
              not-hex\r\n",
        )?;

        server.shutdown(Shutdown::Write)?;
        let mut upstream = Vec::new();

        let error = forward_requests_with_header_injection(&mut client, &mut upstream, &headers);

        assert!(matches!(error, Err(error) if error.kind() == io::ErrorKind::InvalidData));

        Ok(())
    }

    #[test]
    fn replace_attribution_headers_rejects_non_utf8_requests() {
        let mut request = vec![0xff, b'\r', b'\n'];
        let headers = BTreeMap::from([("X-Firma-Agent".to_string(), "guest".to_string())]);

        let error = replace_attribution_headers(&mut request, &headers);

        assert!(matches!(error, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    #[test]
    fn parses_request_body_modes() -> TestResult {
        let none =
            parse_request_metadata(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443")?;
        assert_eq!(none.method, "CONNECT");
        assert_eq!(none.body, BodyKind::None);

        let length = parse_request_metadata(
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5",
        )?;
        assert_eq!(length.method, "POST");
        assert_eq!(length.body, BodyKind::ContentLength(5));

        let chunked = parse_request_metadata(
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked",
        )?;

        assert_eq!(chunked.method, "POST");
        assert_eq!(chunked.body, BodyKind::Chunked);

        Ok(())
    }

    #[test]
    fn parses_zero_and_invalid_content_lengths_as_no_body() -> TestResult {
        let zero = parse_request_metadata(
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0",
        )?;
        assert_eq!(zero.body, BodyKind::None);

        let invalid = parse_request_metadata(
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: nope",
        )?;
        assert_eq!(invalid.body, BodyKind::None);

        Ok(())
    }

    #[test]
    fn parse_request_metadata_rejects_non_utf8_headers() {
        let error = parse_request_metadata(&[0xff, b'\r', b'\n']);

        assert!(matches!(error, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    #[test]
    fn finds_http_header_terminator() {
        let request = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\nbody";

        assert_eq!(find_header_terminator(request), Some(51));
    }

    #[test]
    fn read_until_header_block_uses_buffered_headers_first() -> TestResult {
        let (mut client, _server) = connected_tcp_pair()?;
        let header = b"GET / HTTP/1.1\r\nHost: example.com";
        let mut buffer = [header.as_slice(), b"\r\n\r\nbody"].concat();

        let header_end = read_until_header_block(&mut client, &mut buffer)?;

        assert_eq!(header_end, Some(header.len()));

        Ok(())
    }

    #[test]
    fn read_until_header_block_reads_headers_from_socket() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        let header = b"GET / HTTP/1.1\r\nHost: example.com";
        server.write_all(&[header.as_slice(), b"\r\n\r\n"].concat())?;
        server.shutdown(Shutdown::Write)?;
        let mut buffer = Vec::new();

        let header_end = read_until_header_block(&mut client, &mut buffer)?;

        assert_eq!(header_end, Some(header.len()));
        assert_eq!(buffer, [header.as_slice(), b"\r\n\r\n"].concat());

        Ok(())
    }

    #[test]
    fn read_until_header_block_rejects_oversized_headers() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        let mut buffer = vec![b'a'; 1024 * 128 + 1];
        server.write_all(b"x")?;
        server.shutdown(Shutdown::Write)?;

        let error = read_until_header_block(&mut client, &mut buffer);

        assert!(matches!(error, Err(error) if error.kind() == io::ErrorKind::InvalidData));

        Ok(())
    }

    #[test]
    fn read_until_header_block_reports_mid_header_eof() -> TestResult {
        let (mut client, server) = connected_tcp_pair()?;
        server.shutdown(Shutdown::Write)?;
        let mut buffer = b"GET / HTTP/1.1\r\nHost: example.com".to_vec();

        let error = read_until_header_block(&mut client, &mut buffer);

        assert!(matches!(error, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof));

        Ok(())
    }

    #[test]
    fn read_until_header_block_returns_none_for_clean_eof() -> TestResult {
        let (mut client, server) = connected_tcp_pair()?;
        server.shutdown(Shutdown::Write)?;
        let mut buffer = Vec::new();

        let header_end = read_until_header_block(&mut client, &mut buffer)?;

        assert_eq!(header_end, None);

        Ok(())
    }

    #[test]
    fn ensure_buffered_reads_until_requested_size() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        server.write_all(b"abcd")?;
        server.shutdown(Shutdown::Write)?;
        let mut buffer = Vec::new();

        ensure_buffered(&mut client, &mut buffer, 4)?;

        assert_eq!(buffer, b"abcd");
        Ok(())
    }

    #[test]
    fn ensure_buffered_reports_eof_before_requested_size() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        server.write_all(b"ab")?;
        server.shutdown(Shutdown::Write)?;
        let mut buffer = Vec::new();

        let error = ensure_buffered(&mut client, &mut buffer, 4);

        assert!(matches!(error, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof));

        Ok(())
    }

    #[test]
    fn copy_exact_bytes_copies_only_requested_body_bytes() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        server.write_all(b"abcdef")?;
        server.shutdown(Shutdown::Write)?;
        let mut output = Vec::new();

        copy_exact_bytes(&mut client, &mut output, 4)?;

        assert_eq!(output, b"abcd");

        Ok(())
    }

    #[test]
    fn copy_exact_bytes_reports_mid_body_eof() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        server.write_all(b"ab")?;
        server.shutdown(Shutdown::Write)?;
        let mut output = Vec::new();

        let error = copy_exact_bytes(&mut client, &mut output, 4);

        assert!(matches!(error, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof));

        Ok(())
    }

    #[test]
    fn finds_crlf_line_boundaries() {
        assert_eq!(find_crlf(b"4\r\nWiki"), Some(1));
        assert_eq!(find_crlf(b"no terminator"), None);
    }

    #[test]
    fn read_until_crlf_uses_buffered_line_first() -> TestResult {
        let (mut client, _server) = connected_tcp_pair()?;
        let mut buffer = b"4\r\nWiki".to_vec();

        let line_end = read_until_crlf(&mut client, &mut buffer)?;

        assert_eq!(line_end, 1);

        Ok(())
    }

    #[test]
    fn read_until_crlf_reads_line_from_socket() -> TestResult {
        let (mut client, mut server) = connected_tcp_pair()?;
        server.write_all(b"4\r\nWiki")?;
        server.shutdown(Shutdown::Write)?;
        let mut buffer = Vec::new();

        let line_end = read_until_crlf(&mut client, &mut buffer)?;

        assert_eq!(line_end, 1);
        assert_eq!(buffer, b"4\r\nWiki");

        Ok(())
    }

    #[test]
    fn read_until_crlf_reports_eof_before_line_end() -> TestResult {
        let (mut client, server) = connected_tcp_pair()?;
        server.shutdown(Shutdown::Write)?;
        let mut buffer = b"4".to_vec();

        let error = read_until_crlf(&mut client, &mut buffer);

        assert!(matches!(error, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof));
        Ok(())
    }

    #[test]
    fn dns_refused_response_preserves_query_and_sets_rcode() {
        let query = [
            0x46, 0x7a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b't',
            b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let response = dns_refused_response(&query);

        assert!(matches!(
            response.as_deref(),
            Some(response)
                if response[0..2] == query[0..2]
                    && response[2] & 0x80 == 0x80
                    && response[3] & 0x0f == 5
                    && response[4..6] == query[4..6]
                    && response[12..] == query[12..]
        ));
    }

    #[test]
    fn dns_refused_response_rejects_short_queries() {
        assert_eq!(dns_refused_response(&[0_u8; 11]), None);
    }

    #[test]
    fn tcp_dns_stub_connection_refuses_query_and_exits_on_eof() -> TestResult {
        let (mut client, server) = connected_tcp_pair()?;
        let query = dns_query();
        let handle = thread::spawn(move || handle_tcp_dns_stub_connection(server));

        client.write_all(&u16::try_from(query.len())?.to_be_bytes())?;
        client.write_all(&query)?;
        client.shutdown(Shutdown::Write)?;

        let mut response_len = [0_u8; 2];
        client.read_exact(&mut response_len)?;
        let mut response = vec![0_u8; usize::from(u16::from_be_bytes(response_len))];
        client.read_exact(&mut response)?;

        join_dns_handler(handle)??;

        assert_eq!(response[0..2], query[0..2]);
        assert_eq!(response[3] & 0x0f, super::DNS_REFUSED_RCODE);

        Ok(())
    }

    #[test]
    fn udp_dns_stub_loop_refuses_queries() -> TestResult {
        let server = UdpSocket::bind("127.0.0.1:0")?;
        let server_addr = server.local_addr()?;
        let client = UdpSocket::bind("127.0.0.1:0")?;
        client.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        let handle = thread::Builder::new()
            .name("test-udp-dns-stub".to_string())
            .spawn(move || udp_dns_stub_loop(&server))?;
        let query = dns_query();

        client.send_to(&query, server_addr)?;
        let mut response = [0_u8; 512];
        let read = client.recv(&mut response)?;

        assert_eq!(response[0..2], query[0..2]);
        assert_eq!(response[3] & 0x0f, super::DNS_REFUSED_RCODE);
        assert!(read >= query.len());

        drop(handle);

        Ok(())
    }

    #[test]
    fn tcp_dns_stub_loop_refuses_queries() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::Builder::new()
            .name("test-tcp-dns-stub".to_string())
            .spawn(move || tcp_dns_stub_loop(&listener))?;
        let mut client = TcpStream::connect(addr)?;
        let query = dns_query();

        client.write_all(&u16::try_from(query.len())?.to_be_bytes())?;
        client.write_all(&query)?;

        let mut response_len = [0_u8; 2];
        client.read_exact(&mut response_len)?;
        let mut response = vec![0_u8; usize::from(u16::from_be_bytes(response_len))];
        client.read_exact(&mut response)?;

        assert_eq!(response[0..2], query[0..2]);
        assert_eq!(response[3] & 0x0f, super::DNS_REFUSED_RCODE);

        drop(handle);

        Ok(())
    }

    #[test]
    fn tcp_dns_stub_connection_ignores_invalid_short_queries() -> TestResult {
        let (mut client, server) = connected_tcp_pair()?;
        let handle = thread::spawn(move || handle_tcp_dns_stub_connection(server));

        client.write_all(&2_u16.to_be_bytes())?;
        client.write_all(&[0x46, 0x7a])?;
        client.shutdown(Shutdown::Write)?;

        let mut response = [0_u8; 2];
        assert_eq!(client.read(&mut response)?, 0);
        join_dns_handler(handle)??;

        Ok(())
    }

    #[test]
    fn tcp_dns_stub_connection_reports_short_query_body() -> TestResult {
        let (mut client, server) = connected_tcp_pair()?;

        client.write_all(&4_u16.to_be_bytes())?;
        client.write_all(&[0x46, 0x7a])?;
        client.shutdown(Shutdown::Write)?;

        let error = expect_init_error(
            handle_tcp_dns_stub_connection(server),
            "short TCP DNS body should fail with a typed read-body error",
        )?;

        assert!(matches!(error, InitError::DnsTcpReadBody { .. }));

        Ok(())
    }

    fn expect_init_error<T>(
        result: super::super::error::InitResult<T>,
        message: &'static str,
    ) -> Result<InitError, Box<dyn Error>> {
        let Err(error) = result else {
            return Err(io::Error::other(message).into());
        };

        Ok(error)
    }

    fn connected_tcp_pair() -> TestResult<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;

        Ok((client, server))
    }

    /// Builds a minimal DNS query packet for "A test".
    /// The TCP DNS stub test only needs a valid-enough query so it can verify that
    /// the response preserves the transaction ID/question and sets RCODE=REFUSED.
    ///
    /// 0x46 0x7a        transaction ID
    /// 0x01 0x00        standard query with recursion desired
    /// 0x00 0x01        one question
    /// 0x00 0x00        no answers
    /// 0x00 0x00        no authority records
    /// 0x00 0x00        no additional records
    /// 0x04 test 0x00   query name test.
    /// 0x00 0x01        QTYPE A
    /// 0x00 0x01        QCLASS IN
    fn dns_query() -> Vec<u8> {
        vec![
            0x46, 0x7a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b't',
            b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
        ]
    }

    fn join_dns_handler(
        handle: thread::JoinHandle<super::super::error::InitResult<()>>,
    ) -> Result<super::super::error::InitResult<()>, Box<dyn Error>> {
        handle.join().map_or_else(
            |_| Err(io::Error::other("TCP DNS handler thread panicked").into()),
            Ok,
        )
    }

    fn valid_launch_contract() -> TestResult<LaunchContract> {
        Ok(serde_json::from_str(VALID_CONTRACT_JSON)?)
    }
}
