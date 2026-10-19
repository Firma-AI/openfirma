use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use serde::Deserialize;

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
const BROKER_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const BROKER_PROBE_RETRY_INTERVAL: Duration = Duration::from_millis(25);
const BROKER_RESPONSE_LIMIT: u64 = 64 * 1024;
const BROKER_CONTROL_VERSION: u32 = 1;
const BROKER_READINESS_REQUEST: &[u8] = b"{\"control\":{\"type\":\"readiness\",\"version\":1}}\n";
const BROKER_ADDR_ENV: &str = "FIRMA_SECRET_BROKER_ADDR";
const MAX_BROKER_CONNECTIONS: usize = 32;
const BROKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const BROKER_SUPERVISOR_TICK: Duration = Duration::from_millis(10);
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
    broker: Option<BrokerProxyPlan>,
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
        let broker = contract.secret_shims().map(|shims| BrokerProxyPlan {
            guest_broker_addr: shims.guest_broker_addr(),
            broker_vsock_port: shims.broker_vsock_port(),
        });
        let env = CommandNetworkEnv::from_contract(contract);

        Ok(Self {
            proxy,
            dns,
            broker,
            env,
        })
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

/// Accepted guest broker proxy configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BrokerProxyPlan {
    guest_broker_addr: SocketAddr,
    broker_vsock_port: std::num::NonZeroU32,
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

    /// Prepends a directory to the PATH environment variable.
    pub fn prepend_path(&mut self, dir: &std::path::Path) {
        let mut paths = vec![dir.to_path_buf()];
        if let Some(current) = self.values.get("PATH") {
            paths.extend(std::env::split_paths(current));
        }
        let new_path = std::env::join_paths(paths).map_or_else(
            |_| dir.to_string_lossy().into_owned(),
            |path| path.to_string_lossy().into_owned(),
        );
        self.values.insert("PATH".to_string(), new_path);
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
        if let Some(shims) = contract.secret_shims() {
            values.insert(
                BROKER_ADDR_ENV.to_string(),
                format!("tcp://{}", shims.guest_broker_addr()),
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
    broker: Option<GuestBrokerService>,
}

impl GuestNetworkServices {
    /// Returns how many service listener threads are owned by this handle.
    #[cfg(test)]
    pub fn thread_count(&self) -> usize {
        self.threads.len() + usize::from(self.broker.is_some())
    }

    /// Returns the prepared service thread names for tests.
    #[cfg(test)]
    fn thread_names(&self) -> impl Iterator<Item = Option<&str>> {
        self.threads
            .iter()
            .map(|thread| thread.thread().name())
            .chain(
                self.broker
                    .iter()
                    .filter_map(|broker| broker.thread.as_ref())
                    .map(|thread| thread.thread().name()),
            )
    }
}

impl Drop for GuestNetworkServices {
    /// Releases guest network listener handles when command execution ends.
    fn drop(&mut self) {
        if let Some(mut broker) = self.broker.take() {
            broker.shutdown();
        }
        self.threads.clear();
    }
}

/// Bound guest network sockets that have not started serving traffic yet.
struct GuestNetworkListeners {
    proxy: GuestProxyListener,
    dns: GuestDnsListeners,
    broker: Option<GuestBrokerListener>,
}

impl GuestNetworkListeners {
    /// Binds every guest network socket before any service thread is spawned.
    fn bind(plan: &NetworkServicesPlan) -> InitResult<Self> {
        let proxy = GuestProxyListener::bind(&plan.proxy)?;
        let broker = plan
            .broker
            .as_ref()
            .map(GuestBrokerListener::bind)
            .transpose()?;
        let dns = GuestDnsListeners::bind(&plan.dns)?;

        Ok(Self { proxy, dns, broker })
    }

    /// Starts all prepared guest network listeners.
    fn start(self) -> InitResult<GuestNetworkServices> {
        let mut threads = Vec::with_capacity(self.dns.listener_count() + 1);
        threads.push(start_guest_http_proxy(self.proxy)?);
        let broker = self.broker.map(GuestBrokerListener::start).transpose()?;
        threads.extend(self.dns.start()?);

        Ok(GuestNetworkServices { threads, broker })
    }
}

/// Prepared guest broker TCP listener.
struct GuestBrokerListener {
    addr: SocketAddr,
    listener: TcpListener,
    broker_vsock_port: u32,
}

impl GuestBrokerListener {
    /// Binds the guest broker endpoint before any command can start.
    fn bind(plan: &BrokerProxyPlan) -> InitResult<Self> {
        let addr = plan.guest_broker_addr;
        let listener = TcpListener::bind(addr)
            .map_err(|source| network_setup(format!("bind guest broker proxy {addr}: {source}")))?;

        Ok(Self {
            addr,
            listener,
            broker_vsock_port: plan.broker_vsock_port.get(),
        })
    }

    /// Starts the broker accept loop after every local socket is bound.
    fn start(self) -> InitResult<GuestBrokerService> {
        let Self {
            addr,
            listener,
            broker_vsock_port,
        } = self;
        let service = GuestBrokerService::start(listener, broker_vsock_port)?;

        log(&format!(
            "guest broker proxy listening at {addr} forwarding to host VSOCK port {broker_vsock_port}"
        ));
        Ok(service)
    }
}

/// Owned guest broker listener and forwarding supervisor.
struct GuestBrokerService {
    cancelled: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<InitResult<()>>>,
}

impl GuestBrokerService {
    fn start(listener: TcpListener, broker_vsock_port: u32) -> InitResult<Self> {
        Self::start_with_connector(
            listener,
            broker_vsock_port,
            Arc::new(connect_vsock_host_until),
        )
    }

    fn start_with_connector(
        listener: TcpListener,
        broker_vsock_port: u32,
        connector: Arc<GuestBrokerConnector>,
    ) -> InitResult<Self> {
        listener.set_nonblocking(true).map_err(|source| {
            network_setup(format!("configure guest broker proxy listener: {source}"))
        })?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let supervisor_cancelled = Arc::clone(&cancelled);
        let thread = thread::Builder::new()
            .name("firma-guest-broker-proxy".to_string())
            .spawn(move || {
                guest_broker_proxy_loop(
                    &listener,
                    broker_vsock_port,
                    &supervisor_cancelled,
                    &connector,
                )
            })
            .map_err(|source| {
                network_setup(format!("start guest broker proxy thread: {source}"))
            })?;

        Ok(Self {
            cancelled,
            thread: Some(thread),
        })
    }

    fn shutdown(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(supervisor) = self.thread.take() {
            match supervisor.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log(&format!("guest broker proxy failed: {error}")),
                Err(_) => log("guest broker proxy supervisor panicked during shutdown"),
            }
        }
    }
}

impl Drop for GuestBrokerService {
    fn drop(&mut self) {
        self.shutdown();
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

    let services = listeners.start()?;
    if let Some(broker) = &plan.broker {
        probe_guest_broker(broker.guest_broker_addr)?;
    }

    Ok(services)
}

/// Brings up the guest loopback interface used by the local proxy and DNS stub.
#[expect(
    unsafe_code,
    reason = "Loopback configuration requires a raw control socket, ifreq union access, and interface ioctls"
)]
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

/// Accepts shim clients and forwards their framed broker protocol unchanged.
fn guest_broker_proxy_loop(
    listener: &TcpListener,
    broker_vsock_port: u32,
    cancelled: &Arc<AtomicBool>,
    connector: &Arc<GuestBrokerConnector>,
) -> InitResult<()> {
    let mut connections = Vec::new();
    while !cancelled.load(Ordering::Acquire) {
        reap_guest_broker_connections(&mut connections);
        match listener.accept() {
            Ok((stream, _)) if connections.len() >= MAX_BROKER_CONNECTIONS => {
                let _ = stream.shutdown(Shutdown::Both);
                log(&format!(
                    "guest broker proxy rejected connection at capacity {MAX_BROKER_CONNECTIONS}"
                ));
            }
            Ok((stream, _)) => {
                match GuestBrokerConnection::spawn(
                    stream,
                    broker_vsock_port,
                    Arc::clone(connector),
                    Arc::clone(cancelled),
                ) {
                    Ok(connection) => connections.push(connection),
                    Err(error) => log(&format!("guest broker proxy connection failed: {error}")),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(BROKER_SUPERVISOR_TICK);
            }
            Err(source) => {
                return Err(network_setup(format!(
                    "accept guest broker proxy connection: {source}"
                )));
            }
        }
    }

    for connection in &mut connections {
        connection.cancel();
    }
    for connection in connections {
        report_guest_broker_connection(connection);
    }
    Ok(())
}

type GuestBrokerConnector = dyn Fn(u32, &AtomicBool, Instant) -> io::Result<File> + Send + Sync;

struct GuestBrokerConnection {
    client: Arc<TcpStream>,
    upstream: Arc<std::sync::Mutex<Option<Arc<File>>>>,
    cancelled: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<InitResult<()>>>,
}

impl GuestBrokerConnection {
    fn spawn(
        client: TcpStream,
        broker_vsock_port: u32,
        connector: Arc<GuestBrokerConnector>,
        cancelled: Arc<AtomicBool>,
    ) -> InitResult<Self> {
        client
            .set_nodelay(true)
            .map_err(|source| network_setup(format!("configure guest broker client: {source}")))?;
        let client = Arc::new(client);
        let upstream = Arc::new(std::sync::Mutex::new(None));
        let worker_client = Arc::clone(&client);
        let worker_upstream = Arc::clone(&upstream);
        let worker_cancelled = Arc::clone(&cancelled);
        let worker = thread::Builder::new()
            .name("firma-guest-broker-connection".to_string())
            .spawn(move || {
                run_guest_broker_connection(
                    &worker_client,
                    &worker_upstream,
                    &worker_cancelled,
                    broker_vsock_port,
                    connector.as_ref(),
                )
            })
            .map_err(|source| network_setup(format!("start guest broker connection: {source}")))?;

        Ok(Self {
            client,
            upstream,
            cancelled,
            worker: Some(worker),
        })
    }

    fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.client.shutdown(Shutdown::Both);
        if let Ok(upstream) = self.upstream.lock()
            && let Some(upstream) = upstream.as_ref()
        {
            let _ =
                nix::sys::socket::shutdown(upstream.as_raw_fd(), nix::sys::socket::Shutdown::Both);
        }
    }

    fn join(mut self) -> InitResult<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .unwrap_or_else(|_| Err(network_setup("guest broker connection worker panicked")))
    }
}

impl Drop for GuestBrokerConnection {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.cancel();
            let _ = worker.join();
        }
    }
}

fn run_guest_broker_connection(
    client: &Arc<TcpStream>,
    upstream_slot: &Arc<std::sync::Mutex<Option<Arc<File>>>>,
    cancelled: &Arc<AtomicBool>,
    broker_vsock_port: u32,
    connector: &GuestBrokerConnector,
) -> InitResult<()> {
    let upstream = connector(
        broker_vsock_port,
        cancelled.as_ref(),
        Instant::now() + BROKER_CONNECT_TIMEOUT,
    )
    .map(Arc::new)
    .map_err(|source| {
        network_setup(format!(
            "connect host broker VSOCK port {broker_vsock_port}: {source}"
        ))
    })?;
    {
        let mut slot = upstream_slot
            .lock()
            .map_err(|_| network_setup("guest broker upstream registry poisoned"))?;
        *slot = Some(Arc::clone(&upstream));
    }
    if cancelled.load(Ordering::Acquire) {
        shutdown_guest_broker_streams(client, &upstream);
        return Ok(());
    }

    relay_guest_broker_connection(client, &upstream)
}

fn relay_guest_broker_connection(client: &Arc<TcpStream>, upstream: &Arc<File>) -> InitResult<()> {
    let request_client = Arc::clone(client);
    let request_upstream = Arc::clone(upstream);
    let request = thread::Builder::new()
        .name("firma-guest-broker-request".to_string())
        .spawn(move || {
            copy_guest_broker_direction(
                request_client.as_ref(),
                request_upstream.as_ref(),
                request_client.as_ref(),
                request_upstream.as_ref(),
            )
            .map_err(|error| {
                io::Error::new(error.kind(), format!("copy guest broker request: {error}"))
            })
        })
        .map_err(|source| network_setup(format!("start guest broker request copy: {source}")))?;

    let response_client = Arc::clone(client);
    let response_upstream = Arc::clone(upstream);
    let response = match thread::Builder::new()
        .name("firma-guest-broker-response".to_string())
        .spawn(move || {
            copy_guest_broker_direction(
                response_upstream.as_ref(),
                response_client.as_ref(),
                response_client.as_ref(),
                response_upstream.as_ref(),
            )
            .map_err(|error| {
                io::Error::new(error.kind(), format!("copy host broker response: {error}"))
            })
        }) {
        Ok(worker) => worker,
        Err(source) => {
            shutdown_guest_broker_streams(client, upstream);
            let _ = request.join();
            return Err(network_setup(format!(
                "start guest broker response copy: {source}"
            )));
        }
    };

    let errors = [request, response]
        .into_iter()
        .filter_map(|worker| match worker.join() {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error.to_string()),
            Err(_) => Some("copy worker panicked".to_string()),
        })
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(network_setup(errors.join("; ")))
    }
}

fn copy_guest_broker_direction<R, W>(
    mut reader: &R,
    mut writer: &W,
    client: &TcpStream,
    upstream: &File,
) -> io::Result<()>
where
    for<'a> &'a R: Read,
    for<'a> &'a W: Write,
    W: AsRawFd,
{
    match io::copy(&mut reader, &mut writer) {
        Ok(_) => {
            shutdown_write(writer);
            Ok(())
        }
        Err(error) => {
            shutdown_guest_broker_streams(client, upstream);
            Err(error)
        }
    }
}

fn shutdown_write<T: AsRawFd>(stream: &T) {
    let _ = nix::sys::socket::shutdown(stream.as_raw_fd(), nix::sys::socket::Shutdown::Write);
}

fn shutdown_guest_broker_streams(client: &TcpStream, upstream: &File) {
    let _ = client.shutdown(Shutdown::Both);
    let _ = nix::sys::socket::shutdown(upstream.as_raw_fd(), nix::sys::socket::Shutdown::Both);
}

fn reap_guest_broker_connections(connections: &mut Vec<GuestBrokerConnection>) {
    let mut completed = Vec::new();
    let mut index = 0;
    while index < connections.len() {
        if connections[index].is_finished() {
            completed.push(connections.swap_remove(index));
        } else {
            index += 1;
        }
    }
    for connection in completed {
        report_guest_broker_connection(connection);
    }
}

fn report_guest_broker_connection(connection: GuestBrokerConnection) {
    if let Err(error) = connection.join() {
        log(&format!("guest broker proxy connection failed: {error}"));
    }
}

/// Proves that the complete local TCP to host broker path is protocol-ready.
fn probe_guest_broker(addr: SocketAddr) -> InitResult<()> {
    probe_guest_broker_until(addr, Instant::now() + BROKER_PROBE_TIMEOUT)
}

fn probe_guest_broker_until(addr: SocketAddr, deadline: Instant) -> InitResult<()> {
    loop {
        match probe_guest_broker_once(addr, deadline) {
            Ok(()) => {
                log("guest broker readiness probe succeeded");
                return Ok(());
            }
            Err(BrokerProbeFailure::Fatal(error)) => return Err(error),
            Err(BrokerProbeFailure::Retryable(error)) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(error);
                }
                thread::sleep(remaining.min(BROKER_PROBE_RETRY_INTERVAL));
            }
        }
    }
}

fn probe_guest_broker_once(addr: SocketAddr, deadline: Instant) -> Result<(), BrokerProbeFailure> {
    let mut stream =
        TcpStream::connect_timeout(&addr, probe_time_remaining(deadline)?).map_err(|source| {
            classify_connect_probe_io("connect guest broker readiness probe", &source)
        })?;
    stream
        .set_write_timeout(Some(probe_time_remaining(deadline)?))
        .map_err(|source| fatal_probe(format!("configure broker readiness probe: {source}")))?;
    stream
        .write_all(BROKER_READINESS_REQUEST)
        .map_err(|source| classify_probe_io("write broker readiness probe", &source))?;

    let mut response = Vec::new();
    stream
        .set_read_timeout(Some(probe_time_remaining(deadline)?))
        .map_err(|source| fatal_probe(format!("configure broker readiness probe: {source}")))?;
    BufReader::new(stream)
        .take(BROKER_RESPONSE_LIMIT + 1)
        .read_until(b'\n', &mut response)
        .map_err(|source| classify_probe_io("read broker readiness response", &source))?;
    let response_len = u64::try_from(response.len())
        .map_err(|_| fatal_probe("broker readiness response length overflow"))?;
    if response_len > BROKER_RESPONSE_LIMIT {
        return Err(fatal_probe(format!(
            "broker readiness response exceeded {BROKER_RESPONSE_LIMIT} bytes"
        )));
    }
    if !response.ends_with(b"\n") {
        return Err(BrokerProbeFailure::Retryable(network_setup(
            "broker readiness response ended before its newline terminator",
        )));
    }

    let response: BrokerProbeResponse = serde_json::from_slice(&response)
        .map_err(|source| {
            fatal_probe(format!(
                "host broker returned a malformed readiness response; install matching Firma CLI and VZ guest bundle: {source}"
            ))
        })?;
    match response {
        BrokerProbeResponse::Ready { version } if version == BROKER_CONTROL_VERSION => Ok(()),
        BrokerProbeResponse::Ready { version } => Err(fatal_probe(format!(
            "host broker readiness version {version} is incompatible with guest version {BROKER_CONTROL_VERSION}; install matching Firma CLI and VZ guest bundle"
        ))),
        BrokerProbeResponse::Rejected { error } => Err(fatal_probe(format!(
            "host broker rejected the readiness protocol; install matching Firma CLI and VZ guest bundle: {error}"
        ))),
    }
}

fn probe_time_remaining(deadline: Instant) -> Result<Duration, BrokerProbeFailure> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(BrokerProbeFailure::Retryable(network_setup(
            "broker readiness probe deadline elapsed",
        )));
    }
    Ok(remaining)
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum BrokerProbeResponse {
    Ready { version: u32 },
    Rejected { error: String },
}

enum BrokerProbeFailure {
    Retryable(InitError),
    Fatal(InitError),
}

fn fatal_probe(detail: impl Into<String>) -> BrokerProbeFailure {
    BrokerProbeFailure::Fatal(network_setup(detail))
}

fn retryable_probe_io(action: &str, source: &io::Error) -> BrokerProbeFailure {
    BrokerProbeFailure::Retryable(network_setup(format!("{action}: {source}")))
}

fn classify_connect_probe_io(action: &str, source: &io::Error) -> BrokerProbeFailure {
    match source.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::TimedOut
        | io::ErrorKind::WouldBlock => retryable_probe_io(action, source),
        _ => fatal_probe(format!("{action}: {source}")),
    }
}

fn classify_probe_io(action: &str, source: &io::Error) -> BrokerProbeFailure {
    match source.kind() {
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::TimedOut
        | io::ErrorKind::WouldBlock => retryable_probe_io(action, source),
        _ => fatal_probe(format!("{action}: {source}")),
    }
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
        let result = firma_http::forward_http1_requests(
            &mut client_reader,
            &mut vsock_writer,
            &attribution_headers,
            |_, _| {},
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
#[expect(
    unsafe_code,
    reason = "Connecting AF_VSOCK requires passing the initialized sockaddr_vm layout to libc"
)]
pub fn connect_vsock_host(port: u32) -> io::Result<File> {
    let socket = open_vsock_socket(0)?;
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

/// Connects to the host VSOCK broker without blocking past shutdown or deadline.
#[expect(
    unsafe_code,
    reason = "Nonblocking AF_VSOCK establishment requires connect and poll syscalls"
)]
fn connect_vsock_host_until(
    port: u32,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> io::Result<File> {
    let socket = open_vsock_socket(libc::SOCK_NONBLOCK)?;
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
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock
            && error.raw_os_error() != Some(libc::EINPROGRESS)
        {
            return Err(error);
        }
    }

    if result != 0 {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "guest broker shutdown cancelled host VSOCK connection",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "host broker VSOCK connection timed out after 1s",
                ));
            }
            let wait = deadline
                .saturating_duration_since(now)
                .min(BROKER_SUPERVISOR_TICK);
            let mut poll_fd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let timeout = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
            let poll_result = unsafe { libc::poll(std::ptr::from_mut(&mut poll_fd), 1, timeout) };
            if poll_result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if poll_result == 0 {
                continue;
            }
            let socket_error =
                nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::SocketError)
                    .map_err(io::Error::from)?;
            if socket_error != 0 {
                return Err(io::Error::from_raw_os_error(socket_error));
            }
            break;
        }
    }

    let mut flags = fcntl(&socket, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(io::Error::from)?;
    flags.remove(OFlag::O_NONBLOCK);
    fcntl(&socket, FcntlArg::F_SETFL(flags)).map_err(io::Error::from)?;
    Ok(File::from(socket))
}

/// Opens a raw Linux `AF_VSOCK` stream socket.
#[expect(
    unsafe_code,
    reason = "The standard library has no VSOCK constructor; libc returns a raw descriptor to adopt"
)]
fn open_vsock_socket(flags: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | flags, 0) };
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
    use std::fs::File;
    use std::io::{self, BufRead, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::num::NonZeroU32;
    use std::os::fd::OwnedFd;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::super::contract::{Contract, LaunchContract, SecretShimsContract};
    use super::super::error::InitError;
    use super::{
        BrokerProxyPlan, CommandNetworkEnv, DnsPlan, GuestBrokerConnection, GuestBrokerListener,
        GuestBrokerService, GuestDnsListener, GuestDnsListeners, GuestNetworkListeners,
        GuestProxyListener, IfReq, MAX_BROKER_CONNECTIONS, NetworkServicesPlan, ProxyPlan,
        dns_refused_response, handle_guest_proxy_connection, handle_tcp_dns_stub_connection,
        probe_guest_broker, probe_guest_broker_until, start_guest_http_proxy, tcp_dns_stub_loop,
        udp_dns_stub_loop,
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
    fn network_services_plan_adds_optional_broker_proxy_and_tcp_environment() -> TestResult {
        let mut launch = valid_launch_contract()?;
        launch.secret_shims = Some(valid_secret_shims_contract());
        let contract: Contract = launch.try_into()?;

        let plan = NetworkServicesPlan::try_from(&contract)?;
        let Some(broker) = plan.broker else {
            return Err(io::Error::other("network plan omitted broker proxy").into());
        };

        assert_eq!(broker.guest_broker_addr, "127.0.0.1:18083".parse()?);
        assert_eq!(broker.broker_vsock_port.get(), 18_083);
        assert_eq!(
            plan.command_env()
                .as_map()
                .get("FIRMA_SECRET_BROKER_ADDR")
                .map(String::as_str),
            Some("tcp://127.0.0.1:18083")
        );
        Ok(())
    }

    #[test]
    fn broker_listener_reports_bind_conflicts_before_serving() -> TestResult {
        let existing = TcpListener::bind("127.0.0.1:0")?;
        let addr = existing.local_addr()?;
        let Some(broker_vsock_port) = NonZeroU32::new(18_083) else {
            return Err(io::Error::other("test broker VSOCK port must be non-zero").into());
        };
        let plan = BrokerProxyPlan {
            guest_broker_addr: addr,
            broker_vsock_port,
        };

        let error = expect_init_error(
            GuestBrokerListener::bind(&plan),
            "broker bind should fail while the address is held",
        )?;

        assert!(matches!(
            error,
            InitError::GuestNetworkSetup { detail }
                if detail.starts_with(&format!("bind guest broker proxy {addr}:"))
        ));
        Ok(())
    }

    #[test]
    fn broker_connection_forwards_bytes_in_both_directions() -> TestResult {
        let (mut client, guest_side) = connected_tcp_pair()?;
        let (mut host, vsock_side) = connected_tcp_pair()?;
        let vsock_side = Arc::new(Mutex::new(Some(vsock_side)));
        let handler = thread::spawn(move || {
            GuestBrokerConnection::spawn(
                guest_side,
                18_083,
                Arc::new(move |_port, _cancelled, _deadline| {
                    let vsock_side = vsock_side
                        .lock()
                        .map_err(|_| io::Error::other("test VSOCK connector poisoned"))?
                        .take()
                        .ok_or_else(|| io::Error::other("test VSOCK connector reused"))?;
                    let owned: OwnedFd = vsock_side.into();
                    Ok(File::from(owned))
                }),
                Arc::new(AtomicBool::new(false)),
            )?
            .join()
        });

        client.write_all(b"request bytes\n")?;
        client.shutdown(Shutdown::Write)?;
        let mut request = Vec::new();
        host.read_to_end(&mut request)?;
        assert_eq!(request, b"request bytes\n");

        host.write_all(b"response bytes\n")?;
        host.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        client.read_to_end(&mut response)?;
        assert_eq!(response, b"response bytes\n");

        join_init_handler(handler)??;
        Ok(())
    }

    #[test]
    fn broker_readiness_probe_retries_complete_protocol_until_success() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = thread::spawn(move || -> io::Result<()> {
            for _ in 0..2 {
                let (stream, _) = listener.accept()?;
                drop(stream);
            }
            let (stream, _) = listener.accept()?;
            let mut reader = io::BufReader::new(stream);
            let mut request = String::new();
            reader.read_line(&mut request)?;
            assert_eq!(
                request,
                "{\"control\":{\"type\":\"readiness\",\"version\":1}}\n"
            );
            reader
                .get_mut()
                .write_all(b"{\"type\":\"ready\",\"version\":1}\n")?;
            Ok(())
        });

        probe_guest_broker(addr)?;
        join_io_handler(server)??;
        Ok(())
    }

    #[test]
    fn broker_readiness_probe_rejects_non_ready_responses() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 128];
            let _ = stream.read(&mut request)?;
            stream.write_all(
                b"{\"type\":\"executed\",\"output\":[],\"status\":{\"type\":\"exit_code\",\"code\":0}}\n",
            )?;
            Ok(())
        });

        let started = Instant::now();
        let error = expect_init_error(
            probe_guest_broker_until(addr, Instant::now() + Duration::from_secs(2)),
            "malformed readiness response must be fatal",
        )?;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            error,
            InitError::GuestNetworkSetup { detail }
                if detail.starts_with("host broker returned a malformed readiness response;")
        ));
        join_io_handler(server)??;
        Ok(())
    }

    #[test]
    fn broker_readiness_probe_fails_immediately_for_legacy_rejection() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 128];
            let _ = stream.read(&mut request)?;
            stream.write_all(b"{\"type\":\"rejected\",\"error\":\"missing field `bin`\"}\n")?;
            Ok(())
        });
        let started = Instant::now();

        let error = expect_init_error(
            probe_guest_broker_until(addr, Instant::now() + Duration::from_secs(2)),
            "legacy broker rejection must be fatal",
        )?;

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            error,
            InitError::GuestNetworkSetup { detail }
                if detail == "host broker rejected the readiness protocol; install matching Firma CLI and VZ guest bundle: missing field `bin`"
        ));
        join_io_handler(server)??;
        Ok(())
    }

    #[test]
    fn broker_readiness_probe_fails_immediately_for_wrong_version() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 128];
            let _ = stream.read(&mut request)?;
            stream.write_all(b"{\"type\":\"ready\",\"version\":2}\n")?;
            Ok(())
        });

        let error = expect_init_error(
            probe_guest_broker_until(addr, Instant::now() + Duration::from_secs(2)),
            "wrong broker readiness version must be fatal",
        )?;

        assert!(matches!(
            error,
            InitError::GuestNetworkSetup { detail }
                if detail == "host broker readiness version 2 is incompatible with guest version 1; install matching Firma CLI and VZ guest bundle"
        ));
        join_io_handler(server)??;
        Ok(())
    }

    #[test]
    fn guest_broker_service_caps_active_connections_and_joins_on_shutdown() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let connected = Arc::new(AtomicUsize::new(0));
        let host_peers = Arc::new(Mutex::new(Vec::new()));
        let connector_count = Arc::clone(&connected);
        let connector_peers = Arc::clone(&host_peers);
        let connector = Arc::new(move |_port, _cancelled: &AtomicBool, _deadline| {
            let (host, bridge) = connected_tcp_pair()?;
            connector_peers
                .lock()
                .map_err(|_| io::Error::other("test host peer registry poisoned"))?
                .push(host);
            connector_count.fetch_add(1, Ordering::AcqRel);
            let owned: OwnedFd = bridge.into();
            Ok(File::from(owned))
        });
        let mut service = GuestBrokerService::start_with_connector(listener, 18_083, connector)?;
        let mut clients = Vec::new();
        for _ in 0..MAX_BROKER_CONNECTIONS {
            clients.push(TcpStream::connect(addr)?);
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while connected.load(Ordering::Acquire) != MAX_BROKER_CONNECTIONS
            && Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert_eq!(connected.load(Ordering::Acquire), MAX_BROKER_CONNECTIONS);

        let mut excess = TcpStream::connect(addr)?;
        excess.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut byte = [0_u8; 1];
        assert_eq!(excess.read(&mut byte)?, 0);
        assert_eq!(connected.load(Ordering::Acquire), MAX_BROKER_CONNECTIONS);

        service.shutdown();
        assert!(service.thread.is_none());
        drop(clients);
        Ok(())
    }

    #[test]
    fn guest_broker_service_cancels_pending_connection_and_joins_supervisor() -> TestResult {
        const SHUTDOWN_BOUND: Duration = Duration::from_millis(250);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (started_tx, started_rx) = mpsc::channel();
        let connector = Arc::new(move |_port, cancelled: &AtomicBool, deadline| {
            started_tx
                .send(())
                .map_err(|_| io::Error::other("test connector start receiver dropped"))?;
            while !cancelled.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(super::BROKER_SUPERVISOR_TICK);
            }
            if cancelled.load(Ordering::Acquire) {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "test connector cancelled",
                ))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test connector reached deadline",
                ))
            }
        });
        let mut service = GuestBrokerService::start_with_connector(listener, 18_083, connector)?;
        let _client = TcpStream::connect(addr)?;
        started_rx.recv_timeout(Duration::from_secs(1))?;

        let shutdown_started = Instant::now();
        service.shutdown();

        assert!(shutdown_started.elapsed() < SHUTDOWN_BOUND);
        assert!(service.thread.is_none());
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
            broker: None,
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

        let listeners = GuestNetworkListeners {
            proxy,
            dns,
            broker: None,
        };
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

    fn connected_tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
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

    fn join_init_handler(
        handle: thread::JoinHandle<super::super::error::InitResult<()>>,
    ) -> Result<super::super::error::InitResult<()>, Box<dyn Error>> {
        handle.join().map_or_else(
            |_| Err(io::Error::other("broker handler thread panicked").into()),
            Ok,
        )
    }

    fn join_io_handler(
        handle: thread::JoinHandle<io::Result<()>>,
    ) -> Result<io::Result<()>, Box<dyn Error>> {
        handle.join().map_or_else(
            |_| Err(io::Error::other("broker server thread panicked").into()),
            Ok,
        )
    }

    fn valid_launch_contract() -> TestResult<LaunchContract> {
        Ok(serde_json::from_str(VALID_CONTRACT_JSON)?)
    }

    fn valid_secret_shims_contract() -> SecretShimsContract {
        SecretShimsContract {
            guest_target_triple: "x86_64-unknown-linux-musl".to_string(),
            provider_names: vec!["op".to_string()],
            broker_vsock_port: 18_083,
            guest_broker_addr: "127.0.0.1:18083".to_string(),
            broker_socket_path: "/host/control/broker.sock".into(),
            shim_share_directory: "/host/control/secret-shims".into(),
        }
    }
}
