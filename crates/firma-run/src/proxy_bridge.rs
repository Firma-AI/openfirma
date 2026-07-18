#[cfg(any(unix, test))]
use std::collections::BTreeMap;
#[cfg(any(unix, test))]
use std::io;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::sync::{Arc, Condvar, Mutex};
#[cfg(unix)]
use std::thread::{self, JoinHandle};
#[cfg(unix)]
use std::time::Duration;

use crate::error::RunError;

/// Lib-level input for [`execute_proxy_bridge`]. The CLI layer builds this
/// from its `clap`-derived args struct.
#[derive(Debug, Clone)]
pub struct ProxyBridgeInput {
    /// TCP listen address reachable by the sandboxed agent process.
    pub listen: std::net::SocketAddr,
    /// Upstream host-side Unix socket path exposed by `firma run`.
    pub upstream_uds: PathBuf,
}

/// Run the internal sandbox bridge process.
///
/// The bridge accepts HTTP proxy traffic over TCP (inside the sandbox) and
/// relays bytes bidirectionally to a host-side Unix socket endpoint.
///
/// # Errors
///
/// Returns an error if the bridge cannot bind/listen or if the platform does
/// not support Unix sockets.
pub fn execute_proxy_bridge(args: &ProxyBridgeInput) -> Result<i32, RunError> {
    #[cfg(unix)]
    {
        run_proxy_bridge_unix(args)?;
        Ok(0)
    }

    #[cfg(not(unix))]
    {
        let _ = args;
        Err(RunError::UnsupportedBackend {
            backend: "internal_proxy_bridge".to_string(),
            reason: "unix socket bridge is unavailable on non-unix hosts".to_string(),
        })
    }
}

/// Owning handle for a host-side proxy bridge started on the non-structural
/// (macOS / proxy-mediated) path.
///
/// The bridge listens on an ephemeral loopback TCP port, injects attribution
/// headers (including `x-firma-session-id`) into every outbound HTTP/CONNECT
/// request, and relays the enriched traffic to the sidecar's TCP endpoint.
/// [`Drop`] signals the listener thread to stop and joins it.
///
/// On the structural (Linux/bwrap) path the equivalent bridge is launched as a
/// subprocess inside the sandbox by `bwrap_entrypoint.sh`.  On the
/// non-structural path no entrypoint script is run, so the bridge must live on
/// the host side.
#[cfg(unix)]
pub struct HostBridgeHandle {
    listen_addr: std::net::SocketAddr,
    stop_tx: Option<mpsc::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl HostBridgeHandle {
    /// Start a host-side proxy bridge.
    ///
    /// Binds an ephemeral loopback TCP port, spawns the listener thread, and
    /// returns immediately.  Attribution headers are baked into the thread
    /// closure and injected into every request before it reaches `upstream`.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Spawn`] if the listener cannot be bound or the
    /// thread cannot be spawned.
    pub fn start(
        upstream: std::net::SocketAddr,
        attribution_headers: BTreeMap<String, String>,
    ) -> Result<Self, RunError> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| {
            RunError::Spawn(format!("failed to bind host proxy bridge: {error}"))
        })?;
        let listen_addr = listener.local_addr().map_err(|error| {
            RunError::Spawn(format!(
                "failed to read host proxy bridge listen addr: {error}"
            ))
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            RunError::Spawn(format!(
                "failed to set host proxy bridge listener non-blocking: {error}"
            ))
        })?;

        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        let task = thread::Builder::new()
            .name("firma-run-host-proxy-bridge".to_string())
            .spawn(move || {
                run_host_bridge_loop(&listener, &upstream, &attribution_headers, &stop_rx);
            })
            .map_err(|error| {
                RunError::Spawn(format!("failed to spawn host proxy bridge thread: {error}"))
            })?;

        Ok(Self {
            listen_addr,
            stop_tx: Some(stop_tx),
            task: Some(task),
        })
    }

    /// TCP address the bridge is listening on.
    #[must_use]
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.listen_addr
    }
}

#[cfg(unix)]
impl Drop for HostBridgeHandle {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        // Wake the accept loop so it sees the stop signal within one poll cycle.
        let _ = TcpStream::connect_timeout(&self.listen_addr, Duration::from_millis(200));
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Host-side bridge loop (TCP → TCP with header injection)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn run_host_bridge_loop(
    listener: &TcpListener,
    upstream: &std::net::SocketAddr,
    attribution_headers: &BTreeMap<String, String>,
    stop_rx: &mpsc::Receiver<()>,
) {
    // Bound worker concurrency to avoid unbounded thread growth under load.
    // Extra inbound connections remain queued by the listener backlog until a
    // worker slot is released.
    let limiter = Arc::new(ConnectionLimiter::new(128));

    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((client, client_addr)) => {
                tracing::debug!(
                    client_addr = %client_addr,
                    upstream = %upstream,
                    "host proxy bridge accepted client connection"
                );
                // Listener is non-blocking for stop polling; on some platforms
                // accepted sockets may inherit non-blocking mode. The relay
                // path relies on blocking I/O, so normalize the accepted
                // client socket before handing it to a worker.
                if let Err(error) = client.set_nonblocking(false) {
                    tracing::warn!(
                        "host proxy bridge failed to set blocking mode for {client_addr}: {error}"
                    );
                    continue;
                }
                let permit = limiter.acquire();
                let upstream = *upstream;
                let headers = attribution_headers.clone();
                let listen_addr_str = listener
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                let _limiter = Arc::clone(&limiter);
                thread::spawn(move || {
                    let _permit = permit;
                    if let Err(error) =
                        handle_connection_tcp_upstream(client, upstream, &headers, &listen_addr_str)
                    {
                        log_host_bridge_connection_error(client_addr, &error);
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                tracing::warn!("host proxy bridge accept failed: {error}");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

#[cfg(unix)]
fn log_host_bridge_connection_error(client_addr: std::net::SocketAddr, error: &io::Error) {
    match error.kind() {
        // Common transient cases when clients close/retry during interactive
        // agent traffic; keep these at debug to avoid noisy logs.
        io::ErrorKind::WouldBlock
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => {
            tracing::debug!(
                "host proxy bridge connection from {client_addr} closed/transient: {error}"
            );
        }
        _ => {
            tracing::warn!("host proxy bridge connection from {client_addr} failed: {error}");
        }
    }
}

#[cfg(unix)]
struct ConnectionLimiter {
    limit: usize,
    in_flight: Mutex<usize>,
    cv: Condvar,
}

#[cfg(unix)]
impl ConnectionLimiter {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            in_flight: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> ConnectionPermit {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *in_flight >= self.limit {
            in_flight = self
                .cv
                .wait(in_flight)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *in_flight += 1;
        drop(in_flight);
        ConnectionPermit {
            limiter: Arc::clone(self),
        }
    }

    fn release(&self) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *in_flight = in_flight.saturating_sub(1);
        drop(in_flight);
        self.cv.notify_one();
    }
}

#[cfg(unix)]
struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

#[cfg(unix)]
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.release();
    }
}

/// Handle one inbound client connection via a TCP upstream (sidecar).
///
/// Mirrors [`handle_connection`] but uses a `TcpStream` upstream instead of a
/// `UnixStream`, which is the topology on the non-structural macOS path.
#[cfg(unix)]
fn handle_connection_tcp_upstream(
    mut client: TcpStream,
    upstream_addr: std::net::SocketAddr,
    attribution_headers: &BTreeMap<String, String>,
    bridge_listen_addr: &str,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    let mut upstream = connect_tcp_with_retry_addr(upstream_addr).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to reach sidecar at {upstream_addr}: {error}; \
clients may report connection failures via http://{bridge_listen_addr} (pre-sidecar mediation)"
            ),
        )
    })?;
    upstream.set_nodelay(true)?;

    if attribution_headers.is_empty() {
        return relay_tcp_to_tcp(&client, &upstream);
    }

    let mut upstream_read = upstream.try_clone()?;
    let mut client_write = client.try_clone()?;
    let response_copy = thread::spawn(move || io::copy(&mut upstream_read, &mut client_write));

    let forward_result =
        forward_requests_with_header_injection(&mut client, &mut upstream, attribution_headers);
    let reverse_result = response_copy
        .join()
        .map_err(|_| io::Error::other("host proxy bridge response copy panic"))?;

    forward_result?;
    reverse_result?;
    Ok(())
}

/// TCP-to-TCP bidirectional relay (no header injection).
#[cfg(unix)]
fn relay_tcp_to_tcp(client: &TcpStream, upstream: &TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;

    let c_to_u = thread::spawn(move || io::copy(&mut client_read, &mut upstream_write));
    let u_to_c = thread::spawn(move || io::copy(&mut upstream_read, &mut client_write));

    c_to_u
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    u_to_c
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    Ok(())
}

/// Connect to a TCP address, retrying briefly on `ECONNREFUSED` to smooth
/// out the startup race when the sidecar is still binding its port.
#[cfg(unix)]
fn connect_tcp_with_retry_addr(addr: std::net::SocketAddr) -> io::Result<TcpStream> {
    const ATTEMPTS: usize = 20;
    const SLEEP_BETWEEN: Duration = Duration::from_millis(50);
    let mut last_error: Option<io::Error> = None;
    for attempt in 0..ATTEMPTS {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                last_error = Some(error);
                if attempt + 1 < ATTEMPTS {
                    thread::sleep(SLEEP_BETWEEN);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("tcp connect failed")))
}

// ---------------------------------------------------------------------------
// Sandbox proxy bridge (Unix socket upstream)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn run_proxy_bridge_unix(args: &ProxyBridgeInput) -> Result<(), RunError> {
    let attribution_headers = load_attr_headers_from_env();
    let listener = TcpListener::bind(args.listen).map_err(|error| {
        RunError::Spawn(format!(
            "failed to bind sandbox proxy bridge at {}: {error}",
            args.listen
        ))
    })?;

    // Signal readiness after bind so the entrypoint script can start the agent
    // without a blind sleep. The entrypoint polls for this file's existence.
    if let Ok(dir) = std::env::var("FIRMA_RUN_RUNTIME_DIR") {
        let _ = std::fs::write(std::path::Path::new(&dir).join("proxy-bridge-ready"), []);
    }

    loop {
        let (client_stream, client_addr) = listener
            .accept()
            .map_err(|error| RunError::Spawn(format!("proxy bridge accept failed: {error}")))?;
        tracing::debug!(
            client_addr = %client_addr,
            upstream = %args.upstream_uds.display(),
            "sandbox proxy bridge accepted client connection"
        );
        let upstream_path = args.upstream_uds.clone();
        let attribution_headers = attribution_headers.clone();
        let bridge_listen_addr = args.listen.to_string();

        thread::spawn(move || {
            if let Err(error) = handle_connection(
                client_stream,
                &upstream_path,
                &attribution_headers,
                &bridge_listen_addr,
            ) {
                tracing::warn!(
                    "proxy bridge connection from {client_addr} failed: {}",
                    error
                );
            }
        });
    }
}

/// Handle one inbound client connection via a Unix-socket upstream.
#[cfg(unix)]
fn handle_connection(
    mut client: TcpStream,
    upstream_path: &std::path::Path,
    attribution_headers: &BTreeMap<String, String>,
    bridge_listen_addr: &str,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    let mut upstream = UnixStream::connect(upstream_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to reach host-side sidecar adapter at {}: {error}; \
sandbox clients may report connection failures via http://{bridge_listen_addr} (pre-sidecar mediation)",
                upstream_path.display()
            ),
        )
    })?;
    if attribution_headers.is_empty() {
        return relay_tcp_to_unix(&client, &upstream);
    }

    let mut upstream_read = upstream.try_clone()?;
    let mut client_write = client.try_clone()?;
    let response_copy = thread::spawn(move || io::copy(&mut upstream_read, &mut client_write));

    let forward_result =
        forward_requests_with_header_injection(&mut client, &mut upstream, attribution_headers);
    let reverse_result = response_copy
        .join()
        .map_err(|_| io::Error::other("proxy bridge response copy panic"))?;

    forward_result?;
    reverse_result?;
    Ok(())
}

#[cfg(unix)]
fn relay_tcp_to_unix(client: &TcpStream, upstream: &UnixStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;

    let t1 = thread::spawn(move || io::copy(&mut client_read, &mut upstream_write));
    let t2 = thread::spawn(move || io::copy(&mut upstream_read, &mut client_write));

    let first = t1
        .join()
        .map_err(|_| io::Error::other("proxy bridge copy panic"))?;
    let second = t2
        .join()
        .map_err(|_| io::Error::other("proxy bridge copy panic"))?;

    first?;
    second?;
    Ok(())
}

#[cfg(unix)]
fn load_attr_headers_from_env() -> BTreeMap<String, String> {
    let Ok(raw) = std::env::var("FIRMA_RUN_ATTR_HEADERS_JSON") else {
        return BTreeMap::new();
    };
    if raw.trim().is_empty() {
        return BTreeMap::new();
    }
    serde_json::from_str::<BTreeMap<String, String>>(&raw).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// HTTP/1.1 request header injection — generic over upstream write sink
// ---------------------------------------------------------------------------

/// Parse HTTP/1.1 request headers from `client`, inject any missing
/// attribution headers, and relay the enriched bytes to `upstream`.
/// Handles `Content-Length`, chunked bodies, and `CONNECT` tunnels.
///
/// The function is generic over the upstream write type so it can serve both
/// the Unix-socket path (structural / bwrap sandbox) and the TCP path
/// (non-structural / macOS host bridge).
#[cfg(unix)]
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
        let header_end = read_until_header_block(client, &mut buffer)?;
        let Some(header_end) = header_end else {
            // EOF.
            return Ok(());
        };

        // Reuse allocation and avoid per-request copies.
        let mut request = std::mem::take(&mut buffer);
        let mut remaining = request.split_off(header_end + 4);
        request.truncate(header_end);

        let meta = parse_request_metadata(&request)?;
        tracing::debug!(
            method = %meta.method,
            target = %sanitized_request_target_for_log(&meta.target),
            "proxy bridge forwarding request headers"
        );
        replace_attribution_headers(&mut request, attribution_headers)?;

        // `request` already ends with \r\n (the CRLF of the last header
        // line). Write one more \r\n to complete the blank-line terminator.
        // Writing \r\n\r\n here would produce three CRLFs, injecting a
        // spurious blank line into the stream (e.g. into a CONNECT tunnel
        // before the TLS ClientHello, corrupting the TLS handshake).
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

#[cfg(any(unix, test))]
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
        .collect::<std::collections::BTreeSet<_>>();

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

#[cfg(any(unix, test))]
fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(unix)]
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

#[cfg(any(unix, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyKind {
    None,
    ContentLength(usize),
    Chunked,
}

#[cfg(any(unix, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestMetadata {
    method: String,
    target: String,
    body: BodyKind,
}

#[cfg(any(unix, test))]
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
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts.next().unwrap_or_default().to_string();
    let target = request_line_parts.next().unwrap_or_default().to_string();

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
    } else if let Some(n) = content_length {
        if n == 0 {
            BodyKind::None
        } else {
            BodyKind::ContentLength(n)
        }
    } else {
        BodyKind::None
    };

    Ok(RequestMetadata {
        method,
        target,
        body,
    })
}

#[cfg(any(unix, test))]
fn sanitized_request_target_for_log(target: &str) -> &str {
    let query = target.find('?');
    let fragment = target.find('#');
    let end = match (query, fragment) {
        (Some(query), Some(fragment)) => query.min(fragment),
        (Some(query), None) => query,
        (None, Some(fragment)) => fragment,
        (None, None) => return target,
    };
    &target[..end]
}

#[cfg(unix)]
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

#[cfg(unix)]
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
            .and_then(|s| s.split(';').next())
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
            // Forward trailing headers until CRLF CRLF.
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        BodyKind, find_header_terminator, parse_request_metadata, replace_attribution_headers,
        sanitized_request_target_for_log,
    };

    #[test]
    fn finds_header_terminator() {
        let req = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        let pos = find_header_terminator(req).expect("terminator");
        assert_eq!(&req[pos..pos + 4], b"\r\n\r\n");
    }

    #[test]
    fn appends_missing_attr_headers() {
        let mut req_head = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n".to_vec();
        let mut headers = BTreeMap::new();
        headers.insert("x-firma-session-id".to_string(), "sess_001".to_string());
        headers.insert("x-firma-profile".to_string(), "claude-code".to_string());
        replace_attribution_headers(&mut req_head, &headers).expect("replace headers");
        let rendered = String::from_utf8(req_head).expect("utf8");
        assert!(rendered.contains("x-firma-session-id: sess_001\r\n"));
        assert!(rendered.contains("x-firma-profile: claude-code\r\n"));
    }

    #[test]
    fn replaces_untrusted_attr_headers_case_insensitively() {
        let mut req_head = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Firma-Sandbox-Id: spoofed\r\nX-Firma-Session-Id: spoofed\r\nX-Firma-Agent: spoofed\r\nX-Unrelated: retained\r\n".to_vec();
        let mut headers = BTreeMap::new();
        headers.insert("x-firma-session-id".to_string(), "injected".to_string());
        headers.insert("x-firma-agent".to_string(), "vscode".to_string());
        headers.insert(
            "x-firma-sandbox-id".to_string(),
            "01900000-0000-7000-8000-000000000001".to_string(),
        );

        replace_attribution_headers(&mut req_head, &headers).expect("replace headers");
        let rendered = String::from_utf8(req_head).expect("utf8");

        assert!(rendered.contains("x-firma-session-id: injected\r\n"));
        assert!(rendered.contains("x-firma-agent: vscode\r\n"));
        assert!(rendered.contains("x-firma-sandbox-id: 01900000-0000-7000-8000-000000000001\r\n"));
        assert!(rendered.contains("X-Unrelated: retained\r\n"));
        assert!(!rendered.contains("spoofed"));
    }

    #[test]
    fn replace_attribution_headers_rejects_non_utf8_header_block() {
        let mut req_head = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n".to_vec();
        req_head.push(0xFF);
        let mut headers = BTreeMap::new();
        headers.insert("x-firma-session-id".to_string(), "sess_001".to_string());

        let error = replace_attribution_headers(&mut req_head, &headers)
            .expect_err("non-utf8 headers must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn header_block_ends_with_single_crlf_for_terminator() {
        // `replace_attribution_headers` rebuilds the header block and always
        // ends with `\r\n`. The caller then writes exactly one more `\r\n`
        // to complete the blank-line terminator (`\r\n\r\n` total). Verify
        // that the rebuilt block ends with `\r\n` so that one extra `\r\n`
        // produces exactly the correct HTTP blank-line separator — not a
        // spurious extra blank line that would corrupt CONNECT tunnels.
        let mut req_head =
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n".to_vec();
        let mut headers = BTreeMap::new();
        headers.insert("x-firma-session-id".to_string(), "sess_001".to_string());
        replace_attribution_headers(&mut req_head, &headers).expect("replace headers");
        assert!(
            req_head.ends_with(b"\r\n"),
            "header block must end with \\r\\n so caller can append one more \\r\\n"
        );
        assert!(
            !req_head.ends_with(b"\r\n\r\n"),
            "header block must NOT already contain the blank-line terminator"
        );
    }

    #[test]
    fn parses_content_length_body_metadata() {
        let req = b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\n";
        let meta = parse_request_metadata(req).expect("metadata");
        assert_eq!(meta.method, "POST");
        assert_eq!(meta.target, "http://example.com/upload");
        assert_eq!(meta.body, BodyKind::ContentLength(12));
    }

    #[test]
    fn zero_or_invalid_content_length_is_treated_as_no_body() {
        let zero = b"POST http://example.com/upload HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let invalid = b"POST http://example.com/upload HTTP/1.1\r\nContent-Length: nope\r\n\r\n";

        assert_eq!(
            parse_request_metadata(zero).expect("zero metadata").body,
            BodyKind::None
        );
        assert_eq!(
            parse_request_metadata(invalid)
                .expect("invalid content length metadata")
                .body,
            BodyKind::None
        );
    }

    #[test]
    fn parses_chunked_body_metadata() {
        let req = b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let meta = parse_request_metadata(req).expect("metadata");
        assert_eq!(meta.body, BodyKind::Chunked);
    }

    #[test]
    fn chunked_transfer_encoding_wins_over_content_length() {
        let req = b"POST http://example.com/upload HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 12\r\n\r\n";
        let meta = parse_request_metadata(req).expect("metadata");

        assert_eq!(meta.body, BodyKind::Chunked);
    }

    #[test]
    fn sanitizes_request_target_for_debug_logs() {
        assert_eq!(
            sanitized_request_target_for_log(
                "https://github.com/login/oauth/authorize?client_id=abc#state"
            ),
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(
            sanitized_request_target_for_log("github.com:443"),
            "github.com:443"
        );
    }
}

// The bridge spins up real TCP listeners and only exists on the non-structural
// (macOS) path, so these tests are Unix-only and grouped here to keep the
// platform gate on the module rather than on each test and import.
#[cfg(test)]
#[cfg(unix)]
mod host_bridge_tests {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    use super::HostBridgeHandle;

    /// Verifies that `HostBridgeHandle` injects `x-firma-session-id` into a
    /// plain HTTP request routed through the bridge.
    ///
    /// This is the regression test for FIR-213: on macOS (non-structural path)
    /// the bridge was never started, so the sidecar received an empty
    /// `session_id` and denied every request.
    #[test]
    fn host_bridge_injects_session_id_into_http_request() {
        // ── upstream mock ──────────────────────────────────────────────────
        // Captures the raw bytes of the first request, then closes.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");
        let upstream_addr: SocketAddr = upstream_listener.local_addr().expect("local_addr");

        let received_request = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let received_clone = received_request.clone();
        let upstream_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            // Stop once we have the full header block.
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                *received_clone.lock().expect("lock") = buf;
                // Minimal HTTP response so the client doesn't hang.
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });

        // ── bridge ─────────────────────────────────────────────────────────
        let mut headers = BTreeMap::new();
        headers.insert(
            "x-firma-session-id".to_string(),
            "sess_test_fir213".to_string(),
        );
        headers.insert("x-firma-agent".to_string(), "claude-code".to_string());
        let bridge = HostBridgeHandle::start(upstream_addr, headers).expect("bridge start");
        let bridge_addr = bridge.listen_addr();

        // ── client ─────────────────────────────────────────────────────────
        let request =
            "GET http://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n";
        let mut client = TcpStream::connect(bridge_addr).expect("client connect");
        client.write_all(request.as_bytes()).expect("write");
        // Drain the response so the upstream thread's write_all succeeds.
        let mut resp = [0u8; 256];
        let _ = client.read(&mut resp);
        drop(client);

        upstream_thread.join().expect("upstream join");
        drop(bridge);

        let captured = received_request.lock().expect("lock").clone();
        let captured_str = String::from_utf8_lossy(&captured);
        assert!(
            captured_str.contains("x-firma-session-id: sess_test_fir213"),
            "upstream did not receive x-firma-session-id; got:\n{captured_str}"
        );
        assert!(
            captured_str.contains("x-firma-agent: claude-code"),
            "upstream did not receive x-firma-agent; got:\n{captured_str}"
        );
    }

    /// Verifies that `HostBridgeHandle` injects `x-firma-session-id` into the
    /// CONNECT request that Claude Code issues for HTTPS destinations.
    #[test]
    fn host_bridge_injects_session_id_into_connect_request() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");
        let upstream_addr: SocketAddr = upstream_listener.local_addr().expect("local_addr");

        let received_request = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let received_clone = received_request.clone();
        let upstream_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                *received_clone.lock().expect("lock") = buf;
                // Reply with 200 Connection established (sidecar CONNECT allow response).
                let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
            }
        });

        let mut headers = BTreeMap::new();
        headers.insert(
            "x-firma-session-id".to_string(),
            "sess_connect_fir213".to_string(),
        );
        let bridge = HostBridgeHandle::start(upstream_addr, headers).expect("bridge start");
        let bridge_addr = bridge.listen_addr();

        // Send a CONNECT request as Claude Code would for api.anthropic.com:443.
        let connect_req =
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
        let mut client = TcpStream::connect(bridge_addr).expect("client connect");
        client.set_read_timeout(Some(Duration::from_secs(2))).ok();
        client.write_all(connect_req.as_bytes()).expect("write");
        // Read the tunnel-established response so the bridge write doesn't block.
        let mut resp = [0u8; 256];
        let _ = client.read(&mut resp);
        drop(client);

        upstream_thread.join().expect("upstream join");
        drop(bridge);

        let captured = received_request.lock().expect("lock").clone();
        let captured_str = String::from_utf8_lossy(&captured);
        assert!(
            captured_str.contains("x-firma-session-id: sess_connect_fir213"),
            "upstream CONNECT did not receive x-firma-session-id; got:\n{captured_str}"
        );
    }

    /// Verifies that a client-supplied session ID is replaced, not duplicated.
    #[test]
    fn host_bridge_replaces_existing_session_id() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");
        let upstream_addr: SocketAddr = upstream_listener.local_addr().expect("local_addr");

        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let received_clone = received.clone();
        let upstream_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                *received_clone.lock().expect("lock") = buf;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });

        let mut headers = BTreeMap::new();
        headers.insert(
            "x-firma-session-id".to_string(),
            "sess_bridge_value".to_string(),
        );
        let bridge = HostBridgeHandle::start(upstream_addr, headers).expect("bridge start");
        let bridge_addr = bridge.listen_addr();

        // Client-supplied attribution is untrusted and must be overridden.
        let request = "GET http://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\nx-firma-session-id: sess_client_value\r\n\r\n";
        let mut client = TcpStream::connect(bridge_addr).expect("connect");
        client.write_all(request.as_bytes()).expect("write");
        let mut resp = [0u8; 256];
        let _ = client.read(&mut resp);
        drop(client);

        upstream_thread.join().expect("upstream join");
        drop(bridge);

        let captured = received.lock().expect("lock").clone();
        let captured_str = String::from_utf8_lossy(&captured);
        assert!(
            captured_str.contains("x-firma-session-id: sess_bridge_value"),
            "trusted session-id was not injected; got:\n{captured_str}"
        );
        assert!(!captured_str.contains("sess_client_value"));
        let occurrences = captured_str.matches("x-firma-session-id").count();
        assert_eq!(
            occurrences, 1,
            "x-firma-session-id appears {occurrences} times (expected 1); got:\n{captured_str}"
        );
    }
}
