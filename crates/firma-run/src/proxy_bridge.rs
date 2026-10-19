#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::{Shutdown, TcpListener, TcpStream};
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
    pub(crate) fn start(
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
    pub(crate) fn listen_addr(&self) -> std::net::SocketAddr {
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

    relay_with_header_injection(
        &mut client,
        &mut upstream,
        attribution_headers,
        "host proxy bridge response copy panic",
    )
}

/// A relay endpoint: cloneable per direction, and half-closeable.
///
/// [`TcpStream`] and [`UnixStream`] both expose `try_clone` and `shutdown`,
/// but std gives them no common trait, and the relays need one so a single
/// copy helper can serve both the TCP-upstream (macOS host) and Unix-upstream
/// (sandbox) topologies.
#[cfg(unix)]
trait RelayStream: Read + Write + Send + Sized + 'static {
    fn try_clone_stream(&self) -> io::Result<Self>;
    fn half_close(&self, how: Shutdown) -> io::Result<()>;
}

#[cfg(unix)]
impl RelayStream for TcpStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn half_close(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

#[cfg(unix)]
impl RelayStream for UnixStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn half_close(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

/// Spawn one direction of a relay, propagating the half-close on completion.
///
/// `io::copy` returning is the only signal that this direction is finished,
/// and nothing in the process will write to `sink` again. Without the shutdown
/// the peer never receives a FIN, so the opposite direction's copy blocks
/// forever on a stream that no longer has a writer, and the whole connection —
/// this thread, both sockets, and the sidecar tunnel behind them — is never
/// reclaimed. The sidecar's own relay gets this from `copy_bidirectional`,
/// which shuts the opposite write half down on EOF; the bridge has to do it by
/// hand.
///
/// Only the sink's write half and the source's read half close, so a peer that
/// half-closes still receives the rest of the traffic flowing the other way.
/// Both shutdowns are best-effort: a peer that already vanished makes them
/// fail, and there is nothing left to reclaim in that case.
#[cfg(unix)]
fn spawn_relay_half<S, T>(mut source: S, mut sink: T) -> JoinHandle<io::Result<u64>>
where
    S: RelayStream,
    T: RelayStream,
{
    thread::spawn(move || {
        let copied = io::copy(&mut source, &mut sink);
        let _ = sink.half_close(Shutdown::Write);
        let _ = source.half_close(Shutdown::Read);
        copied
    })
}

/// TCP-to-TCP bidirectional relay (no header injection).
#[cfg(unix)]
fn relay_tcp_to_tcp(client: &TcpStream, upstream: &TcpStream) -> io::Result<()> {
    let c_to_u = spawn_relay_half(client.try_clone()?, upstream.try_clone()?);
    let u_to_c = spawn_relay_half(upstream.try_clone()?, client.try_clone()?);

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

    relay_with_header_injection(
        &mut client,
        &mut upstream,
        attribution_headers,
        "proxy bridge response copy panic",
    )
}

/// Relay one connection whose forward direction rewrites attribution headers.
///
/// The response direction is a plain copy on its own thread, so this reduces to
/// the same teardown obligation [`spawn_relay_half`] carries: whoever finishes
/// first has to tell the other peer, or the sibling blocks forever.
///
/// The forward loop ends when the client stops sending. Half-closing the
/// upstream write side is what lets the sidecar finish its response and close,
/// which is in turn what ends the response copy. Skipping it is the leak: the
/// client sits in `FIN_WAIT2`, the bridge in `CLOSE_WAIT`, and the sidecar
/// holds both the CONNECT tunnel and its upstream TLS connection open.
///
/// A forward error is different in kind: nothing will arrive on either socket
/// again, so both are torn down completely. Leaving the response thread parked
/// would strand the `join` below along with it.
#[cfg(unix)]
fn relay_with_header_injection<U>(
    client: &mut TcpStream,
    upstream: &mut U,
    attribution_headers: &BTreeMap<String, String>,
    copy_panic_message: &'static str,
) -> io::Result<()>
where
    U: RelayStream,
{
    let response_copy = spawn_relay_half(upstream.try_clone_stream()?, client.try_clone_stream()?);

    let forward_result = firma_http::forward_http1_requests(
        client,
        upstream,
        attribution_headers,
        |method, target| {
            tracing::debug!(
                method,
                target = %sanitized_request_target_for_log(target),
                "proxy bridge forwarding request headers"
            );
        },
    );
    let _ = upstream.half_close(Shutdown::Write);
    if forward_result.is_err() {
        let _ = upstream.half_close(Shutdown::Both);
        let _ = client.half_close(Shutdown::Both);
    }

    let reverse_result = response_copy
        .join()
        .map_err(|_| io::Error::other(copy_panic_message))?;

    forward_result?;
    reverse_result?;
    Ok(())
}

#[cfg(unix)]
fn relay_tcp_to_unix(client: &TcpStream, upstream: &UnixStream) -> io::Result<()> {
    let t1 = spawn_relay_half(client.try_clone()?, upstream.try_clone()?);
    let t2 = spawn_relay_half(upstream.try_clone()?, client.try_clone()?);

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

#[cfg(test)]
mod tests {
    use super::sanitized_request_target_for_log;

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
    /// Regression test: on macOS (non-structural path)
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

/// Relay teardown tests.
///
/// A relay direction finishing is only half the story: the peer has to observe
/// it. These cover the half-close propagation that keeps a finished connection
/// from stranding its sibling copy thread, both sockets, and the sidecar tunnel
/// behind them. Unix-only for the same reason as [`host_bridge_tests`].
#[cfg(test)]
#[cfg(unix)]
mod relay_teardown_tests {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{relay_tcp_to_tcp, relay_with_header_injection};

    /// How long a correct implementation is given to propagate the FIN. Failure
    /// here is a hang, so every wait is bounded rather than left to the harness.
    const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(3);

    /// Connect a client to `listener` and return both ends.
    fn connected_pair(listener: &TcpListener) -> (TcpStream, TcpStream) {
        let addr: SocketAddr = listener.local_addr().expect("local_addr");
        let near = TcpStream::connect(addr).expect("connect");
        let (far, _) = listener.accept().expect("accept");
        (near, far)
    }

    /// A client that half-closes must be visible as EOF at the upstream.
    ///
    /// Without the propagation the upstream keeps waiting for bytes that will
    /// never come, so the reverse copy thread never returns and the relay never
    /// reclaims the connection.
    #[test]
    fn relay_propagates_client_half_close_to_upstream() {
        let client_listener = TcpListener::bind("127.0.0.1:0").expect("client bind");
        let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");

        let (mut client, bridge_client) = connected_pair(&client_listener);
        let (bridge_upstream, mut upstream) = connected_pair(&upstream_listener);

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(relay_tcp_to_tcp(&bridge_client, &bridge_upstream));
        });

        client.write_all(b"ping").expect("client write");
        client.shutdown(Shutdown::Write).expect("client half-close");

        upstream
            .set_read_timeout(Some(PROPAGATION_TIMEOUT))
            .expect("read timeout");

        let mut received = [0u8; 4];
        upstream.read_exact(&mut received).expect("upstream read");
        assert_eq!(&received, b"ping");

        let mut trailing = [0u8; 1];
        let eof = upstream.read(&mut trailing);
        assert!(
            matches!(eof, Ok(0)),
            "upstream never saw the client's half-close; read returned {eof:?}"
        );

        // The upstream's own close is what ends the reverse direction. A relay
        // that propagated the FIN reaches this; one that did not has a copy
        // thread parked on a socket with no writer left.
        drop(upstream);
        let relay_result = done_rx
            .recv_timeout(PROPAGATION_TIMEOUT)
            .expect("relay never returned after both sides closed");
        assert!(relay_result.is_ok(), "relay failed: {relay_result:?}");
    }

    /// The header-injecting path owes the same half-close as the plain relay.
    ///
    /// Its forward direction is a parsing loop rather than a copy, so the
    /// shutdown has to be issued by the caller once that loop returns.
    #[test]
    fn header_injection_relay_propagates_client_half_close_to_upstream() {
        let client_listener = TcpListener::bind("127.0.0.1:0").expect("client bind");
        let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");

        let (mut client, mut bridge_client) = connected_pair(&client_listener);
        let (mut bridge_upstream, mut upstream) = connected_pair(&upstream_listener);

        let mut headers = BTreeMap::new();
        headers.insert("x-firma-session-id".to_string(), "sess_607".to_string());

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = relay_with_header_injection(
                &mut bridge_client,
                &mut bridge_upstream,
                &headers,
                "test copy panic",
            );
            let _ = done_tx.send(result);
        });

        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .expect("client write");
        client.shutdown(Shutdown::Write).expect("client half-close");

        upstream
            .set_read_timeout(Some(PROPAGATION_TIMEOUT))
            .expect("read timeout");

        let mut forwarded = Vec::new();
        let mut chunk = [0u8; 512];
        let eof = loop {
            match upstream.read(&mut chunk) {
                Ok(0) => break Ok(0),
                Ok(n) => forwarded.extend_from_slice(&chunk[..n]),
                Err(error) => break Err(error),
            }
        };
        assert!(
            matches!(eof, Ok(0)),
            "upstream never saw the client's half-close; read returned {eof:?}"
        );
        let forwarded = String::from_utf8_lossy(&forwarded);
        assert!(
            forwarded.contains("x-firma-session-id: sess_607"),
            "attribution header was not injected; got:\n{forwarded}"
        );

        drop(upstream);
        let relay_result = done_rx
            .recv_timeout(PROPAGATION_TIMEOUT)
            .expect("relay never returned after both sides closed");
        assert!(relay_result.is_ok(), "relay failed: {relay_result:?}");
    }

    /// A forward-path error must tear both halves down, not just report.
    ///
    /// The response thread is parked on an upstream that will never speak
    /// again, so without the teardown the `join` inside the relay is what
    /// hangs — the error never even reaches the caller.
    #[test]
    fn header_injection_relay_unblocks_response_copy_on_forward_error() {
        let client_listener = TcpListener::bind("127.0.0.1:0").expect("client bind");
        let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");

        let (mut client, mut bridge_client) = connected_pair(&client_listener);
        let (mut bridge_upstream, _upstream) = connected_pair(&upstream_listener);

        let mut headers = BTreeMap::new();
        headers.insert("x-firma-session-id".to_string(), "sess_607".to_string());

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = relay_with_header_injection(
                &mut bridge_client,
                &mut bridge_upstream,
                &headers,
                "test copy panic",
            );
            let _ = done_tx.send(result);
        });

        // Non-UTF-8 in the request line fails header parsing. The upstream is
        // held open and silent for the whole test, so only the error-path
        // teardown can end the response copy.
        client
            .write_all(b"GET \xff\xfe HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .expect("client write");

        let relay_result = done_rx
            .recv_timeout(PROPAGATION_TIMEOUT)
            .expect("relay never returned after a forward-path error");
        assert!(
            relay_result.is_err(),
            "malformed request headers should surface as an error, got {relay_result:?}"
        );
    }
}
