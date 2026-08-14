use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// Best-effort discovery of this host's primary non-loopback (outbound) IP.
///
/// Uses the "connect a UDP socket and read its local address" trick: no packets
/// are sent, but the kernel picks the source address it would route through.
/// Returns `None` when the host has no non-loopback route (e.g. a stripped CI
/// container), leaving the caller to fall back to loopback.
#[must_use]
pub fn outbound_host_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() { None } else { Some(ip) }
}

/// A TCP proxy that counts accepted client connections while forwarding their
/// bytes to an upstream address.
///
/// wiremock only records *HTTP* requests, so a raw `connect()` + non-HTTP
/// `send()` leaves no server-side trace. Fronting wiremock with this proxy gives
/// the egress scenarios a real "the agent's socket reached us" signal — the
/// count of accepted TCP connections — while HTTP scenarios keep working because
/// every byte is spliced through to the wiremock backend.
///
/// The bind interface is caller-chosen: loopback exercises the seccomp loopback
/// guard, while a non-loopback host IP exercises the network-namespace egress
/// boundary.
pub struct RawTcpProxy {
    addr: SocketAddr,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RawTcpProxy {
    /// Bind a loopback listener on an ephemeral port and forward every accepted
    /// connection to `upstream`, counting connections as they arrive.
    ///
    /// # Errors
    ///
    /// Returns an error if the front listener cannot bind or its address cannot
    /// be read.
    pub fn start(upstream: SocketAddr) -> io::Result<Self> {
        Self::start_on(IpAddr::from([127, 0, 0, 1]), upstream)
    }

    /// Like [`Self::start`] but binds the front listener on `bind_ip`, so the
    /// agent's destination can be steered onto loopback or a routable interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the front listener cannot bind or its address cannot
    /// be read.
    pub fn start_on(bind_ip: IpAddr, upstream: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0))?;
        let addr = listener.local_addr()?;
        // Non-blocking accept so the loop can observe the stop flag between
        // connections instead of parking forever in `accept`.
        listener.set_nonblocking(true)?;

        let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let count = Arc::clone(&count);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            count.fetch_add(1, Ordering::SeqCst);
                            std::thread::spawn(move || forward(client, upstream));
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        // A transient accept error (e.g. EMFILE) must not tear
                        // down counting for the rest of the run, or a later phase
                        // would silently see zero connections. Keep serving.
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            })
        };

        Ok(Self {
            addr,
            count,
            stop,
            handle: Some(handle),
        })
    }

    /// Address clients should connect to.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    /// Number of TCP connections accepted since the last [`Self::reset`].
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Reset the accepted-connection counter to zero. Called between the
    /// baseline and enforcement phases so each phase is measured in isolation.
    pub fn reset(&self) {
        self.count.store(0, Ordering::SeqCst);
    }
}

impl Drop for RawTcpProxy {
    fn drop(&mut self) {
        // Stops and joins only the accept loop. In-flight `forward` workers are
        // detached; they wind down on their own via the read timeout in
        // `forward`, well within the harness process lifetime.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Splice `client` <-> `upstream` in both directions. Best-effort: any error
/// (including a non-HTTP payload that the upstream rejects) just ends the copy.
/// The connection has already been counted before this runs.
fn forward(client: TcpStream, upstream: SocketAddr) {
    let Ok(server) = TcpStream::connect_timeout(&upstream, Duration::from_secs(5)) else {
        return;
    };
    // Bound each direction so a peer that never closes cannot pin the worker
    // thread forever; payloads in these scenarios are tiny.
    let timeout = Some(Duration::from_secs(10));
    let _ = client.set_read_timeout(timeout);
    let _ = server.set_read_timeout(timeout);

    let (Ok(mut client_rx), Ok(mut server_tx)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut client_rx, &mut server_tx);
    });
    let mut server_rx = server;
    let mut client_tx = client;
    let _ = io::copy(&mut server_rx, &mut client_tx);
    let _ = up.join();
}
