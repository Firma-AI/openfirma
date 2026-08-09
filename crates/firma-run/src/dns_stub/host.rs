use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use crate::error::RunError;

use super::{handle_tcp_client, refused_response};

/// Owning handle for a host-side DNS refusal stub started for the macOS
/// structural network path.
///
/// The stub binds an ephemeral loopback UDP+TCP port and returns `REFUSED`
/// (RCODE 5) for every DNS query. It is the DNS analog of
/// [`crate::proxy_bridge::HostBridgeHandle`]: a host-side service that the
/// sandbox-exec profile allows through (loopback), while all other DNS
/// destinations are blocked by the `deny network-outbound` policy.
///
/// [`Drop`] signals the listener threads to stop and joins them.
#[expect(
    clippy::redundant_pub_crate,
    reason = "Hawk requires the source visibility to match its crate-only use"
)]
pub(crate) struct HostDnsStubHandle {
    listen_addr: SocketAddr,
    udp_stop_tx: Option<mpsc::Sender<()>>,
    tcp_stop_tx: Option<mpsc::Sender<()>>,
    udp_task: Option<JoinHandle<()>>,
    tcp_task: Option<JoinHandle<()>>,
}

impl HostDnsStubHandle {
    /// Start a host-side DNS refusal stub on an ephemeral loopback port.
    ///
    /// Binds both UDP and TCP DNS listeners on `127.0.0.1:0`, spawns listener
    /// threads, and returns immediately.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Spawn`] if the listeners cannot be bound or threads
    /// cannot be spawned.
    pub(crate) fn start() -> Result<Self, RunError> {
        let (udp, tcp, listen_addr) = bind_stub_pair()?;

        udp.set_nonblocking(true).map_err(|error| {
            RunError::Spawn(format!("failed to set DNS stub UDP non-blocking: {error}"))
        })?;
        tcp.set_nonblocking(true).map_err(|error| {
            RunError::Spawn(format!("failed to set DNS stub TCP non-blocking: {error}"))
        })?;

        let (udp_stop_tx, udp_stop_rx) = mpsc::channel::<()>();
        let (tcp_stop_tx, tcp_stop_rx) = mpsc::channel::<()>();

        let udp_task = thread::Builder::new()
            .name("firma-run-host-dns-stub-udp".to_string())
            .spawn(move || run_stub_udp_nonblocking(&udp, &udp_stop_rx))
            .map_err(|error| {
                RunError::Spawn(format!("failed to spawn host DNS stub UDP thread: {error}"))
            })?;

        let tcp_task = thread::Builder::new()
            .name("firma-run-host-dns-stub-tcp".to_string())
            .spawn(move || run_stub_tcp_nonblocking(&tcp, &tcp_stop_rx))
            .map_err(|error| {
                RunError::Spawn(format!("failed to spawn host DNS stub TCP thread: {error}"))
            })?;

        tracing::info!(
            %listen_addr,
            "host DNS refusal stub started for macOS structural network path"
        );

        Ok(Self {
            listen_addr,
            udp_stop_tx: Some(udp_stop_tx),
            tcp_stop_tx: Some(tcp_stop_tx),
            udp_task: Some(udp_task),
            tcp_task: Some(tcp_task),
        })
    }

    /// UDP+TCP address the stub is listening on.
    #[must_use]
    pub(crate) const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

impl Drop for HostDnsStubHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.udp_stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.tcp_stop_tx.take() {
            let _ = tx.send(());
        }
        // Wake the TCP accept loop by connecting briefly.
        let _ = std::net::TcpStream::connect_timeout(
            &self.listen_addr,
            std::time::Duration::from_millis(100),
        );
        if let Some(task) = self.udp_task.take() {
            let _ = task.join();
        }
        if let Some(task) = self.tcp_task.take() {
            let _ = task.join();
        }
    }
}

/// Binds a UDP and TCP loopback listener on the *same* ephemeral port.
///
/// Windows maintains independent TCP and UDP excluded-port ranges. Alternate
/// which protocol chooses the candidate so a sequence allocated from one
/// protocol's excluded range does not exhaust every attempt.
fn bind_stub_pair() -> Result<(UdpSocket, TcpListener, SocketAddr), RunError> {
    const MAX_ATTEMPTS: usize = 32;

    let mut last_error = None;

    for _ in 0..MAX_ATTEMPTS {
        match bind_udp_first() {
            Ok(pair) => return Ok(pair),
            Err(error) => last_error = Some(format!("UDP-first: {error}")),
        }

        match bind_tcp_first() {
            Ok(pair) => return Ok(pair),
            Err(error) => {
                last_error = Some(last_error.map_or_else(
                    || format!("TCP-first: {error}"),
                    |prev| format!("{prev}; TCP-first: {error}"),
                ));
            }
        }
    }

    Err(RunError::Spawn(format!(
        "failed to bind host DNS stub UDP+TCP on a shared loopback port after \
         {} candidates: {}",
        MAX_ATTEMPTS * 2,
        last_error.unwrap_or_else(|| "unknown error".into()),
    )))
}

fn bind_udp_first() -> std::io::Result<(UdpSocket, TcpListener, SocketAddr)> {
    let udp = UdpSocket::bind("127.0.0.1:0")?;
    let addr = udp.local_addr()?;
    let tcp = TcpListener::bind(addr)?;
    Ok((udp, tcp, addr))
}

fn bind_tcp_first() -> std::io::Result<(UdpSocket, TcpListener, SocketAddr)> {
    let tcp = TcpListener::bind("127.0.0.1:0")?;
    let addr = tcp.local_addr()?;
    let udp = UdpSocket::bind(addr)?;
    Ok((udp, tcp, addr))
}

fn run_stub_udp_nonblocking(socket: &UdpSocket, stop_rx: &mpsc::Receiver<()>) {
    let mut buf = [0_u8; 4096];
    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                if let Some(response) = refused_response(&buf[..len]) {
                    let _ = socket.send_to(&response, peer);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => {
                tracing::warn!("host DNS stub UDP receive failed: {error}");
                thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

fn run_stub_tcp_nonblocking(listener: &TcpListener, stop_rx: &mpsc::Receiver<()>) {
    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if let Err(error) = stream.set_nonblocking(false) {
                    tracing::warn!("host DNS stub TCP set blocking failed for {peer}: {error}");
                    continue;
                }
                thread::spawn(move || {
                    if let Err(error) = handle_tcp_client(stream) {
                        tracing::debug!("host DNS stub TCP client {peer} closed: {error}");
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => {
                tracing::warn!("host DNS stub TCP accept failed: {error}");
                thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}
