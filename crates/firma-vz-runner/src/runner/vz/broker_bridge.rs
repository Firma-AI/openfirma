use std::io;
use std::net::Shutdown;
use std::num::NonZeroU32;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use objc2::runtime::ProtocolObject;
use objc2::{AnyThread, DefinedClass, define_class, msg_send, rc::Retained};
use objc2_foundation::{NSObject, NSObjectProtocol};
use objc2_virtualization::{
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketListener,
    VZVirtioSocketListenerDelegate, VZVirtualMachine,
};

use super::super::{RunnerError, RunnerResult};
use crate::vm::BrokerPlan;

/// Accepted host broker bridge shape derived from a validated VM plan.
#[derive(Debug, Clone)]
pub struct BrokerBridgePlan {
    guest_port: NonZeroU32,
    socket_path: PathBuf,
    guest_addr: std::net::SocketAddr,
}

impl BrokerBridgePlan {
    /// Carries the validated VM broker plan into the VZ transport boundary.
    pub fn from_vm_plan(plan: &BrokerPlan) -> Self {
        Self {
            guest_port: plan.vsock_port,
            socket_path: plan.socket_path.clone(),
            guest_addr: plan.guest_addr,
        }
    }

    /// Returns the guest-side VSOCK port used for broker traffic.
    pub const fn guest_port(&self) -> NonZeroU32 {
        self.guest_port
    }

    /// Returns the guest-local address that forwards to this VSOCK listener.
    pub const fn guest_addr(&self) -> std::net::SocketAddr {
        self.guest_addr
    }
}

/// Installs the optional broker listener on the VM's existing VSOCK device.
pub fn install_broker_bridge(
    vm: &VZVirtualMachine,
    plan: Option<&BrokerBridgePlan>,
) -> RunnerResult<Option<BrokerBridge>> {
    let Some(plan) = plan else {
        return Ok(None);
    };

    let socket_device = broker_socket_device(vm)?;
    let listener = unsafe { VZVirtioSocketListener::new() };
    let delegate = BrokerBridgeDelegate::new(BrokerBridgeConfig {
        guest_port: plan.guest_port(),
        socket_path: plan.socket_path.clone(),
    })?;

    unsafe {
        listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        socket_device.setSocketListener_forPort(&listener, plan.guest_port().get());
    }

    eprintln!(
        "firma-vz-runner: broker VSOCK bridge listening guest_port={} guest_addr={} upstream={}",
        plan.guest_port(),
        plan.guest_addr(),
        plan.socket_path.display()
    );

    Ok(Some(BrokerBridge {
        socket_device: Some(socket_device),
        _listener: listener,
        delegate,
        guest_port: plan.guest_port(),
    }))
}

/// Owns the broker listener, accepted streams, and all forwarding workers.
pub struct BrokerBridge {
    socket_device: Option<Retained<VZVirtioSocketDevice>>,
    _listener: Retained<VZVirtioSocketListener>,
    delegate: Retained<BrokerBridgeDelegate>,
    guest_port: NonZeroU32,
}

impl BrokerBridge {
    /// Removes admission and joins all pending and active broker work.
    pub fn shutdown(mut self) -> RunnerResult<()> {
        self.remove_listener();
        self.delegate.shutdown_connections()
    }

    fn remove_listener(&mut self) {
        if let Some(socket_device) = self.socket_device.take() {
            unsafe {
                socket_device.removeSocketListenerForPort(self.guest_port.get());
            }
        }
    }
}

impl Drop for BrokerBridge {
    fn drop(&mut self) {
        self.remove_listener();
        if let Err(error) = self.delegate.shutdown_connections() {
            eprintln!("firma-vz-runner: broker bridge shutdown failed: {error}");
        }
    }
}

#[derive(Debug, Clone)]
struct BrokerBridgeConfig {
    guest_port: NonZeroU32,
    socket_path: PathBuf,
}

#[derive(Debug)]
struct BrokerBridgeDelegateIvars {
    config: BrokerBridgeConfig,
    connections: BrokerConnections,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[ivars = BrokerBridgeDelegateIvars]
    struct BrokerBridgeDelegate;

    unsafe impl NSObjectProtocol for BrokerBridgeDelegate {}

    unsafe impl VZVirtioSocketListenerDelegate for BrokerBridgeDelegate {
        #[unsafe(method(listener:shouldAcceptNewConnection:fromSocketDevice:))]
        #[allow(non_snake_case)]
        unsafe fn listener_shouldAcceptNewConnection_fromSocketDevice(
            &self,
            _listener: &VZVirtioSocketListener,
            connection: &VZVirtioSocketConnection,
            _socket_device: &VZVirtioSocketDevice,
        ) -> bool {
            self.accept_connection(connection)
        }
    }
);

impl BrokerBridgeDelegate {
    fn new(config: BrokerBridgeConfig) -> RunnerResult<Retained<Self>> {
        let connections = BrokerConnections::new(config.socket_path.clone())?;
        let this = Self::alloc().set_ivars(BrokerBridgeDelegateIvars {
            config,
            connections,
        });
        Ok(unsafe { msg_send![super(this), init] })
    }

    fn accept_connection(&self, connection: &VZVirtioSocketConnection) -> bool {
        let config = &self.ivars().config;
        let destination_port = unsafe { connection.destinationPort() };
        if destination_port != config.guest_port.get() {
            eprintln!(
                "firma-vz-runner: rejecting broker VSOCK connection for unexpected port {destination_port}"
            );
            return false;
        }

        let file_descriptor = unsafe { connection.fileDescriptor() };
        let result = self.ivars().connections.admit(file_descriptor);

        match result {
            Ok(admitted_connections) => {
                eprintln!(
                    "firma-vz-runner: accepted broker VSOCK connection guest_port={} upstream={} admitted_connections={admitted_connections}",
                    config.guest_port,
                    config.socket_path.display()
                );
                true
            }
            Err(error) => {
                eprintln!(
                    "firma-vz-runner: rejecting broker VSOCK connection guest_port={} upstream={}: {error}",
                    config.guest_port,
                    config.socket_path.display()
                );
                false
            }
        }
    }

    fn shutdown_connections(&self) -> RunnerResult<()> {
        self.ivars().connections.shutdown()
    }
}

const MAX_BROKER_CONNECTIONS: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const SUPERVISOR_TICK: Duration = Duration::from_millis(10);

#[derive(Debug)]
struct BrokerConnections {
    shared: Arc<BrokerConnectionsShared>,
    sender: mpsc::Sender<VsockStream>,
    supervisor: Mutex<Option<thread::JoinHandle<()>>>,
}

#[derive(Debug)]
struct BrokerConnectionsShared {
    state: Mutex<BrokerConnectionsState>,
    cancelled: AtomicBool,
}

#[derive(Debug, Default)]
struct BrokerConnectionsState {
    shutting_down: bool,
    admitted: usize,
}

impl Default for BrokerConnectionsShared {
    fn default() -> Self {
        Self {
            state: Mutex::new(BrokerConnectionsState::default()),
            cancelled: AtomicBool::new(false),
        }
    }
}

impl BrokerConnections {
    fn new(socket_path: PathBuf) -> RunnerResult<Self> {
        Self::new_with_connector(socket_path, Arc::new(UnixBrokerConnector))
    }

    fn new_with_connector(
        socket_path: PathBuf,
        connector: Arc<dyn BrokerConnector>,
    ) -> RunnerResult<Self> {
        Self::new_with_supervisor_start(socket_path, connector, |task| {
            thread::Builder::new()
                .name(String::from("firma-broker-bridge"))
                .spawn(task)
        })
    }

    fn new_with_supervisor_start(
        socket_path: PathBuf,
        connector: Arc<dyn BrokerConnector>,
        start: impl FnOnce(Box<dyn FnOnce() + Send>) -> io::Result<thread::JoinHandle<()>>,
    ) -> RunnerResult<Self> {
        let shared = Arc::new(BrokerConnectionsShared::default());
        let supervisor_shared = Arc::clone(&shared);
        let (sender, receiver) = mpsc::channel();
        let supervisor = start(Box::new(move || {
            supervise_connections(&supervisor_shared, &receiver, &socket_path, &*connector);
        }))
        .map_err(|source| RunnerError::BrokerBridgeSupervisorSpawn { source })?;
        Ok(Self {
            shared,
            sender,
            supervisor: Mutex::new(Some(supervisor)),
        })
    }

    #[cfg(test)]
    fn enqueue(&self, stream: VsockStream) -> RunnerResult<usize> {
        let admitted = self.reserve()?;
        self.send_reserved(stream, admitted)
    }

    fn admit(&self, file_descriptor: RawFd) -> RunnerResult<usize> {
        let admitted = self.reserve()?;
        let stream = match VsockStream::duplicate(file_descriptor) {
            Ok(stream) => stream,
            Err(source) => {
                self.release_one()?;
                return Err(RunnerError::HostOperation {
                    action: "duplicate broker VSOCK connection",
                    source,
                });
            }
        };
        self.send_reserved(stream, admitted)
    }

    fn reserve(&self) -> RunnerResult<usize> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)?;
        if state.shutting_down {
            return Err(RunnerError::BrokerBridgeShuttingDown);
        }
        if state.admitted == MAX_BROKER_CONNECTIONS {
            return Err(RunnerError::BrokerBridgeCapacity {
                limit: MAX_BROKER_CONNECTIONS,
            });
        }
        state.admitted += 1;
        let admitted = state.admitted;
        drop(state);
        Ok(admitted)
    }

    fn send_reserved(&self, stream: VsockStream, admitted: usize) -> RunnerResult<usize> {
        if self.sender.send(stream).is_err() {
            self.release_one()?;
            return Err(RunnerError::BrokerBridgeShuttingDown);
        }
        Ok(admitted)
    }

    fn shutdown(&self) -> RunnerResult<()> {
        {
            let mut state = self
                .shared
                .state
                .lock()
                .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)?;
            state.shutting_down = true;
            drop(state);
            self.shared.cancelled.store(true, Ordering::Release);
        }

        let supervisor = self
            .supervisor
            .lock()
            .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)?
            .take();
        if supervisor.is_some_and(|worker| worker.join().is_err()) {
            return Err(RunnerError::BrokerBridgeSupervisorPanicked);
        }
        Ok(())
    }

    fn release_one(&self) -> RunnerResult<()> {
        release_admission(&self.shared)
    }

    #[cfg(test)]
    fn admitted_count(&self) -> RunnerResult<usize> {
        self.shared
            .state
            .lock()
            .map(|state| state.admitted)
            .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)
    }
}

impl Drop for BrokerConnections {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn supervise_connections(
    shared: &BrokerConnectionsShared,
    receiver: &mpsc::Receiver<VsockStream>,
    socket_path: &Path,
    connector: &dyn BrokerConnector,
) {
    let mut active = Vec::new();
    loop {
        reap_finished(&mut active, shared);
        if shared.cancelled.load(Ordering::Acquire) {
            break;
        }
        match receiver.recv_timeout(SUPERVISOR_TICK) {
            Ok(guest) => match connector.connect(socket_path, &shared.cancelled) {
                Ok(upstream) => match BrokerConnection::spawn(guest, upstream) {
                    Ok(connection) => active.push(connection),
                    Err(error) => {
                        eprintln!("firma-vz-runner: spawn broker forwarding workers: {error}");
                        let _ = release_admission(shared);
                    }
                },
                Err(error) => {
                    if !shared.cancelled.load(Ordering::Acquire) {
                        eprintln!(
                            "firma-vz-runner: connect broker bridge upstream {}: {error}",
                            socket_path.display()
                        );
                    }
                    let _ = release_admission(shared);
                }
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    drop(active);
    for pending in receiver.try_iter() {
        drop(pending);
    }
    if let Ok(mut state) = shared.state.lock() {
        state.admitted = 0;
    }
}

fn reap_finished(active: &mut Vec<BrokerConnection>, shared: &BrokerConnectionsShared) {
    let mut completed = Vec::new();
    let mut index = 0;
    while index < active.len() {
        if active[index].is_finished() {
            completed.push(active.swap_remove(index));
        } else {
            index += 1;
        }
    }
    for _ in &completed {
        let _ = release_admission(shared);
    }
    drop(completed);
}

fn release_admission(shared: &BrokerConnectionsShared) -> RunnerResult<()> {
    let mut state = shared
        .state
        .lock()
        .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)?;
    state.admitted = state.admitted.saturating_sub(1);
    drop(state);
    Ok(())
}

trait BrokerConnector: Send + Sync {
    fn connect(&self, path: &Path, cancelled: &AtomicBool) -> io::Result<UnixStream>;
}

struct UnixBrokerConnector;

impl BrokerConnector for UnixBrokerConnector {
    fn connect(&self, path: &Path, cancelled: &AtomicBool) -> io::Result<UnixStream> {
        use socket2::{Domain, SockAddr, Socket, Type};

        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        let address = SockAddr::unix(path)?;
        match socket.connect(&address) {
            Ok(()) => {
                socket.set_nonblocking(false)?;
                return Ok(UnixStream::from(OwnedFd::from(socket)));
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(error) => return Err(error),
        }

        let deadline = Instant::now() + CONNECT_TIMEOUT;
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "broker bridge shutdown cancelled upstream connection",
                ));
            }
            if let Some(error) = socket.take_error()? {
                return Err(error);
            }
            if socket.peer_addr().is_ok() {
                socket.set_nonblocking(false)?;
                return Ok(UnixStream::from(OwnedFd::from(socket)));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "broker bridge upstream connection timed out after 1s",
                ));
            }
            thread::sleep(SUPERVISOR_TICK);
        }
    }
}

#[derive(Debug)]
struct VsockStream(UnixStream);

impl VsockStream {
    fn duplicate(file_descriptor: RawFd) -> io::Result<Self> {
        duplicate_fd(file_descriptor)
            .map(UnixStream::from)
            .map(Self)
    }
}

#[derive(Debug)]
struct BrokerConnection {
    guest: Arc<UnixStream>,
    upstream: Arc<UnixStream>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl BrokerConnection {
    fn spawn(guest: VsockStream, upstream: UnixStream) -> io::Result<Self> {
        let guest = Arc::new(guest.0);
        let upstream = Arc::new(upstream);
        let guest_reader = Arc::clone(&guest);
        let upstream_writer = Arc::clone(&upstream);
        let guest_to_broker = thread::Builder::new()
            .name(String::from("firma-broker-guest-to-host"))
            .spawn(move || {
                let result = io::copy(&mut &*guest_reader, &mut &*upstream_writer);
                let _ = upstream_writer.shutdown(Shutdown::Write);
                if let Err(error) = result {
                    eprintln!("firma-vz-runner: VSOCK guest-to-broker forwarding failed: {error}");
                }
            })?;
        let upstream_reader = Arc::clone(&upstream);
        let guest_writer = Arc::clone(&guest);
        let broker_to_guest = match thread::Builder::new()
            .name(String::from("firma-broker-host-to-guest"))
            .spawn(move || {
                let result = io::copy(&mut &*upstream_reader, &mut &*guest_writer);
                let _ = guest_writer.shutdown(Shutdown::Write);
                if let Err(error) = result {
                    eprintln!("firma-vz-runner: broker-to-VSOCK guest forwarding failed: {error}");
                }
            }) {
            Ok(worker) => worker,
            Err(error) => {
                let _ = guest.shutdown(Shutdown::Both);
                let _ = upstream.shutdown(Shutdown::Both);
                let _ = guest_to_broker.join();
                return Err(error);
            }
        };

        Ok(Self {
            guest,
            upstream,
            workers: vec![guest_to_broker, broker_to_guest],
        })
    }

    fn is_finished(&self) -> bool {
        self.workers.iter().all(thread::JoinHandle::is_finished)
    }
}

impl Drop for BrokerConnection {
    fn drop(&mut self) {
        let _ = self.guest.shutdown(Shutdown::Both);
        let _ = self.upstream.shutdown(Shutdown::Both);
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                eprintln!("firma-vz-runner: broker forwarding worker panicked during shutdown");
            }
        }
    }
}

fn broker_socket_device(vm: &VZVirtualMachine) -> RunnerResult<Retained<VZVirtioSocketDevice>> {
    let socket_devices = unsafe { vm.socketDevices() };
    let count = socket_devices.len();
    if count == 0 {
        return Err(RunnerError::MissingRuntimeSocketDevice);
    }
    if count != 1 {
        return Err(RunnerError::UnexpectedRuntimeSocketDevice { count });
    }

    socket_devices
        .to_vec()
        .into_iter()
        .next()
        .ok_or(RunnerError::MissingRuntimeSocketDevice)?
        .downcast::<VZVirtioSocketDevice>()
        .map_err(|_| RunnerError::UnexpectedRuntimeSocketDeviceKind)
}

fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "VSOCK connection file descriptor is closed",
        ));
    }

    unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::mpsc;

    use super::*;

    fn vsock_pair() -> io::Result<(UnixStream, VsockStream)> {
        let (guest, bridge) = UnixStream::pair()?;
        Ok((guest, VsockStream(bridge)))
    }

    fn wait_for_no_admissions(connections: &BrokerConnections) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while connections.admitted_count()? != 0 && Instant::now() < deadline {
            thread::yield_now();
        }
        anyhow::ensure!(
            connections.admitted_count()? == 0,
            "broker admission was not released"
        );
        Ok(())
    }

    fn shutdown_with_timeout(connections: BrokerConnections) -> anyhow::Result<BrokerConnections> {
        let (result_tx, result_rx) = mpsc::channel();
        let _worker = thread::spawn(move || {
            let result = connections.shutdown();
            let _ = result_tx.send((result, connections));
        });
        let (result, connections) = result_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|error| anyhow::anyhow!("broker connections did not shut down: {error}"))?;
        result?;
        Ok(connections)
    }

    fn shutdown_stream_with_timeout(stream: UnixStream) -> anyhow::Result<()> {
        let (result_tx, result_rx) = mpsc::channel();
        let _worker = thread::spawn(move || {
            let result = stream.shutdown(Shutdown::Both);
            let _ = result_tx.send(result);
        });
        result_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|error| anyhow::anyhow!("guest socket did not shut down: {error}"))??;
        Ok(())
    }

    struct StalledConnector {
        started: Mutex<Option<mpsc::Sender<()>>>,
    }

    impl BrokerConnector for StalledConnector {
        fn connect(&self, _path: &Path, cancelled: &AtomicBool) -> io::Result<UnixStream> {
            if let Ok(mut sender) = self.started.lock()
                && let Some(sender) = sender.take()
            {
                let _ = sender.send(());
            }
            while !cancelled.load(Ordering::Acquire) {
                thread::sleep(SUPERVISOR_TICK);
            }
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "test connector cancelled",
            ))
        }
    }

    #[test]
    fn broker_bridge_relay_preserves_half_close_and_explicit_shutdown() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let broker = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request)?;
            assert_eq!(&request, b"ping");
            let mut eof = [0_u8; 1];
            assert_eq!(stream.read(&mut eof)?, 0);
            stream.write_all(b"pong")?;
            Ok(())
        });
        let (mut guest, bridge_end) = vsock_pair()?;
        let connections = BrokerConnections::new(socket_path)?;
        assert_eq!(connections.enqueue(bridge_end)?, 1);

        guest.write_all(b"ping")?;
        guest.shutdown(Shutdown::Write)?;
        let mut response = [0_u8; 4];
        guest.read_exact(&mut response)?;
        assert_eq!(&response, b"pong");
        broker
            .join()
            .map_err(|_| anyhow::anyhow!("broker test thread panicked"))??;
        connections.shutdown()?;
        assert_eq!(connections.admitted_count()?, 0);
        Ok(())
    }

    #[test]
    fn completed_broker_connection_releases_capacity() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (broker_result_tx, broker_result_rx) = mpsc::channel();
        let _broker = thread::spawn(move || {
            let result = (|| -> io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                let _ = accepted_tx.send(());
                let mut eof = [0_u8; 1];
                assert_eq!(stream.read(&mut eof)?, 0);
                Ok(())
            })();
            let _ = broker_result_tx.send(result);
        });
        let (guest, bridge_end) = vsock_pair()?;
        let mut guest = Some(guest);
        let connections = BrokerConnections::new(socket_path)?;

        let result = (|| {
            assert_eq!(connections.enqueue(bridge_end)?, 1);
            accepted_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| {
                    anyhow::anyhow!("broker did not accept bridge connection: {error}")
                })?;
            let guest = guest
                .take()
                .ok_or_else(|| anyhow::anyhow!("guest socket was already shut down"))?;
            shutdown_stream_with_timeout(guest)?;
            broker_result_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| anyhow::anyhow!("broker did not observe bridge EOF: {error}"))??;
            wait_for_no_admissions(&connections)
        })();
        let guest_shutdown = guest.take().map(shutdown_stream_with_timeout).transpose();
        let shutdown = shutdown_with_timeout(connections);
        result?;
        let _ = guest_shutdown?;
        shutdown.map(drop)
    }

    #[test]
    fn callback_admission_is_nonblocking_and_capacity_counts_pending_work() -> anyhow::Result<()> {
        let (started_tx, started_rx) = mpsc::channel();
        let connector = Arc::new(StalledConnector {
            started: Mutex::new(Some(started_tx)),
        });
        let connections = BrokerConnections::new_with_connector(PathBuf::new(), connector)?;
        let mut guests = Vec::new();
        let started_at = Instant::now();
        for expected in 1..=MAX_BROKER_CONNECTIONS {
            let (guest, bridge) = UnixStream::pair()?;
            guests.push(guest);
            assert_eq!(connections.admit(bridge.as_raw_fd())?, expected);
        }
        assert_eq!(guests.len(), MAX_BROKER_CONNECTIONS);
        anyhow::ensure!(
            started_at.elapsed() < Duration::from_millis(100),
            "callback admission blocked on the injected connector"
        );
        started_rx.recv_timeout(Duration::from_secs(1))?;
        assert_eq!(connections.admitted_count()?, MAX_BROKER_CONNECTIONS);

        let (_guest, excess) = UnixStream::pair()?;
        let error = connections
            .admit(excess.as_raw_fd())
            .expect_err("the thirty-third pending connection must be rejected");
        assert!(matches!(
            error,
            RunnerError::BrokerBridgeCapacity {
                limit: MAX_BROKER_CONNECTIONS
            }
        ));
        connections.shutdown()?;
        assert_eq!(connections.admitted_count()?, 0);
        Ok(())
    }

    #[test]
    fn shutdown_cancels_stalled_upstream_connect() -> anyhow::Result<()> {
        let (started_tx, started_rx) = mpsc::channel();
        let connector = Arc::new(StalledConnector {
            started: Mutex::new(Some(started_tx)),
        });
        let connections = BrokerConnections::new_with_connector(PathBuf::new(), connector)?;
        let (_guest, bridge) = vsock_pair()?;
        connections.enqueue(bridge)?;
        started_rx.recv_timeout(Duration::from_secs(1))?;

        let started_at = Instant::now();
        let connections = shutdown_with_timeout(connections)?;
        anyhow::ensure!(
            started_at.elapsed() < Duration::from_millis(250),
            "shutdown did not cancel stalled connect promptly"
        );
        assert_eq!(connections.admitted_count()?, 0);
        Ok(())
    }

    #[test]
    fn supervisor_spawn_failure_is_returned() {
        let connector = Arc::new(StalledConnector {
            started: Mutex::new(None),
        });
        let result =
            BrokerConnections::new_with_supervisor_start(PathBuf::new(), connector, |_task| {
                Err(io::Error::other("injected spawn failure"))
            });
        let error = result.expect_err("supervisor spawn failure must reject bridge creation");
        assert!(matches!(
            error,
            RunnerError::BrokerBridgeSupervisorSpawn { source }
                if source.to_string() == "injected spawn failure"
        ));
    }
}
