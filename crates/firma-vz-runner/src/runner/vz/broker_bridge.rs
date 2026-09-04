use std::io;
use std::net::Shutdown;
use std::num::NonZeroU32;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

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

/// Checks that the configured host broker socket accepts connections before VM boot.
pub fn preflight_broker_bridge(plan: Option<&BrokerBridgePlan>) -> RunnerResult<()> {
    let Some(plan) = plan else {
        return Ok(());
    };

    UnixStream::connect(&plan.socket_path)
        .map(|_| ())
        .map_err(|source| RunnerError::BrokerUpstreamConnect {
            path: plan.socket_path.clone(),
            source,
        })
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
    });

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
        socket_device,
        _listener: listener,
        delegate,
        guest_port: plan.guest_port(),
    }))
}

/// Owns the broker listener, accepted streams, and all forwarding workers.
pub struct BrokerBridge {
    socket_device: Retained<VZVirtioSocketDevice>,
    _listener: Retained<VZVirtioSocketListener>,
    delegate: Retained<BrokerBridgeDelegate>,
    guest_port: NonZeroU32,
}

impl Drop for BrokerBridge {
    fn drop(&mut self) {
        unsafe {
            self.socket_device
                .removeSocketListenerForPort(self.guest_port.get());
        }
        self.delegate.shutdown_connections();
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
    fn new(config: BrokerBridgeConfig) -> Retained<Self> {
        let this = Self::alloc().set_ivars(BrokerBridgeDelegateIvars {
            config,
            connections: BrokerConnections::default(),
        });
        unsafe { msg_send![super(this), init] }
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
        let result = BrokerConnection::spawn(file_descriptor, &config.socket_path)
            .map_err(|source| RunnerError::BrokerUpstreamConnect {
                path: config.socket_path.clone(),
                source,
            })
            .and_then(|connection| self.ivars().connections.retain(connection));

        match result {
            Ok(active_connections) => {
                eprintln!(
                    "firma-vz-runner: accepted broker VSOCK connection guest_port={} upstream={} active_connections={active_connections}",
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

    fn shutdown_connections(&self) {
        if let Err(error) = self.ivars().connections.shutdown() {
            eprintln!("firma-vz-runner: broker bridge shutdown failed: {error}");
        }
    }
}

const CONNECTION_REAP_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug)]
struct BrokerConnections {
    shared: Arc<BrokerConnectionsShared>,
    reaper: Mutex<Option<thread::JoinHandle<()>>>,
}

#[derive(Debug, Default)]
struct BrokerConnectionsShared {
    state: Mutex<BrokerConnectionsState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct BrokerConnectionsState {
    shutting_down: bool,
    active: Vec<BrokerConnection>,
}

impl Default for BrokerConnections {
    fn default() -> Self {
        let shared = Arc::new(BrokerConnectionsShared::default());
        let reaper_shared = Arc::clone(&shared);
        let reaper = thread::spawn(move || reap_connections(&reaper_shared));
        Self {
            shared,
            reaper: Mutex::new(Some(reaper)),
        }
    }
}

impl BrokerConnections {
    fn retain(&self, connection: BrokerConnection) -> RunnerResult<usize> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)?;
        if state.shutting_down {
            return Err(RunnerError::BrokerBridgeShuttingDown);
        }
        state.active.push(connection);
        self.shared.changed.notify_one();
        Ok(state.active.len())
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
            self.shared.changed.notify_one();
        }

        let reaper = self
            .reaper
            .lock()
            .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)?
            .take();
        if reaper.is_some_and(|worker| worker.join().is_err()) {
            eprintln!("firma-vz-runner: broker connection reaper panicked during shutdown");
        }

        let connections = std::mem::take(
            &mut self
                .shared
                .state
                .lock()
                .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)?
                .active,
        );
        drop(connections);
        Ok(())
    }

    #[cfg(test)]
    fn active_count(&self) -> RunnerResult<usize> {
        self.shared
            .state
            .lock()
            .map(|state| state.active.len())
            .map_err(|_| RunnerError::BrokerConnectionRegistryPoisoned)
    }
}

impl Drop for BrokerConnections {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn reap_connections(shared: &BrokerConnectionsShared) {
    let Ok(mut state) = shared.state.lock() else {
        return;
    };

    loop {
        state.active.retain(|connection| !connection.is_finished());
        if state.shutting_down {
            return;
        }

        let Ok((next_state, _)) = shared.changed.wait_timeout(state, CONNECTION_REAP_INTERVAL)
        else {
            return;
        };
        state = next_state;
    }
}

#[derive(Debug)]
struct BrokerConnection {
    guest: UnixStream,
    upstream: UnixStream,
    workers: Vec<thread::JoinHandle<()>>,
}

impl BrokerConnection {
    fn spawn(guest_file_descriptor: RawFd, socket_path: &Path) -> io::Result<Self> {
        let guest = UnixStream::from(duplicate_fd(guest_file_descriptor)?);
        let upstream = UnixStream::connect(socket_path)?;

        let mut guest_reader = guest.try_clone()?;
        let mut guest_writer = guest.try_clone()?;
        let mut upstream_reader = upstream.try_clone()?;
        let mut upstream_writer = upstream.try_clone()?;

        let guest_to_broker = thread::spawn(move || {
            let result = io::copy(&mut guest_reader, &mut upstream_writer);
            let _ = upstream_writer.shutdown(Shutdown::Write);
            if let Err(error) = result {
                eprintln!("firma-vz-runner: VSOCK guest-to-broker forwarding failed: {error}");
            }
        });
        let broker_to_guest = thread::spawn(move || {
            let result = io::copy(&mut upstream_reader, &mut guest_writer);
            let _ = guest_writer.shutdown(Shutdown::Write);
            if let Err(error) = result {
                eprintln!("firma-vz-runner: broker-to-VSOCK guest forwarding failed: {error}");
            }
        });

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

    use super::*;

    #[test]
    fn broker_connection_forwards_bytes_and_shutdown_joins_workers() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let broker = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request)?;
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong")?;
            let mut eof = [0_u8; 1];
            assert_eq!(stream.read(&mut eof)?, 0);
            Ok(())
        });
        let (mut guest, bridge_end) = UnixStream::pair()?;
        let connections = BrokerConnections::default();
        let connection = BrokerConnection::spawn(bridge_end.as_raw_fd(), &socket_path)?;
        drop(bridge_end);
        assert_eq!(connections.retain(connection)?, 1);

        guest.write_all(b"ping")?;
        let mut response = [0_u8; 4];
        guest.read_exact(&mut response)?;
        assert_eq!(&response, b"pong");

        connections.shutdown()?;
        broker
            .join()
            .map_err(|_| anyhow::anyhow!("broker test thread panicked"))??;
        Ok(())
    }

    #[test]
    fn completed_broker_connections_are_reaped_during_operation() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let broker = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut eof = [0_u8; 1];
            assert_eq!(stream.read(&mut eof)?, 0);
            Ok(())
        });
        let (guest, bridge_end) = UnixStream::pair()?;
        let connections = BrokerConnections::default();
        let connection = BrokerConnection::spawn(bridge_end.as_raw_fd(), &socket_path)?;
        drop(bridge_end);
        assert_eq!(connections.retain(connection)?, 1);

        guest.shutdown(Shutdown::Both)?;
        broker
            .join()
            .map_err(|_| anyhow::anyhow!("broker test thread panicked"))??;

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while connections.active_count()? != 0 && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(connections.active_count()?, 0);
        connections.shutdown()?;
        Ok(())
    }

    #[test]
    fn broker_preflight_rejects_an_unavailable_socket() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("missing.sock");
        let plan = BrokerBridgePlan {
            guest_port: NonZeroU32::new(18083)
                .ok_or_else(|| anyhow::anyhow!("test port must be non-zero"))?,
            socket_path: socket_path.clone(),
            guest_addr: "127.0.0.1:18084".parse()?,
        };

        let error = preflight_broker_bridge(Some(&plan))
            .err()
            .ok_or_else(|| anyhow::anyhow!("missing broker should fail preflight"))?;

        assert!(matches!(
            error,
            RunnerError::BrokerUpstreamConnect { path, .. } if path == socket_path
        ));
        Ok(())
    }
}
