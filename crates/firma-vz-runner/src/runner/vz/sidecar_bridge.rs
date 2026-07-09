use std::fs::File;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::num::NonZeroU32;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::thread;
use std::time::Duration;

use objc2::runtime::ProtocolObject;
use objc2::{AnyThread, DefinedClass, define_class, msg_send, rc::Retained};
use objc2_foundation::{NSArray, NSObject, NSObjectProtocol};
use objc2_virtualization::{
    VZSocketDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
    VZVirtioSocketDeviceConfiguration, VZVirtioSocketListener, VZVirtioSocketListenerDelegate,
    VZVirtualMachine, VZVirtualMachineConfiguration,
};

use super::super::{RunnerError, RunnerResult};
use crate::vm::{SocketDeviceKind, VmNetworkMode, VmPlan};

const SIDECAR_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Accepted VSOCK sidecar bridge shape derived from a validated VM plan.
#[derive(Debug, Clone, Copy)]
pub struct SidecarBridgePlan {
    guest_port: NonZeroU32,
    sidecar_host_addr: SocketAddr,
}

impl TryFrom<&VmPlan> for SidecarBridgePlan {
    type Error = RunnerError;

    /// Accepts exactly one VSOCK sidecar bridge from the VM plan.
    fn try_from(plan: &VmPlan) -> Result<Self, Self::Error> {
        if plan.network_mode != VmNetworkMode::VsockSidecar {
            return Err(RunnerError::InvalidVsockNetworkMode);
        }

        if plan.socket_devices.len() != 1 {
            return Err(RunnerError::InvalidSocketDeviceCount {
                count: plan.socket_devices.len(),
            });
        }

        let socket_device = &plan.socket_devices[0];
        if socket_device.kind != SocketDeviceKind::VirtioVsockSidecar {
            return Err(RunnerError::InvalidSocketDeviceKind);
        }

        let guest_port =
            NonZeroU32::new(socket_device.sidecar_port).ok_or(RunnerError::ZeroSidecarPort)?;

        Ok(Self {
            guest_port,
            sidecar_host_addr: socket_device.sidecar_host_addr,
        })
    }
}

/// Configures the VZ socket device used for sidecar transport.
pub fn configure_socket_devices(
    config: &VZVirtualMachineConfiguration,
    _sidecar_bridge: &SidecarBridgePlan,
) {
    let socket_device = unsafe { VZVirtioSocketDeviceConfiguration::new() };
    let socket_devices: Retained<NSArray<VZSocketDeviceConfiguration>> =
        NSArray::from_retained_slice(&[Retained::into_super(socket_device)]);

    unsafe {
        config.setSocketDevices(&socket_devices);
    }
}

/// Installs the VSOCK listener that bridges guest traffic to the host Sidecar.
pub fn install_vsock_bridges(
    vm: &VZVirtualMachine,
    sidecar_bridge: &SidecarBridgePlan,
) -> RunnerResult<VsockBridges> {
    let socket_devices = unsafe { vm.socketDevices() };
    let socket_device_count = socket_devices.len();
    if socket_device_count == 0 {
        return Err(RunnerError::MissingRuntimeSocketDevice);
    }

    if socket_device_count != 1 {
        return Err(RunnerError::UnexpectedRuntimeSocketDevice {
            count: socket_device_count,
        });
    }

    let socket_device = socket_devices
        .to_vec()
        .into_iter()
        .next()
        .ok_or(RunnerError::MissingRuntimeSocketDevice)?;

    let socket_device = socket_device
        .downcast::<VZVirtioSocketDevice>()
        .map_err(|_| RunnerError::UnexpectedRuntimeSocketDeviceKind)?;

    let listener = unsafe { VZVirtioSocketListener::new() };
    let delegate = SidecarBridgeDelegate::new(SidecarBridgeConfig {
        guest_port: sidecar_bridge.guest_port.get(),
        sidecar_host_addr: sidecar_bridge.sidecar_host_addr,
    });

    unsafe {
        listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        socket_device.setSocketListener_forPort(&listener, sidecar_bridge.guest_port.get());
    }

    eprintln!(
        "firma-vz-runner: sidecar VSOCK bridge listening guest_port={} upstream={}",
        sidecar_bridge.guest_port, sidecar_bridge.sidecar_host_addr
    );

    Ok(VsockBridges {
        socket_device,
        _sidecar_listener: listener,
        _sidecar_delegate: delegate,
        sidecar_port: sidecar_bridge.guest_port,
    })
}

/// Checks that the accepted sidecar bridge target is reachable.
pub fn preflight_sidecar_bridge(sidecar_bridge: &SidecarBridgePlan) -> RunnerResult<()> {
    preflight_sidecar_bridge_upstream(sidecar_bridge.sidecar_host_addr).map_err(|source| {
        RunnerError::SidecarUpstreamConnect {
            addr: sidecar_bridge.sidecar_host_addr,
            source,
        }
    })
}

/// Checks that the host Sidecar endpoint is reachable before guest boot proceeds.
fn preflight_sidecar_bridge_upstream(sidecar_host_addr: SocketAddr) -> io::Result<()> {
    let stream = TcpStream::connect_timeout(&sidecar_host_addr, SIDECAR_CONNECT_TIMEOUT)?;
    stream.set_nodelay(true)?;
    Ok(())
}

/// Owns the installed VSOCK listener and removes it when the VM stops.
pub struct VsockBridges {
    socket_device: Retained<VZVirtioSocketDevice>,
    _sidecar_listener: Retained<VZVirtioSocketListener>,
    _sidecar_delegate: Retained<SidecarBridgeDelegate>,
    sidecar_port: NonZeroU32,
}

impl Drop for VsockBridges {
    fn drop(&mut self) {
        unsafe {
            self.socket_device
                .removeSocketListenerForPort(self.sidecar_port.get());
        }
    }
}

/// Runtime settings for one guest-to-Sidecar bridge listener.
#[derive(Debug, Clone, Copy)]
struct SidecarBridgeConfig {
    guest_port: u32,
    sidecar_host_addr: SocketAddr,
}

/// Objective-C delegate storage for VZ socket listener callbacks.
#[derive(Debug)]
struct SidecarBridgeDelegateIvars {
    config: SidecarBridgeConfig,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[ivars = SidecarBridgeDelegateIvars]
    struct SidecarBridgeDelegate;

    unsafe impl NSObjectProtocol for SidecarBridgeDelegate {}

    unsafe impl VZVirtioSocketListenerDelegate for SidecarBridgeDelegate {
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

impl SidecarBridgeDelegate {
    /// Creates a VZ socket listener delegate for one sidecar bridge.
    fn new(config: SidecarBridgeConfig) -> Retained<Self> {
        let this = Self::alloc().set_ivars(SidecarBridgeDelegateIvars { config });
        unsafe { msg_send![super(this), init] }
    }

    /// Accepts valid guest connections and starts host-side forwarding.
    fn accept_connection(&self, connection: &VZVirtioSocketConnection) -> bool {
        let config = self.ivars().config;
        let destination_port = unsafe { connection.destinationPort() };
        if destination_port != config.guest_port {
            eprintln!(
                "firma-vz-runner: rejecting VSOCK connection for unexpected port {destination_port}"
            );
            return false;
        }

        let file_descriptor = unsafe { connection.fileDescriptor() };
        match spawn_sidecar_bridge_connection(file_descriptor, config.sidecar_host_addr) {
            Ok(()) => {
                let guest_port = config.guest_port;
                let sidecar_host_addr = config.sidecar_host_addr;
                eprintln!(
                    "firma-vz-runner: accepted VSOCK sidecar connection guest_port={guest_port} upstream={sidecar_host_addr}"
                );
                true
            }
            Err(error) => {
                let guest_port = config.guest_port;
                let sidecar_host_addr = config.sidecar_host_addr;
                eprintln!(
                    "firma-vz-runner: rejecting VSOCK sidecar connection guest_port={guest_port} upstream={sidecar_host_addr}: {error}"
                );
                false
            }
        }
    }
}

/// Starts bidirectional forwarding between one guest VSOCK fd and the Sidecar.
fn spawn_sidecar_bridge_connection(
    guest_file_descriptor: RawFd,
    sidecar_host_addr: SocketAddr,
) -> io::Result<()> {
    let guest = File::from(duplicate_fd(guest_file_descriptor)?);
    let upstream = TcpStream::connect_timeout(&sidecar_host_addr, SIDECAR_CONNECT_TIMEOUT)?;
    upstream.set_nodelay(true)?;

    let mut guest_reader = guest.try_clone()?;
    let mut guest_writer = guest;
    let mut upstream_reader = upstream.try_clone()?;
    let mut upstream_writer = upstream;

    let _guest_to_sidecar = thread::spawn(move || {
        let result = io::copy(&mut guest_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
        if let Err(error) = result {
            eprintln!("firma-vz-runner: VSOCK guest-to-sidecar forwarding failed: {error}");
        }
    });

    let _sidecar_to_guest = thread::spawn(move || {
        if let Err(error) = io::copy(&mut upstream_reader, &mut guest_writer) {
            eprintln!("firma-vz-runner: VSOCK sidecar-to-guest forwarding failed: {error}");
        }
    });

    Ok(())
}

/// Duplicates a raw VZ connection file descriptor into an owned descriptor.
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
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::test_utils::{VZ_TEST_ROOTFS_SIZE_BYTES, vm_plan_fixture};

    #[test]
    fn sidecar_bridge_plan_accepts_vm_plan_socket_device() -> anyhow::Result<()> {
        let (_temp, plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;

        let sidecar_bridge = SidecarBridgePlan::try_from(&plan)?;

        assert_eq!(
            sidecar_bridge.guest_port.get(),
            plan.socket_devices[0].sidecar_port
        );
        assert_eq!(
            sidecar_bridge.sidecar_host_addr,
            plan.socket_devices[0].sidecar_host_addr
        );

        Ok(())
    }

    #[test]
    fn sidecar_bridge_plan_rejects_missing_socket_device() -> anyhow::Result<()> {
        let (_temp, mut plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        plan.socket_devices.clear();

        let error = SidecarBridgePlan::try_from(&plan)
            .err()
            .ok_or_else(|| anyhow::anyhow!("missing socket device should fail"))?;

        assert!(matches!(
            error,
            RunnerError::InvalidSocketDeviceCount { count: 0 }
        ));
        Ok(())
    }

    #[test]
    fn sidecar_bridge_plan_rejects_multiple_socket_devices() -> anyhow::Result<()> {
        let (_temp, mut plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        let extra_socket_device = plan.socket_devices[0].clone();
        plan.socket_devices.push(extra_socket_device);

        let error = SidecarBridgePlan::try_from(&plan)
            .err()
            .ok_or_else(|| anyhow::anyhow!("multiple socket devices should fail"))?;

        assert!(matches!(
            error,
            RunnerError::InvalidSocketDeviceCount { count: 2 }
        ));
        Ok(())
    }

    #[test]
    fn sidecar_bridge_plan_rejects_zero_sidecar_port() -> anyhow::Result<()> {
        let (_temp, mut plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        plan.socket_devices[0].sidecar_port = 0;

        let error = SidecarBridgePlan::try_from(&plan)
            .err()
            .ok_or_else(|| anyhow::anyhow!("zero sidecar port should fail"))?;

        assert!(matches!(error, RunnerError::ZeroSidecarPort));

        Ok(())
    }

    #[test]
    fn preflight_reports_typed_upstream_connection_failure() -> anyhow::Result<()> {
        let sidecar = TcpListener::bind("127.0.0.1:0")?;
        let sidecar_addr = sidecar.local_addr()?;
        drop(sidecar);

        let sidecar_bridge = SidecarBridgePlan {
            guest_port: NonZeroU32::new(1)
                .ok_or_else(|| anyhow::anyhow!("test port must be non-zero"))?,
            sidecar_host_addr: sidecar_addr,
        };
        let error = preflight_sidecar_bridge(&sidecar_bridge)
            .err()
            .ok_or_else(|| anyhow::anyhow!("closed upstream should fail preflight"))?;

        assert!(matches!(
            error,
            RunnerError::SidecarUpstreamConnect { addr, .. } if addr == sidecar_addr
        ));

        Ok(())
    }

    #[test]
    fn sidecar_bridge_forwards_guest_bytes_to_configured_upstream() -> io::Result<()> {
        let sidecar = TcpListener::bind("127.0.0.1:0")?;
        let sidecar_addr = sidecar.local_addr()?;
        let sidecar_thread = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = sidecar.accept()?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request)?;
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong")?;
            Ok(())
        });

        let (mut guest, bridge_end) = UnixStream::pair()?;
        guest.set_read_timeout(Some(Duration::from_secs(2)))?;
        guest.set_write_timeout(Some(Duration::from_secs(2)))?;
        spawn_sidecar_bridge_connection(bridge_end.as_raw_fd(), sidecar_addr)?;
        drop(bridge_end);

        guest.write_all(b"ping")?;
        guest.shutdown(Shutdown::Write)?;

        let mut response = [0_u8; 4];
        guest.read_exact(&mut response)?;
        assert_eq!(&response, b"pong");

        sidecar_thread
            .join()
            .map_err(|_| io::Error::other("sidecar bridge test thread panicked"))??;
        Ok(())
    }
}
