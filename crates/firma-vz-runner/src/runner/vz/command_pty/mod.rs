use std::fmt;

use objc2::rc::Retained;
use objc2_virtualization::{VZVirtioSocketDevice, VZVirtualMachine};

use super::super::{RunnerError, RunnerResult};

mod data;
mod interop;
mod plan;
mod terminal;

pub use data::install_command_pty_bridge;
pub use plan::{CommandPtyBridgePlan, CommandPtyBridgePorts};
pub use terminal::ensure_host_terminal_available;

/// Returns the single VZ virtio socket device exposed by the running VM.
fn command_pty_socket_device(
    vm: &VZVirtualMachine,
) -> RunnerResult<Retained<VZVirtioSocketDevice>> {
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

    socket_device
        .downcast::<VZVirtioSocketDevice>()
        .map_err(|_| RunnerError::UnexpectedRuntimeSocketDeviceKind)
}

/// Stable identity assigned to an accepted command PTY connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandPtyConnectionId(u64);

impl fmt::Display for CommandPtyConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Result of retaining an accepted command PTY connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandPtyConnectionRegistration {
    id: CommandPtyConnectionId,
    active_count: usize,
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use anyhow::Result;

    use super::data::{
        CommandPtyBridgeConfig, CommandPtyConnection, CommandPtyConnections,
        CommandPtyForwarderDirection, CommandPtyForwarderEvent, CommandPtyVsockStream,
    };
    use super::terminal::duplicate_fd;
    use super::*;

    #[test]
    fn command_pty_bridge_plan_accepts_data_port() -> Result<()> {
        let data_port = NonZeroU32::new(18081)
            .ok_or_else(|| anyhow::anyhow!("test data port must be non-zero"))?;
        let sidecar_port = NonZeroU32::new(18080)
            .ok_or_else(|| anyhow::anyhow!("test sidecar port must be non-zero"))?;

        let accepted = CommandPtyBridgePlan::from_ports(CommandPtyBridgePorts {
            data: data_port,
            control: NonZeroU32::new(18082)
                .ok_or_else(|| anyhow::anyhow!("test PTY control port must be non-zero"))?,
            sidecar: sidecar_port,
        })?;

        assert_eq!(accepted.data_port().get(), 18081);
        assert_eq!(accepted.control_port().get(), 18082);

        Ok(())
    }

    #[test]
    fn command_pty_bridge_plan_rejects_sidecar_port_reuse() -> Result<()> {
        let pty_port = NonZeroU32::new(18081)
            .ok_or_else(|| anyhow::anyhow!("test PTY port must be non-zero"))?;
        let control_port = NonZeroU32::new(18082)
            .ok_or_else(|| anyhow::anyhow!("test PTY control port must be non-zero"))?;

        let error = CommandPtyBridgePlan::from_ports(CommandPtyBridgePorts {
            data: pty_port,
            control: control_port,
            sidecar: pty_port,
        })
        .err()
        .ok_or_else(|| anyhow::anyhow!("Sidecar data port reuse should fail"))?;

        assert!(matches!(
            error,
            RunnerError::CommandPtyPortConflictsWithSidecar {
                pty_port: actual_pty_port,
                sidecar_port,
            } if actual_pty_port == pty_port && sidecar_port == pty_port.get()
        ));

        let error = CommandPtyBridgePlan::from_ports(CommandPtyBridgePorts {
            data: pty_port,
            control: control_port,
            sidecar: control_port,
        })
        .err()
        .ok_or_else(|| anyhow::anyhow!("Sidecar control port reuse should fail"))?;

        assert!(matches!(
            error,
            RunnerError::CommandPtyPortConflictsWithSidecar {
                pty_port: actual_pty_port,
                sidecar_port,
            } if actual_pty_port == control_port && sidecar_port == control_port.get()
        ));

        Ok(())
    }

    #[test]
    fn command_pty_bridge_config_rejects_wrong_destination_port() -> Result<()> {
        let guest_port = NonZeroU32::new(18081)
            .ok_or_else(|| anyhow::anyhow!("test PTY port must be non-zero"))?;
        let config = CommandPtyBridgeConfig { guest_port };

        assert!(config.accepts_destination_port(18081));
        assert!(!config.accepts_destination_port(18082));

        Ok(())
    }

    #[test]
    fn host_terminal_availability_returns_typed_error() {
        assert!(terminal::ensure_host_terminal_available_for_stdio(true, true).is_ok());

        let missing_stdin = terminal::ensure_host_terminal_available_for_stdio(false, true).err();
        assert!(matches!(
            missing_stdin,
            Some(RunnerError::CommandPtyHostTerminalUnavailable)
        ));

        let missing_stdout = terminal::ensure_host_terminal_available_for_stdio(true, false).err();
        assert!(matches!(
            missing_stdout,
            Some(RunnerError::CommandPtyHostTerminalUnavailable)
        ));

        let missing_both = terminal::ensure_host_terminal_available_for_stdio(false, false).err();
        assert!(matches!(
            missing_both,
            Some(RunnerError::CommandPtyHostTerminalUnavailable)
        ));
    }

    #[test]
    fn duplicate_fd_rejects_closed_connection_fd() {
        let error = duplicate_fd(-1).err();

        assert!(matches!(
            error,
            Some(RunnerError::CommandPtyClosedConnectionFd)
        ));
    }

    #[test]
    fn command_pty_vsock_stream_rejects_closed_connection_fd() {
        let error = CommandPtyVsockStream::accept(-1).err();

        assert!(matches!(
            error,
            Some(RunnerError::CommandPtyClosedConnectionFd)
        ));
    }

    #[test]
    fn command_pty_connections_retains_connection_handles() -> Result<()> {
        let connections = CommandPtyConnections::default();
        assert_eq!(connections.active_count()?, 0);

        let connection_id = connections.next_id();
        let guest_port = NonZeroU32::new(18081)
            .ok_or_else(|| anyhow::anyhow!("test PTY port must be non-zero"))?;

        let registration = connections.retain(test_connection(connection_id, guest_port))?;

        assert_eq!(connection_id, CommandPtyConnectionId(1));
        assert_eq!(
            registration,
            CommandPtyConnectionRegistration {
                id: connection_id,
                active_count: 1,
            }
        );
        assert_eq!(connections.active_count()?, 1);

        let second_id = connections.next_id();
        let second_registration = connections.retain(test_connection(second_id, guest_port))?;
        assert_eq!(
            second_registration,
            CommandPtyConnectionRegistration {
                id: second_id,
                active_count: 2,
            }
        );
        assert_eq!(connections.active_count()?, 2);
        assert_eq!(connections.next_id(), CommandPtyConnectionId(3));

        Ok(())
    }

    #[test]
    fn command_pty_forwarder_event_messages_include_connection_context() -> Result<()> {
        let connection_id = CommandPtyConnectionId(7);
        let guest_port = NonZeroU32::new(18081)
            .ok_or_else(|| anyhow::anyhow!("test PTY port must be non-zero"))?;

        let host_input_closed = CommandPtyForwarderEvent::HostInputClosed {
            connection_id,
            guest_port,
        };
        assert_eq!(
            host_input_closed.message(),
            "firma-vz-runner: command PTY host input closed id=7 guest_port=18081"
        );

        let guest_output_closed = CommandPtyForwarderEvent::GuestOutputClosed {
            connection_id,
            guest_port,
        };
        assert_eq!(
            guest_output_closed.message(),
            "firma-vz-runner: command PTY guest output closed id=7 guest_port=18081"
        );

        let forwarding_failed = CommandPtyForwarderEvent::ForwardingFailed {
            connection_id,
            guest_port,
            direction: CommandPtyForwarderDirection::HostToGuest,
            source: std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "host terminal input closed",
            ),
        };

        assert_eq!(
            forwarding_failed.message(),
            "firma-vz-runner: command PTY forwarding failed id=7 guest_port=18081 \
             direction=host-to-guest: host terminal input closed"
        );

        Ok(())
    }

    fn test_connection(id: CommandPtyConnectionId, guest_port: NonZeroU32) -> CommandPtyConnection {
        CommandPtyConnection {
            id,
            guest_port,
            _host_to_guest: std::thread::spawn(|| {}),
            _guest_to_host: std::thread::spawn(|| {}),
            _event_logger: std::thread::spawn(|| {}),
        }
    }
}
