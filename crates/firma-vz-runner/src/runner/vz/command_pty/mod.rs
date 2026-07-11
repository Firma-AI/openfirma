use std::fmt;

use objc2::rc::Retained;
use objc2_virtualization::{VZVirtioSocketDevice, VZVirtualMachine};

use super::super::{RunnerError, RunnerResult};

mod control;
mod data;
mod interop;
mod plan;
mod signals;
mod terminal;

pub use control::install_command_pty_control_bridge;
pub use data::install_command_pty_bridge;
pub use plan::{CommandPtyBridgePlan, CommandPtyBridgePorts};
pub use signals::{host_sigterm_count, install_sigterm_handler, record_host_sigint};
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
    use std::sync::mpsc;

    use anyhow::Result;

    use super::control::{
        CommandPtyControlBridgeConfig, CommandPtyControlConnection, CommandPtyControlConnections,
        CommandPtyControlSession, PtyControlEvent, PtyControlMessage, PtySignal, parse_pty_signal,
        send_pty_resize, send_pty_signal,
    };
    use super::data::{
        CommandPtyBridgeConfig, CommandPtyConnection, CommandPtyConnections,
        CommandPtyForwarderDirection, CommandPtyForwarderEvent, CommandPtyVsockStream,
    };
    use super::terminal::{TerminalSize, duplicate_fd, parse_terminal_size};
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
    fn command_pty_control_bridge_config_rejects_wrong_destination_port() -> Result<()> {
        let guest_port = NonZeroU32::new(18082)
            .ok_or_else(|| anyhow::anyhow!("test PTY control port must be non-zero"))?;
        let config = CommandPtyControlBridgeConfig {
            guest_port,
            startup_resize: None,
            startup_signal: None,
        };

        assert!(config.accepts_destination_port(18082));
        assert!(!config.accepts_destination_port(18081));
        Ok(())
    }

    #[test]
    fn parses_test_terminal_size() -> Result<()> {
        assert_eq!(
            parse_terminal_size("40x120")?,
            TerminalSize {
                rows: 40,
                cols: 120,
            }
        );
        assert_eq!(
            parse_terminal_size("24,80")?,
            TerminalSize { rows: 24, cols: 80 }
        );
        assert!(parse_terminal_size("0x120").is_err());
        assert!(parse_terminal_size("40").is_err());
        Ok(())
    }

    #[test]
    fn parses_test_pty_signal_names() {
        assert_eq!(parse_pty_signal("INT"), Some(PtySignal::Int));
        assert_eq!(parse_pty_signal("sigint"), Some(PtySignal::Int));
        assert_eq!(parse_pty_signal("TERM"), Some(PtySignal::Term));
        assert_eq!(parse_pty_signal("sigterm"), Some(PtySignal::Term));
        assert_eq!(parse_pty_signal("hup"), None);
    }

    #[test]
    fn control_messages_are_line_oriented() -> Result<()> {
        let mut messages = Vec::new();

        send_pty_resize(
            &mut messages,
            TerminalSize {
                rows: 33,
                cols: 101,
            },
        )?;
        send_pty_signal(&mut messages, PtySignal::Int)?;
        send_pty_signal(&mut messages, PtySignal::Term)?;

        assert_eq!(messages, b"resize 33 101\nsignal INT\nsignal TERM\n");
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
    fn command_pty_control_connections_retains_connection_handles() -> Result<()> {
        let connections = CommandPtyControlConnections::default();
        assert_eq!(connections.active_count()?, 0);

        let connection_id = connections.next_id();
        let guest_port = NonZeroU32::new(18082)
            .ok_or_else(|| anyhow::anyhow!("test PTY control port must be non-zero"))?;

        let registration =
            connections.retain(test_control_connection(connection_id, guest_port))?;

        assert_eq!(connection_id, CommandPtyConnectionId(1));
        assert_eq!(
            registration,
            CommandPtyConnectionRegistration {
                id: connection_id,
                active_count: 1,
            }
        );
        assert_eq!(connections.active_count()?, 1);

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

    #[test]
    fn pty_control_event_messages_include_connection_context() -> Result<()> {
        let connection_id = CommandPtyConnectionId(9);
        let guest_port = NonZeroU32::new(18082)
            .ok_or_else(|| anyhow::anyhow!("test PTY control port must be non-zero"))?;

        let control_closed = PtyControlEvent::ControlClosed {
            connection_id,
            guest_port,
        };
        assert_eq!(
            control_closed.message(),
            "firma-vz-runner: command PTY control closed id=9 guest_port=18082"
        );

        let resize_failed = PtyControlEvent::ResizeForwardFailed {
            connection_id,
            guest_port,
            source: std::io::Error::new(std::io::ErrorKind::BrokenPipe, "resize channel closed"),
        };
        assert_eq!(
            resize_failed.message(),
            "firma-vz-runner: command PTY resize forwarding failed id=9 guest_port=18082: \
             resize channel closed"
        );

        let signal_failed = PtyControlEvent::SignalForwardFailed {
            connection_id,
            guest_port,
            source: std::io::Error::new(std::io::ErrorKind::BrokenPipe, "signal channel closed"),
        };
        assert_eq!(
            signal_failed.message(),
            "firma-vz-runner: command PTY signal forwarding failed id=9 guest_port=18082: \
             signal channel closed"
        );

        Ok(())
    }

    #[test]
    fn command_pty_control_session_emits_failure_and_closed_events() -> Result<()> {
        let connection_id = CommandPtyConnectionId(11);
        let guest_port = NonZeroU32::new(18082)
            .ok_or_else(|| anyhow::anyhow!("test PTY control port must be non-zero"))?;
        let (event_sender, event_receiver) = mpsc::channel();
        let mut session = CommandPtyControlSession::new(
            connection_id,
            guest_port,
            FailingControlWriter,
            event_sender,
        );

        let result = session.forward(PtyControlMessage::Resize(TerminalSize {
            rows: 40,
            cols: 120,
        }));

        assert!(result.is_err());
        let failure = event_receiver.recv()?;
        match failure {
            PtyControlEvent::ResizeForwardFailed {
                connection_id: actual_id,
                guest_port: actual_port,
                source,
            } => {
                assert_eq!(actual_id, connection_id);
                assert_eq!(actual_port, guest_port);
                assert_eq!(source.kind(), std::io::ErrorKind::BrokenPipe);
                assert_eq!(source.to_string(), "control stream reset");
            }
            _ => return Err(anyhow::anyhow!("expected resize failure event")),
        }

        let closed = event_receiver.recv()?;
        assert!(matches!(
            closed,
            PtyControlEvent::ControlClosed {
                connection_id: actual_id,
                guest_port: actual_port,
            } if actual_id == connection_id && actual_port == guest_port
        ));

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

    fn test_control_connection(
        id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
    ) -> CommandPtyControlConnection {
        CommandPtyControlConnection {
            id,
            guest_port,
            _session: std::thread::spawn(|| {}),
            _event_logger: std::thread::spawn(|| {}),
        }
    }

    struct FailingControlWriter;

    impl std::io::Write for FailingControlWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "control stream reset",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
