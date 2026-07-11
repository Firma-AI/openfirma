use std::fmt;
use std::fs::File;
use std::io::{self, IsTerminal as _, Write as _};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
    mpsc::{self, Receiver, Sender},
};
use std::thread;

use objc2::runtime::ProtocolObject;
use objc2::{AnyThread, DefinedClass, define_class, msg_send, rc::Retained};
use objc2_foundation::{NSObject, NSObjectProtocol};
use objc2_virtualization::{
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketListener,
    VZVirtioSocketListenerDelegate, VZVirtualMachine,
};

use super::super::{RunnerError, RunnerResult};

/// Accepted command PTY data bridge shape derived from a validated VM plan.
#[derive(Debug, Clone, Copy)]
pub struct CommandPtyBridgePlan {
    data_port: NonZeroU32,
    control_port: NonZeroU32,
}

/// Command PTY and Sidecar ports checked together before accepting the bridge plan.
#[derive(Debug, Clone, Copy)]
pub struct CommandPtyBridgePorts {
    pub data: NonZeroU32,
    pub control: NonZeroU32,
    pub sidecar: NonZeroU32,
}

impl CommandPtyBridgePlan {
    /// Accepts the command PTY data listener after the VSOCK transport shape is known.
    pub fn from_ports(ports: CommandPtyBridgePorts) -> RunnerResult<Self> {
        if ports.data == ports.sidecar {
            return Err(RunnerError::CommandPtyPortConflictsWithSidecar {
                pty_port: ports.data,
                sidecar_port: ports.sidecar.get(),
            });
        }

        if ports.control == ports.sidecar {
            return Err(RunnerError::CommandPtyPortConflictsWithSidecar {
                pty_port: ports.control,
                sidecar_port: ports.sidecar.get(),
            });
        }

        Ok(Self {
            data_port: ports.data,
            control_port: ports.control,
        })
    }

    /// Returns the guest-side VSOCK data port used for command PTY traffic.
    pub const fn data_port(self) -> NonZeroU32 {
        self.data_port
    }

    /// Returns the guest-side VSOCK control port reserved for command PTY control traffic.
    pub const fn control_port(self) -> NonZeroU32 {
        self.control_port
    }
}

/// Ensures command PTY mode only starts with a usable host terminal.
pub fn ensure_host_terminal_available() -> RunnerResult<()> {
    ensure_host_terminal_available_for_stdio(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    )
}

/// Accepts host terminal availability before the runner enters PTY mode.
fn ensure_host_terminal_available_for_stdio(
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> RunnerResult<()> {
    if !stdin_is_terminal || !stdout_is_terminal {
        return Err(RunnerError::CommandPtyHostTerminalUnavailable);
    }

    Ok(())
}

/// Installs the command PTY data listener on the VM's VSOCK device.
pub fn install_command_pty_bridge(
    vm: &VZVirtualMachine,
    command_pty: Option<&CommandPtyBridgePlan>,
) -> RunnerResult<Option<CommandPtyBridge>> {
    let Some(command_pty) = command_pty else {
        return Ok(None);
    };

    let socket_device = command_pty_socket_device(vm)?;
    let listener = unsafe { VZVirtioSocketListener::new() };
    let delegate = CommandPtyBridgeDelegate::new(CommandPtyBridgeConfig {
        guest_port: command_pty.data_port,
    });

    unsafe {
        listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        socket_device.setSocketListener_forPort(&listener, command_pty.data_port.get());
    }

    eprintln!(
        "firma-vz-runner: command PTY VSOCK bridge listening guest_port={}",
        command_pty.data_port
    );

    Ok(Some(CommandPtyBridge {
        socket_device,
        _listener: listener,
        _delegate: delegate,
        data_port: command_pty.data_port,
    }))
}

/// Owns the installed command PTY listener and removes it when the VM stops.
pub struct CommandPtyBridge {
    socket_device: Retained<VZVirtioSocketDevice>,
    _listener: Retained<VZVirtioSocketListener>,
    _delegate: Retained<CommandPtyBridgeDelegate>,
    data_port: NonZeroU32,
}

impl Drop for CommandPtyBridge {
    fn drop(&mut self) {
        unsafe {
            self.socket_device
                .removeSocketListenerForPort(self.data_port.get());
        }
    }
}

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

#[derive(Debug, Clone, Copy)]
struct CommandPtyBridgeConfig {
    guest_port: NonZeroU32,
}

impl CommandPtyBridgeConfig {
    /// Returns whether a guest connection targets this command PTY listener.
    const fn accepts_destination_port(self, destination_port: u32) -> bool {
        destination_port == self.guest_port.get()
    }
}

#[derive(Debug)]
struct CommandPtyBridgeDelegateIvars {
    config: CommandPtyBridgeConfig,
    connections: CommandPtyConnections,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[ivars = CommandPtyBridgeDelegateIvars]
    struct CommandPtyBridgeDelegate;

    unsafe impl NSObjectProtocol for CommandPtyBridgeDelegate {}

    unsafe impl VZVirtioSocketListenerDelegate for CommandPtyBridgeDelegate {
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

impl CommandPtyBridgeDelegate {
    /// Creates a VZ socket listener delegate for one command PTY bridge.
    fn new(config: CommandPtyBridgeConfig) -> Retained<Self> {
        let this = Self::alloc().set_ivars(CommandPtyBridgeDelegateIvars {
            config,
            connections: CommandPtyConnections::default(),
        });
        unsafe { msg_send![super(this), init] }
    }

    /// Accepts valid command PTY guest connections and starts host terminal forwarding.
    fn accept_connection(&self, connection: &VZVirtioSocketConnection) -> bool {
        let config = self.ivars().config;
        let destination_port = unsafe { connection.destinationPort() };
        if !config.accepts_destination_port(destination_port) {
            eprintln!(
                "firma-vz-runner: rejecting command PTY VSOCK connection for unexpected port {destination_port}"
            );
            return false;
        }

        let file_descriptor = unsafe { connection.fileDescriptor() };
        let connection_id = self.ivars().connections.next_id();
        match CommandPtyConnection::spawn(connection_id, file_descriptor, config.guest_port)
            .and_then(|connection| self.ivars().connections.retain(connection))
        {
            Ok(registration) => {
                let guest_port = config.guest_port;
                let connection_id = registration.id;
                let active_connections = registration.active_count;
                eprintln!(
                    "firma-vz-runner: accepted command PTY VSOCK connection id={connection_id} guest_port={guest_port} active_connections={active_connections}"
                );
                true
            }
            Err(error) => {
                let guest_port = config.guest_port;
                eprintln!(
                    "firma-vz-runner: rejecting command PTY VSOCK connection id={connection_id} guest_port={guest_port}: {error}"
                );
                false
            }
        }
    }
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

/// Owns accepted command PTY connection handles for the listener delegate.
#[derive(Debug, Default)]
struct CommandPtyConnections {
    active: Mutex<Vec<CommandPtyConnection>>,
    next_id: AtomicU64,
}

impl CommandPtyConnections {
    /// Allocates the next stable PTY connection id.
    fn next_id(&self) -> CommandPtyConnectionId {
        let previous = self.next_id.fetch_add(1, Ordering::Relaxed);

        CommandPtyConnectionId(previous.saturating_add(1))
    }

    /// Keeps an accepted PTY connection alive for the lifetime of the registry.
    fn retain(
        &self,
        connection: CommandPtyConnection,
    ) -> RunnerResult<CommandPtyConnectionRegistration> {
        let id = connection.id;
        let mut active = self
            .active
            .lock()
            .map_err(|_| RunnerError::CommandPtyConnectionRegistryPoisoned)?;

        active.push(connection);

        Ok(CommandPtyConnectionRegistration {
            id,
            active_count: active.len(),
        })
    }

    #[cfg(test)]
    /// Returns the number of retained PTY connections.
    fn active_count(&self) -> RunnerResult<usize> {
        self.active
            .lock()
            .map(|active| active.len())
            .map_err(|_| RunnerError::CommandPtyConnectionRegistryPoisoned)
    }
}

/// Owns the host forwarding threads for one accepted command PTY connection.
#[derive(Debug)]
struct CommandPtyConnection {
    id: CommandPtyConnectionId,
    guest_port: NonZeroU32,
    _host_to_guest: thread::JoinHandle<()>,
    _guest_to_host: thread::JoinHandle<()>,
    _event_logger: thread::JoinHandle<()>,
}

impl CommandPtyConnection {
    /// Starts bidirectional forwarding between one guest VSOCK fd and the host terminal.
    fn spawn(
        id: CommandPtyConnectionId,
        vsock_fd: RawFd,
        guest_port: NonZeroU32,
    ) -> RunnerResult<Self> {
        let terminal = CommandPtyTerminalSession::accept()?;
        let vsock_stream = CommandPtyVsockStream::accept(vsock_fd)?;

        let (event_sender, event_receiver) = mpsc::channel();
        let event_logger = spawn_forwarder_event_logger(event_receiver);
        let host_to_guest = spawn_host_to_guest_forwarder(
            id,
            guest_port,
            terminal.stdin,
            vsock_stream.write,
            event_sender.clone(),
        );
        let guest_to_host = spawn_guest_to_host_forwarder(
            id,
            guest_port,
            terminal.raw_terminal,
            vsock_stream.read,
            terminal.stdout,
            event_sender,
        );

        Ok(Self {
            id,
            guest_port,
            _host_to_guest: host_to_guest,
            _guest_to_host: guest_to_host,
            _event_logger: event_logger,
        })
    }
}

/// Accepted host terminal state for one command PTY connection.
#[derive(Debug)]
struct CommandPtyTerminalSession {
    raw_terminal: RawTerminalMode,
    stdin: OwnedFd,
    stdout: OwnedFd,
}

impl CommandPtyTerminalSession {
    /// Accepts the host terminal by entering raw mode and duplicating stdio fds.
    fn accept() -> RunnerResult<Self> {
        let raw_terminal = RawTerminalMode::enable()
            .map_err(|source| RunnerError::CommandPtyRawMode { source })?;
        let stdin = duplicate_fd(libc::STDIN_FILENO)?;
        let stdout = duplicate_fd(libc::STDOUT_FILENO)?;

        Ok(Self {
            raw_terminal,
            stdin,
            stdout,
        })
    }
}

/// Accepted VSOCK stream fds for one command PTY connection.
#[derive(Debug)]
struct CommandPtyVsockStream {
    read: OwnedFd,
    write: OwnedFd,
}

impl CommandPtyVsockStream {
    /// Accepts a guest VSOCK connection by duplicating read and write fds.
    fn accept(fd: RawFd) -> RunnerResult<Self> {
        Ok(Self {
            read: duplicate_fd(fd)?,
            write: duplicate_fd(fd)?,
        })
    }
}

impl Drop for CommandPtyConnection {
    fn drop(&mut self) {
        eprintln!(
            "firma-vz-runner: dropping command PTY connection handle id={} guest_port={}",
            self.id, self.guest_port
        );
    }
}

/// Starts the host-terminal-to-guest-PTY forwarding thread.
fn spawn_host_to_guest_forwarder(
    connection_id: CommandPtyConnectionId,
    guest_port: NonZeroU32,
    host_stdin: OwnedFd,
    vsock_write_fd: OwnedFd,
    event_sender: Sender<CommandPtyForwarderEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut input = File::from(host_stdin);
        let mut vsock_writer = File::from(vsock_write_fd);
        let result = io::copy(&mut input, &mut vsock_writer);
        let _ = unsafe { libc::shutdown(vsock_writer.as_raw_fd(), libc::SHUT_WR) };
        let event = match result {
            Ok(_) => CommandPtyForwarderEvent::HostInputClosed {
                connection_id,
                guest_port,
            },
            Err(source) => CommandPtyForwarderEvent::ForwardingFailed {
                connection_id,
                guest_port,
                direction: CommandPtyForwarderDirection::HostToGuest,
                source,
            },
        };

        let _ = event_sender.send(event);
    })
}

/// Starts the guest-PTY-to-host-terminal forwarding thread.
fn spawn_guest_to_host_forwarder(
    connection_id: CommandPtyConnectionId,
    guest_port: NonZeroU32,
    raw_terminal: RawTerminalMode,
    vsock_read_fd: OwnedFd,
    host_stdout: OwnedFd,
    event_sender: Sender<CommandPtyForwarderEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let raw_terminal_guard = raw_terminal;
        let mut vsock_reader = File::from(vsock_read_fd);
        let mut output = File::from(host_stdout);
        let result = io::copy(&mut vsock_reader, &mut output);
        let flush_result = output.flush();
        let event = match (result, flush_result) {
            (Err(source), _) | (Ok(_), Err(source)) => CommandPtyForwarderEvent::ForwardingFailed {
                connection_id,
                guest_port,
                direction: CommandPtyForwarderDirection::GuestToHost,
                source,
            },
            (Ok(_), Ok(())) => CommandPtyForwarderEvent::GuestOutputClosed {
                connection_id,
                guest_port,
            },
        };
        let _ = event_sender.send(event);
        drop(raw_terminal_guard);
    })
}

/// Starts the event logger for one command PTY connection's forwarding threads.
fn spawn_forwarder_event_logger(
    event_receiver: Receiver<CommandPtyForwarderEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for event in event_receiver {
            eprintln!("{}", event.message());
        }
    })
}

/// Direction of command PTY byte forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandPtyForwarderDirection {
    HostToGuest,
    GuestToHost,
}

impl CommandPtyForwarderDirection {
    /// Returns a label for command PTY diagnostics.
    const fn as_str(self) -> &'static str {
        match self {
            Self::HostToGuest => "host-to-guest",
            Self::GuestToHost => "guest-to-host",
        }
    }
}

/// The lifecycle event emitted by a command PTY forwarding thread.
#[derive(Debug)]
enum CommandPtyForwarderEvent {
    HostInputClosed {
        connection_id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
    },
    GuestOutputClosed {
        connection_id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
    },
    ForwardingFailed {
        connection_id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
        direction: CommandPtyForwarderDirection,
        source: io::Error,
    },
}

impl CommandPtyForwarderEvent {
    /// Renders a stable diagnostic message for command PTY forwarding lifecycle events.
    fn message(&self) -> String {
        match self {
            Self::HostInputClosed {
                connection_id,
                guest_port,
            } => {
                format!(
                    "firma-vz-runner: command PTY host input closed id={connection_id} guest_port={guest_port}"
                )
            }
            Self::GuestOutputClosed {
                connection_id,
                guest_port,
            } => {
                format!(
                    "firma-vz-runner: command PTY guest output closed id={connection_id} guest_port={guest_port}"
                )
            }
            Self::ForwardingFailed {
                connection_id,
                guest_port,
                direction,
                source,
            } => {
                let direction = direction.as_str();
                format!(
                    "firma-vz-runner: command PTY forwarding failed id={connection_id} guest_port={guest_port} direction={direction}: {source}"
                )
            }
        }
    }
}

/// Restores host terminal mode when the PTY bridge exits.
#[derive(Debug)]
struct RawTerminalMode {
    fd: RawFd,
    original: libc::termios,
}

impl RawTerminalMode {
    /// Switches the host terminal into raw mode until the guard is dropped.
    fn enable() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command PTY mode requires host stdin and stdout to be terminals",
            ));
        }

        let fd = libc::STDIN_FILENO;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let original = unsafe { original.assume_init() };
        let mut raw = original;
        unsafe {
            libc::cfmakeraw(std::ptr::addr_of_mut!(raw));
        }

        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, std::ptr::addr_of!(raw)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, original })
    }
}

impl Drop for RawTerminalMode {
    fn drop(&mut self) {
        let _ =
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, std::ptr::addr_of!(self.original)) };
    }
}

/// Duplicates a raw file descriptor into an owned descriptor.
fn duplicate_fd(fd: RawFd) -> RunnerResult<OwnedFd> {
    if fd < 0 {
        return Err(RunnerError::CommandPtyClosedConnectionFd);
    }

    unsafe { BorrowedFd::borrow_raw(fd) }
        .try_clone_to_owned()
        .map_err(|source| RunnerError::CommandPtyDuplicateFd { fd, source })
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

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

        assert_eq!(accepted.data_port.get(), 18081);
        assert_eq!(accepted.control_port.get(), 18082);
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
        assert!(ensure_host_terminal_available_for_stdio(true, true).is_ok());

        let missing_stdin = ensure_host_terminal_available_for_stdio(false, true).err();
        assert!(matches!(
            missing_stdin,
            Some(RunnerError::CommandPtyHostTerminalUnavailable)
        ));

        let missing_stdout = ensure_host_terminal_available_for_stdio(true, false).err();
        assert!(matches!(
            missing_stdout,
            Some(RunnerError::CommandPtyHostTerminalUnavailable)
        ));

        let missing_both = ensure_host_terminal_available_for_stdio(false, false).err();
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
