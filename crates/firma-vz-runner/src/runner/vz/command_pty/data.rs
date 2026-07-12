use std::fs::File;
use std::io::{self, Write as _};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
    mpsc::{self, Receiver, Sender},
};
use std::thread;

use objc2::runtime::ProtocolObject;
use objc2::{AnyThread, DefinedClass, msg_send, rc::Retained};
use objc2_virtualization::{
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketListener, VZVirtualMachine,
};

use crate::runner::{RunnerError, RunnerResult};

use super::interop::{CommandPtyBridgeDelegate, CommandPtyBridgeDelegateIvars};
use super::plan::CommandPtyBridgePlan;
use super::terminal::{RawTerminalMode, duplicate_fd};
use super::{CommandPtyConnectionId, CommandPtyConnectionRegistration, command_pty_socket_device};

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

#[derive(Debug, Clone, Copy)]
pub struct CommandPtyBridgeConfig {
    pub guest_port: NonZeroU32,
}

impl CommandPtyBridgeConfig {
    /// Returns whether a guest connection targets this command PTY listener.
    pub const fn accepts_destination_port(self, destination_port: u32) -> bool {
        destination_port == self.guest_port.get()
    }
}

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
    pub fn accept_connection(&self, connection: &VZVirtioSocketConnection) -> bool {
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

/// Owns accepted command PTY connection handles for the listener delegate.
#[derive(Debug, Default)]
pub struct CommandPtyConnections {
    active: Mutex<Vec<CommandPtyConnection>>,
    next_id: AtomicU64,
}

impl CommandPtyConnections {
    /// Allocates the next stable PTY connection id.
    pub fn next_id(&self) -> CommandPtyConnectionId {
        let previous = self.next_id.fetch_add(1, Ordering::Relaxed);

        CommandPtyConnectionId(previous.saturating_add(1))
    }

    /// Keeps an accepted PTY connection alive for the lifetime of the registry.
    pub fn retain(
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
    pub fn active_count(&self) -> RunnerResult<usize> {
        self.active
            .lock()
            .map(|active| active.len())
            .map_err(|_| RunnerError::CommandPtyConnectionRegistryPoisoned)
    }
}

/// Owns the host forwarding threads for one accepted command PTY connection.
#[derive(Debug)]
pub struct CommandPtyConnection {
    pub id: CommandPtyConnectionId,
    pub guest_port: NonZeroU32,
    pub _host_to_guest: thread::JoinHandle<()>,
    pub _guest_to_host: thread::JoinHandle<()>,
    pub _event_logger: thread::JoinHandle<()>,
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
pub struct CommandPtyTerminalSession {
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
pub struct CommandPtyVsockStream {
    read: OwnedFd,
    write: OwnedFd,
}

impl CommandPtyVsockStream {
    /// Accepts a guest VSOCK connection by duplicating read and write fds.
    pub fn accept(fd: RawFd) -> RunnerResult<Self> {
        Ok(Self {
            read: duplicate_fd(fd)?,
            write: duplicate_fd(fd)?,
        })
    }
}

impl Drop for CommandPtyConnection {
    fn drop(&mut self) {
        let id = self.id;
        let guest_port = self.guest_port;
        eprintln!(
            "firma-vz-runner: dropping command PTY connection handle id={id} guest_port={guest_port}"
        );
    }
}

/// Direction of command PTY byte forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandPtyForwarderDirection {
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
pub enum CommandPtyForwarderEvent {
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
    pub fn message(&self) -> String {
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
    let data_port = command_pty.data_port();
    let delegate = CommandPtyBridgeDelegate::new(CommandPtyBridgeConfig {
        guest_port: data_port,
    });

    unsafe {
        listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        socket_device.setSocketListener_forPort(&listener, data_port.get());
    }

    eprintln!("firma-vz-runner: command PTY VSOCK bridge listening guest_port={data_port}");

    Ok(Some(CommandPtyBridge {
        socket_device,
        _listener: listener,
        _delegate: delegate,
        data_port,
    }))
}

/// Starts the event logger for one command PTY connection's forwarding threads.
fn spawn_forwarder_event_logger(
    event_receiver: Receiver<CommandPtyForwarderEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for event in event_receiver {
            let message = event.message();
            eprintln!("{message}");
        }
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
