use std::fs::File;
use std::io;
use std::num::NonZeroU32;
use std::os::fd::RawFd;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
    mpsc::{self, Receiver, Sender},
};
use std::thread;
use std::time::Duration;

use objc2::runtime::ProtocolObject;
use objc2::{AnyThread, DefinedClass, msg_send, rc::Retained};
use objc2_virtualization::{
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketListener, VZVirtualMachine,
};

use crate::runner::{RunnerError, RunnerResult};

use super::interop::{CommandPtyControlBridgeDelegate, CommandPtyControlBridgeDelegateIvars};
use super::plan::CommandPtyBridgePlan;
use super::terminal::{TerminalSize, duplicate_fd, read_host_terminal_size};
use super::{CommandPtyConnectionId, CommandPtyConnectionRegistration, command_pty_socket_device};
use super::{signals, terminal};

const PTY_STARTUP_RESIZE_ENV: &str = "FIRMA_VZ_RUNNER_PTY_STARTUP_RESIZE";
const PTY_STARTUP_SIGNAL_ENV: &str = "FIRMA_VZ_RUNNER_PTY_STARTUP_SIGNAL";
const PTY_STARTUP_CONTROL_DELAY: Duration = Duration::from_millis(250);
const PTY_HOST_CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Installs the command PTY control listener on the VM's VSOCK device.
pub fn install_command_pty_control_bridge(
    vm: &VZVirtualMachine,
    command_pty: Option<&CommandPtyBridgePlan>,
) -> RunnerResult<Option<CommandPtyControlBridge>> {
    let Some(command_pty) = command_pty else {
        return Ok(None);
    };

    let control_port = command_pty.control_port();
    let socket_device = command_pty_socket_device(vm)?;
    let listener = unsafe { VZVirtioSocketListener::new() };
    let delegate = CommandPtyControlBridgeDelegate::new(CommandPtyControlBridgeConfig {
        guest_port: control_port,
        startup_resize: parse_startup_terminal_size_env(),
        startup_signal: parse_startup_pty_signal_env(),
    });

    unsafe {
        listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        socket_device.setSocketListener_forPort(&listener, control_port.get());
    }

    eprintln!(
        "firma-vz-runner: command PTY control VSOCK bridge listening guest_port={control_port}"
    );

    Ok(Some(CommandPtyControlBridge {
        socket_device,
        _listener: listener,
        _delegate: delegate,
        control_port,
    }))
}

/// Owns the installed command PTY control listener and removes it when the VM stops.
pub struct CommandPtyControlBridge {
    socket_device: Retained<VZVirtioSocketDevice>,
    _listener: Retained<VZVirtioSocketListener>,
    _delegate: Retained<CommandPtyControlBridgeDelegate>,
    control_port: NonZeroU32,
}

impl Drop for CommandPtyControlBridge {
    fn drop(&mut self) {
        unsafe {
            self.socket_device
                .removeSocketListenerForPort(self.control_port.get());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtySignal {
    Int,
    Term,
}

#[derive(Debug, Clone, Copy)]
pub struct CommandPtyControlBridgeConfig {
    pub guest_port: NonZeroU32,
    pub startup_resize: Option<TerminalSize>,
    pub startup_signal: Option<PtySignal>,
}

impl CommandPtyControlBridgeConfig {
    /// Returns whether a guest connection targets this command PTY control listener.
    pub const fn accepts_destination_port(self, destination_port: u32) -> bool {
        destination_port == self.guest_port.get()
    }
}

impl CommandPtyControlBridgeDelegate {
    /// Creates a VZ socket listener delegate for one command PTY control bridge.
    fn new(config: CommandPtyControlBridgeConfig) -> Retained<Self> {
        let this = Self::alloc().set_ivars(CommandPtyControlBridgeDelegateIvars {
            config,
            connections: CommandPtyControlConnections::default(),
        });
        unsafe { msg_send![super(this), init] }
    }

    /// Accepts valid command PTY control connections and starts control forwarding.
    pub fn accept_connection(&self, connection: &VZVirtioSocketConnection) -> bool {
        let config = self.ivars().config;
        let destination_port = unsafe { connection.destinationPort() };
        if !config.accepts_destination_port(destination_port) {
            eprintln!(
                "firma-vz-runner: rejecting command PTY control VSOCK connection for unexpected port {destination_port}"
            );
            return false;
        }

        let file_descriptor = unsafe { connection.fileDescriptor() };
        let connection_id = self.ivars().connections.next_id();
        match self
            .ivars()
            .connections
            .accept(connection_id, file_descriptor, config)
        {
            Ok(registration) => {
                let guest_port = config.guest_port;
                let connection_id = registration.id;
                let active_connections = registration.active_count;
                eprintln!(
                    "firma-vz-runner: accepted command PTY control VSOCK connection id={connection_id} guest_port={guest_port} active_connections={active_connections}"
                );
                true
            }
            Err(error) => {
                let guest_port = config.guest_port;
                eprintln!(
                    "firma-vz-runner: rejecting command PTY control VSOCK connection id={connection_id} guest_port={guest_port}: {error}"
                );
                false
            }
        }
    }
}

/// Owns accepted command PTY control connection handles for the listener delegate.
#[derive(Debug, Default)]
pub struct CommandPtyControlConnections {
    active: Mutex<Vec<CommandPtyControlConnection>>,
    next_id: AtomicU64,
}

impl CommandPtyControlConnections {
    /// Allocates the next stable PTY control connection id.
    pub fn next_id(&self) -> CommandPtyConnectionId {
        let previous = self.next_id.fetch_add(1, Ordering::Relaxed);

        CommandPtyConnectionId(previous.saturating_add(1))
    }

    /// Accepts and retains one command PTY control connection.
    pub fn accept(
        &self,
        connection_id: CommandPtyConnectionId,
        file_descriptor: RawFd,
        config: CommandPtyControlBridgeConfig,
    ) -> RunnerResult<CommandPtyConnectionRegistration> {
        let connection =
            spawn_command_pty_control_connection(connection_id, file_descriptor, config)?;

        self.retain(connection)
    }

    /// Keeps an accepted PTY control connection alive for the lifetime of the registry.
    pub fn retain(
        &self,
        connection: CommandPtyControlConnection,
    ) -> RunnerResult<CommandPtyConnectionRegistration> {
        let id = connection.id;
        let mut active = self
            .active
            .lock()
            .map_err(|_| RunnerError::CommandPtyControlConnectionRegistryPoisoned)?;

        active.push(connection);

        Ok(CommandPtyConnectionRegistration {
            id,
            active_count: active.len(),
        })
    }

    #[cfg(test)]
    /// Returns the number of retained PTY control connections.
    pub fn active_count(&self) -> RunnerResult<usize> {
        self.active
            .lock()
            .map(|active| active.len())
            .map_err(|_| RunnerError::CommandPtyControlConnectionRegistryPoisoned)
    }
}

/// Owns the control forwarding thread for one accepted command PTY control connection.
#[derive(Debug)]
pub struct CommandPtyControlConnection {
    pub id: CommandPtyConnectionId,
    pub guest_port: NonZeroU32,
    pub _session: thread::JoinHandle<()>,
    pub _event_logger: thread::JoinHandle<()>,
}

impl Drop for CommandPtyControlConnection {
    fn drop(&mut self) {
        let id = self.id;
        let guest_port = self.guest_port;
        eprintln!(
            "firma-vz-runner: dropping command PTY control connection handle id={id} guest_port={guest_port}"
        );
    }
}

/// Bridges one accepted command PTY control VSOCK descriptor to resize and signal events.
pub fn spawn_command_pty_control_connection(
    connection_id: CommandPtyConnectionId,
    vsock_fd: RawFd,
    config: CommandPtyControlBridgeConfig,
) -> RunnerResult<CommandPtyControlConnection> {
    signals::install_sigwinch_handler().map_err(|source| RunnerError::HostOperation {
        action: "install SIGWINCH handler for command PTY control",
        source,
    })?;
    let vsock_control_fd = duplicate_fd(vsock_fd)?;
    let guest_port = config.guest_port;
    let (event_sender, event_receiver) = mpsc::channel();
    let event_logger = spawn_control_event_logger(event_receiver);
    let session = thread::spawn(move || {
        CommandPtyControlSession::new(
            connection_id,
            config.guest_port,
            File::from(vsock_control_fd),
            event_sender,
        )
        .run(config);
    });

    Ok(CommandPtyControlConnection {
        id: connection_id,
        guest_port,
        _session: session,
        _event_logger: event_logger,
    })
}

/// Runs the lifecycle for one accepted command PTY control stream.
pub struct CommandPtyControlSession<W = File> {
    connection_id: CommandPtyConnectionId,
    guest_port: NonZeroU32,
    control: W,
    events: Sender<PtyControlEvent>,
}

impl<W: io::Write> CommandPtyControlSession<W> {
    /// Creates a control session for one accepted command PTY connection.
    pub fn new(
        connection_id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
        control: W,
        events: Sender<PtyControlEvent>,
    ) -> Self {
        Self {
            connection_id,
            guest_port,
            control,
            events,
        }
    }

    /// Runs initial setup, test hooks and host control forwarding.
    pub fn run(mut self, config: CommandPtyControlBridgeConfig) {
        if self.forward_initial_size().is_err() {
            return;
        }

        if self.forward_startup_control_messages(config).is_err() {
            return;
        }

        self.forward_host_events();
    }

    /// Sends the current terminal size once when the control stream starts.
    fn forward_initial_size(&mut self) -> Result<(), PtyControlClosed> {
        if let Ok(size) = read_host_terminal_size() {
            self.forward(PtyControlMessage::Resize(size))?;
        }

        Ok(())
    }

    /// Sends configured PTY control messages after the guest connects.
    fn forward_startup_control_messages(
        &mut self,
        config: CommandPtyControlBridgeConfig,
    ) -> Result<(), PtyControlClosed> {
        if let Some(size) = config.startup_resize {
            thread::sleep(PTY_STARTUP_CONTROL_DELAY);
            self.forward(PtyControlMessage::Resize(size))?;
        }

        if let Some(signal) = config.startup_signal {
            thread::sleep(PTY_STARTUP_CONTROL_DELAY);
            self.forward(PtyControlMessage::Signal(signal))?;
        }

        Ok(())
    }

    /// Polls host resize and signal counters and forwards changes to the guest.
    fn forward_host_events(&mut self) {
        let mut last_sigint = signals::host_sigint_count();
        let mut last_sigterm = signals::host_sigterm_count();
        let mut last_sigwinch = signals::host_sigwinch_count();
        loop {
            thread::sleep(PTY_HOST_CONTROL_POLL_INTERVAL);
            let next_sigint = signals::host_sigint_count();
            if next_sigint != last_sigint {
                last_sigint = next_sigint;
                if self
                    .forward(PtyControlMessage::Signal(PtySignal::Int))
                    .is_err()
                {
                    return;
                }
            }

            let next_sigterm = signals::host_sigterm_count();
            if next_sigterm != last_sigterm {
                last_sigterm = next_sigterm;
                if self
                    .forward(PtyControlMessage::Signal(PtySignal::Term))
                    .is_err()
                {
                    return;
                }
            }

            let next_sigwinch = signals::host_sigwinch_count();
            if next_sigwinch == last_sigwinch {
                continue;
            }
            last_sigwinch = next_sigwinch;
            let size = match read_host_terminal_size() {
                Ok(size) => size,
                Err(error) => {
                    eprintln!(
                        "firma-vz-runner: read host terminal size after SIGWINCH failed: {error}"
                    );
                    continue;
                }
            };

            if self.forward(PtyControlMessage::Resize(size)).is_err() {
                return;
            }
        }
    }

    /// Forwards one control message to the guest.
    pub fn forward(&mut self, message: PtyControlMessage) -> Result<(), PtyControlClosed> {
        if let Err(source) = message.send(&mut self.control) {
            let failure =
                message.forward_failure_event(self.connection_id, self.guest_port, source);
            let _ = self.events.send(failure);
            let _ = self.events.send(PtyControlEvent::ControlClosed {
                connection_id: self.connection_id,
                guest_port: self.guest_port,
            });
            return Err(PtyControlClosed);
        }

        Ok(())
    }
}

/// The command PTY control stream closed while forwarding to the guest.
#[derive(Debug, Clone, Copy)]
pub struct PtyControlClosed;

/// A control message sent from the host runner to the guest PTY runtime.
#[derive(Debug, Clone, Copy)]
pub enum PtyControlMessage {
    Resize(TerminalSize),
    Signal(PtySignal),
}

impl PtyControlMessage {
    /// Sends the message over the accepted control stream.
    fn send(self, control: &mut impl io::Write) -> io::Result<()> {
        match self {
            Self::Resize(size) => send_pty_resize(control, size),
            Self::Signal(signal) => send_pty_signal(control, signal),
        }
    }

    /// Converts a send failure into the matching lifecycle event.
    fn forward_failure_event(
        self,
        connection_id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
        source: io::Error,
    ) -> PtyControlEvent {
        match self {
            Self::Resize(_) => PtyControlEvent::ResizeForwardFailed {
                connection_id,
                guest_port,
                source,
            },
            Self::Signal(_) => PtyControlEvent::SignalForwardFailed {
                connection_id,
                guest_port,
                source,
            },
        }
    }
}

/// Starts the event logger for one command PTY control forwarding thread.
pub fn spawn_control_event_logger(
    event_receiver: Receiver<PtyControlEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for event in event_receiver {
            let message = event.message();
            eprintln!("{message}");
        }
    })
}

/// The lifecycle event emitted by a command PTY control forwarding thread.
#[derive(Debug)]
pub enum PtyControlEvent {
    ControlClosed {
        connection_id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
    },
    ResizeForwardFailed {
        connection_id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
        source: io::Error,
    },
    SignalForwardFailed {
        connection_id: CommandPtyConnectionId,
        guest_port: NonZeroU32,
        source: io::Error,
    },
}

impl PtyControlEvent {
    /// Renders a stable diagnostic message for command PTY control lifecycle events.
    pub fn message(&self) -> String {
        match self {
            Self::ControlClosed {
                connection_id,
                guest_port,
            } => {
                format!(
                    "firma-vz-runner: command PTY control closed id={connection_id} guest_port={guest_port}"
                )
            }
            Self::ResizeForwardFailed {
                connection_id,
                guest_port,
                source,
            } => {
                format!(
                    "firma-vz-runner: command PTY resize forwarding failed id={connection_id} guest_port={guest_port}: {source}"
                )
            }
            Self::SignalForwardFailed {
                connection_id,
                guest_port,
                source,
            } => {
                format!(
                    "firma-vz-runner: command PTY signal forwarding failed id={connection_id} guest_port={guest_port}: {source}"
                )
            }
        }
    }
}

/// Sends one PTY resize control message to the guest.
pub fn send_pty_resize(control: &mut impl io::Write, size: TerminalSize) -> io::Result<()> {
    let rows = size.rows;
    let cols = size.cols;
    writeln!(control, "resize {rows} {cols}")?;
    control.flush()
}

/// Sends one PTY signal control message to the guest.
pub fn send_pty_signal(control: &mut impl io::Write, signal: PtySignal) -> io::Result<()> {
    let name = match signal {
        PtySignal::Int => "INT",
        PtySignal::Term => "TERM",
    };
    writeln!(control, "signal {name}")?;
    control.flush()
}

/// Reads an optional startup terminal resize from the environment.
fn parse_startup_terminal_size_env() -> Option<TerminalSize> {
    let value = std::env::var(PTY_STARTUP_RESIZE_ENV).ok()?;
    terminal::parse_terminal_size(&value).ok()
}

/// Reads an optional startup PTY signal from the environment.
fn parse_startup_pty_signal_env() -> Option<PtySignal> {
    let value = std::env::var(PTY_STARTUP_SIGNAL_ENV).ok()?;
    parse_pty_signal(&value)
}

/// Parses a PTY control signal name from startup configuration.
pub fn parse_pty_signal(value: &str) -> Option<PtySignal> {
    match value.trim().to_ascii_uppercase().as_str() {
        "INT" | "SIGINT" => Some(PtySignal::Int),
        "TERM" | "SIGTERM" => Some(PtySignal::Term),
        _ => None,
    }
}
