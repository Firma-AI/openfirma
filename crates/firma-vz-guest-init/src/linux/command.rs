use std::fs::File;
use std::io::{self, BufRead, Write as _};
use std::num::NonZeroU16;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use super::contract::{CommandContract, Contract, PtyPlan, Terminal};
use super::error::{InitError, InitResult};
use super::log;
use super::mount::create_dir_path;
use super::network::{CommandNetworkEnv, connect_vsock_host};

const GUEST_STDIN_FILE: &str = "guest-stdin.bin";
const GUEST_STDOUT_FILE: &str = "guest-stdout.log";
const GUEST_STDERR_FILE: &str = "guest-stderr.log";

/// Guest command completion reported back to the host runner.
#[derive(Debug)]
pub enum CommandOutcome {
    /// Process exited normally with an exit status.
    Exited(u8),
    /// Process terminated because of a Unix signal.
    Signaled(i32),
}

/// Runtime command path used for status logging and missing-status errors.
#[derive(Clone, Copy, Debug)]
enum CommandKind {
    /// Noninteractive command with stdio persisted through runtime files.
    NonInteractive,
    /// Interactive command attached to a guest PTY.
    Pty,
}

impl CommandKind {
    /// Readable command label for guest serial diagnostics.
    const fn log_label(self) -> &'static str {
        match self {
            Self::NonInteractive => "command",
            Self::Pty => "PTY command",
        }
    }

    /// Error emitted when the kernel reports neither exit code nor signal.
    const fn missing_status_error(self) -> InitError {
        match self {
            Self::NonInteractive => InitError::CommandMissingStatus,
            Self::Pty => InitError::CommandPtyMissingStatus,
        }
    }
}

/// Converts a process status into the guest command result protocol.
fn command_outcome_from_status(
    kind: CommandKind,
    status: ExitStatus,
) -> InitResult<CommandOutcome> {
    match (status.code(), status.signal()) {
        (Some(code), _) => {
            let code = u8::try_from(code).unwrap_or(u8::MAX);
            log(&format!("{} exited with status {code}", kind.log_label()));
            Ok(CommandOutcome::Exited(code))
        }
        (None, Some(signal)) => {
            log(&format!(
                "{} terminated by signal {signal}",
                kind.log_label()
            ));
            Ok(CommandOutcome::Signaled(signal))
        }
        (None, None) => Err(kind.missing_status_error()),
    }
}

/// Runs the accepted launch contract command.
pub fn execute_contract(
    contract_path: &Path,
    contract: &Contract,
    command_env: &CommandNetworkEnv,
) -> InitResult<CommandOutcome> {
    match contract.terminal() {
        Terminal::NonInteractive => run_command(contract_path, contract, command_env),
        Terminal::Pty(pty) => run_command_with_pty(contract, pty, command_env),
    }
}

/// Spawns the payload with the contract-provided cwd, argv, and environment.
fn run_command(
    contract_path: &Path,
    contract: &Contract,
    command_env: &CommandNetworkEnv,
) -> InitResult<CommandOutcome> {
    let command = contract.command();
    create_dir_path(&command.cwd)?;
    let stdin = command_stdin(contract_path)?;
    let stdout = create_command_stdio_file(contract_path, GUEST_STDOUT_FILE)?;
    let stderr = create_command_stdio_file(contract_path, GUEST_STDERR_FILE)?;

    log(&format!(
        "running command: {} {:?} cwd={}",
        command.executable,
        command.args,
        command.cwd.display()
    ));

    let status = Command::new(&command.executable)
        .args(&command.args)
        .current_dir(&command.cwd)
        .env_clear()
        .envs(command_env.as_map())
        .stdin(stdin)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .map_err(|error| InitError::SpawnCommand {
            executable: command.executable.clone(),
            source: error,
        })?;

    command_outcome_from_status(CommandKind::NonInteractive, status)
}

/// Spawns the payload behind a guest PTY and forwards that PTY over VSOCK.
fn run_command_with_pty(
    contract: &Contract,
    pty_plan: &PtyPlan,
    command_env: &CommandNetworkEnv,
) -> InitResult<CommandOutcome> {
    let plan = PtyCommandPlan::from_accepted(contract, pty_plan, command_env);
    plan.prepare_workdir()?;
    let session = PreparedPtySession::prepare(&plan)?;
    let running = RunningPtyCommand::start(&plan, session)?;

    running.wait()
}

/// Accepted PTY command execution inputs.
struct PtyCommandPlan<'a> {
    command: &'a CommandContract,
    pty: &'a PtyPlan,
    command_env: &'a CommandNetworkEnv,
}

impl<'a> PtyCommandPlan<'a> {
    /// Builds the PTY command plan from already accepted contract state.
    fn from_accepted(
        contract: &'a Contract,
        pty: &'a PtyPlan,
        command_env: &'a CommandNetworkEnv,
    ) -> Self {
        Self {
            command: contract.command(),
            pty,
            command_env,
        }
    }

    /// Prepares the command working directory before command spawn.
    fn prepare_workdir(&self) -> InitResult<()> {
        create_dir_path(&self.command.cwd)
    }

    /// Returns the accepted PTY data VSOCK port.
    const fn data_port(&self) -> u32 {
        self.pty.data_port().get()
    }

    /// Returns the accepted PTY control VSOCK port.
    const fn control_port(&self) -> u32 {
        self.pty.control_port().get()
    }
}

/// Prepared PTY session resources used to spawn the command.
struct PreparedPtySession {
    pty: CommandPty,
    host_stream: File,
    control_stream: File,
}

impl PreparedPtySession {
    /// Opens the guest PTY and connects both host VSOCK channels.
    fn prepare(plan: &PtyCommandPlan<'_>) -> InitResult<Self> {
        Self::prepare_with_connector(plan, connect_vsock_host)
    }

    /// Opens the guest PTY and connects both host channels through the provided connector.
    fn prepare_with_connector(
        plan: &PtyCommandPlan<'_>,
        mut connect: impl FnMut(u32) -> io::Result<File>,
    ) -> InitResult<Self> {
        let pty = open_command_pty(plan.pty)?;
        let host_stream =
            connect(plan.data_port()).map_err(|source| InitError::ConnectCommandPtyData {
                port: plan.data_port(),
                source,
            })?;

        log(&format!(
            "connected command PTY to host VSOCK port {}",
            plan.data_port()
        ));

        let control_stream =
            connect(plan.control_port()).map_err(|source| InitError::ConnectCommandPtyControl {
                port: plan.control_port(),
                source,
            })?;

        log(&format!(
            "connected command PTY control to host VSOCK port {}",
            plan.control_port()
        ));

        Ok(Self {
            pty,
            host_stream,
            control_stream,
        })
    }
}

/// Running guest PTY command waiting for completion.
struct RunningPtyCommand {
    child: Child,
    executable: String,
    runtime_handles: PtyRuntimeHandles,
}

impl RunningPtyCommand {
    /// Spawns the command behind the prepared PTY session.
    fn start(plan: &PtyCommandPlan<'_>, session: PreparedPtySession) -> InitResult<Self> {
        let PreparedPtySession {
            pty,
            host_stream,
            control_stream,
        } = session;
        let command = plan.command;
        let (stdin, stdout, stderr) = duplicate_pty_slave_stdio(&pty)?;
        let controlling_tty_fd = pty.slave.as_raw_fd();
        let env = plan.command_env.as_map().clone();
        log(&format!(
            "running PTY command: {} {:?} cwd={}",
            command.executable,
            command.args,
            command.cwd.display()
        ));

        let child = spawn_pty_child(command, stdin, stdout, stderr, env, controlling_tty_fd)?;
        drop(pty.slave);

        let pty_control_master = File::from(
            duplicate_fd(pty.master.as_raw_fd())
                .map_err(|source| InitError::DuplicatePtyMasterForControl { source })?,
        );

        let child_pgid =
            libc::pid_t::try_from(child.id()).map_err(|source| InitError::InvalidChildPgid {
                pid: child.id(),
                source,
            })?;

        let (event_sender, events) = mpsc::channel();
        let control_handler = spawn_pty_control_handler(
            control_stream,
            pty_control_master,
            child_pgid,
            event_sender.clone(),
        );
        let data_forwarders = spawn_pty_io_forwarders(pty.master, host_stream, event_sender)?;
        let runtime_handles = PtyRuntimeHandles::new(data_forwarders, control_handler, events);

        Ok(Self {
            child,
            executable: command.executable.clone(),
            runtime_handles,
        })
    }

    /// Waits for the PTY command and converts the process status into a guest result.
    fn wait(mut self) -> InitResult<CommandOutcome> {
        let status = self
            .child
            .wait()
            .map_err(|source| InitError::WaitPtyCommand {
                executable: self.executable.clone(),
                source,
            })?;

        self.runtime_handles.drain_events();

        command_outcome_from_status(CommandKind::Pty, status)
    }
}

/// Guest PTY runtime threads owned by a running PTY command.
struct PtyRuntimeHandles {
    data: Option<PtyForwarders>,
    control: Option<PtyControlHandler>,
    events: Receiver<PtyRuntimeEvent>,
}

impl PtyRuntimeHandles {
    /// Groups the PTY data and control thread handles under one runtime owner.
    fn new(
        data: PtyForwarders,
        control: PtyControlHandler,
        events: Receiver<PtyRuntimeEvent>,
    ) -> Self {
        Self {
            data: Some(data),
            control: Some(control),
            events,
        }
    }

    /// Drains any lifecycle events already emitted by PTY worker threads.
    fn drain_events(&self) {
        for event in self.events.try_iter() {
            event.log();
        }
    }
}

impl Drop for PtyRuntimeHandles {
    fn drop(&mut self) {
        self.drain_events();
        self.data.take();
        self.control.take();
    }
}

/// Guest PTY data forwarding threads owned by a running PTY command.
struct PtyForwarders {
    host_to_guest: Option<JoinHandle<()>>,
    guest_to_host: Option<JoinHandle<()>>,
}

impl Drop for PtyForwarders {
    fn drop(&mut self) {
        self.host_to_guest.take();
        self.guest_to_host.take();
    }
}

/// Guest PTY control-message handler owned by a running PTY command.
struct PtyControlHandler {
    handle: Option<JoinHandle<()>>,
}

impl Drop for PtyControlHandler {
    fn drop(&mut self) {
        self.handle.take();
    }
}

/// Lifecycle event emitted by guest PTY runtime worker threads.
enum PtyRuntimeEvent {
    HostInputClosed,
    GuestOutputClosed,
    ControlClosed,
    ForwardingFailed {
        direction: PtyDirection,
        source: io::Error,
    },
    ControlFailed {
        source: InitError,
    },
}

impl PtyRuntimeEvent {
    /// Logs the PTY worker event after the command lifecycle observes it.
    fn log(self) {
        match self {
            Self::HostInputClosed => log("command PTY host input closed"),
            Self::GuestOutputClosed => log("command PTY guest output closed"),
            Self::ControlClosed => log("command PTY control channel closed"),
            Self::ForwardingFailed { direction, source } => {
                log(&format!(
                    "command PTY forwarding failed direction={}: {source}",
                    direction.diagnostic_label()
                ));
            }
            Self::ControlFailed { source } => {
                log(&format!("command PTY control failed: {source}"));
            }
        }
    }
}

/// Direction of a PTY data forwarding loop.
enum PtyDirection {
    HostToGuest,
    GuestToHost,
}

impl PtyDirection {
    /// Returns a stable diagnostic label for the forwarding direction.
    const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::HostToGuest => "host_to_guest",
            Self::GuestToHost => "guest_to_host",
        }
    }
}

/// Duplicates the PTY slave for child stdin, stdout and stderr.
fn duplicate_pty_slave_stdio(pty: &CommandPty) -> InitResult<(File, File, File)> {
    Ok((
        duplicate_pty_slave(&pty.slave)?,
        duplicate_pty_slave(&pty.slave)?,
        duplicate_pty_slave(&pty.slave)?,
    ))
}

/// Duplicates a PTY slave file descriptor.
fn duplicate_pty_slave(slave: &OwnedFd) -> InitResult<File> {
    duplicate_fd(slave.as_raw_fd())
        .map(File::from)
        .map_err(|source| InitError::DuplicatePtySlave { source })
}

/// Spawns the command process with the PTY slave as its controlling terminal.
fn spawn_pty_child(
    command: &super::contract::CommandContract,
    stdin: File,
    stdout: File,
    stderr: File,
    env: std::collections::BTreeMap<String, String>,
    controlling_tty_fd: RawFd,
) -> InitResult<Child> {
    let mut child_command = Command::new(&command.executable);
    child_command
        .args(&command.args)
        .current_dir(&command.cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    unsafe {
        child_command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(controlling_tty_fd, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    child_command
        .spawn()
        .map_err(|source| InitError::SpawnPtyCommand {
            executable: command.executable.clone(),
            source,
        })
}

/// A newly opened command PTY pair.
struct CommandPty {
    master: OwnedFd,
    slave: OwnedFd,
}

/// Opens the guest command PTY with the requested terminal size.
fn open_command_pty(pty_plan: &PtyPlan) -> InitResult<CommandPty> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let settings = pty_plan.settings();
    let winsize = libc::winsize {
        ws_row: settings.rows().unwrap_or(24),
        ws_col: settings.cols().unwrap_or(80),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let result = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::from_ref(&winsize),
        )
    };

    if result != 0 {
        return Err(InitError::OpenCommandPty {
            source: io::Error::last_os_error(),
        });
    }

    Ok(CommandPty {
        master: unsafe { OwnedFd::from_raw_fd(master) },
        slave: unsafe { OwnedFd::from_raw_fd(slave) },
    })
}

/// Starts the PTY control-message handler.
fn spawn_pty_control_handler(
    control_stream: File,
    pty_master: File,
    child_pgid: libc::pid_t,
    event_sender: Sender<PtyRuntimeEvent>,
) -> PtyControlHandler {
    let handle = thread::spawn(move || {
        let reader = io::BufReader::new(control_stream);
        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    send_pty_runtime_event(
                        &event_sender,
                        PtyRuntimeEvent::ControlFailed {
                            source: InitError::ReadCommandPtyControl { source: error },
                        },
                    );
                    return;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            if let Err(error) = apply_pty_control_message(&line, &pty_master, child_pgid) {
                send_pty_runtime_event(
                    &event_sender,
                    PtyRuntimeEvent::ControlFailed { source: error },
                );
            }
        }
        send_pty_runtime_event(&event_sender, PtyRuntimeEvent::ControlClosed);
    });
    PtyControlHandler {
        handle: Some(handle),
    }
}

/// Applies one PTY control message from the host runner.
fn apply_pty_control_message(
    line: &str,
    pty_master: &File,
    child_pgid: libc::pid_t,
) -> InitResult<()> {
    let Some(message) = PtyControlMessage::parse(line)? else {
        return Ok(());
    };

    apply_parsed_pty_control_message(message, pty_master, child_pgid)
}

/// Applies one parsed PTY control message from the host runner.
fn apply_parsed_pty_control_message(
    message: PtyControlMessage,
    pty_master: &File,
    child_pgid: libc::pid_t,
) -> InitResult<()> {
    match message {
        PtyControlMessage::Resize(size) => {
            resize_command_pty(pty_master, size.rows.get(), size.cols.get())?;
            signal_process_group(child_pgid, libc::SIGWINCH)?;
            log(&format!(
                "FIRMA_PTY_RESIZE rows={} cols={}",
                size.rows, size.cols
            ));
            Ok(())
        }
        PtyControlMessage::Signal(signal) => {
            let raw_signal = signal.as_raw_signal();
            signal_process_group(child_pgid, raw_signal)?;
            log(&format!("FIRMA_PTY_SIGNAL signal={raw_signal}"));
            Ok(())
        }
    }
}

/// Parsed PTY control message from the host runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PtyControlMessage {
    Resize(TerminalSize),
    Signal(PtySignal),
}

impl PtyControlMessage {
    /// Parses a PTY control message without applying device or process side effects.
    fn parse(line: &str) -> InitResult<Option<Self>> {
        let mut parts = line.split_whitespace();
        let Some(command) = parts.next() else {
            return Ok(None);
        };
        match command {
            "resize" => TerminalSize::parse(&mut parts, line).map(|size| Some(Self::Resize(size))),
            "signal" => PtySignal::parse(&mut parts, line).map(|signal| Some(Self::Signal(signal))),
            _other => Err(InitError::UnsupportedPtyControlMessage {
                message: line.to_string(),
            }),
        }
    }
}

/// Terminal dimensions accepted from a PTY control resize message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalSize {
    rows: NonZeroU16,
    cols: NonZeroU16,
}

impl TerminalSize {
    /// Parses a non-zero PTY terminal size from a resize control message.
    fn parse<'a>(parts: &mut impl Iterator<Item = &'a str>, original: &str) -> InitResult<Self> {
        let rows = parse_resize_dimension(parts.next(), original)?;
        let cols = parse_resize_dimension(parts.next(), original)?;
        reject_trailing_control_tokens(parts, original)?;

        Ok(Self { rows, cols })
    }
}

/// PTY process signal accepted from a control message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PtySignal {
    Int,
    Term,
}

impl PtySignal {
    /// Parses a PTY signal control message.
    fn parse<'a>(parts: &mut impl Iterator<Item = &'a str>, original: &str) -> InitResult<Self> {
        let signal = parts
            .next()
            .ok_or_else(|| InitError::UnsupportedPtyControlMessage {
                message: original.to_string(),
            })?;

        match signal {
            "INT" | "SIGINT" => {
                reject_trailing_control_tokens(parts, original)?;
                Ok(Self::Int)
            }
            "TERM" | "SIGTERM" => {
                reject_trailing_control_tokens(parts, original)?;
                Ok(Self::Term)
            }
            other => Err(InitError::UnsupportedPtySignal {
                signal: other.to_string(),
            }),
        }
    }

    /// Returns the raw Linux signal number used by `kill`.
    const fn as_raw_signal(self) -> libc::c_int {
        match self {
            Self::Int => libc::SIGINT,
            Self::Term => libc::SIGTERM,
        }
    }
}

/// Rejects PTY control messages with extra tokens after the expected payload.
fn reject_trailing_control_tokens<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
    original: &str,
) -> InitResult<()> {
    if parts.next().is_some() {
        return Err(InitError::UnsupportedPtyControlMessage {
            message: original.to_string(),
        });
    }

    Ok(())
}

/// Parses one non-zero terminal dimension from a resize control message.
fn parse_resize_dimension(value: Option<&str>, original: &str) -> InitResult<NonZeroU16> {
    let value = value.ok_or_else(|| InitError::InvalidPtyResizeMessage {
        message: original.to_string(),
    })?;
    let parsed = value
        .parse::<u16>()
        .map_err(|_source| InitError::InvalidPtyResizeMessage {
            message: original.to_string(),
        })?;

    NonZeroU16::new(parsed).ok_or_else(|| InitError::InvalidPtyResizeMessage {
        message: original.to_string(),
    })
}

/// Resizes the guest command PTY.
fn resize_command_pty(pty_master: &File, rows: u16, cols: u16) -> InitResult<()> {
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    if unsafe {
        libc::ioctl(
            pty_master.as_raw_fd(),
            libc::TIOCSWINSZ,
            std::ptr::from_ref(&winsize),
        )
    } != 0
    {
        return Err(InitError::ResizeCommandPty {
            source: io::Error::last_os_error(),
        });
    }

    Ok(())
}

/// Sends a signal to the guest command process group.
fn signal_process_group(child_pgid: libc::pid_t, signal: libc::c_int) -> InitResult<()> {
    if unsafe { libc::kill(-child_pgid, signal) } != 0 {
        return Err(InitError::SignalCommandProcessGroup {
            signal,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Starts PTY-to-host and host-to-PTY forwarders.
fn spawn_pty_io_forwarders(
    master: OwnedFd,
    host_stream: File,
    event_sender: Sender<PtyRuntimeEvent>,
) -> InitResult<PtyForwarders> {
    let master_read = File::from(
        duplicate_fd(master.as_raw_fd())
            .map_err(|source| InitError::DuplicatePtyMaster { source })?,
    );
    let master_write = File::from(master);
    let host_read = host_stream
        .try_clone()
        .map_err(|source| InitError::CloneCommandPtyDataStream { source })?;
    let host_write = host_stream;

    let guest_to_host_events = event_sender.clone();
    let guest_to_host = thread::spawn(move || {
        let mut pty_reader = master_read;
        let mut host_writer = host_write;
        let result = io::copy(&mut pty_reader, &mut host_writer);
        let _ = host_writer.flush();
        let _ = unsafe { libc::shutdown(host_writer.as_raw_fd(), libc::SHUT_WR) };
        match result {
            Ok(_) => {
                send_pty_runtime_event(&guest_to_host_events, PtyRuntimeEvent::GuestOutputClosed);
            }
            Err(source) => {
                send_pty_runtime_event(
                    &guest_to_host_events,
                    PtyRuntimeEvent::ForwardingFailed {
                        direction: PtyDirection::GuestToHost,
                        source,
                    },
                );
            }
        }
    });

    let host_to_guest_events = event_sender;
    let host_to_guest = thread::spawn(move || {
        let mut host_reader = host_read;
        let mut pty_writer = master_write;
        match io::copy(&mut host_reader, &mut pty_writer) {
            Ok(_) => {
                send_pty_runtime_event(&host_to_guest_events, PtyRuntimeEvent::HostInputClosed);
            }
            Err(source) => {
                send_pty_runtime_event(
                    &host_to_guest_events,
                    PtyRuntimeEvent::ForwardingFailed {
                        direction: PtyDirection::HostToGuest,
                        source,
                    },
                );
            }
        }
    });

    Ok(PtyForwarders {
        host_to_guest: Some(host_to_guest),
        guest_to_host: Some(guest_to_host),
    })
}

/// Emits a PTY runtime event when the command lifecycle is still observing it.
fn send_pty_runtime_event(sender: &Sender<PtyRuntimeEvent>, event: PtyRuntimeEvent) -> bool {
    sender.send(event).is_ok()
}

/// Duplicates an owned file descriptor for independent stdio ownership.
fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "file descriptor is closed",
        ));
    }
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

/// Opens optional guest stdin captured by the host runner.
fn command_stdin(contract_path: &Path) -> InitResult<Stdio> {
    let Some(parent) = contract_path.parent() else {
        return Ok(Stdio::null());
    };
    let stdin_path = parent.join(GUEST_STDIN_FILE);
    match File::open(&stdin_path) {
        Ok(file) => {
            log(&format!("using guest stdin {}", stdin_path.display()));
            Ok(Stdio::from(file))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Stdio::null()),
        Err(source) => Err(InitError::OpenGuestStdin {
            path: stdin_path,
            source,
        }),
    }
}

/// Creates an owner-only command output stream file for host replay.
fn create_command_stdio_file(contract_path: &Path, file_name: &str) -> InitResult<File> {
    let parent =
        contract_path
            .parent()
            .ok_or_else(|| InitError::CommandStdioPathWithoutParent {
                path: contract_path.to_path_buf(),
            })?;
    let path = parent.join(file_name);
    let file = File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .map_err(|source| InitError::CreateCommandStdioFile {
            path: path.clone(),
            source,
        })?;
    let mut permissions = file
        .metadata()
        .map_err(|source| InitError::StatCommandStdioFile {
            path: path.clone(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .map_err(|source| InitError::SetCommandStdioFilePermissions { path, source })?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::fs;
    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::super::contract::{
        DnsMode, GuestContract, InvariantContract, LaunchContract, MountContract, NetworkContract,
        NetworkMode, RunnerContract, TerminalContract,
    };
    use super::super::network::NetworkServicesPlan;
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn command_status_conversion_keeps_exit_code() -> TestResult {
        let outcome =
            command_outcome_from_status(CommandKind::NonInteractive, ExitStatus::from_raw(7 << 8))?;

        assert!(matches!(outcome, CommandOutcome::Exited(7)));

        Ok(())
    }

    #[test]
    fn command_status_conversion_keeps_pty_signal() -> TestResult {
        let outcome =
            command_outcome_from_status(CommandKind::Pty, ExitStatus::from_raw(libc::SIGTERM))?;

        assert!(matches!(
            outcome,
            CommandOutcome::Signaled(signal) if signal == libc::SIGTERM
        ));

        Ok(())
    }

    #[test]
    fn pty_control_parser_accepts_resize_message() -> TestResult {
        let Some(PtyControlMessage::Resize(size)) = PtyControlMessage::parse("resize 40 120")?
        else {
            return Err(io::Error::other("expected PTY resize message").into());
        };

        assert_eq!(size.rows.get(), 40);
        assert_eq!(size.cols.get(), 120);

        Ok(())
    }

    #[test]
    fn pty_control_parser_accepts_signal_aliases() -> TestResult {
        assert_eq!(
            PtyControlMessage::parse("signal INT")?,
            Some(PtyControlMessage::Signal(PtySignal::Int))
        );
        assert_eq!(
            PtyControlMessage::parse("signal SIGINT")?,
            Some(PtyControlMessage::Signal(PtySignal::Int))
        );
        assert_eq!(
            PtyControlMessage::parse("signal TERM")?,
            Some(PtyControlMessage::Signal(PtySignal::Term))
        );
        assert_eq!(
            PtyControlMessage::parse("signal SIGTERM")?,
            Some(PtyControlMessage::Signal(PtySignal::Term))
        );

        Ok(())
    }

    #[test]
    fn pty_control_parser_ignores_empty_messages() -> TestResult {
        assert_eq!(PtyControlMessage::parse("")?, None);
        assert_eq!(PtyControlMessage::parse("   \t  ")?, None);

        Ok(())
    }

    #[test]
    fn pty_control_parser_rejects_invalid_resize_messages() {
        assert_invalid_resize("resize");
        assert_invalid_resize("resize 24");
        assert_invalid_resize("resize 0 80");
        assert_invalid_resize("resize 24 nope");
    }

    #[test]
    fn pty_control_parser_rejects_trailing_tokens() -> TestResult {
        let Some(error) = PtyControlMessage::parse("resize 40 120 ignored").err() else {
            return Err(io::Error::other("expected trailing resize token rejection").into());
        };
        assert!(matches!(
            error,
            InitError::UnsupportedPtyControlMessage { .. }
        ));

        let Some(error) = PtyControlMessage::parse("signal INT ignored").err() else {
            return Err(io::Error::other("expected trailing signal token rejection").into());
        };
        assert!(matches!(
            error,
            InitError::UnsupportedPtyControlMessage { .. }
        ));

        Ok(())
    }

    #[test]
    fn pty_control_parser_rejects_unsupported_control_messages() -> TestResult {
        let Some(error) = PtyControlMessage::parse("unknown").err() else {
            return Err(io::Error::other("expected unsupported control message").into());
        };
        assert!(matches!(
            error,
            InitError::UnsupportedPtyControlMessage { .. }
        ));

        let Some(error) = PtyControlMessage::parse("signal HUP").err() else {
            return Err(io::Error::other("expected unsupported PTY signal").into());
        };
        assert!(matches!(error, InitError::UnsupportedPtySignal { .. }));

        Ok(())
    }

    #[test]
    fn pty_command_plan_uses_accepted_ports_and_prepares_workdir() -> TestResult {
        let temp = tempfile::tempdir()?;
        let cwd = temp.path().join("workspace");
        let contract =
            accepted_contract(&cwd, "/bin/sh", &["-c", "true"], pty_terminal_contract())?;
        let command_env = command_env_for(&contract)?;
        let Some(pty) = contract.terminal().pty_plan() else {
            return Err(io::Error::other("accepted contract should expose PTY plan").into());
        };

        let plan = PtyCommandPlan::from_accepted(&contract, pty, &command_env);

        assert_eq!(plan.data_port(), 20000);
        assert_eq!(plan.control_port(), 20001);
        assert!(!cwd.exists());
        plan.prepare_workdir()?;
        assert!(cwd.is_dir());

        Ok(())
    }

    #[test]
    fn prepared_pty_session_reports_data_connect_failure() -> TestResult {
        let temp = tempfile::tempdir()?;
        let contract = accepted_contract(
            temp.path(),
            "/bin/sh",
            &["-c", "true"],
            pty_terminal_contract(),
        )?;
        let command_env = command_env_for(&contract)?;
        let Some(pty) = contract.terminal().pty_plan() else {
            return Err(io::Error::other("accepted contract should expose PTY plan").into());
        };
        let plan = PtyCommandPlan::from_accepted(&contract, pty, &command_env);

        let Some(error) = PreparedPtySession::prepare_with_connector(&plan, |port| {
            assert_eq!(port, 20000);
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "data channel refused",
            ))
        })
        .err() else {
            return Err(io::Error::other("data channel should fail").into());
        };

        assert!(matches!(
            error,
            InitError::ConnectCommandPtyData {
                port: 20000,
                source,
            } if source.kind() == io::ErrorKind::ConnectionRefused
        ));

        Ok(())
    }

    #[test]
    fn prepared_pty_session_reports_control_connect_failure() -> TestResult {
        let temp = tempfile::tempdir()?;
        let contract = accepted_contract(
            temp.path(),
            "/bin/sh",
            &["-c", "true"],
            pty_terminal_contract(),
        )?;
        let command_env = command_env_for(&contract)?;
        let Some(pty) = contract.terminal().pty_plan() else {
            return Err(io::Error::other("accepted contract should expose PTY plan").into());
        };
        let plan = PtyCommandPlan::from_accepted(&contract, pty, &command_env);
        let (data_stream, _peer) = UnixStream::pair()?;

        let Some(error) = PreparedPtySession::prepare_with_connector(&plan, |port| match port {
            20000 => Ok(file_from_unix_stream(data_stream.try_clone()?)),
            20001 => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "control channel reset",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected PTY port",
            )),
        })
        .err() else {
            return Err(io::Error::other("control channel should fail").into());
        };

        assert!(matches!(
            error,
            InitError::ConnectCommandPtyControl {
                port: 20001,
                source,
            } if source.kind() == io::ErrorKind::ConnectionReset
        ));

        Ok(())
    }

    #[test]
    fn command_stdio_files_are_owner_only() -> TestResult {
        let temp = tempfile::tempdir()?;
        let contract_path = temp.path().join("vz-guest-launch.json");

        let file = create_command_stdio_file(&contract_path, GUEST_STDOUT_FILE)?;
        drop(file);

        assert_eq!(
            fs::metadata(temp.path().join(GUEST_STDOUT_FILE))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        Ok(())
    }

    #[test]
    fn command_stdio_file_rejects_paths_without_parent() -> TestResult {
        let Some(error) = create_command_stdio_file(Path::new("/"), GUEST_STDOUT_FILE).err() else {
            return Err(io::Error::other("root contract path should not have a parent").into());
        };

        assert!(matches!(
            error,
            InitError::CommandStdioPathWithoutParent { path } if path == Path::new("/")
        ));

        Ok(())
    }

    #[test]
    fn duplicate_fd_rejects_closed_descriptor_and_duplicates_open_descriptor() -> TestResult {
        let null = File::open("/dev/null")?;
        let duplicate = duplicate_fd(null.as_raw_fd())?;

        assert!(duplicate.as_raw_fd() >= 0);

        let Some(error) = duplicate_fd(-1).err() else {
            return Err(io::Error::other("closed descriptor should be rejected").into());
        };
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);

        Ok(())
    }

    #[test]
    fn pty_runtime_event_send_reports_observer_state() -> TestResult {
        let (sender, receiver) = mpsc::channel();

        assert!(send_pty_runtime_event(
            &sender,
            PtyRuntimeEvent::HostInputClosed
        ));
        let event = receiver.recv_timeout(Duration::from_secs(1))?;
        assert!(matches!(event, PtyRuntimeEvent::HostInputClosed));

        drop(receiver);
        assert!(!send_pty_runtime_event(
            &sender,
            PtyRuntimeEvent::ControlClosed
        ));

        Ok(())
    }

    #[test]
    fn pty_direction_diagnostic_labels_are_stable() {
        assert_eq!(
            PtyDirection::HostToGuest.diagnostic_label(),
            "host_to_guest"
        );
        assert_eq!(
            PtyDirection::GuestToHost.diagnostic_label(),
            "guest_to_host"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn running_pty_command_forwards_guest_output_to_host_stream() -> TestResult {
        let temp = tempfile::tempdir()?;
        let contract = accepted_contract(
            temp.path(),
            "/bin/sh",
            &["-c", "printf pty-output"],
            pty_terminal_contract(),
        )?;
        let command_env = command_env_for(&contract)?;
        let Some(pty) = contract.terminal().pty_plan() else {
            return Err(io::Error::other("accepted contract should expose PTY plan").into());
        };
        let plan = PtyCommandPlan::from_accepted(&contract, pty, &command_env);
        let (mut host_data, guest_data) = UnixStream::pair()?;
        let (host_control, guest_control) = UnixStream::pair()?;
        host_data.set_read_timeout(Some(Duration::from_secs(2)))?;

        let session = PreparedPtySession {
            pty: open_command_pty(plan.pty)?,
            host_stream: file_from_unix_stream(guest_data),
            control_stream: file_from_unix_stream(guest_control),
        };
        let running = RunningPtyCommand::start(&plan, session)?;

        host_data.shutdown(std::net::Shutdown::Write)?;
        drop(host_control);
        let output = read_until_contains(&mut host_data, "pty-output")?;
        let outcome = running.wait()?;

        assert!(output.contains("pty-output"));
        assert!(matches!(outcome, CommandOutcome::Exited(0)));

        Ok(())
    }

    fn assert_invalid_resize(message: &str) {
        let error = PtyControlMessage::parse(message);
        assert!(matches!(
            error,
            Err(InitError::InvalidPtyResizeMessage { .. })
        ));
    }

    fn accepted_contract(
        cwd: &Path,
        executable: &str,
        args: &[&str],
        terminal: TerminalContract,
    ) -> Result<Contract, Box<dyn Error>> {
        Ok(LaunchContract {
            version: 1,
            sandbox_id: Some("sandbox-test".to_string()),
            runtime_dir: Some(PathBuf::from("/runtime")),
            runner: Some(RunnerContract {
                path: PathBuf::from("/firma-vz-runner"),
            }),
            guest: Some(GuestContract {
                kernel: PathBuf::from("/vmlinuz"),
                initrd: PathBuf::from("/initrd.img"),
                rootfs: PathBuf::from("/rootfs.img"),
            }),
            command: CommandContract {
                executable: executable.to_string(),
                args: args.iter().map(|arg| (*arg).to_string()).collect(),
                cwd: cwd.to_path_buf(),
                env: BTreeMap::new(),
                identity_mode: Some("sandbox_user".to_string()),
            },
            terminal,
            mounts: vec![MountContract {
                source: Some(cwd.to_path_buf()),
                target: cwd.to_path_buf(),
                read_only: false,
            }],
            network: NetworkContract {
                mode: NetworkMode::VsockSidecar,
                guest_http_proxy_addr: "127.0.0.1:18080".to_string(),
                guest_dns_stub_addr: "127.0.0.1:1053".to_string(),
                vsock_sidecar_port: 18080,
                sidecar_host_addr: "127.0.0.1:19080".to_string(),
                direct_network_devices_allowed: false,
                dns_mode: DnsMode::ConfinedStub,
                attribution_headers: BTreeMap::from([(
                    "x-firma-sandbox-id".to_string(),
                    "sandbox-test".to_string(),
                )]),
            },
            invariants: vec![InvariantContract {
                name: "preserve_stdio_signals_exit".to_string(),
                mode: "required".to_string(),
            }],
        }
        .try_into()?)
    }

    fn pty_terminal_contract() -> TerminalContract {
        TerminalContract {
            interactive: true,
            pty: true,
            pty_vsock_port: Some(20000),
            pty_control_vsock_port: Some(20001),
            term: Some("xterm-256color".to_string()),
            rows: Some(40),
            cols: Some(120),
        }
    }

    fn command_env_for(contract: &Contract) -> Result<CommandNetworkEnv, Box<dyn Error>> {
        Ok(NetworkServicesPlan::try_from(contract)?
            .command_env()
            .clone())
    }

    fn file_from_unix_stream(stream: UnixStream) -> File {
        let fd: OwnedFd = stream.into();
        File::from(fd)
    }

    #[cfg(target_os = "linux")]
    fn read_until_contains(stream: &mut UnixStream, needle: &str) -> io::Result<String> {
        use std::io::Read as _;

        let mut output = Vec::new();
        let mut buffer = [0_u8; 256];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(String::from_utf8_lossy(&output).into_owned()),
                Ok(read) => {
                    output.extend_from_slice(&buffer[..read]);
                    let text = String::from_utf8_lossy(&output).into_owned();
                    if text.contains(needle) {
                        return Ok(text);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "timed out waiting for {needle:?}; output={}",
                            String::from_utf8_lossy(&output)
                        ),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }
}
