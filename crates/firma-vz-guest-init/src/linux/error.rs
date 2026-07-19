use std::fmt;
use std::io;
use std::net::{AddrParseError, SocketAddr};
use std::num::TryFromIntError;
use std::path::PathBuf;

use firma_runtime_state::{SandboxId, SandboxIdParseError};

/// Typed failures raised while preparing or running the VZ guest init payload.
#[derive(Debug)]
pub enum InitError {
    /// A required guest directory could not be created.
    CreateDir { path: PathBuf, source: io::Error },
    /// A guest symlink could not be created.
    CreateSymlink {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    /// `/dev/ptmx` could not be inspected before PTY setup.
    StatPtmx { path: PathBuf, source: io::Error },
    /// `/proc/cmdline` could not be read after procfs is mounted.
    ReadKernelCmdline { source: io::Error },
    /// A pseudo filesystem mount failed.
    MountPseudo {
        file_system: &'static str,
        target: &'static str,
        source: io::Error,
    },
    /// The host runtime virtiofs share could not be mounted.
    MountVirtiofs {
        tag: String,
        target: &'static str,
        source: io::Error,
    },
    /// A contract share could not be bind-mounted into the guest.
    BindMount {
        source: PathBuf,
        target: PathBuf,
        error: io::Error,
    },
    /// A contract share could not be remounted read-only.
    RemountReadOnly {
        source: PathBuf,
        target: PathBuf,
        error: io::Error,
    },
    /// A required Firma kernel argument is missing.
    MissingKernelArg { name: &'static str },
    /// The requested boot network mode is not supported by this init payload.
    UnsupportedNetworkMode { mode: String },
    /// The launch contract path is not visible inside the guest.
    ContractNotVisible { path: PathBuf, source: io::Error },
    /// The launch contract path exists but is not a regular file.
    ContractNotRegularFile { path: PathBuf },
    /// The launch contract could not be read.
    ReadContract { path: PathBuf, source: io::Error },
    /// The launch contract JSON could not be parsed.
    ParseContract {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// The launch contract version is unsupported.
    InvalidContractVersion { version: u32 },
    /// The contract command executable is empty.
    EmptyExecutable,
    /// The contract command working directory is not absolute.
    RelativeCommandCwd { path: PathBuf },
    /// The contract environment contains a host-only secret key.
    SecretEnvKey { key: &'static str },
    /// The contract requested interactive mode without a supported terminal runtime.
    UnsupportedTerminalInteractive,
    /// The contract requested PTY mode without a usable PTY VSOCK port.
    TerminalPtyPortRequired,
    /// The contract provided a PTY VSOCK port while PTY mode was disabled.
    TerminalPtyPortWithoutPty,
    /// The contract requested PTY mode without interactive mode.
    TerminalPtyRequiresInteractive,
    /// The PTY VSOCK port conflicts with the network sidecar port.
    TerminalPtyPortConflictsWithNetwork,
    /// The contract requested PTY mode without a usable control VSOCK port.
    TerminalPtyControlPortRequired,
    /// The contract provided a PTY control VSOCK port while PTY mode was disabled.
    TerminalPtyControlPortWithoutPty,
    /// The PTY control VSOCK port conflicts with the network sidecar port.
    TerminalPtyControlPortConflictsWithNetwork,
    /// The PTY control VSOCK port conflicts with the PTY data port.
    TerminalPtyControlPortConflictsWithPtyPort,
    /// The contract provided an empty terminal type.
    EmptyTerminalTerm,
    /// The contract provided a zero terminal dimension.
    ZeroTerminalDimension { field: &'static str },
    /// A contract mount target is not absolute.
    RelativeMountTarget { path: PathBuf },
    /// A network socket address could not be parsed.
    InvalidNetworkSocketAddr {
        field: &'static str,
        value: String,
        source: AddrParseError,
    },
    /// A network socket address was not loopback.
    NonLoopbackNetworkSocketAddr { field: &'static str, value: String },
    /// A required network port was zero.
    ZeroNetworkPort { field: &'static str },
    /// The contract allowed direct guest network devices.
    DirectNetworkDevicesAllowed,
    /// The network attribution header map contained an empty key.
    EmptyAttributionHeaderName,
    /// The network attribution header map contained an empty value.
    EmptyAttributionHeaderValue { name: String },
    /// The network attribution headers omitted the sandbox identity.
    MissingSandboxAttribution,
    /// The network attribution headers repeated the sandbox identity using
    /// case variants.
    DuplicateSandboxAttribution,
    /// The network sandbox attribution is not a valid sandbox ID.
    InvalidSandboxAttribution {
        value: String,
        source: SandboxIdParseError,
    },
    /// The network sandbox attribution does not match the launch contract.
    SandboxAttributionMismatch {
        expected: SandboxId,
        actual: SandboxId,
    },
    /// The loopback control socket could not be opened.
    LoopbackControlOpen { source: io::Error },
    /// The loopback interface flags could not be read.
    LoopbackReadFlags { source: io::Error },
    /// The loopback interface could not be enabled.
    LoopbackEnable { source: io::Error },
    /// The guest HTTP proxy listener could not bind.
    ProxyBind { addr: SocketAddr, source: io::Error },
    /// The guest HTTP proxy listener thread could not start.
    ProxyThreadSpawn { source: io::Error },
    /// The guest proxy client stream could not enable `TCP_NODELAY`.
    ProxyClientNoDelay { source: io::Error },
    /// The guest proxy client stream could not be cloned.
    ProxyClientClone { source: io::Error },
    /// The guest proxy could not connect to the host VSOCK sidecar port.
    VsockConnect { source: io::Error },
    /// The guest VSOCK sidecar stream could not be cloned.
    ProxyVsockClone { source: io::Error },
    /// The guest proxy response copy failed.
    ProxyCopyResponse { source: io::Error },
    /// The guest proxy request copy failed.
    ProxyCopyRequest { source: io::Error },
    /// The UDP DNS refusal listener could not bind.
    DnsUdpBind { addr: SocketAddr, source: io::Error },
    /// The TCP DNS refusal listener could not bind.
    DnsTcpBind { addr: SocketAddr, source: io::Error },
    /// The UDP DNS refusal listener thread could not start.
    DnsUdpThreadSpawn { addr: SocketAddr, source: io::Error },
    /// The TCP DNS refusal listener thread could not start.
    DnsTcpThreadSpawn { addr: SocketAddr, source: io::Error },
    /// A TCP DNS query length could not be read.
    DnsTcpReadLength { source: io::Error },
    /// A TCP DNS query body could not be read.
    DnsTcpReadBody { source: io::Error },
    /// A TCP DNS response length could not be written.
    DnsTcpWriteLength { source: io::Error },
    /// A TCP DNS response body could not be written.
    DnsTcpWriteBody { source: io::Error },
    /// Guest resolver configuration could not be written.
    ResolvConfWrite { source: io::Error },
    /// A guest network setup value was invalid.
    GuestNetworkSetup { detail: String },
    /// The indexed virtiofs share for a contract mount is missing.
    MissingShareSource { path: PathBuf },
    /// The guest payload process could not be spawned.
    SpawnCommand {
        executable: String,
        source: io::Error,
    },
    /// The guest command PTY could not be opened.
    OpenCommandPty { source: io::Error },
    /// The guest command PTY slave could not be duplicated.
    DuplicatePtySlave { source: io::Error },
    /// The guest command PTY master could not be duplicated for I/O forwarding.
    DuplicatePtyMaster { source: io::Error },
    /// The guest command PTY master could not be duplicated for control messages.
    DuplicatePtyMasterForControl { source: io::Error },
    /// The guest command PTY data stream could not connect to the host.
    ConnectCommandPtyData { port: u32, source: io::Error },
    /// The guest command PTY control stream could not connect to the host.
    ConnectCommandPtyControl { port: u32, source: io::Error },
    /// The guest command PTY data stream could not be cloned.
    CloneCommandPtyDataStream { source: io::Error },
    /// A guest command PTY control message could not be read.
    ReadCommandPtyControl { source: io::Error },
    /// The guest command process id could not be used as a process group id.
    InvalidChildPgid { pid: u32, source: TryFromIntError },
    /// The guest PTY payload exited without an exit status or signal.
    CommandPtyMissingStatus,
    /// A guest command PTY resize message was invalid.
    InvalidPtyResizeMessage { message: String },
    /// A guest command PTY control message was unsupported.
    UnsupportedPtyControlMessage { message: String },
    /// A guest command PTY signal message was unsupported.
    UnsupportedPtySignal { signal: String },
    /// The guest command PTY could not be resized.
    ResizeCommandPty { source: io::Error },
    /// The guest command process group could not be signaled.
    SignalCommandProcessGroup {
        signal: libc::c_int,
        source: io::Error,
    },
    /// The guest PTY payload process could not be spawned.
    SpawnPtyCommand {
        executable: String,
        source: io::Error,
    },
    /// The guest PTY payload process could not be waited on.
    WaitPtyCommand {
        executable: String,
        source: io::Error,
    },
    /// Guest stdin captured by the host runner could not be opened.
    OpenGuestStdin { path: PathBuf, source: io::Error },
    /// The contract path has no parent for command output streams.
    CommandStdioPathWithoutParent { path: PathBuf },
    /// A command stdout/stderr replay file could not be created.
    CreateCommandStdioFile { path: PathBuf, source: io::Error },
    /// A command stdout/stderr replay file could not be inspected.
    StatCommandStdioFile { path: PathBuf, source: io::Error },
    /// A command stdout/stderr replay file could not be made owner-only.
    SetCommandStdioFilePermissions { path: PathBuf, source: io::Error },
    /// The guest payload exited without an exit status or signal.
    CommandMissingStatus,
    /// The contract path has no parent directory for the result file.
    ResultPathWithoutParent { path: PathBuf },
    /// The guest result JSON could not be serialized.
    SerializeGuestResult {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// The guest result temp file could not be written.
    WriteGuestResultTemp { path: PathBuf, source: io::Error },
    /// The guest result temp file metadata could not be read.
    StatGuestResultTemp { path: PathBuf, source: io::Error },
    /// The guest result temp file permissions could not be restricted.
    SetGuestResultTempPermissions { path: PathBuf, source: io::Error },
    /// The guest result temp file could not be atomically renamed.
    RenameGuestResult {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    /// A bundled kernel module could not be opened.
    OpenModule { path: PathBuf, source: io::Error },
    /// Module parameters could not be converted for `finit_module`.
    ModuleParams { source: io::Error },
    /// A bundled kernel module could not be loaded.
    LoadModule { path: PathBuf, source: io::Error },
}

impl fmt::Display for InitError {
    /// Formats the init error for serial logs and guest result payloads.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDir { path, source } => {
                write!(formatter, "create {}: {source}", path.display())
            }
            Self::CreateSymlink { from, to, source } => write!(
                formatter,
                "create symlink {} -> {}: {source}",
                to.display(),
                from.display()
            ),
            Self::StatPtmx { path, source } => {
                write!(
                    formatter,
                    "inspect {} before PTY setup: {source}",
                    path.display()
                )
            }
            Self::ReadKernelCmdline { source } => {
                write!(
                    formatter,
                    "read /proc/cmdline after mounting proc failed: {source}"
                )
            }
            Self::MountPseudo {
                file_system,
                target,
                source,
            } => write!(formatter, "mount {file_system} on {target}: {source}"),
            Self::MountVirtiofs {
                tag,
                target,
                source,
            } => write!(formatter, "mount virtiofs tag {tag} on {target}: {source}"),
            Self::BindMount {
                source,
                target,
                error,
            } => write!(
                formatter,
                "bind mount {} on {}: {error}",
                source.display(),
                target.display()
            ),
            Self::RemountReadOnly {
                source,
                target,
                error,
            } => write!(
                formatter,
                "remount read-only bind {} on {}: {error}",
                source.display(),
                target.display()
            ),
            Self::MissingKernelArg { name } => {
                write!(formatter, "missing {name} kernel argument")
            }
            Self::UnsupportedNetworkMode { mode } => write!(
                formatter,
                "unexpected firma.network={mode}; current lifecycle guest expects none or vsock_sidecar"
            ),
            Self::ContractNotVisible { path, source } => {
                write!(
                    formatter,
                    "contract {} is not visible in guest: {source}",
                    path.display()
                )
            }
            Self::ContractNotRegularFile { path } => {
                write!(
                    formatter,
                    "contract {} is not a regular file",
                    path.display()
                )
            }
            Self::ReadContract { path, source } => {
                write!(formatter, "read contract {}: {source}", path.display())
            }
            Self::ParseContract { path, source } => {
                write!(formatter, "parse contract {}: {source}", path.display())
            }
            Self::InvalidContractVersion { version } => {
                write!(formatter, "unsupported contract version {version}")
            }
            Self::EmptyExecutable => formatter.write_str("command.executable must not be empty"),
            Self::RelativeCommandCwd { path } => {
                write!(
                    formatter,
                    "command.cwd must be absolute: {}",
                    path.display()
                )
            }
            Self::SecretEnvKey { key } => {
                write!(formatter, "command.env contains secret key {key}")
            }
            Self::UnsupportedTerminalInteractive => {
                formatter.write_str("terminal.interactive requires terminal.pty=true")
            }
            Self::TerminalPtyPortRequired => {
                formatter.write_str("terminal.pty=true requires non-zero terminal.pty_vsock_port")
            }
            Self::TerminalPtyPortWithoutPty => {
                formatter.write_str("terminal.pty_vsock_port requires terminal.pty=true")
            }
            Self::TerminalPtyRequiresInteractive => {
                formatter.write_str("terminal.pty=true requires terminal.interactive=true")
            }
            Self::TerminalPtyPortConflictsWithNetwork => formatter.write_str(
                "terminal.pty_vsock_port must be distinct from network.vsock_sidecar_port",
            ),
            Self::TerminalPtyControlPortRequired => formatter
                .write_str("terminal.pty=true requires non-zero terminal.pty_control_vsock_port"),
            Self::TerminalPtyControlPortWithoutPty => {
                formatter.write_str("terminal.pty_control_vsock_port requires terminal.pty=true")
            }
            Self::TerminalPtyControlPortConflictsWithNetwork => formatter.write_str(
                "terminal.pty_control_vsock_port must be distinct from network.vsock_sidecar_port",
            ),
            Self::TerminalPtyControlPortConflictsWithPtyPort => formatter.write_str(
                "terminal.pty_control_vsock_port must be distinct from terminal.pty_vsock_port",
            ),
            Self::EmptyTerminalTerm => formatter.write_str("terminal.term must not be empty"),
            Self::ZeroTerminalDimension { field } => {
                write!(formatter, "{field} must be greater than zero")
            }
            Self::RelativeMountTarget { path } => {
                write!(
                    formatter,
                    "mount.target must be absolute: {}",
                    path.display()
                )
            }
            Self::InvalidNetworkSocketAddr {
                field,
                value,
                source,
            } => write!(
                formatter,
                "{field} must be a socket address, got {value}: {source}"
            ),
            Self::NonLoopbackNetworkSocketAddr { field, value } => {
                write!(formatter, "{field} must be loopback, got {value}")
            }
            Self::ZeroNetworkPort { field } => {
                write!(formatter, "{field} port must be greater than zero")
            }
            Self::DirectNetworkDevicesAllowed => {
                formatter.write_str("network.direct_network_devices_allowed must be false")
            }
            Self::EmptyAttributionHeaderName => {
                formatter.write_str("network.attribution_headers contains an empty header name")
            }
            Self::EmptyAttributionHeaderValue { name } => write!(
                formatter,
                "network.attribution_headers[{name}] must not be empty"
            ),
            Self::MissingSandboxAttribution => {
                formatter.write_str("network.attribution_headers must contain x-firma-sandbox-id")
            }
            Self::DuplicateSandboxAttribution => formatter.write_str(
                "network.attribution_headers contains duplicate x-firma-sandbox-id names",
            ),
            Self::InvalidSandboxAttribution { value, source } => write!(
                formatter,
                "network x-firma-sandbox-id value '{value}' is invalid: {source}"
            ),
            Self::SandboxAttributionMismatch { expected, actual } => write!(
                formatter,
                "network x-firma-sandbox-id {actual} does not match contract sandbox_id {expected}"
            ),
            Self::LoopbackControlOpen { source } => {
                write!(formatter, "open loopback control socket: {source}")
            }
            Self::LoopbackReadFlags { source } => {
                write!(formatter, "read loopback interface flags: {source}")
            }
            Self::LoopbackEnable { source } => {
                write!(formatter, "bring loopback interface up: {source}")
            }
            Self::ProxyBind { addr, source } => {
                write!(
                    formatter,
                    "bind guest HTTP proxy for VSOCK sidecar bridge {addr}: {source}"
                )
            }
            Self::ProxyThreadSpawn { source } => {
                write!(formatter, "start guest HTTP proxy thread: {source}")
            }
            Self::ProxyClientNoDelay { source } => {
                write!(formatter, "set guest proxy client TCP_NODELAY: {source}")
            }
            Self::ProxyClientClone { source } => {
                write!(formatter, "clone guest proxy client stream: {source}")
            }
            Self::VsockConnect { source } => {
                write!(formatter, "connect host VSOCK sidecar port: {source}")
            }
            Self::ProxyVsockClone { source } => {
                write!(formatter, "clone guest VSOCK sidecar stream: {source}")
            }
            Self::ProxyCopyResponse { source } => {
                write!(
                    formatter,
                    "copy VSOCK sidecar response to guest proxy client: {source}"
                )
            }
            Self::ProxyCopyRequest { source } => {
                write!(
                    formatter,
                    "copy guest proxy request to VSOCK sidecar: {source}"
                )
            }
            Self::DnsUdpBind { addr, source } => {
                write!(
                    formatter,
                    "bind guest UDP DNS refusal stub {addr}: {source}"
                )
            }
            Self::DnsTcpBind { addr, source } => {
                write!(
                    formatter,
                    "bind guest TCP DNS refusal stub {addr}: {source}"
                )
            }
            Self::DnsUdpThreadSpawn { addr, source } => {
                write!(
                    formatter,
                    "start guest UDP DNS refusal stub {addr}: {source}"
                )
            }
            Self::DnsTcpThreadSpawn { addr, source } => {
                write!(
                    formatter,
                    "start guest TCP DNS refusal stub {addr}: {source}"
                )
            }
            Self::DnsTcpReadLength { source } => {
                write!(formatter, "read TCP DNS query length: {source}")
            }
            Self::DnsTcpReadBody { source } => {
                write!(formatter, "read TCP DNS query body: {source}")
            }
            Self::DnsTcpWriteLength { source } => {
                write!(formatter, "write TCP DNS response length: {source}")
            }
            Self::DnsTcpWriteBody { source } => {
                write!(formatter, "write TCP DNS response body: {source}")
            }
            Self::ResolvConfWrite { source } => {
                write!(formatter, "write /etc/resolv.conf: {source}")
            }
            Self::GuestNetworkSetup { detail } => formatter.write_str(detail),
            Self::MissingShareSource { path } => {
                write!(formatter, "missing VZ share source {}", path.display())
            }
            Self::SpawnCommand { executable, source } => {
                write!(formatter, "spawn command {executable}: {source}")
            }
            Self::OpenCommandPty { source } => write!(formatter, "open command PTY: {source}"),
            Self::DuplicatePtySlave { source } => {
                write!(formatter, "duplicate command PTY slave: {source}")
            }
            Self::DuplicatePtyMaster { source } => {
                write!(formatter, "duplicate command PTY master: {source}")
            }
            Self::DuplicatePtyMasterForControl { source } => {
                write!(
                    formatter,
                    "duplicate command PTY master for control: {source}"
                )
            }
            Self::ConnectCommandPtyData { port, source } => {
                write!(
                    formatter,
                    "connect host command PTY VSOCK port {port}: {source}"
                )
            }
            Self::ConnectCommandPtyControl { port, source } => write!(
                formatter,
                "connect host command PTY control VSOCK port {port}: {source}"
            ),
            Self::CloneCommandPtyDataStream { source } => {
                write!(formatter, "clone command PTY VSOCK stream: {source}")
            }
            Self::ReadCommandPtyControl { source } => {
                write!(formatter, "read command PTY control message: {source}")
            }
            Self::InvalidChildPgid { pid, source } => {
                write!(formatter, "convert child pid {pid} to pgid: {source}")
            }
            Self::CommandPtyMissingStatus => {
                formatter.write_str("PTY command ended without exit code or signal")
            }
            Self::InvalidPtyResizeMessage { message } => {
                write!(formatter, "invalid command PTY resize message {message:?}")
            }
            Self::UnsupportedPtyControlMessage { message } => {
                write!(
                    formatter,
                    "unsupported command PTY control message {message:?}"
                )
            }
            Self::UnsupportedPtySignal { signal } => {
                write!(formatter, "unsupported command PTY signal {signal:?}")
            }
            Self::ResizeCommandPty { source } => {
                write!(formatter, "resize command PTY: {source}")
            }
            Self::SignalCommandProcessGroup { signal, source } => {
                write!(
                    formatter,
                    "signal command process group with signal {signal}: {source}"
                )
            }
            Self::SpawnPtyCommand { executable, source } => {
                write!(formatter, "spawn PTY command {executable}: {source}")
            }
            Self::WaitPtyCommand { executable, source } => {
                write!(formatter, "wait for PTY command {executable}: {source}")
            }
            Self::OpenGuestStdin { path, source } => {
                write!(formatter, "open guest stdin {}: {source}", path.display())
            }
            Self::CommandStdioPathWithoutParent { path } => write!(
                formatter,
                "contract path {} has no parent for command stdio file",
                path.display()
            ),
            Self::CreateCommandStdioFile { path, source } => write!(
                formatter,
                "create command stdio file {}: {source}",
                path.display()
            ),
            Self::StatCommandStdioFile { path, source } => write!(
                formatter,
                "stat command stdio file {}: {source}",
                path.display()
            ),
            Self::SetCommandStdioFilePermissions { path, source } => write!(
                formatter,
                "set command stdio file permissions {}: {source}",
                path.display()
            ),
            Self::CommandMissingStatus => {
                formatter.write_str("command ended without exit code or signal")
            }
            Self::ResultPathWithoutParent { path } => {
                write!(
                    formatter,
                    "contract path {} has no parent for result",
                    path.display()
                )
            }
            Self::SerializeGuestResult { path, source } => {
                write!(
                    formatter,
                    "serialize guest result {}: {source}",
                    path.display()
                )
            }
            Self::WriteGuestResultTemp { path, source } => {
                write!(
                    formatter,
                    "write guest result temp {}: {source}",
                    path.display()
                )
            }
            Self::StatGuestResultTemp { path, source } => {
                write!(
                    formatter,
                    "stat guest result temp {}: {source}",
                    path.display()
                )
            }
            Self::SetGuestResultTempPermissions { path, source } => write!(
                formatter,
                "set guest result temp permissions {}: {source}",
                path.display()
            ),
            Self::RenameGuestResult { from, to, source } => write!(
                formatter,
                "rename guest result {} to {}: {source}",
                from.display(),
                to.display()
            ),
            Self::OpenModule { path, source } => {
                write!(formatter, "open module {}: {source}", path.display())
            }
            Self::ModuleParams { source } => {
                write!(formatter, "create module params CString: {source}")
            }
            Self::LoadModule { path, source } => {
                write!(formatter, "load module {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for InitError {
    /// Returns the underlying I/O or parse error when one exists.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateDir { source, .. }
            | Self::CreateSymlink { source, .. }
            | Self::StatPtmx { source, .. }
            | Self::ReadKernelCmdline { source }
            | Self::MountPseudo { source, .. }
            | Self::MountVirtiofs { source, .. }
            | Self::LoopbackControlOpen { source }
            | Self::LoopbackReadFlags { source }
            | Self::LoopbackEnable { source }
            | Self::ProxyBind { source, .. }
            | Self::ProxyThreadSpawn { source }
            | Self::ProxyClientNoDelay { source }
            | Self::ProxyClientClone { source }
            | Self::VsockConnect { source }
            | Self::ProxyVsockClone { source }
            | Self::ProxyCopyResponse { source }
            | Self::ProxyCopyRequest { source }
            | Self::DnsUdpBind { source, .. }
            | Self::DnsTcpBind { source, .. }
            | Self::DnsUdpThreadSpawn { source, .. }
            | Self::DnsTcpThreadSpawn { source, .. }
            | Self::DnsTcpReadLength { source }
            | Self::DnsTcpReadBody { source }
            | Self::DnsTcpWriteLength { source }
            | Self::DnsTcpWriteBody { source }
            | Self::ResolvConfWrite { source }
            | Self::ContractNotVisible { source, .. }
            | Self::ReadContract { source, .. }
            | Self::SpawnCommand { source, .. }
            | Self::OpenCommandPty { source }
            | Self::DuplicatePtySlave { source }
            | Self::DuplicatePtyMaster { source }
            | Self::DuplicatePtyMasterForControl { source }
            | Self::ConnectCommandPtyData { source, .. }
            | Self::ConnectCommandPtyControl { source, .. }
            | Self::CloneCommandPtyDataStream { source }
            | Self::ReadCommandPtyControl { source }
            | Self::ResizeCommandPty { source }
            | Self::SignalCommandProcessGroup { source, .. }
            | Self::SpawnPtyCommand { source, .. }
            | Self::WaitPtyCommand { source, .. }
            | Self::OpenGuestStdin { source, .. }
            | Self::CreateCommandStdioFile { source, .. }
            | Self::StatCommandStdioFile { source, .. }
            | Self::SetCommandStdioFilePermissions { source, .. }
            | Self::WriteGuestResultTemp { source, .. }
            | Self::StatGuestResultTemp { source, .. }
            | Self::SetGuestResultTempPermissions { source, .. }
            | Self::RenameGuestResult { source, .. }
            | Self::OpenModule { source, .. }
            | Self::ModuleParams { source }
            | Self::LoadModule { source, .. } => Some(source),
            Self::InvalidNetworkSocketAddr { source, .. } => Some(source),
            Self::InvalidSandboxAttribution { source, .. } => Some(source),
            Self::BindMount { error, .. } | Self::RemountReadOnly { error, .. } => Some(error),
            Self::ParseContract { source, .. } | Self::SerializeGuestResult { source, .. } => {
                Some(source)
            }
            Self::InvalidChildPgid { source, .. } => Some(source),
            Self::MissingKernelArg { .. }
            | Self::UnsupportedNetworkMode { .. }
            | Self::ContractNotRegularFile { .. }
            | Self::InvalidContractVersion { .. }
            | Self::EmptyExecutable
            | Self::RelativeCommandCwd { .. }
            | Self::SecretEnvKey { .. }
            | Self::UnsupportedTerminalInteractive
            | Self::TerminalPtyPortRequired
            | Self::TerminalPtyPortWithoutPty
            | Self::TerminalPtyRequiresInteractive
            | Self::TerminalPtyPortConflictsWithNetwork
            | Self::TerminalPtyControlPortRequired
            | Self::TerminalPtyControlPortWithoutPty
            | Self::TerminalPtyControlPortConflictsWithNetwork
            | Self::TerminalPtyControlPortConflictsWithPtyPort
            | Self::EmptyTerminalTerm
            | Self::ZeroTerminalDimension { .. }
            | Self::RelativeMountTarget { .. }
            | Self::NonLoopbackNetworkSocketAddr { .. }
            | Self::ZeroNetworkPort { .. }
            | Self::DirectNetworkDevicesAllowed
            | Self::EmptyAttributionHeaderName
            | Self::EmptyAttributionHeaderValue { .. }
            | Self::MissingSandboxAttribution
            | Self::DuplicateSandboxAttribution
            | Self::SandboxAttributionMismatch { .. }
            | Self::GuestNetworkSetup { .. }
            | Self::CommandPtyMissingStatus
            | Self::InvalidPtyResizeMessage { .. }
            | Self::UnsupportedPtyControlMessage { .. }
            | Self::UnsupportedPtySignal { .. }
            | Self::MissingShareSource { .. }
            | Self::CommandStdioPathWithoutParent { .. }
            | Self::CommandMissingStatus
            | Self::ResultPathWithoutParent { .. } => None,
        }
    }
}

/// Result type used by the Linux guest init payload.
pub type InitResult<T> = Result<T, InitError>;
