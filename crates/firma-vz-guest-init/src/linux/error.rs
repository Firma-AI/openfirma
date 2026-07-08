use std::fmt;
use std::io;
use std::path::PathBuf;

/// Typed failures raised while preparing or running the VZ guest init payload.
#[derive(Debug)]
pub enum InitError {
    /// A required guest directory could not be created.
    CreateDir { path: PathBuf, source: io::Error },
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
    /// A contract mount target is not absolute.
    RelativeMountTarget { path: PathBuf },
    /// The indexed virtiofs share for a contract mount is missing.
    MissingShareSource { path: PathBuf },
    /// The guest payload process could not be spawned.
    SpawnCommand {
        executable: String,
        source: io::Error,
    },
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
                "unexpected firma.network={mode}; current lifecycle guest expects none"
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
            Self::RelativeMountTarget { path } => {
                write!(
                    formatter,
                    "mount.target must be absolute: {}",
                    path.display()
                )
            }
            Self::MissingShareSource { path } => {
                write!(formatter, "missing VZ share source {}", path.display())
            }
            Self::SpawnCommand { executable, source } => {
                write!(formatter, "spawn command {executable}: {source}")
            }
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
            | Self::ReadKernelCmdline { source }
            | Self::MountPseudo { source, .. }
            | Self::MountVirtiofs { source, .. }
            | Self::ContractNotVisible { source, .. }
            | Self::ReadContract { source, .. }
            | Self::SpawnCommand { source, .. }
            | Self::WriteGuestResultTemp { source, .. }
            | Self::StatGuestResultTemp { source, .. }
            | Self::SetGuestResultTempPermissions { source, .. }
            | Self::RenameGuestResult { source, .. }
            | Self::OpenModule { source, .. }
            | Self::ModuleParams { source }
            | Self::LoadModule { source, .. } => Some(source),
            Self::BindMount { error, .. } | Self::RemountReadOnly { error, .. } => Some(error),
            Self::ParseContract { source, .. } | Self::SerializeGuestResult { source, .. } => {
                Some(source)
            }
            Self::MissingKernelArg { .. }
            | Self::UnsupportedNetworkMode { .. }
            | Self::ContractNotRegularFile { .. }
            | Self::InvalidContractVersion { .. }
            | Self::EmptyExecutable
            | Self::RelativeCommandCwd { .. }
            | Self::SecretEnvKey { .. }
            | Self::RelativeMountTarget { .. }
            | Self::MissingShareSource { .. }
            | Self::CommandMissingStatus
            | Self::ResultPathWithoutParent { .. } => None,
        }
    }
}

/// Result type used by the Linux guest init payload.
pub type InitResult<T> = Result<T, InitError>;
