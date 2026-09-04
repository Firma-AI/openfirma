use std::net::AddrParseError;
use std::path::PathBuf;

use thiserror::Error;

use firma_identifiers::{SandboxId, SandboxIdParseError};

use super::InvariantName;

pub type ValidationResult<T> = std::result::Result<T, ContractValidationError>;

#[derive(Debug, Error)]
pub enum ContractValidationError {
    #[error("unsupported VZ launch contract version {actual}; runner supports version {supported}")]
    UnsupportedVersion { actual: u32, supported: u32 },
    #[error("{field} has {actual} items, exceeding limit of {max}")]
    TooManyItems {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("{field} has length {actual}, exceeding limit of {max}")]
    FieldTooLong {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("{field} must be absolute: {}", path.display())]
    RelativePath { field: &'static str, path: PathBuf },
    #[error("{field} must be an existing file: {}", path.display())]
    MissingFile { field: &'static str, path: PathBuf },
    #[error("command.args must not contain empty arguments")]
    EmptyCommandArgument,
    #[error("command.env must not serialize secret key {key}")]
    SecretEnvSerialized { key: &'static str },
    #[error("terminal.pty=true requires non-zero terminal.pty_vsock_port")]
    TerminalPtyRequiresVsockPort,
    #[error("terminal.pty_vsock_port requires terminal.pty=true")]
    TerminalPtyPortRequiresPty,
    #[error("terminal.pty=true requires terminal.interactive=true")]
    TerminalPtyRequiresInteractive,
    #[error("terminal.pty_vsock_port must be distinct from network.vsock_sidecar_port")]
    TerminalPtyPortConflictsWithSidecar,
    #[error("terminal.pty=true requires non-zero terminal.pty_control_vsock_port")]
    TerminalPtyRequiresControlVsockPort,
    #[error("terminal.pty_control_vsock_port requires terminal.pty=true")]
    TerminalPtyControlPortRequiresPty,
    #[error("terminal.pty_control_vsock_port must be distinct from network.vsock_sidecar_port")]
    TerminalPtyControlPortConflictsWithSidecar,
    #[error("terminal.pty_control_vsock_port must be distinct from terminal.pty_vsock_port")]
    TerminalPtyControlPortConflictsWithDataPort,
    #[error("{field} must be non-zero when set")]
    ZeroTerminalDimension { field: &'static str },
    #[error("{field} must be a host:port socket address, got {value}")]
    InvalidSocketAddr {
        field: &'static str,
        value: String,
        source: AddrParseError,
    },
    #[error("{field} must be loopback, got {value}")]
    NonLoopbackSocketAddr { field: &'static str, value: String },
    #[error("{field} must be non-zero")]
    ZeroPort { field: &'static str },
    #[error("secret_shims provider name must be a single portable path component: {name}")]
    UnsafeSecretShimProviderName { name: String },
    #[error("secret_shims provider name is reserved for internal broker readiness checks: {name}")]
    ReservedSecretShimProviderName { name: String },
    #[error("secret_shims.provider_names must not be empty when secret_shims is present")]
    EmptySecretShimProviders,
    #[error("{field} must not be within guest-writable runtime_dir {runtime_dir}: {path}")]
    SecretShimPathWithinRuntime {
        field: &'static str,
        path: PathBuf,
        runtime_dir: PathBuf,
    },
    #[error("secret_shims.broker_vsock_port must be distinct from network.vsock_sidecar_port")]
    BrokerPortConflictsWithSidecar,
    #[error("secret_shims.broker_vsock_port must be distinct from terminal.pty_vsock_port")]
    BrokerPortConflictsWithPtyData,
    #[error("secret_shims.broker_vsock_port must be distinct from terminal.pty_control_vsock_port")]
    BrokerPortConflictsWithPtyControl,
    #[error("network.direct_network_devices_allowed must be false for VZ guest mode")]
    DirectNetworkDevicesAllowed,
    #[error("network.attribution_headers must contain x-firma-sandbox-id")]
    MissingSandboxAttribution,
    #[error("network.attribution_headers contains duplicate x-firma-sandbox-id names")]
    DuplicateSandboxAttribution,
    #[error("network x-firma-sandbox-id value '{value}' is invalid")]
    InvalidSandboxAttribution {
        value: String,
        #[source]
        source: SandboxIdParseError,
    },
    #[error("network x-firma-sandbox-id {actual} does not match contract sandbox_id {expected}")]
    SandboxAttributionMismatch {
        expected: SandboxId,
        actual: SandboxId,
    },
    #[error("duplicate VZ launch invariant {name:?}")]
    DuplicateInvariant { name: InvariantName },
    #[error("VZ launch invariant {name:?} cannot be disabled")]
    DisabledInvariant { name: InvariantName },
    #[error("missing required VZ launch invariant {name:?}")]
    MissingInvariant { name: InvariantName },
}
