use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use firma_identifiers::SandboxId;
use serde::Deserialize;

mod custody;
mod error;
mod validation;

#[cfg(all(test, unix))]
use custody::validate_contract_file_mode;

use custody::validate_contract_file_access;
pub use error::{ContractValidationError, ValidationResult};
pub use validation::ContractValidationLimits;
use validation::{
    require_count_at_most, require_file, require_guest_path, require_len_at_most,
    require_loopback_socket_addr, require_non_empty, require_path,
};

const SUPPORTED_CONTRACT_VERSION: u32 = 2;
const SECRET_ENV_KEYS: &[&str] = &["FIRMA_CAPABILITY_TOKEN"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractDocument {
    #[serde(skip)]
    source_path: Option<PathBuf>,
    version: u32,
    sandbox_id: SandboxId,
    runtime_dir: PathBuf,
    runner: Runner,
    guest: Guest,
    command: Command,
    terminal: Terminal,
    mounts: Vec<Mount>,
    network: Network,
    invariants: Vec<Invariant>,
    #[serde(default)]
    secret_shims: Option<SecretShims>,
}

impl ContractDocument {
    /// Reads a launch contract from disk after checking file custody.
    ///
    /// Custody is validated before parsing so that insecurely exposed launch
    /// context fails before the runner trusts any contract contents.
    pub fn read_from_path(path: &Path) -> Result<Self> {
        validate_contract_file_access(path)?;
        let source_path = absolute_path(path)?;
        let json = fs::read(path)
            .with_context(|| format!("read VZ launch contract {}", path.display()))?;
        let mut contract = Self::parse_from_slice(path, &json)?;
        contract.source_path = Some(source_path);
        Ok(contract)
    }

    /// Reads a source-path-aware contract fixture without file custody checks.
    ///
    /// Tests outside the contract module use this when they need a validated
    /// contract with `source_path` populated, but should not also exercise Unix
    /// file permission enforcement.
    #[cfg(test)]
    pub fn read_fixture_from_path_without_custody(path: &Path) -> Result<Self> {
        let source_path = absolute_path(path)?;
        let json = fs::read(path)
            .with_context(|| format!("read VZ launch contract {}", path.display()))?;
        let mut contract = Self::parse_from_slice(path, &json)?;
        contract.source_path = Some(source_path);

        Ok(contract)
    }

    /// Parses raw JSON bytes into the contract schema without semantic checks.
    fn parse_from_slice(path: &Path, json: &[u8]) -> Result<Self> {
        serde_json::from_slice(json)
            .with_context(|| format!("parse VZ launch contract {}", path.display()))
    }

    /// Converts a parsed contract document into a prepared runner contract.
    ///
    /// This performs semantic validation on paths, artifacts, network fields,
    /// environment contents, and required invariants. Runner code should use the
    /// returned `Contract`, not the raw JSON document.
    pub fn validate(self) -> ValidationResult<Contract> {
        self.validate_with_file_checker(Path::is_file)
    }

    /// Validates a parsed contract with the default limits and injected file check.
    fn validate_with_file_checker(
        self,
        is_file: impl FnMut(&Path) -> bool,
    ) -> ValidationResult<Contract> {
        self.validate_with_limits_and_file_checker(ContractValidationLimits::default(), is_file)
    }

    /// Validates a parsed contract using explicit limits and injected file checks.
    fn validate_with_limits_and_file_checker(
        self,
        limits: ContractValidationLimits,
        mut is_file: impl FnMut(&Path) -> bool,
    ) -> ValidationResult<Contract> {
        self.validate_version()?;
        self.validate_runtime(&limits)?;
        self.validate_guest(&limits, &mut is_file)?;
        self.validate_command(&limits)?;
        self.validate_terminal()?;
        self.validate_mounts(&limits)?;
        self.validate_network(&limits)?;
        self.validate_terminal_network_ports()?;
        self.validate_secret_shims(&limits)?;
        validate_invariants(&self.invariants)?;

        Ok(Contract { document: self })
    }

    /// Validates that the contract uses the schema version supported by this runner.
    fn validate_version(&self) -> ValidationResult<()> {
        if self.version != SUPPORTED_CONTRACT_VERSION {
            return Err(ContractValidationError::UnsupportedVersion {
                actual: self.version,
                supported: SUPPORTED_CONTRACT_VERSION,
            });
        }
        Ok(())
    }

    /// Validates runtime identity fields and host-side runner paths.
    fn validate_runtime(&self, limits: &ContractValidationLimits) -> ValidationResult<()> {
        require_path("runtime_dir", &self.runtime_dir, limits.path_len)?;
        require_path("runner.path", &self.runner.path, limits.path_len)
    }

    /// Validates guest artifact paths before any VM planning can happen.
    fn validate_guest(
        &self,
        limits: &ContractValidationLimits,
        is_file: &mut impl FnMut(&Path) -> bool,
    ) -> ValidationResult<()> {
        require_file("guest.kernel", &self.guest.kernel, limits.path_len, is_file)?;
        require_file("guest.initrd", &self.guest.initrd, limits.path_len, is_file)?;
        require_file("guest.rootfs", &self.guest.rootfs, limits.path_len, is_file)
    }

    /// Validates command shape, argv/env bounds, and secret exclusion.
    fn validate_command(&self, limits: &ContractValidationLimits) -> ValidationResult<()> {
        require_non_empty("command.executable", &self.command.executable)?;
        require_len_at_most(
            "command.executable",
            self.command.executable.len(),
            limits.command_arg_len,
        )?;
        require_path("command.cwd", &self.command.cwd, limits.path_len)?;
        require_count_at_most("command.args", self.command.args.len(), limits.command_args)?;
        for arg in &self.command.args {
            if arg.is_empty() {
                return Err(ContractValidationError::EmptyCommandArgument);
            }
            require_len_at_most("command.args", arg.len(), limits.command_arg_len)?;
        }
        require_count_at_most("command.env", self.command.env.len(), limits.env_vars)?;
        for (key, value) in &self.command.env {
            require_non_empty("command.env key", key)?;
            require_len_at_most("command.env key", key.len(), limits.env_key_len)?;
            require_len_at_most("command.env value", value.len(), limits.env_value_len)?;
        }

        for key in SECRET_ENV_KEYS {
            if self.command.env.contains_key(*key) {
                return Err(ContractValidationError::SecretEnvSerialized { key });
            }
        }

        let _ = self.command.identity_mode;
        Ok(())
    }

    /// Validates terminal metadata while PTY transport is still unsupported.
    fn validate_terminal(&self) -> ValidationResult<()> {
        self.terminal.validate()
    }

    /// Validates mount declarations for count, path shape, and bounded size.
    fn validate_mounts(&self, limits: &ContractValidationLimits) -> ValidationResult<()> {
        require_count_at_most("mounts", self.mounts.len(), limits.mounts)?;
        for mount in &self.mounts {
            require_path("mount.source", &mount.source, limits.path_len)?;
            require_guest_path("mount.target", &mount.target, limits.path_len)?;
            let _ = mount.read_only;
        }
        Ok(())
    }

    /// Validates the sidecar proxy, DNS stub, and attribution header contract.
    fn validate_network(&self, limits: &ContractValidationLimits) -> ValidationResult<()> {
        let _ = self.network.mode;
        let _ = self.network.dns_mode;

        require_len_at_most(
            "network.guest_http_proxy_addr",
            self.network.guest_http_proxy_addr.len(),
            limits.dns_stub_addr_len,
        )?;

        require_loopback_socket_addr(
            "network.guest_http_proxy_addr",
            &self.network.guest_http_proxy_addr,
        )?;

        require_len_at_most(
            "network.guest_dns_stub_addr",
            self.network.guest_dns_stub_addr.len(),
            limits.dns_stub_addr_len,
        )?;

        require_loopback_socket_addr(
            "network.guest_dns_stub_addr",
            &self.network.guest_dns_stub_addr,
        )?;

        if self.network.vsock_sidecar_port == 0 {
            return Err(ContractValidationError::ZeroPort {
                field: "network.vsock_sidecar_port",
            });
        }

        require_len_at_most(
            "network.sidecar_host_addr",
            self.network.sidecar_host_addr.len(),
            limits.dns_stub_addr_len,
        )?;
        require_loopback_socket_addr("network.sidecar_host_addr", &self.network.sidecar_host_addr)?;

        if self.network.direct_network_devices_allowed {
            return Err(ContractValidationError::DirectNetworkDevicesAllowed);
        }

        require_count_at_most(
            "network.attribution_headers",
            self.network.attribution_headers.len(),
            limits.attribution_headers,
        )?;

        for (name, value) in &self.network.attribution_headers {
            require_non_empty("network.attribution_headers key", name)?;
            require_len_at_most(
                "network.attribution_headers key",
                name.len(),
                limits.attribution_header_name_len,
            )?;
            require_non_empty("network.attribution_headers value", value)?;
            require_len_at_most(
                "network.attribution_headers value",
                value.len(),
                limits.attribution_header_value_len,
            )?;
        }

        let mut sandbox_headers = self
            .network
            .attribution_headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-firma-sandbox-id"));
        let Some((_, value)) = sandbox_headers.next() else {
            return Err(ContractValidationError::MissingSandboxAttribution);
        };
        if sandbox_headers.next().is_some() {
            return Err(ContractValidationError::DuplicateSandboxAttribution);
        }
        let attributed_id =
            value.parse().map_err(
                |source| ContractValidationError::InvalidSandboxAttribution {
                    value: value.clone(),
                    source,
                },
            )?;
        if attributed_id != self.sandbox_id {
            return Err(ContractValidationError::SandboxAttributionMismatch {
                expected: self.sandbox_id,
                actual: attributed_id,
            });
        }

        Ok(())
    }

    /// Validates the optional `secret_shims` contract section.
    fn validate_secret_shims(&self, limits: &ContractValidationLimits) -> ValidationResult<()> {
        let Some(shims) = &self.secret_shims else {
            return Ok(());
        };
        require_non_empty(
            "secret_shims.guest_target_triple",
            &shims.guest_target_triple,
        )?;
        require_len_at_most(
            "secret_shims.guest_target_triple",
            shims.guest_target_triple.len(),
            limits.path_len,
        )?;
        require_count_at_most(
            "secret_shims.provider_names",
            shims.provider_names.len(),
            limits.env_vars,
        )?;
        for name in &shims.provider_names {
            require_non_empty("secret_shims.provider_names entry", name)?;
        }
        if shims.broker_vsock_port == 0 {
            return Err(ContractValidationError::ZeroPort {
                field: "secret_shims.broker_vsock_port",
            });
        }
        require_path(
            "secret_shims.shim_share_directory",
            &shims.shim_share_directory,
            limits.path_len,
        )?;
        Ok(())
    }

    /// Validates PTY ports do not reuse the network sidecar VSOCK port.
    fn validate_terminal_network_ports(&self) -> ValidationResult<()> {
        if self.terminal.pty_vsock_port == Some(self.network.vsock_sidecar_port) {
            return Err(ContractValidationError::TerminalPtyPortConflictsWithSidecar);
        }

        if self.terminal.pty_control_vsock_port == Some(self.network.vsock_sidecar_port) {
            return Err(ContractValidationError::TerminalPtyControlPortConflictsWithSidecar);
        }

        if self.terminal.pty_control_vsock_port == self.terminal.pty_vsock_port
            && self.terminal.pty_control_vsock_port.is_some()
        {
            return Err(ContractValidationError::TerminalPtyControlPortConflictsWithDataPort);
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Contract {
    document: ContractDocument,
}

impl Contract {
    /// Returns the validated launch contract schema version.
    pub const fn version(&self) -> u32 {
        self.document.version
    }

    /// Returns the sandbox id associated with this launch contract.
    pub const fn sandbox_id(&self) -> &SandboxId {
        &self.document.sandbox_id
    }

    pub fn source_path(&self) -> Option<&Path> {
        self.document.source_path.as_deref()
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.document.runtime_dir
    }

    pub fn guest(&self) -> &Guest {
        &self.document.guest
    }

    pub fn mounts(&self) -> &[Mount] {
        &self.document.mounts
    }

    /// Returns the optional secret shims contract section.
    pub fn secret_shims(&self) -> Option<&SecretShims> {
        self.document.secret_shims.as_ref()
    }

    /// Returns host terminal metadata carried by the launch contract.
    pub const fn terminal(&self) -> &Terminal {
        &self.document.terminal
    }

    /// Returns the guest network mode accepted by contract validation.
    pub const fn network_mode(&self) -> NetworkMode {
        self.document.network.mode
    }

    /// Returns the guest VSOCK port reserved for Sidecar traffic.
    pub const fn vsock_sidecar_port(&self) -> u32 {
        self.document.network.vsock_sidecar_port
    }

    /// Returns the optional command PTY data VSOCK port.
    pub const fn command_pty_vsock_port(&self) -> Option<u32> {
        self.document.terminal.pty_vsock_port()
    }

    /// Returns the optional command PTY control VSOCK port.
    pub const fn command_pty_control_vsock_port(&self) -> Option<u32> {
        self.document.terminal.pty_control_vsock_port()
    }

    /// Returns the host Sidecar endpoint reached by the runner bridge.
    pub fn sidecar_host_addr(
        &self,
    ) -> std::result::Result<std::net::SocketAddr, ContractValidationError> {
        require_loopback_socket_addr(
            "network.sidecar_host_addr",
            &self.document.network.sidecar_host_addr,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    kernel: PathBuf,
    initrd: PathBuf,
    rootfs: PathBuf,
}

impl Guest {
    pub fn kernel(&self) -> &Path {
        &self.kernel
    }

    pub fn initrd(&self) -> &Path {
        &self.initrd
    }

    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    executable: String,
    args: Vec<String>,
    cwd: PathBuf,
    env: BTreeMap<String, String>,
    identity_mode: IdentityMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terminal {
    interactive: bool,
    pty: bool,
    pty_vsock_port: Option<u32>,
    pty_control_vsock_port: Option<u32>,
    term: Option<String>,
    rows: Option<u16>,
    cols: Option<u16>,
}

impl Terminal {
    /// Returns whether the host command was launched from an interactive TTY.
    pub const fn interactive(&self) -> bool {
        self.interactive
    }

    /// Returns whether the launch requested guest PTY transport.
    pub const fn pty(&self) -> bool {
        self.pty
    }

    /// Returns the host terminal type, when available.
    pub fn term(&self) -> Option<&str> {
        self.term.as_deref()
    }

    /// Returns the host terminal row count, when available.
    pub const fn rows(&self) -> Option<u16> {
        self.rows
    }

    /// Returns the host terminal column count, when available.
    pub const fn cols(&self) -> Option<u16> {
        self.cols
    }

    /// Validates terminal metadata and PTY transport port requirements.
    fn validate(&self) -> ValidationResult<()> {
        match (self.pty, self.pty_vsock_port) {
            (true, Some(port)) if port != 0 => {}
            (true, _) => return Err(ContractValidationError::TerminalPtyRequiresVsockPort),
            (false, Some(_)) => return Err(ContractValidationError::TerminalPtyPortRequiresPty),
            (false, None) => {}
        }

        match (self.pty, self.pty_control_vsock_port) {
            (true, Some(port)) if port != 0 => {}
            (true, _) => return Err(ContractValidationError::TerminalPtyRequiresControlVsockPort),
            (false, Some(_)) => {
                return Err(ContractValidationError::TerminalPtyControlPortRequiresPty);
            }
            (false, None) => {}
        }

        if self.pty && !self.interactive {
            return Err(ContractValidationError::TerminalPtyRequiresInteractive);
        }

        require_optional_non_empty("terminal.term", self.term.as_deref())?;
        reject_zero_terminal_dimension("terminal.rows", self.rows)?;
        reject_zero_terminal_dimension("terminal.cols", self.cols)?;

        Ok(())
    }

    /// Returns the optional guest PTY data VSOCK port.
    pub const fn pty_vsock_port(&self) -> Option<u32> {
        self.pty_vsock_port
    }

    /// Returns the optional guest PTY control VSOCK port.
    pub const fn pty_control_vsock_port(&self) -> Option<u32> {
        self.pty_control_vsock_port
    }
}

/// Validates that an optional string is non-empty when present.
fn require_optional_non_empty(field: &'static str, value: Option<&str>) -> ValidationResult<()> {
    if let Some(value) = value {
        require_non_empty(field, value)?;
    }

    Ok(())
}

/// Rejects terminal dimensions that are present but zero.
fn reject_zero_terminal_dimension(
    field: &'static str,
    dimension: Option<u16>,
) -> ValidationResult<()> {
    if dimension == Some(0) {
        return Err(ContractValidationError::ZeroTerminalDimension { field });
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IdentityMode {
    SandboxUser,
    HostUser,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    source: PathBuf,
    target: PathBuf,
    read_only: bool,
}

impl Mount {
    pub fn source(&self) -> &Path {
        &self.source
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    mode: NetworkMode,
    guest_http_proxy_addr: String,
    guest_dns_stub_addr: String,
    vsock_sidecar_port: u32,
    sidecar_host_addr: String,
    direct_network_devices_allowed: bool,
    dns_mode: DnsMode,
    attribution_headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    VsockSidecar,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DnsMode {
    ConfinedStub,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretShims {
    guest_target_triple: String,
    provider_names: Vec<String>,
    broker_vsock_port: u32,
    shim_share_directory: PathBuf,
}

impl SecretShims {
    /// Returns the guest target triple for the shim binary.
    #[expect(
        dead_code,
        reason = "used by the runner binary for VSOCK broker bridge planning"
    )]
    pub fn guest_target_triple(&self) -> &str {
        &self.guest_target_triple
    }

    /// Returns the provider names that need shim entries.
    #[expect(
        dead_code,
        reason = "used by the runner binary for VSOCK broker bridge planning"
    )]
    pub fn provider_names(&self) -> &[String] {
        &self.provider_names
    }

    /// Returns the VSOCK port used for the broker bridge.
    #[expect(
        dead_code,
        reason = "used by the runner binary for VSOCK broker bridge planning"
    )]
    pub const fn broker_vsock_port(&self) -> u32 {
        self.broker_vsock_port
    }

    /// Returns the host directory containing the shim binary.
    pub fn shim_share_directory(&self) -> &Path {
        &self.shim_share_directory
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invariant {
    name: InvariantName,
    mode: InvariantMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantName {
    SidecarOnlyEgress,
    DnsConfined,
    FailClosedStartup,
    FailClosedRuntime,
    DirectBypassResistant,
    PreserveStdioSignalsExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InvariantMode {
    Required,
    DisabledByPolicy,
}

/// Validates that all runner invariants are present exactly once and required.
fn validate_invariants(invariants: &[Invariant]) -> ValidationResult<()> {
    let mut seen = BTreeMap::new();
    for invariant in invariants {
        if seen.insert(invariant.name, invariant.mode).is_some() {
            return Err(ContractValidationError::DuplicateInvariant {
                name: invariant.name,
            });
        }
    }

    for required in [
        InvariantName::SidecarOnlyEgress,
        InvariantName::DnsConfined,
        InvariantName::FailClosedRuntime,
        InvariantName::DirectBypassResistant,
        InvariantName::PreserveStdioSignalsExit,
    ] {
        match seen.get(&required) {
            Some(InvariantMode::Required) => {}
            Some(InvariantMode::DisabledByPolicy) => {
                return Err(ContractValidationError::DisabledInvariant { name: required });
            }
            None => return Err(ContractValidationError::MissingInvariant { name: required }),
        }
    }

    if !seen.contains_key(&InvariantName::FailClosedStartup) {
        return Err(ContractValidationError::MissingInvariant {
            name: InvariantName::FailClosedStartup,
        });
    }

    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(std::env::current_dir()
        .with_context(|| format!("resolve current directory for {}", path.display()))?
        .join(path))
}

#[cfg(test)]
mod tests;
