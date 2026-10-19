use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::num::NonZeroU32;
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

pub const SUPPORTED_CONTRACT_VERSION: u32 = 2;
const FORBIDDEN_COMMAND_ENV_KEYS: &[&str] = &[
    "FIRMA_CAPABILITY_TOKEN",
    "FIRMA_SECRET_BROKER_ADDR",
    "FIRMA_SECRET_PROVIDER_NAMES",
    "FIRMA_SECRET_SHIM_SHARE_DIRECTORY",
    "FIRMA_SECRET_BROKER_SOCKET_PATH",
];
const VMADDR_PORT_ANY: u32 = u32::MAX;

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
        let command_pty_ports = self.validate_terminal()?;
        self.validate_mounts(&limits)?;
        let network = self.validate_network(&limits)?;
        let guest_broker = self.validate_secret_shims(&limits)?;
        validate_guest_broker_listener_collisions(&network, guest_broker.as_ref())?;
        let vsock_ports = VsockPorts {
            sidecar: network.vsock_sidecar_port,
            command_pty: command_pty_ports,
            broker: guest_broker.as_ref().map(|broker| broker.vsock_port),
        };
        validate_vsock_port_collisions(&vsock_ports)?;
        validate_invariants(&self.invariants)?;

        Ok(Contract {
            document: self,
            sidecar_host_addr: network.sidecar_host_addr,
            guest_broker,
            vsock_ports,
        })
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
        require_guest_path("command.cwd", &self.command.cwd, limits.path_len)?;
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

        for key in FORBIDDEN_COMMAND_ENV_KEYS {
            if self.command.env.contains_key(*key) {
                return Err(ContractValidationError::SecretEnvSerialized { key });
            }
        }

        let _ = self.command.identity_mode;
        Ok(())
    }

    /// Validates terminal metadata while PTY transport is still unsupported.
    fn validate_terminal(&self) -> ValidationResult<Option<CommandPtyPorts>> {
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
    fn validate_network(
        &self,
        limits: &ContractValidationLimits,
    ) -> ValidationResult<AcceptedNetwork> {
        let _ = self.network.mode;
        let _ = self.network.dns_mode;

        require_len_at_most(
            "network.guest_http_proxy_addr",
            self.network.guest_http_proxy_addr.len(),
            limits.dns_stub_addr_len,
        )?;

        let guest_http_proxy_addr = require_loopback_socket_addr(
            "network.guest_http_proxy_addr",
            &self.network.guest_http_proxy_addr,
        )?;

        require_len_at_most(
            "network.guest_dns_stub_addr",
            self.network.guest_dns_stub_addr.len(),
            limits.dns_stub_addr_len,
        )?;

        let guest_dns_stub_addr = require_loopback_socket_addr(
            "network.guest_dns_stub_addr",
            &self.network.guest_dns_stub_addr,
        )?;

        let vsock_sidecar_port = require_vsock_port(
            "network.vsock_sidecar_port",
            self.network.vsock_sidecar_port,
        )?;

        require_len_at_most(
            "network.sidecar_host_addr",
            self.network.sidecar_host_addr.len(),
            limits.dns_stub_addr_len,
        )?;
        let sidecar_host_addr = require_loopback_socket_addr(
            "network.sidecar_host_addr",
            &self.network.sidecar_host_addr,
        )?;

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

        Ok(AcceptedNetwork {
            guest_http_proxy_addr,
            guest_dns_stub_addr,
            sidecar_host_addr,
            vsock_sidecar_port,
        })
    }

    /// Validates the optional `secret_shims` contract section.
    fn validate_secret_shims(
        &self,
        limits: &ContractValidationLimits,
    ) -> ValidationResult<Option<GuestBroker>> {
        let Some(shims) = &self.secret_shims else {
            return Ok(None);
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
        if shims.provider_names.is_empty() {
            return Err(ContractValidationError::EmptySecretShimProviders);
        }
        let mut provider_names = BTreeSet::new();
        for name in &shims.provider_names {
            require_non_empty("secret_shims.provider_names entry", name)?;
            if !is_portable_basename(name) {
                return Err(ContractValidationError::UnsafeSecretShimProviderName {
                    name: name.clone(),
                });
            }
            if !provider_names.insert(name.as_str()) {
                return Err(ContractValidationError::DuplicateSecretShimProviderName {
                    name: name.clone(),
                });
            }
        }
        let broker_vsock_port =
            require_vsock_port("secret_shims.broker_vsock_port", shims.broker_vsock_port)?;
        require_path(
            "secret_shims.shim_share_directory",
            &shims.shim_share_directory,
            limits.path_len,
        )?;
        require_path(
            "secret_shims.broker_socket_path",
            &shims.broker_socket_path,
            limits.path_len,
        )?;
        for (field, path) in [
            (
                "secret_shims.shim_share_directory",
                &shims.shim_share_directory,
            ),
            ("secret_shims.broker_socket_path", &shims.broker_socket_path),
        ] {
            if path.starts_with(&self.runtime_dir) {
                return Err(ContractValidationError::SecretShimPathWithinRuntime {
                    field,
                    path: path.clone(),
                    runtime_dir: self.runtime_dir.clone(),
                });
            }
        }
        require_len_at_most(
            "secret_shims.guest_broker_addr",
            shims.guest_broker_addr.len(),
            limits.dns_stub_addr_len,
        )?;
        let guest_addr = require_loopback_socket_addr(
            "secret_shims.guest_broker_addr",
            &shims.guest_broker_addr,
        )?;

        Ok(Some(GuestBroker {
            guest_addr,
            vsock_port: broker_vsock_port,
        }))
    }
}

fn validate_guest_broker_listener_collisions(
    network: &AcceptedNetwork,
    guest_broker: Option<&GuestBroker>,
) -> ValidationResult<()> {
    let Some(guest_broker) = guest_broker else {
        return Ok(());
    };
    let dns_resolver_addr = SocketAddr::new(network.guest_dns_stub_addr.ip(), 53);
    for (field, addr) in [
        (
            "network.guest_http_proxy_addr",
            network.guest_http_proxy_addr,
        ),
        ("network.guest_dns_stub_addr", network.guest_dns_stub_addr),
        ("guest DNS resolver listener", dns_resolver_addr),
    ] {
        if guest_broker.guest_addr == addr {
            return Err(ContractValidationError::GuestBrokerAddrCollision { field });
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct Contract {
    document: ContractDocument,
    sidecar_host_addr: SocketAddr,
    guest_broker: Option<GuestBroker>,
    vsock_ports: VsockPorts,
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
    pub const fn vsock_sidecar_port(&self) -> NonZeroU32 {
        self.vsock_ports.sidecar
    }

    pub(crate) const fn command_pty_ports(&self) -> Option<(NonZeroU32, NonZeroU32)> {
        match self.vsock_ports.command_pty {
            Some(ports) => Some((ports.data, ports.control)),
            None => None,
        }
    }

    /// Returns the host Sidecar endpoint reached by the runner bridge.
    pub const fn sidecar_host_addr(&self) -> SocketAddr {
        self.sidecar_host_addr
    }

    /// Returns the validated guest broker loopback address, when secret shims are enabled.
    pub const fn guest_broker_addr(&self) -> Option<SocketAddr> {
        match &self.guest_broker {
            Some(broker) => Some(broker.guest_addr),
            None => None,
        }
    }

    /// Returns the validated broker VSOCK port, when secret shims are enabled.
    pub const fn broker_vsock_port(&self) -> Option<NonZeroU32> {
        self.vsock_ports.broker
    }
}

#[derive(Debug, Clone, Copy)]
struct AcceptedNetwork {
    guest_http_proxy_addr: SocketAddr,
    guest_dns_stub_addr: SocketAddr,
    sidecar_host_addr: SocketAddr,
    vsock_sidecar_port: NonZeroU32,
}

#[derive(Debug, Clone, Copy)]
struct GuestBroker {
    guest_addr: SocketAddr,
    vsock_port: NonZeroU32,
}

#[derive(Debug, Clone, Copy)]
struct CommandPtyPorts {
    data: NonZeroU32,
    control: NonZeroU32,
}

#[derive(Debug, Clone, Copy)]
struct VsockPorts {
    sidecar: NonZeroU32,
    command_pty: Option<CommandPtyPorts>,
    broker: Option<NonZeroU32>,
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
    fn validate(&self) -> ValidationResult<Option<CommandPtyPorts>> {
        if !self.pty {
            if self.pty_vsock_port.is_some() {
                return Err(ContractValidationError::TerminalPtyPortRequiresPty);
            }
            if self.pty_control_vsock_port.is_some() {
                return Err(ContractValidationError::TerminalPtyControlPortRequiresPty);
            }

            require_optional_non_empty("terminal.term", self.term.as_deref())?;
            reject_zero_terminal_dimension("terminal.rows", self.rows)?;
            reject_zero_terminal_dimension("terminal.cols", self.cols)?;
            return Ok(None);
        }

        let data_port = self
            .pty_vsock_port
            .and_then(NonZeroU32::new)
            .ok_or(ContractValidationError::TerminalPtyRequiresVsockPort)?;
        let control_port = self
            .pty_control_vsock_port
            .and_then(NonZeroU32::new)
            .ok_or(ContractValidationError::TerminalPtyRequiresControlVsockPort)?;

        if !self.interactive {
            return Err(ContractValidationError::TerminalPtyRequiresInteractive);
        }

        require_optional_non_empty("terminal.term", self.term.as_deref())?;
        reject_zero_terminal_dimension("terminal.rows", self.rows)?;
        reject_zero_terminal_dimension("terminal.cols", self.cols)?;

        reject_reserved_vsock_port("terminal.pty_vsock_port", data_port)?;
        reject_reserved_vsock_port("terminal.pty_control_vsock_port", control_port)?;
        Ok(Some(CommandPtyPorts {
            data: data_port,
            control: control_port,
        }))
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
    broker_socket_path: PathBuf,
    guest_broker_addr: String,
}

impl SecretShims {
    /// Returns the guest target triple for the shim binary.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "used by the runner binary for VSOCK broker bridge planning"
        )
    )]
    pub fn guest_target_triple(&self) -> &str {
        &self.guest_target_triple
    }

    /// Returns the provider names that need shim entries.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "used by the runner binary for VSOCK broker bridge planning"
        )
    )]
    pub fn provider_names(&self) -> &[String] {
        &self.provider_names
    }
    /// Returns the host directory containing the shim binary.
    pub fn shim_share_directory(&self) -> &Path {
        &self.shim_share_directory
    }

    /// Returns the host Unix socket reached by the broker VSOCK bridge.
    pub fn broker_socket_path(&self) -> &Path {
        &self.broker_socket_path
    }
}

/// Applies the shared portable executable-basename invariant defensively at the contract boundary.
fn is_portable_basename(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value
            .chars()
            .any(|character| matches!(character, '/' | '\\' | ':' | '\0'))
}

fn require_vsock_port(field: &'static str, port: u32) -> ValidationResult<NonZeroU32> {
    let port = NonZeroU32::new(port).ok_or(ContractValidationError::ZeroPort { field })?;
    reject_reserved_vsock_port(field, port)?;
    Ok(port)
}

fn reject_reserved_vsock_port(field: &'static str, port: NonZeroU32) -> ValidationResult<()> {
    if port.get() == VMADDR_PORT_ANY {
        return Err(ContractValidationError::ReservedVsockPort { field });
    }
    Ok(())
}

fn validate_vsock_port_collisions(ports: &VsockPorts) -> ValidationResult<()> {
    let pairs = [
        (
            ports.command_pty.map(|pty| pty.data),
            "terminal.pty_vsock_port",
            Some(ports.sidecar),
            "network.vsock_sidecar_port",
        ),
        (
            ports.command_pty.map(|pty| pty.control),
            "terminal.pty_control_vsock_port",
            Some(ports.sidecar),
            "network.vsock_sidecar_port",
        ),
        (
            ports.command_pty.map(|pty| pty.control),
            "terminal.pty_control_vsock_port",
            ports.command_pty.map(|pty| pty.data),
            "terminal.pty_vsock_port",
        ),
        (
            ports.broker,
            "secret_shims.broker_vsock_port",
            Some(ports.sidecar),
            "network.vsock_sidecar_port",
        ),
        (
            ports.broker,
            "secret_shims.broker_vsock_port",
            ports.command_pty.map(|pty| pty.data),
            "terminal.pty_vsock_port",
        ),
        (
            ports.broker,
            "secret_shims.broker_vsock_port",
            ports.command_pty.map(|pty| pty.control),
            "terminal.pty_control_vsock_port",
        ),
    ];

    for (first, first_field, second, second_field) in pairs {
        if first.is_some() && first == second {
            return Err(ContractValidationError::VsockPortCollision {
                first_field,
                second_field,
            });
        }
    }
    Ok(())
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
