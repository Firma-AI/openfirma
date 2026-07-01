use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
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
    require_non_empty, require_path,
};

const SUPPORTED_CONTRACT_VERSION: u32 = 1;
const SECRET_ENV_KEYS: &[&str] = &["FIRMA_CAPABILITY_TOKEN"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractDocument {
    #[serde(skip)]
    source_path: Option<PathBuf>,
    version: u32,
    sandbox_id: String,
    runtime_dir: PathBuf,
    runner: Runner,
    guest: Guest,
    command: Command,
    mounts: Vec<Mount>,
    network: Network,
    invariants: Vec<Invariant>,
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
        self.validate_command(&limits, &mut is_file)?;
        self.validate_mounts(&limits)?;
        self.validate_network(&limits)?;
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
        require_non_empty("sandbox_id", &self.sandbox_id)?;
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
    fn validate_command(
        &self,
        limits: &ContractValidationLimits,
        is_file: &mut impl FnMut(&Path) -> bool,
    ) -> ValidationResult<()> {
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
        if let Some(seccomp_filter_path) = &self.command.seccomp_filter_path {
            require_file(
                "command.seccomp_filter_path",
                seccomp_filter_path,
                limits.path_len,
                is_file,
            )?;
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
        require_non_empty("network.proxy_url", &self.network.proxy_url)?;
        require_len_at_most(
            "network.proxy_url",
            self.network.proxy_url.len(),
            limits.proxy_url_len,
        )?;

        if !self.network.proxy_url.starts_with("http://") {
            return Err(ContractValidationError::NonHttpProxyUrl {
                value: self.network.proxy_url.clone(),
            });
        }

        require_len_at_most(
            "network.dns_stub_addr",
            self.network.dns_stub_addr.len(),
            limits.dns_stub_addr_len,
        )?;

        self.network
            .dns_stub_addr
            .parse::<SocketAddr>()
            .map_err(|source| ContractValidationError::InvalidSocketAddr {
                field: "network.dns_stub_addr",
                value: self.network.dns_stub_addr.clone(),
                source,
            })?;

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
    pub fn sandbox_id(&self) -> &str {
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
    seccomp_filter_path: Option<PathBuf>,
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
    proxy_url: String,
    dns_stub_addr: String,
    attribution_headers: BTreeMap<String, String>,
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
