use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
#[cfg(target_os = "linux")]
use crate::backend::platform::{WslKind, detect_wsl};
use crate::error::RunError;
use crate::profile::{BuiltInProfileId, built_in_profile};
use crate::runtime::RunInput;

fn backend_supports_structural_network(backend: BackendKind) -> bool {
    matches!(backend, BackendKind::Bwrap)
}

/// Resolved runtime profile after combining built-in defaults, optional file
/// config, and CLI overrides.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedProfile {
    pub id: String,
    pub backend: BackendKind,
    pub sidecar_endpoint: SidecarEndpoint,
    pub sidecar_selection: crate::sidecar::SidecarSelection,
    pub env_passthrough: BTreeSet<String>,
    pub env_set: BTreeMap<String, String>,
    pub mounts: Vec<MountSpec>,
    pub seccomp_policy: Option<SeccompPolicyConfig>,
    pub allowed_domains: Vec<String>,
    pub network: NetworkPolicy,
    pub identity_mode: SandboxIdentityMode,
    pub capability: CapabilityLeaseConfig,
    pub sidecar_local_exec: Option<CommandMediatorConfig>,
    pub executable_policies: BTreeMap<String, ExecutableLaunchPolicy>,
    /// When `true`, the autostarted sidecar is configured in HTTP proxy
    /// interceptor mode (TCP listener). When `false`, UDS interceptor mode.
    /// Set for profiles whose agent tool uses standard HTTP proxy env vars.
    pub use_http_proxy_sidecar: bool,
    /// When `true`, allow non-structural (proxy-only) backends to run without
    /// failing closed. Comes from config `[defaults] allow_non_structural = true`
    /// and is OR'd with the CLI `--allow-non-structural` flag and env var
    /// `FIRMA_RUN_ALLOW_NON_STRUCTURAL`.
    pub allow_non_structural: bool,
}

impl ResolvedProfile {
    /// Validate resolved values before execution starts.
    ///
    /// # Errors
    ///
    /// Returns an error when resolved profile values violate runtime
    /// invariants (invalid ids, lease settings, or mount paths).
    pub fn validate(&self) -> Result<(), RunError> {
        if self.id.trim().is_empty() {
            return Err(RunError::ConfigValidation(
                "profile id must not be empty".to_string(),
            ));
        }

        if self.capability.refresh_ratio <= 0.0 || self.capability.refresh_ratio >= 1.0 {
            return Err(RunError::ConfigValidation(
                "capability.refresh_ratio must be within (0.0, 1.0)".to_string(),
            ));
        }

        if self.capability.grace_seconds == 0 {
            return Err(RunError::ConfigValidation(
                "capability.grace_seconds must be > 0".to_string(),
            ));
        }

        for mount in &self.mounts {
            if !mount.source.is_absolute() {
                return Err(RunError::ConfigValidation(format!(
                    "mount source must be absolute: {}",
                    mount.source.display()
                )));
            }
            if !mount.target.is_absolute() {
                return Err(RunError::ConfigValidation(format!(
                    "mount target must be absolute: {}",
                    mount.target.display()
                )));
            }
        }

        if let Some(managed) = &self.seccomp_policy {
            if !managed.source_policy_path.is_absolute() {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_policy.source_policy_path must be absolute: {}",
                    managed.source_policy_path.display()
                )));
            }
            if !managed.source_policy_path.is_file() {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_policy.source_policy_path must point to an existing file: {}",
                    managed.source_policy_path.display()
                )));
            }
            if !managed.artifact_dir.is_absolute() {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_policy.artifact_dir must be absolute: {}",
                    managed.artifact_dir.display()
                )));
            }
            if !managed.verify_checksum {
                return Err(RunError::ConfigValidation(
                    "seccomp_policy.verify_checksum=false is unsupported; checksum verification is mandatory"
                        .to_string(),
                ));
            }
            if self.backend != BackendKind::Bwrap {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_policy is only supported with backend 'bwrap', got '{backend}'",
                    backend = self.backend
                )));
            }
        }

        if let Some(mediator) = &self.sidecar_local_exec {
            if mediator.timeout_ms == 0 {
                return Err(RunError::ConfigValidation(
                    "sidecar_local_exec.timeout_ms must be > 0".to_string(),
                ));
            }
            #[cfg(target_family = "unix")]
            if !matches!(self.sidecar_endpoint, SidecarEndpoint::Unix { .. }) {
                return Err(RunError::ConfigValidation(
                    "sidecar_local_exec requires sidecar_endpoint to use unix:// on unix hosts"
                        .to_string(),
                ));
            }
            #[cfg(target_family = "unix")]
            if matches!(mediator.endpoint, CommandMediatorEndpoint::Tcp { .. }) {
                return Err(RunError::ConfigValidation(
                    "sidecar_local_exec.endpoint must use unix:// on unix hosts".to_string(),
                ));
            }
            if let CommandMediatorEndpoint::Unix { path } = &mediator.endpoint
                && !path.is_absolute()
            {
                return Err(RunError::ConfigValidation(format!(
                    "sidecar_local_exec.endpoint unix path must be absolute: {}",
                    path.display()
                )));
            }
            if mediator.enforce_known_executables && mediator.allowed_executables.is_empty() {
                return Err(RunError::ConfigValidation(
                    "sidecar_local_exec.enforce_known_executables=true requires non-empty sidecar_local_exec.allowed_executables"
                        .to_string(),
                ));
            }
        } else if env_truthy(REQUIRE_LOCAL_EXEC_GOVERNANCE_ENV) {
            return Err(RunError::ConfigValidation(format!(
                "{REQUIRE_LOCAL_EXEC_GOVERNANCE_ENV}=true requires [profiles.<id>.sidecar_local_exec] configuration"
            )));
        }

        Ok(())
    }
}

/// Sidecar endpoint form used by the wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SidecarEndpoint {
    Tcp { addr: SocketAddr },
    Unix { path: PathBuf },
}

impl SidecarEndpoint {
    /// Returns the HTTP proxy URL when represented as TCP endpoint.
    #[must_use]
    pub fn proxy_url(&self) -> Option<String> {
        match self {
            Self::Tcp { addr } => Some(format!("http://{addr}")),
            Self::Unix { .. } => None,
        }
    }
}

impl FromStr for SidecarEndpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = value.strip_prefix("tcp://") {
            let addr = rest
                .parse::<SocketAddr>()
                .map_err(|err| format!("invalid tcp sidecar endpoint '{value}': {err}"))?;
            return Ok(Self::Tcp { addr });
        }

        if let Some(rest) = value.strip_prefix("unix://") {
            let path = PathBuf::from(rest);
            if path.as_os_str().is_empty() {
                return Err("unix sidecar endpoint path must not be empty".to_string());
            }
            return Ok(Self::Unix { path });
        }

        Err(format!(
            "unsupported sidecar endpoint '{value}'; expected tcp://host:port or unix:///path"
        ))
    }
}

/// Mount entry passed to sandbox backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MountSpec {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
}

/// Network policy toggles used by backend implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkPolicy {
    pub enforce_network_namespace: bool,
    pub fail_closed: bool,
}

/// Identity mode used inside sandboxed execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxIdentityMode {
    SandboxUser,
    HostUser,
}

/// Capability lease refresh settings.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapabilityLeaseConfig {
    pub source: CapabilitySource,
    pub refresh_ratio: f64,
    pub grace_seconds: u64,
}

/// Per-executable CLI argument policy injected by `firma run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutableLaunchPolicy {
    pub enforce_wrapper_defaults: bool,
    pub sandbox_mode: Option<String>,
    pub approval_policy: Option<String>,
    pub config_overrides: BTreeMap<String, String>,
}

/// Runtime command mediation settings for governed local execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandMediatorConfig {
    pub endpoint: CommandMediatorEndpoint,
    pub timeout_ms: u64,
    pub hitl_mode: CommandMediatorHitlMode,
    /// Maximum total wall-clock time `firma-run` will block waiting for a
    /// human to approve a `pending_hitl` token. Applies only when
    /// `hitl_mode = "async_token"`. Fail-closed once exceeded.
    /// Default: 300 000 ms (5 minutes).
    pub hitl_max_wait_ms: u64,
    pub enforce_known_executables: bool,
    pub allowed_executables: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommandMediatorEndpoint {
    Tcp { addr: SocketAddr },
    Unix { path: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandMediatorHitlMode {
    SyncWait,
    AsyncToken,
}

/// Seccomp policy compilation settings for Linux bwrap backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeccompPolicyConfig {
    pub source_policy_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub verify_checksum: bool,
    pub runtime_mode: SeccompRuntimeMode,
}

/// Runtime behavior for managed seccomp artifact selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompRuntimeMode {
    /// Compile/update managed seccomp artifacts during launch and then load.
    CompileOnLaunch,
    /// Require a precompiled managed seccomp artifact; do not compile at launch.
    PrecompiledOnly,
}

/// Fallback sidecar endpoint used only to keep `ResolvedProfile.sidecar_endpoint`
/// populated on local autostart, where the supervisor substitutes its own UDS.
const DEFAULT_SIDECAR_ENDPOINT: &str = "tcp://127.0.0.1:8080";
const DEFAULT_MANAGED_POLICY_FILE: &str = "generic-local-command-v1.toml";
const MANAGED_POLICY_ENV: &str = "FIRMA_RUN_MANAGED_SECCOMP_POLICY_PATH";
const MANAGED_ARTIFACT_DIR_ENV: &str = "FIRMA_RUN_MANAGED_SECCOMP_ARTIFACT_DIR";
const MANAGED_RUNTIME_MODE_ENV: &str = "FIRMA_RUN_MANAGED_SECCOMP_RUNTIME_MODE";
const MANAGED_DEFAULT_DISABLE_ENV: &str = "FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT";
const REQUIRE_LOCAL_EXEC_GOVERNANCE_ENV: &str = "FIRMA_RUN_REQUIRE_LOCAL_EXEC_GOVERNANCE";

/// Source for capability material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapabilitySource {
    Disabled,
    File { path: PathBuf },
}

/// Top-level file config.
#[derive(Debug, Clone, Deserialize, Default)]
struct FileConfig {
    #[allow(dead_code)]
    schema_version: Option<u32>,
    #[serde(default)]
    defaults: ProfilePatch,
    #[serde(default)]
    profiles: BTreeMap<String, ProfilePatch>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ProfilePatch {
    pub(crate) backend: Option<BackendKind>,
    pub(crate) sidecar_endpoint: Option<String>,
    pub(crate) seccomp_policy: Option<SeccompPolicyPatch>,
    #[serde(default)]
    pub(crate) env_passthrough: Vec<String>,
    #[serde(default)]
    pub(crate) env_set: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) mounts: Vec<MountPatch>,
    #[serde(default)]
    pub(crate) allowed_domains: Vec<String>,
    pub(crate) network: Option<NetworkPolicyPatch>,
    pub(crate) identity_mode: Option<SandboxIdentityMode>,
    pub(crate) capability: Option<CapabilityLeasePatch>,
    /// Preferred governance config path. This routes local tool execution
    /// decisions through a Sidecar-owned endpoint.
    pub(crate) sidecar_local_exec: Option<CommandMediatorPatch>,
    #[serde(default)]
    pub(crate) executable_policies: BTreeMap<String, ExecutableLaunchPolicyPatch>,
    #[serde(default)]
    pub(crate) codex_cli: Option<ExecutableLaunchPolicyPatch>,
    /// Configure the autostarted sidecar in HTTP proxy interceptor mode.
    /// Should be `true` for profiles whose agent uses standard HTTP proxy env vars.
    #[serde(default)]
    pub(crate) use_http_proxy_sidecar: bool,
    /// Allow non-structural (proxy-only) backends to run without failing closed.
    /// Intentional opt-in: proxy-only enforcement can be bypassed by clients
    /// that ignore `HTTP_PROXY`, open raw sockets, or spawn children with
    /// a clean environment.
    #[serde(default)]
    pub(crate) allow_non_structural: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct MountPatch {
    pub(crate) source: PathBuf,
    pub(crate) target: PathBuf,
    #[serde(default)]
    pub(crate) read_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct NetworkPolicyPatch {
    pub(crate) enforce_network_namespace: Option<bool>,
    pub(crate) fail_closed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SeccompPolicyPatch {
    pub(crate) source_policy_path: PathBuf,
    pub(crate) artifact_dir: PathBuf,
    pub(crate) verify_checksum: Option<bool>,
    pub(crate) runtime_mode: Option<SeccompRuntimeMode>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CapabilityLeasePatch {
    pub(crate) source: Option<CapabilitySourcePatch>,
    #[serde(default)]
    pub(crate) kind: Option<String>,
    #[serde(default)]
    pub(crate) path: Option<PathBuf>,
    pub(crate) refresh_ratio: Option<f64>,
    pub(crate) grace_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ExecutableLaunchPolicyPatch {
    pub(crate) enforce_wrapper_defaults: Option<bool>,
    pub(crate) sandbox_mode: Option<String>,
    pub(crate) approval_policy: Option<String>,
    #[serde(default)]
    pub(crate) config_overrides: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CommandMediatorPatch {
    pub(crate) endpoint: Option<String>,
    pub(crate) timeout_ms: Option<u64>,
    pub(crate) hitl_mode: Option<CommandMediatorHitlMode>,
    pub(crate) hitl_max_wait_ms: Option<u64>,
    pub(crate) enforce_known_executables: Option<bool>,
    #[serde(default)]
    pub(crate) allowed_executables: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CapabilitySourcePatch {
    Disabled,
    File { path: PathBuf },
}

impl ProfilePatch {
    fn merge(self, higher: Self) -> Self {
        let mut env_set = self.env_set;
        env_set.extend(higher.env_set);

        let mut env_passthrough = self.env_passthrough;
        env_passthrough.extend(higher.env_passthrough);
        let mut executable_policies = self.executable_policies;
        executable_policies.extend(higher.executable_policies);

        let mounts = if higher.mounts.is_empty() {
            self.mounts
        } else {
            higher.mounts
        };

        let allowed_domains = if higher.allowed_domains.is_empty() {
            self.allowed_domains
        } else {
            higher.allowed_domains
        };

        Self {
            backend: higher.backend.or(self.backend),
            sidecar_endpoint: higher.sidecar_endpoint.or(self.sidecar_endpoint),
            seccomp_policy: higher.seccomp_policy.or(self.seccomp_policy),
            env_passthrough,
            env_set,
            mounts,
            allowed_domains,
            network: higher.network.or(self.network),
            identity_mode: higher.identity_mode.or(self.identity_mode),
            capability: higher.capability.or(self.capability),
            sidecar_local_exec: higher.sidecar_local_exec.or(self.sidecar_local_exec),
            executable_policies,
            codex_cli: higher.codex_cli.or(self.codex_cli),
            use_http_proxy_sidecar: higher.use_http_proxy_sidecar || self.use_http_proxy_sidecar,
            allow_non_structural: higher.allow_non_structural || self.allow_non_structural,
        }
    }
}

/// Resolve profile configuration for a run invocation.
///
/// # Errors
///
/// Returns an error when profile resolution fails due to invalid inputs,
/// parse errors, or resulting validation failures.
#[allow(
    clippy::too_many_lines,
    reason = "sequential profile resolution (patch merge + endpoint/selection + network + capability) reads more clearly inline"
)]
pub fn resolve_profile(args: &RunInput) -> Result<ResolvedProfile, RunError> {
    let mut patch = built_in_profile(&args.profile)?;

    if let Some(path) = &args.config {
        let file_patch = read_config(path, &args.profile)?;
        patch = patch.merge(file_patch);
    }

    let cli_patch = cli_profile_patch(args);
    patch = patch.merge(cli_patch);

    let backend = resolve_backend(patch.backend);

    // The explicitly-configured endpoint (config file or env), without the
    // hard-coded fallback. `None` means "nothing was set" — which lets the
    // selector default an unset `--sidecar` to local autostart.
    let configured_endpoint = patch.sidecar_endpoint.clone().or_else(|| {
        std::env::var("FIRMA_SIDECAR_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
    });
    let sidecar_selection = crate::sidecar::resolve(
        &args.sidecar_cli,
        args.no_autostart,
        configured_endpoint.as_deref(),
    )?;
    // `sidecar_endpoint` stays populated for the external-probe path and for
    // local-exec endpoint derivation. On local autostart the supervisor
    // substitutes its own UDS for the *traffic* endpoint, so this value is
    // not used as the autostart target.
    let sidecar_endpoint = match &sidecar_selection {
        crate::sidecar::SidecarSelection::Remote(endpoint) => endpoint.clone(),
        crate::sidecar::SidecarSelection::Local => configured_endpoint
            .as_deref()
            .unwrap_or(DEFAULT_SIDECAR_ENDPOINT)
            .parse::<SidecarEndpoint>()
            .map_err(RunError::ConfigValidation)?,
    };
    let sidecar_local_exec = resolve_sidecar_local_exec_config(&patch, &sidecar_endpoint)?;

    let env_passthrough = patch
        .env_passthrough
        .into_iter()
        .filter(|item: &String| !item.trim().is_empty())
        .collect::<BTreeSet<_>>();

    let mounts = patch
        .mounts
        .into_iter()
        .map(|mount| MountSpec {
            source: mount.source,
            target: mount.target,
            read_only: mount.read_only,
        })
        .collect::<Vec<_>>();

    let network = NetworkPolicy {
        enforce_network_namespace: patch
            .network
            .as_ref()
            .and_then(|cfg| cfg.enforce_network_namespace)
            .unwrap_or_else(|| backend_supports_structural_network(backend)),
        fail_closed: patch
            .network
            .as_ref()
            .and_then(|cfg| cfg.fail_closed)
            .unwrap_or(true),
    };

    if network.enforce_network_namespace && !backend_supports_structural_network(backend) {
        return Err(RunError::ConfigValidation(format!(
            "network.enforce_network_namespace=true is unsupported for backend '{backend}'; use backend 'bwrap' or set enforce_network_namespace=false"
        )));
    }
    let capability = patch
        .capability
        .map_or_else(default_capability_config, capability_from_patch);

    let identity_mode = patch
        .identity_mode
        .unwrap_or(SandboxIdentityMode::SandboxUser);

    let executable_policies =
        resolve_executable_policies(patch.executable_policies, patch.codex_cli);

    let seccomp_policy = patch
        .seccomp_policy
        .map(seccomp_policy_from_patch)
        .or(default_managed_seccomp_policy(&args.profile, backend)?);
    let resolved = ResolvedProfile {
        id: args.profile.clone(),
        backend,
        sidecar_endpoint,
        sidecar_selection,
        env_passthrough,
        env_set: patch.env_set,
        mounts,
        seccomp_policy,
        allowed_domains: patch.allowed_domains,
        network,
        identity_mode,
        capability,
        sidecar_local_exec,
        executable_policies,
        use_http_proxy_sidecar: patch.use_http_proxy_sidecar,
        allow_non_structural: patch.allow_non_structural,
    };

    if matches!(
        BuiltInProfileId::from_str(&resolved.id),
        Some(BuiltInProfileId::ClaudeCode)
    ) && resolved.backend != BackendKind::Bwrap
    {
        tracing::warn!(
            profile = %resolved.id,
            backend = %resolved.backend,
            "claude-code profile is running in compatibility mode; full Linux structural confinement guarantees require backend=bwrap"
        );
    }

    resolved.validate()?;
    Ok(resolved)
}

fn resolve_backend(configured_backend: Option<BackendKind>) -> BackendKind {
    let backend = configured_backend.unwrap_or_else(default_backend_for_host);

    if backend_supported_on_host(backend) {
        return backend;
    }

    let fallback = BackendKind::default_for_current_host();
    tracing::warn!(
        configured = %backend,
        fallback = %fallback,
        "configured sandbox backend is unsupported on this host; using platform default"
    );
    fallback
}

fn default_backend_for_host() -> BackendKind {
    #[cfg(target_os = "linux")]
    {
        resolve_backend_for_linux(None, detect_wsl())
    }
    #[cfg(not(target_os = "linux"))]
    {
        BackendKind::default_for_current_host()
    }
}

fn backend_supported_on_host(kind: BackendKind) -> bool {
    match kind {
        BackendKind::Bwrap | BackendKind::Firecracker => cfg!(target_os = "linux"),
        BackendKind::Vz => cfg!(target_os = "macos"),
        BackendKind::Wsl2 => cfg!(target_os = "windows"),
    }
}

#[cfg(target_os = "linux")]
fn resolve_backend_for_linux(configured_backend: Option<BackendKind>, wsl: WslKind) -> BackendKind {
    if let Some(backend) = configured_backend {
        return backend;
    }
    if wsl.is_wsl() {
        return BackendKind::Wsl2;
    }
    BackendKind::Bwrap
}

fn cli_profile_patch(args: &RunInput) -> ProfilePatch {
    ProfilePatch {
        backend: args.backend,
        sidecar_endpoint: None,
        seccomp_policy: None,
        env_passthrough: Vec::new(),
        env_set: BTreeMap::new(),
        mounts: Vec::new(),
        allowed_domains: Vec::new(),
        network: None,
        identity_mode: if args.preserve_host_user {
            Some(SandboxIdentityMode::HostUser)
        } else {
            args.identity_mode
        },
        capability: args
            .capability_file
            .as_ref()
            .map(|path| CapabilityLeasePatch {
                source: Some(CapabilitySourcePatch::File { path: path.clone() }),
                kind: None,
                path: None,
                refresh_ratio: None,
                grace_seconds: None,
            }),
        sidecar_local_exec: None,
        executable_policies: BTreeMap::new(),
        codex_cli: None,
        use_http_proxy_sidecar: false,
        allow_non_structural: args.allow_non_structural,
    }
}

fn resolve_executable_policies(
    patch: BTreeMap<String, ExecutableLaunchPolicyPatch>,
    legacy_codex: Option<ExecutableLaunchPolicyPatch>,
) -> BTreeMap<String, ExecutableLaunchPolicy> {
    let mut resolved = patch
        .into_iter()
        .map(|(executable, policy)| (executable, resolve_executable_policy(policy)))
        .collect::<BTreeMap<_, _>>();

    if let Some(codex_policy) = legacy_codex {
        resolved
            .entry("codex".to_string())
            .or_insert_with(|| resolve_executable_policy(codex_policy));
    }

    resolved
}

fn resolve_executable_policy(policy: ExecutableLaunchPolicyPatch) -> ExecutableLaunchPolicy {
    ExecutableLaunchPolicy {
        enforce_wrapper_defaults: policy.enforce_wrapper_defaults.unwrap_or(true),
        sandbox_mode: policy.sandbox_mode,
        approval_policy: policy.approval_policy,
        config_overrides: policy.config_overrides,
    }
}

fn capability_from_patch(patch: CapabilityLeasePatch) -> CapabilityLeaseConfig {
    let source = if let Some(source) = patch.source {
        match source {
            CapabilitySourcePatch::Disabled => CapabilitySource::Disabled,
            CapabilitySourcePatch::File { path } => CapabilitySource::File { path },
        }
    } else {
        parse_legacy_capability_source(patch.kind.as_deref(), patch.path)
    };

    CapabilityLeaseConfig {
        source,
        refresh_ratio: patch.refresh_ratio.unwrap_or(0.60),
        grace_seconds: patch.grace_seconds.unwrap_or(30),
    }
}

fn parse_legacy_capability_source(kind: Option<&str>, path: Option<PathBuf>) -> CapabilitySource {
    match kind {
        Some("file") => path.map_or(CapabilitySource::Disabled, |path| CapabilitySource::File {
            path,
        }),
        Some("disabled" | _) | None => CapabilitySource::Disabled,
    }
}

fn default_capability_config() -> CapabilityLeaseConfig {
    CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        refresh_ratio: 0.60,
        grace_seconds: 30,
    }
}

fn seccomp_policy_from_patch(patch: SeccompPolicyPatch) -> SeccompPolicyConfig {
    SeccompPolicyConfig {
        source_policy_path: patch.source_policy_path,
        artifact_dir: patch.artifact_dir,
        verify_checksum: patch.verify_checksum.unwrap_or(true),
        runtime_mode: patch
            .runtime_mode
            .unwrap_or(SeccompRuntimeMode::CompileOnLaunch),
    }
}

fn sidecar_local_exec_from_patch(
    patch: &CommandMediatorPatch,
    sidecar_endpoint: &SidecarEndpoint,
) -> Result<CommandMediatorConfig, RunError> {
    let endpoint = if let Some(endpoint) = &patch.endpoint {
        parse_sidecar_local_exec_endpoint(endpoint)?
    } else {
        derive_sidecar_local_exec_endpoint(sidecar_endpoint)?
    };
    let allowed_executables = patch
        .allowed_executables
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    Ok(CommandMediatorConfig {
        endpoint,
        timeout_ms: patch.timeout_ms.unwrap_or(500),
        hitl_mode: patch.hitl_mode.unwrap_or(CommandMediatorHitlMode::SyncWait),
        hitl_max_wait_ms: patch.hitl_max_wait_ms.unwrap_or(300_000),
        enforce_known_executables: patch.enforce_known_executables.unwrap_or(false),
        allowed_executables,
    })
}

fn resolve_sidecar_local_exec_config(
    patch: &ProfilePatch,
    sidecar_endpoint: &SidecarEndpoint,
) -> Result<Option<CommandMediatorConfig>, RunError> {
    patch
        .sidecar_local_exec
        .as_ref()
        .map(|cfg| sidecar_local_exec_from_patch(cfg, sidecar_endpoint))
        .transpose()
}

fn parse_sidecar_local_exec_endpoint(value: &str) -> Result<CommandMediatorEndpoint, RunError> {
    if let Some(rest) = value.strip_prefix("tcp://") {
        let addr = rest.parse::<SocketAddr>().map_err(|err| {
            RunError::ConfigValidation(format!(
                "invalid sidecar_local_exec.endpoint '{value}': {err}"
            ))
        })?;
        return Ok(CommandMediatorEndpoint::Tcp { addr });
    }
    if let Some(rest) = value.strip_prefix("unix://") {
        let path = PathBuf::from(rest);
        if path.as_os_str().is_empty() {
            return Err(RunError::ConfigValidation(
                "sidecar_local_exec.endpoint unix path must not be empty".to_string(),
            ));
        }
        return Ok(CommandMediatorEndpoint::Unix { path });
    }
    Err(RunError::ConfigValidation(format!(
        "unsupported sidecar_local_exec.endpoint '{value}'; expected tcp://host:port or unix:///path"
    )))
}

fn derive_sidecar_local_exec_endpoint(
    sidecar_endpoint: &SidecarEndpoint,
) -> Result<CommandMediatorEndpoint, RunError> {
    match sidecar_endpoint {
        SidecarEndpoint::Unix { path } => {
            let parent = path.parent().ok_or_else(|| {
                RunError::ConfigValidation(format!(
                    "cannot derive sidecar local-exec endpoint from unix path {}",
                    path.display()
                ))
            })?;
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    RunError::ConfigValidation(format!(
                        "cannot derive sidecar local-exec endpoint from unix path {}",
                        path.display()
                    ))
                })?;
            let derived_file_name = file_name.strip_suffix(".sock").map_or_else(
                || format!("{file_name}-tools.sock"),
                |base| format!("{base}-tools.sock"),
            );
            let derived_path = parent.join(derived_file_name);
            Ok(CommandMediatorEndpoint::Unix { path: derived_path })
        }
        SidecarEndpoint::Tcp { addr } => Err(RunError::ConfigValidation(format!(
            "sidecar_local_exec endpoint is required when sidecar endpoint is tcp://{addr}; automatic derivation only supports unix sidecar endpoints"
        ))),
    }
}

fn default_managed_seccomp_policy(
    profile_id: &str,
    backend: BackendKind,
) -> Result<Option<SeccompPolicyConfig>, RunError> {
    if !cfg!(target_os = "linux") || backend != BackendKind::Bwrap || profile_id != "generic" {
        return Ok(None);
    }

    if env_truthy(MANAGED_DEFAULT_DISABLE_ENV) {
        tracing::warn!(
            profile = profile_id,
            env = MANAGED_DEFAULT_DISABLE_ENV,
            "managed static seccomp default disabled by environment override"
        );
        return Ok(None);
    }

    let source_policy_path = std::env::var(MANAGED_POLICY_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or_else(ensure_managed_policy_path, PathBuf::from);

    let artifact_dir = std::env::var(MANAGED_ARTIFACT_DIR_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or_else(default_managed_artifact_dir, PathBuf::from);

    let runtime_mode = std::env::var(MANAGED_RUNTIME_MODE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_managed_runtime_mode(&value))
        .transpose()?
        .unwrap_or(SeccompRuntimeMode::CompileOnLaunch);

    Ok(Some(SeccompPolicyConfig {
        source_policy_path,
        artifact_dir,
        verify_checksum: true,
        runtime_mode,
    }))
}

fn parse_managed_runtime_mode(value: &str) -> Result<SeccompRuntimeMode, RunError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "compile_on_launch" => Ok(SeccompRuntimeMode::CompileOnLaunch),
        "precompiled_only" => Ok(SeccompRuntimeMode::PrecompiledOnly),
        other => Err(RunError::ConfigValidation(format!(
            "{MANAGED_RUNTIME_MODE_ENV} must be 'compile_on_launch' or 'precompiled_only', got '{other}'"
        ))),
    }
}

/// Embedded default seccomp policy. Always written to `XDG_RUNTIME_DIR/firma/seccomp/` on
/// startup so the on-disk copy stays in sync with the running binary. Used only when no
/// override is set via env var or profile config.
const MANAGED_SECCOMP_POLICY: &str = include_str!("../seccomp/generic-local-command-v1.toml");

/// Writes the embedded seccomp policy to the runtime dir and returns its path.
/// Always overwrites — this is a binary-embedded fallback, not a user-editable file.
/// To override, set `FIRMA_RUN_MANAGED_SECCOMP_POLICY_PATH` or `seccomp_policy.source_policy_path` in the profile config.
/// Creates the directory with restricted permissions (0o700/0o600).
fn ensure_managed_policy_path() -> PathBuf {
    let dir = firma_stack::runtime_paths::default_runtime_dir().join("seccomp");
    write_managed_policy_to_dir(&dir)
}

fn write_managed_policy_to_dir(dir: &std::path::Path) -> PathBuf {
    let path = dir.join(DEFAULT_MANAGED_POLICY_FILE);
    if let Err(error) = firma_stack::fs::create_private_dir_all(dir) {
        tracing::warn!(%error, "failed to create seccomp policy dir; falling back to unextracted path");
        return path;
    }
    match firma_stack::fs::write_private_file(&path, MANAGED_SECCOMP_POLICY.as_bytes()) {
        Ok(()) => {
            tracing::debug!(path = %path.display(), "wrote default managed seccomp policy");
        }
        Err(error) => tracing::warn!(%error, "failed to write default seccomp policy"),
    }
    path
}

fn default_managed_artifact_dir() -> PathBuf {
    let dir = firma_stack::runtime_paths::default_runtime_dir().join("seccomp-artifacts");
    tracing::debug!(path = %dir.display(), "seccomp artifact dir");
    dir
}

pub(crate) fn env_truthy(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn read_config(path: &Path, profile: &str) -> Result<ProfilePatch, RunError> {
    let section = firma_config::load_section(path, "run").map_err(|reason| {
        // load_section prefixes the path; strip it to avoid doubling in the
        // RunError::ConfigParse display ("{path}: {reason}").
        let prefix = format!("{}: ", path.display());
        let reason = reason.strip_prefix(&prefix).unwrap_or(&reason).to_string();
        let hint = if reason.contains("[run]") {
            "; run `firma config` to add a [run] section"
        } else {
            ""
        };
        RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: format!("{reason}{hint}"),
        }
    })?;

    let parsed = toml::from_str::<FileConfig>(&section).map_err(|error| RunError::ConfigParse {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;

    let profile_patch = parsed.profiles.get(profile).cloned().unwrap_or_default();
    Ok(parsed.defaults.merge(profile_patch))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use pretty_assertions::assert_eq;

    use crate::runtime::RunInput;

    use super::{
        BackendKind, CapabilitySource, SandboxIdentityMode, SeccompRuntimeMode, SidecarEndpoint,
        resolve_profile,
    };
    #[cfg(target_os = "linux")]
    use crate::backend::platform::WslKind;

    fn args(profile: &str) -> RunInput {
        RunInput {
            profile: profile.to_string(),
            config: None,
            backend: None,
            sidecar_cli: crate::sidecar::SidecarCli::Unset,
            capability_file: None,
            identity_mode: None,
            preserve_host_user: false,
            print_effective_config: false,
            no_autostart: false,
            sidecar_template_path: None,
            sidecar_startup_timeout_secs: 10,
            command: vec!["echo".to_string(), "ok".to_string()],
            authority_cli: crate::authority::AuthorityCli::Unset,
            authority_profile: firma_authority::DEFAULT_PROFILE.to_string(),
            user_config_path: None,
            allow_non_structural: true,
        }
    }

    fn non_bwrap_backend_for_current_host() -> BackendKind {
        #[cfg(target_os = "linux")]
        {
            return BackendKind::Firecracker;
        }

        #[cfg(target_os = "macos")]
        {
            return BackendKind::Vz;
        }

        #[cfg(target_os = "windows")]
        {
            return BackendKind::Wsl2;
        }

        #[allow(unreachable_code)]
        BackendKind::Firecracker
    }

    #[test]
    fn resolves_generic_defaults() {
        let resolved = resolve_profile(&args("generic")).unwrap();
        assert_eq!(resolved.id, "generic");
        assert_eq!(resolved.backend, BackendKind::default_for_current_host());
        assert_eq!(
            resolved.sidecar_endpoint,
            SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap()
            }
        );
        assert_eq!(resolved.identity_mode, SandboxIdentityMode::SandboxUser);
        if cfg!(target_os = "linux")
            && resolved.backend == BackendKind::Bwrap
            && !super::env_truthy(super::MANAGED_DEFAULT_DISABLE_ENV)
        {
            let managed = resolved.seccomp_policy.as_ref().unwrap();
            assert!(managed.verify_checksum);
            assert_eq!(managed.runtime_mode, SeccompRuntimeMode::CompileOnLaunch);
            assert!(
                managed
                    .source_policy_path
                    .ends_with("seccomp/generic-local-command-v1.toml"),
                "unexpected managed default policy path: {}",
                managed.source_policy_path.display()
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn implicit_backend_selection_uses_wsl2_on_wsl() {
        let backend = super::resolve_backend_for_linux(None, WslKind::Wsl2);
        assert_eq!(backend, BackendKind::Wsl2);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn explicit_backend_is_kept_on_wsl() {
        let backend = super::resolve_backend_for_linux(Some(BackendKind::Bwrap), WslKind::Wsl);
        assert_eq!(backend, BackendKind::Bwrap);
    }

    #[test]
    fn toml_config_overrides_profile() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join("firma.toml");

        let toml = r#"
[run.defaults]
sidecar_endpoint = "tcp://127.0.0.1:18080"

[run.profiles.codex]
backend = "bwrap"
identity_mode = "host_user"
env_passthrough = ["HOME"]

[run.profiles.codex.capability]
kind = "file"
path = "/tmp/capability.token"
"#
        .to_string();
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);

        let resolved = resolve_profile(&run_args).unwrap();
        let expected_backend = if cfg!(target_os = "linux") {
            BackendKind::Bwrap
        } else {
            BackendKind::default_for_current_host()
        };
        assert_eq!(resolved.backend, expected_backend);
        assert_eq!(resolved.identity_mode, SandboxIdentityMode::HostUser);
        assert!(resolved.env_passthrough.contains("HOME"));
        assert_eq!(
            resolved.capability.source,
            CapabilitySource::File {
                path: PathBuf::from("/tmp/capability.token")
            }
        );
    }

    #[test]
    fn legacy_codex_cli_config_maps_to_executable_policy() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join("firma.toml");
        let toml = r#"
[run.profiles.codex.codex_cli]
enforce_wrapper_defaults = true
sandbox_mode = "workspace-write"
approval_policy = "never"
"#;
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();

        let policy = resolved.executable_policies.get("codex").unwrap();
        assert!(policy.enforce_wrapper_defaults);
        assert_eq!(policy.sandbox_mode.as_deref(), Some("workspace-write"));
        assert_eq!(policy.approval_policy.as_deref(), Some("never"));
    }

    #[test]
    fn preserve_host_user_cli_overrides_profile_identity_mode() {
        let mut run_args = args("generic");
        run_args.identity_mode = Some(SandboxIdentityMode::SandboxUser);
        run_args.preserve_host_user = true;

        let resolved = resolve_profile(&run_args).unwrap();
        assert_eq!(resolved.identity_mode, SandboxIdentityMode::HostUser);
    }

    #[test]
    fn resolves_claude_code_profile() {
        let resolved = resolve_profile(&args("claude-code")).unwrap();
        assert_eq!(resolved.id, "claude-code");
        assert!(resolved.env_passthrough.contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn configured_bwrap_backend_falls_back_on_non_linux() {
        if cfg!(target_os = "linux") {
            return;
        }
        let mut run_args = args("generic");
        run_args.backend = Some(BackendKind::Bwrap);
        let resolved = resolve_profile(&run_args).unwrap();
        assert_eq!(resolved.backend, BackendKind::default_for_current_host());
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn structural_network_defaults_to_true_for_bwrap_backend() {
        let mut run_args = args("generic");
        run_args.backend = Some(BackendKind::Bwrap);

        let resolved = resolve_profile(&run_args).unwrap();
        assert!(resolved.network.enforce_network_namespace);
        assert!(resolved.network.fail_closed);
    }

    #[test]
    fn structural_network_defaults_to_false_for_non_bwrap_backends() {
        let mut run_args = args("generic");
        run_args.backend = Some(non_bwrap_backend_for_current_host());

        let resolved = resolve_profile(&run_args).unwrap();
        assert!(!resolved.network.enforce_network_namespace);
        assert!(resolved.network.fail_closed);
    }

    #[test]
    fn structural_network_true_on_non_bwrap_backend_is_rejected() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join("firma.toml");
        let backend = non_bwrap_backend_for_current_host();
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "{backend}"

[run.profiles.generic.network]
enforce_network_namespace = true
fail_closed = true
"#
        );
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);

        let error = resolve_profile(&run_args).expect_err("expected validation error");
        assert!(
            error
                .to_string()
                .contains("enforce_network_namespace=true is unsupported"),
            "unexpected error: {error}"
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn seccomp_policy_resolves_when_configured_for_bwrap() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");

        let config_path = tmpdir.path().join("firma.toml");
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/sidecar.sock"

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
verify_checksum = true
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();
        assert!(resolved.seccomp_policy.is_some());
    }

    #[test]
    fn seccomp_policy_rejected_for_non_bwrap_backend() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");

        let config_path = tmpdir.path().join("firma.toml");
        let backend = non_bwrap_backend_for_current_host();
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "{backend}"

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let err = resolve_profile(&run_args).expect_err("expected backend validation error");
        assert!(
            err.to_string()
                .contains("seccomp_policy is only supported with backend 'bwrap'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn seccomp_policy_runtime_mode_parses_precompiled_only() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");

        let config_path = tmpdir.path().join("firma.toml");
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/sidecar.sock"

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
runtime_mode = "precompiled_only"
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();
        let seccomp = resolved.seccomp_policy.unwrap();
        assert_eq!(seccomp.runtime_mode, SeccompRuntimeMode::PrecompiledOnly);
    }

    #[test]
    fn seccomp_policy_rejects_checksum_disable() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");

        let config_path = tmpdir.path().join("firma.toml");
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/sidecar.sock"

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
verify_checksum = false
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let err = resolve_profile(&run_args).expect_err("expected checksum validation error");
        assert!(
            err.to_string()
                .contains("seccomp_policy.verify_checksum=false is unsupported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn sidecar_local_exec_parses_unix_endpoint() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");
        let socket_path = tmpdir.path().join("mediator.sock");
        let config_path = tmpdir.path().join("firma.toml");
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/sidecar.sock"

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
runtime_mode = "precompiled_only"

[run.profiles.generic.sidecar_local_exec]
endpoint = 'unix://{}'
timeout_ms = 700
"#,
            policy_path.display(),
            artifact_dir.display(),
            socket_path.display()
        );
        fs::write(&config_path, toml).unwrap();
        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();
        let mediator = resolved.sidecar_local_exec.unwrap();
        assert_eq!(mediator.timeout_ms, 700);
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn sidecar_local_exec_rejects_relative_unix_path() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");
        let config_path = tmpdir.path().join("firma.toml");
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/sidecar.sock"

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
runtime_mode = "precompiled_only"

[run.profiles.generic.sidecar_local_exec]
endpoint = "unix://relative.sock"
timeout_ms = 500
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap();
        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let err = resolve_profile(&run_args).expect_err("expected validation failure");
        assert!(
            err.to_string()
                .contains("sidecar_local_exec.endpoint unix path must be absolute"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn sidecar_local_exec_rejects_empty_allowlist_when_enforced() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");
        let config_path = tmpdir.path().join("firma.toml");
        let endpoint = if cfg!(target_family = "unix") {
            "unix:///tmp/sidecar-local-exec.sock"
        } else {
            "tcp://127.0.0.1:19090"
        };
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/sidecar.sock"

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
runtime_mode = "precompiled_only"

[run.profiles.generic.sidecar_local_exec]
endpoint = "{endpoint}"
timeout_ms = 500
enforce_known_executables = true
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap();
        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let err = resolve_profile(&run_args).expect_err("expected validation failure");
        assert!(
            err.to_string()
                .contains("sidecar_local_exec.enforce_known_executables=true requires non-empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn sidecar_local_exec_parses_async_hitl_mode_and_allowlist() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");
        let config_path = tmpdir.path().join("firma.toml");
        let endpoint = if cfg!(target_family = "unix") {
            "unix:///tmp/sidecar-local-exec.sock"
        } else {
            "tcp://127.0.0.1:19090"
        };
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/sidecar.sock"

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
runtime_mode = "precompiled_only"

[run.profiles.generic.sidecar_local_exec]
endpoint = "{endpoint}"
timeout_ms = 800
hitl_mode = "async_token"
enforce_known_executables = true
allowed_executables = ["codex", "claude", "bash"]
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap();
        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();
        let mediator = resolved.sidecar_local_exec.unwrap();
        assert!(mediator.enforce_known_executables);
        assert!(mediator.allowed_executables.contains("codex"));
        assert_eq!(
            mediator.hitl_mode,
            super::CommandMediatorHitlMode::AsyncToken
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn sidecar_local_exec_derives_unix_tools_endpoint() {
        let tmpdir = tempfile::tempdir().unwrap();
        let policy_path = tmpdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap();
        let artifact_dir = tmpdir.path().join("artifacts");
        let config_path = tmpdir.path().join("firma.toml");
        let sidecar_sock = tmpdir.path().join("sidecar.sock");
        let toml = format!(
            r#"
[run.profiles.generic]
backend = "bwrap"
sidecar_endpoint = 'unix://{}'

[run.profiles.generic.seccomp_policy]
source_policy_path = '{}'
artifact_dir = '{}'
runtime_mode = "precompiled_only"

[run.profiles.generic.sidecar_local_exec]
timeout_ms = 700
"#,
            sidecar_sock.display(),
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap();
        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();
        let mediator = resolved.sidecar_local_exec.unwrap();
        match mediator.endpoint {
            super::CommandMediatorEndpoint::Unix { path } => {
                assert!(path.ends_with("sidecar-tools.sock"));
            }
            other @ super::CommandMediatorEndpoint::Tcp { .. } => {
                panic!("expected unix endpoint, got {other:?}")
            }
        }
    }

    #[test]
    fn managed_policy_overwrites_stale_content() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let seccomp_dir = tmpdir.path().join("seccomp");
        fs::create_dir_all(&seccomp_dir).unwrap_or_else(|e| panic!("{e}"));
        let policy_path = seccomp_dir.join(super::DEFAULT_MANAGED_POLICY_FILE);
        fs::write(&policy_path, b"stale content from old binary version")
            .unwrap_or_else(|e| panic!("{e}"));

        let result_path = super::write_managed_policy_to_dir(&seccomp_dir);

        assert_eq!(result_path, policy_path);
        let written = fs::read_to_string(&policy_path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            written,
            super::MANAGED_SECCOMP_POLICY,
            "stale policy not overwritten by embedded version"
        );
    }
}
