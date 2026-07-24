use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use firma_config_loader::AgentProfile;
use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
use crate::backend::platform::detect_wsl;
use crate::error::RunError;
use crate::profile::built_in_profile;
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
    /// Executables to interpose on with a secret-mediation shim (stdio routed
    /// through the firma-run broker). This carries no behavior — Cedar policy
    /// decides intercept vs redact and all directives; see the secrets design
    /// doc. Merged across `[run.defaults]` and the active profile.
    pub shims: BTreeSet<String>,
    /// Custom integration specs from `[[run.defaults.shim_specs]]`. Merged
    /// across `[run.defaults]` and the active profile; custom specs take
    /// precedence over built-ins when names collide.
    pub shim_specs: Vec<crate::secret::integration::IntegrationSpec>,
    /// When `true`, the autostarted sidecar is configured in HTTP proxy
    /// interceptor mode (TCP listener). When `false`, UDS interceptor mode.
    /// Set for profiles whose agent tool uses standard HTTP proxy env vars.
    pub use_http_proxy_sidecar: bool,
    /// When `true`, allow non-structural (proxy-only) backends to run without
    /// failing closed. Comes from config `[defaults] allow_non_structural = true`
    /// and is OR'd with the CLI `--allow-non-structural` flag and env var
    /// `FIRMA_RUN_ALLOW_NON_STRUCTURAL`.
    pub allow_non_structural: bool,
    /// How the sandbox CA trust store is assembled (sole firma-ca vs. appended
    /// to system roots).
    pub ca_trust_mode: CaTrustMode,
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
    /// Raw Ed25519 public key used to verify Authority-issued capabilities.
    pub public_key_path: Option<PathBuf>,
    pub refresh_ratio: f64,
    pub grace_seconds: u64,
    /// Action classes the auto-minted per-session token requests. Defaults to
    /// every action class (`DEFAULT_REQUESTED_ACTIONS`); the Authority narrows
    /// the grant to `requested ∩ Cedar-permitted`, so over-requesting is safe
    /// and the issuance policy stays the source of truth for what is grantable.
    /// Setting this narrows the request further — an opt-in extra-restriction
    /// knob for running with fewer permissions than the policy would allow.
    pub requested_actions: Vec<String>,
}

impl CapabilityLeaseConfig {
    #[must_use]
    pub fn grace(&self) -> Duration {
        Duration::from_secs(self.grace_seconds)
    }

    /// Fallback action set when a profile does not set `requested_actions`.
    #[must_use]
    pub fn default_requested_actions() -> Vec<String> {
        crate::capability::issue::DEFAULT_REQUESTED_ACTIONS
            .iter()
            .map(|class| class.as_str().to_string())
            .collect()
    }
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

/// How the sandbox CA trust store is assembled for the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaTrustMode {
    /// Inject only the firma-ca path (current behavior). System roots are not
    /// added; correct when every reachable host is MITM'd by firma.
    #[default]
    Sole,
    /// Inject a bundle of system roots + firma-ca. Needed for agents that talk
    /// to non-MITM'd hosts (e.g. Copilot → real GitHub) while still trusting
    /// firma-ca for intercepted hosts.
    AppendSystemRoots,
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
#[cfg(target_family = "unix")]
const DEFAULT_SIDECAR_ENDPOINT: &str = "unix:///tmp/sidecar.sock";
#[cfg(not(target_family = "unix"))]
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
    /// Profile used by `firma run` when `--profile` is not supplied.
    profile: Option<String>,
    #[serde(default)]
    defaults: ProfilePatch,
    #[serde(default)]
    profiles: BTreeMap<String, ProfilePatch>,
}

/// Matcher configuration for a custom shim spec (`[[run.defaults.shim_specs]]`).
///
/// Mirrors [`firma_core::SecretMatcher`] with a `type` discriminator tag so
/// TOML config reads naturally (e.g. `type = "json"`).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ShimMatcherConfig {
    Json {
        value_path: String,
        name_path: String,
        #[serde(default)]
        item_path: Option<String>,
        #[serde(default)]
        domain_path: Option<String>,
        #[serde(default)]
        domain_is_url: bool,
    },
    Regex {
        pattern: String,
        #[serde(default)]
        domain_is_url: bool,
    },
}

impl From<ShimMatcherConfig> for firma_core::SecretMatcher {
    fn from(c: ShimMatcherConfig) -> Self {
        match c {
            ShimMatcherConfig::Json {
                value_path,
                name_path,
                item_path,
                domain_path,
                domain_is_url,
            } => Self::Json {
                value_path,
                name_path,
                item_path,
                domain_path,
                domain_is_url,
            },
            ShimMatcherConfig::Regex {
                pattern,
                domain_is_url,
            } => Self::Regex {
                pattern,
                domain_is_url,
            },
        }
    }
}

/// A custom shim integration spec defined in `[[run.defaults.shim_specs]]`.
///
/// Minimal example (JSON output with `{ key, value }` pairs):
///
/// ```toml
/// [[run.defaults.shim_specs]]
/// name = "mock-vault"
/// placeholder_template = "firma-secret://demo/{name}"
/// matcher = {type = "json", value_path = "$[*].value", name_path = "$[*].key"}
/// ```
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ShimSpec {
    /// Binary basename; must match an entry in `shims`.
    pub(crate) name: String,
    /// Placeholder token template; `{name}` is substituted with the
    /// percent-encoded secret key (e.g. `"firma-secret://demo/{name}"`).
    pub(crate) placeholder_template: String,
    /// How to extract `(name, value)` pairs from the tool's stdout.
    pub(crate) matcher: ShimMatcherConfig,
    /// Credential env vars to forward from the broker's environment to the
    /// subprocess. Defaults to none.
    #[serde(default)]
    pub(crate) credential_env_vars: Vec<String>,
    /// Arg flags to strip before appending `forced_args`. Defaults to none.
    #[serde(default)]
    pub(crate) strip_arg_flags: Vec<String>,
    /// Args appended after stripping. Defaults to none.
    #[serde(default)]
    pub(crate) forced_args: Vec<String>,
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
    /// Executables to interpose on with a secret-mediation shim. Additive across
    /// `[run.defaults]` and the active profile (like `env_passthrough`).
    #[serde(default)]
    pub(crate) shims: Vec<String>,
    /// Custom integration specs for shimmed tools not covered by the built-ins.
    /// Additive across `[run.defaults]` and the active profile.
    #[serde(default)]
    pub(crate) shim_specs: Vec<ShimSpec>,
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
    /// Home-relative paths to mask with a tmpfs overlay inside the bwrap sandbox.
    /// Overrides the built-in `DEFAULT_SENSITIVE_HOME_SUFFIXES` for this profile.
    /// Example: `[".ssh", ".gnupg", ".aws"]` leaves `.config` accessible.
    pub(crate) mask_home_paths: Option<Vec<String>>,
    /// How the sandbox CA trust store is assembled. `None` resolves to the
    /// default `CaTrustMode::Sole`.
    pub(crate) ca_trust_mode: Option<CaTrustMode>,
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
    pub(crate) public_key_path: Option<PathBuf>,
    pub(crate) refresh_ratio: Option<f64>,
    pub(crate) grace_seconds: Option<u64>,
    #[serde(default)]
    pub(crate) requested_actions: Option<Vec<String>>,
}

impl CapabilityLeasePatch {
    fn merge(self, higher: Self) -> Self {
        let (source, kind, path) = if higher.source.is_some() {
            (higher.source, None, None)
        } else if higher.kind.is_some() || higher.path.is_some() {
            (None, higher.kind.or(self.kind), higher.path.or(self.path))
        } else {
            (self.source, self.kind, self.path)
        };
        Self {
            source,
            kind,
            path,
            public_key_path: higher.public_key_path.or(self.public_key_path),
            refresh_ratio: higher.refresh_ratio.or(self.refresh_ratio),
            grace_seconds: higher.grace_seconds.or(self.grace_seconds),
            requested_actions: higher.requested_actions.or(self.requested_actions),
        }
    }
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
        let mut shims = self.shims;
        shims.extend(higher.shims);
        let mut shim_specs = self.shim_specs;
        shim_specs.extend(higher.shim_specs);

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
            capability: match (self.capability, higher.capability) {
                (Some(lower), Some(higher)) => Some(lower.merge(higher)),
                (lower, higher) => higher.or(lower),
            },
            sidecar_local_exec: higher.sidecar_local_exec.or(self.sidecar_local_exec),
            executable_policies,
            shims,
            shim_specs,
            codex_cli: higher.codex_cli.or(self.codex_cli),
            use_http_proxy_sidecar: higher.use_http_proxy_sidecar || self.use_http_proxy_sidecar,
            allow_non_structural: higher.allow_non_structural || self.allow_non_structural,
            mask_home_paths: higher.mask_home_paths.or(self.mask_home_paths),
            ca_trust_mode: higher.ca_trust_mode.or(self.ca_trust_mode),
        }
    }
}

/// Resolve profile configuration for a run invocation.
///
/// # Errors
///
/// Returns an error when profile resolution fails due to invalid inputs,
/// parse errors, or resulting validation failures.
#[expect(
    clippy::too_many_lines,
    reason = "sequential profile resolution (patch merge + endpoint/selection + network + capability) reads more clearly inline"
)]
pub fn resolve_profile(args: &RunInput) -> Result<ResolvedProfile, RunError> {
    let profile_id = AgentProfile::from_name(&args.profile).map_or_else(
        || args.profile.clone(),
        |profile| profile.as_str().to_string(),
    );
    let mut patch = built_in_profile(&profile_id)?;

    if let Some(path) = &args.config {
        let file_patch = read_config(path, &profile_id)?;
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
        .filter(|item| !item.trim().is_empty())
        .collect::<BTreeSet<_>>();

    let shims = patch
        .shims
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .map(|item| item.trim().to_string())
        .collect::<BTreeSet<_>>();

    let shim_specs = patch
        .shim_specs
        .into_iter()
        .map(|s| crate::secret::integration::IntegrationSpec {
            binary_name: s.name,
            credential_env_vars: s.credential_env_vars,
            matcher: s.matcher.into(),
            placeholder_template: s.placeholder_template,
            strip_arg_flags: s.strip_arg_flags,
            forced_args: s.forced_args,
        })
        .collect::<Vec<_>>();

    let mut env_set = patch.env_set;
    if let Some(paths) = patch.mask_home_paths {
        env_set.insert(
            "FIRMA_RUN_BWRAP_MASK_HOME_PATHS".to_string(),
            paths.join(","),
        );
    }

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
        .or(default_managed_seccomp_policy(&profile_id, backend)?);
    let resolved = ResolvedProfile {
        id: profile_id,
        backend,
        sidecar_endpoint,
        sidecar_selection,
        env_passthrough,
        env_set,
        mounts,
        seccomp_policy,
        allowed_domains: patch.allowed_domains,
        network,
        identity_mode,
        capability,
        sidecar_local_exec,
        executable_policies,
        shims,
        shim_specs,
        use_http_proxy_sidecar: patch.use_http_proxy_sidecar,
        allow_non_structural: patch.allow_non_structural,
        ca_trust_mode: patch.ca_trust_mode.unwrap_or_default(),
    };

    if matches!(
        AgentProfile::from_name(&resolved.id),
        Some(AgentProfile::ClaudeCode)
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

    let fallback = default_backend_for_host();
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
        BackendKind::Wsl2 => {
            cfg!(target_os = "windows") || (cfg!(target_os = "linux") && detect_wsl().is_wsl())
        }
    }
}

#[cfg(target_os = "linux")]
fn resolve_backend_for_linux(
    configured_backend: Option<BackendKind>,
    wsl: crate::backend::platform::WslKind,
) -> BackendKind {
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
                public_key_path: None,
                refresh_ratio: None,
                grace_seconds: None,
                requested_actions: None,
            }),
        sidecar_local_exec: None,
        executable_policies: BTreeMap::new(),
        shims: Vec::new(),
        shim_specs: Vec::new(),
        codex_cli: None,
        use_http_proxy_sidecar: false,
        allow_non_structural: args.allow_non_structural,
        mask_home_paths: None,
        ca_trust_mode: None,
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
        public_key_path: patch.public_key_path,
        refresh_ratio: patch.refresh_ratio.unwrap_or(0.60),
        grace_seconds: patch.grace_seconds.unwrap_or(30),
        requested_actions: patch
            .requested_actions
            .filter(|actions| !actions.is_empty())
            .unwrap_or_else(CapabilityLeaseConfig::default_requested_actions),
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
        public_key_path: None,
        refresh_ratio: 0.60,
        grace_seconds: 30,
        requested_actions: CapabilityLeaseConfig::default_requested_actions(),
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

/// Decides whether the managed default seccomp policy applies to a given
/// profile/backend pair. Every recognized agent profile shares the same managed
/// baseline on the bwrap backend, so all agents enforce `credential.write`
/// identically (FIR-274 parity requirement). `filesystem.delete` is not part of
/// the seccomp baseline: seccomp cannot encode path scopes, so workspace-scoped
/// delete is enforced structurally by the read-only rootfs plus read-write
/// workspace mount instead. The OS gate (`target_os = "linux"`) is applied
/// separately by the caller.
fn managed_seccomp_applies(profile_id: &str, backend: BackendKind) -> bool {
    backend == BackendKind::Bwrap && AgentProfile::from_name(profile_id).is_some()
}

fn default_managed_seccomp_policy(
    profile_id: &str,
    backend: BackendKind,
) -> Result<Option<SeccompPolicyConfig>, RunError> {
    if !cfg!(target_os = "linux") || !managed_seccomp_applies(profile_id, backend) {
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
        .map_or_else(|| ensure_managed_policy_path(profile_id), PathBuf::from);

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

/// Copilot managed seccomp baseline. Same deny set as the generic baseline
/// (`credential.write` denied, `filesystem.delete` not denied — scoped
/// structurally by the read-only rootfs mount); carries a distinct `policy_id`
/// for audit clarity. Selected for the copilot profile.
const COPILOT_SECCOMP_POLICY: &str = include_str!("../seccomp/copilot-local-command-v1.toml");
const COPILOT_MANAGED_POLICY_FILE: &str = "copilot-local-command-v1.toml";

/// VS Code managed seccomp baseline. Permits atomic extension manifest writes.
const VSCODE_SECCOMP_POLICY: &str = include_str!("../seccomp/vscode-local-command-v1.toml");
const VSCODE_MANAGED_POLICY_FILE: &str = "vscode-local-command-v1.toml";

/// Returns the embedded managed seccomp policy content and on-disk filename
/// for `profile_id`. Copilot gets a baseline with its own `policy_id`; every
/// other profile gets the generic baseline. Both permit `filesystem.delete`
/// (scoped structurally by the read-only rootfs mount) and deny
/// `credential.write`.
fn managed_policy_for_profile(profile_id: &str) -> (&'static str, &'static str) {
    match AgentProfile::from_name(profile_id) {
        Some(AgentProfile::Copilot) => (COPILOT_SECCOMP_POLICY, COPILOT_MANAGED_POLICY_FILE),
        Some(AgentProfile::Vscode) => (VSCODE_SECCOMP_POLICY, VSCODE_MANAGED_POLICY_FILE),
        _ => (MANAGED_SECCOMP_POLICY, DEFAULT_MANAGED_POLICY_FILE),
    }
}

/// Writes the embedded seccomp policy to the runtime dir and returns its path.
/// Always overwrites — this is a binary-embedded fallback, not a user-editable file.
/// To override, set `FIRMA_RUN_MANAGED_SECCOMP_POLICY_PATH` or `seccomp_policy.source_policy_path` in the profile config.
/// Creates the directory with restricted permissions (0o700/0o600).
fn ensure_managed_policy_path(profile_id: &str) -> PathBuf {
    let dir = firma_runtime_state::runtime_paths::default_runtime_dir().join("seccomp");
    write_managed_policy_to_dir(&dir, profile_id)
}

fn write_managed_policy_to_dir(dir: &std::path::Path, profile_id: &str) -> PathBuf {
    let (content, filename) = managed_policy_for_profile(profile_id);
    let path = dir.join(filename);
    if let Err(error) = firma_fs::create_private_dir_all(dir) {
        tracing::warn!(%error, "failed to create seccomp policy dir; falling back to unextracted path");
        return path;
    }
    match firma_fs::write_private_file(&path, content.as_bytes()) {
        Ok(()) => {
            tracing::debug!(path = %path.display(), "wrote managed seccomp policy");
        }
        Err(error) => tracing::warn!(%error, "failed to write managed seccomp policy"),
    }
    path
}

fn default_managed_artifact_dir() -> PathBuf {
    let dir = firma_runtime_state::runtime_paths::default_runtime_dir().join("seccomp-artifacts");
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
    let section = firma_config_loader::load_section(path, "run").map_err(|reason| {
        // load_section prefixes the path; strip it to avoid doubling in the
        // RunError::ConfigParse display ("{path}: {reason}").
        let prefix = format!("{}: ", path.display());
        let reason = reason.to_string();
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

/// Read `[run].profile` from `firma.toml`, if present.
///
/// # Errors
///
/// Returns an error when the file cannot be read or the `[run]` section
/// cannot be parsed as `FileConfig`.
pub fn read_configured_profile(path: &Path) -> Result<Option<String>, RunError> {
    let section = firma_config_loader::load_section(path, "run").map_err(|reason| {
        let prefix = format!("{}: ", path.display());
        let reason = reason.to_string();
        let reason = reason.strip_prefix(&prefix).unwrap_or(&reason).to_string();
        RunError::ConfigParse {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    let parsed = toml::from_str::<FileConfig>(&section).map_err(|error| RunError::ConfigParse {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    Ok(parsed.profile)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use firma_config_loader::CONFIG_FILE_NAME;
    use pretty_assertions::assert_eq;

    use crate::runtime::RunInput;

    use super::{
        BackendKind, CapabilityLeaseConfig, CapabilityLeasePatch, CapabilitySource,
        SandboxIdentityMode, SeccompRuntimeMode, capability_from_patch, resolve_profile,
    };
    #[cfg(target_os = "linux")]
    use crate::backend::platform::WslKind;

    fn lease_patch(requested_actions: Option<Vec<String>>) -> CapabilityLeasePatch {
        CapabilityLeasePatch {
            source: Some(super::CapabilitySourcePatch::Disabled),
            kind: None,
            path: None,
            public_key_path: None,
            refresh_ratio: None,
            grace_seconds: None,
            requested_actions,
        }
    }

    #[test]
    fn capability_patch_requested_actions_override_wins() {
        let custom = vec!["communication.internal.send".to_string()];
        let resolved = capability_from_patch(lease_patch(Some(custom.clone())));
        assert_eq!(resolved.requested_actions, custom);
    }

    #[test]
    fn capability_patch_absent_actions_fall_back_to_default() {
        let resolved = capability_from_patch(lease_patch(None));
        assert_eq!(
            resolved.requested_actions,
            CapabilityLeaseConfig::default_requested_actions()
        );
    }

    #[test]
    fn capability_patch_empty_actions_fall_back_to_default() {
        let resolved = capability_from_patch(lease_patch(Some(Vec::new())));
        assert_eq!(
            resolved.requested_actions,
            CapabilityLeaseConfig::default_requested_actions()
        );
    }

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
            monitor_mode: false,
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

        #[expect(
            unreachable_code,
            reason = "fallback satisfies exhaustive return typing after cfg-gated platform branches"
        )]
        BackendKind::Firecracker
    }

    #[test]
    fn resolves_generic_defaults() {
        let resolved = resolve_profile(&args("generic")).unwrap();
        assert_eq!(resolved.id, "generic");
        assert_eq!(resolved.backend, BackendKind::default_for_current_host());
        assert_eq!(
            resolved.sidecar_endpoint,
            super::DEFAULT_SIDECAR_ENDPOINT.parse().unwrap()
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
    fn managed_seccomp_applies_to_all_recognized_bwrap_profiles() {
        for profile in ["generic", "codex", "claude-code", "copilot", "vscode"] {
            assert!(
                super::managed_seccomp_applies(profile, BackendKind::Bwrap),
                "managed seccomp must apply to profile '{profile}' on bwrap"
            );
        }
    }

    #[test]
    fn managed_baselines_do_not_deny_filesystem_delete() {
        // Neither the copilot nor the generic seccomp baseline denies
        // filesystem.delete. Both still deny credential.write. Workspace-scoped
        // delete is enforced structurally by the read-only rootfs mount.
        for profile in ["copilot", "generic"] {
            let (content, _) = super::managed_policy_for_profile(profile);
            assert!(
                content.contains("credential.write"),
                "profile '{profile}' baseline must still deny credential.write"
            );
            assert!(
                !content.contains("filesystem.delete"),
                "profile '{profile}' baseline must not deny filesystem.delete"
            );
        }
        let (_, copilot_filename) = super::managed_policy_for_profile("copilot");
        assert_eq!(copilot_filename, "copilot-local-command-v1.toml");
        let (_, generic_filename) = super::managed_policy_for_profile("generic");
        assert_eq!(generic_filename, "generic-local-command-v1.toml");
    }

    #[test]
    fn vscode_managed_policy_drops_filesystem_delete() {
        let (content, filename) = super::managed_policy_for_profile("vscode");
        assert_eq!(filename, "vscode-local-command-v1.toml");
        assert!(content.contains("credential.write"));
        assert!(!content.contains("filesystem.delete"));
    }

    #[test]
    fn unknown_profile_uses_generic_managed_policy() {
        let (content, filename) = super::managed_policy_for_profile("unknown-agent");
        assert_eq!(filename, "generic-local-command-v1.toml");
        assert_eq!(content, super::MANAGED_SECCOMP_POLICY);
    }

    #[test]
    fn managed_seccomp_applies_to_copilot_on_bwrap() {
        assert!(super::managed_seccomp_applies(
            "copilot",
            BackendKind::Bwrap
        ));
    }

    #[test]
    fn managed_seccomp_skips_non_bwrap_and_unknown_profiles() {
        assert!(
            !super::managed_seccomp_applies("codex", BackendKind::Firecracker),
            "managed seccomp is bwrap-only; non-bwrap backends must opt out"
        );
        assert!(
            !super::managed_seccomp_applies("not-a-profile", BackendKind::Bwrap),
            "unrecognized profiles must not receive the managed baseline"
        );
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
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);

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
    fn shims_merge_across_defaults_and_profile() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);

        let toml = r#"
[run.defaults]
shims = ["bws", "  "]

[run.profiles.codex]
shims = ["npx"]
"#;
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);

        let resolved = resolve_profile(&run_args).unwrap();
        // Defaults and profile are additive; blank entries are dropped.
        assert!(resolved.shims.contains("bws"));
        assert!(resolved.shims.contains("npx"));
        assert!(!resolved.shims.iter().any(|s| s.trim().is_empty()));
    }

    #[test]
    fn shims_default_to_empty() {
        let resolved = resolve_profile(&args("codex")).unwrap();
        assert!(resolved.shims.is_empty());
    }

    #[test]
    fn user_executable_policy_overrides_builtin_sandbox_mode() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        let toml = r#"
[run.profiles.codex.executable_policies.codex]
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
        assert!(resolved.use_http_proxy_sidecar);
        assert_eq!(
            resolved.sidecar_endpoint,
            super::DEFAULT_SIDECAR_ENDPOINT.parse().unwrap()
        );
        assert!(resolved.env_passthrough.contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn generic_profile_defaults_to_sole_ca_trust() {
        let resolved = resolve_profile(&args("generic")).unwrap();
        assert_eq!(resolved.ca_trust_mode, super::CaTrustMode::Sole);
    }

    #[test]
    fn resolves_copilot_profile() {
        let resolved = resolve_profile(&args("copilot")).unwrap();
        assert_eq!(resolved.id, "copilot");
        assert_eq!(
            resolved.ca_trust_mode,
            super::CaTrustMode::AppendSystemRoots
        );
        assert!(resolved.env_passthrough.contains("GITHUB_TOKEN"));
    }

    #[test]
    fn resolves_vscode_profile() {
        let resolved = resolve_profile(&args("vscode")).unwrap();
        assert_eq!(resolved.id, "vscode");
        assert_eq!(
            resolved.ca_trust_mode,
            super::CaTrustMode::AppendSystemRoots
        );
        assert!(resolved.use_http_proxy_sidecar);
        assert_eq!(
            resolved.env_set.get("FIRMA_RUN_VSCODE_SHIM"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn resolves_codex_profile_with_proxy_sidecar() {
        let resolved = resolve_profile(&args("codex")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved.id, "codex");
        assert!(resolved.use_http_proxy_sidecar);
        assert_eq!(
            resolved.sidecar_endpoint,
            super::DEFAULT_SIDECAR_ENDPOINT.parse().unwrap()
        );
    }

    #[test]
    fn resolves_generic_profile_with_proxy_sidecar() {
        let mut run_args = args("generic");
        run_args.backend = Some(non_bwrap_backend_for_current_host());
        let resolved = resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved.id, "generic");
        assert!(resolved.use_http_proxy_sidecar);
        assert_eq!(
            resolved.sidecar_endpoint,
            super::DEFAULT_SIDECAR_ENDPOINT.parse().unwrap()
        );
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
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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

        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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

        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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

        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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
    fn managed_runtime_mode_parser_accepts_case_and_rejects_unknown_values() {
        assert_eq!(
            super::parse_managed_runtime_mode(" PRECOMPILED_ONLY ")
                .unwrap_or_else(|error| panic!("{error}")),
            SeccompRuntimeMode::PrecompiledOnly
        );
        assert_eq!(
            super::parse_managed_runtime_mode("compile_on_launch")
                .unwrap_or_else(|error| panic!("{error}")),
            SeccompRuntimeMode::CompileOnLaunch
        );

        let error = super::parse_managed_runtime_mode("eager")
            .expect_err("unknown runtime mode must fail validation");
        assert!(
            error
                .to_string()
                .contains("compile_on_launch' or 'precompiled_only"),
            "unexpected error: {error}"
        );
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

        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
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

        let result_path = super::write_managed_policy_to_dir(&seccomp_dir, "generic");

        assert_eq!(result_path, policy_path);
        let written = fs::read_to_string(&policy_path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            written,
            super::MANAGED_SECCOMP_POLICY,
            "stale policy not overwritten by embedded version"
        );
    }

    #[test]
    fn read_configured_profile_returns_run_profile_field() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(
            &config_path,
            r#"
[run]
profile = "vscode"
"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let profile =
            super::read_configured_profile(&config_path).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(profile.as_deref(), Some("vscode"));
    }

    #[test]
    fn read_configured_profile_returns_none_when_field_is_absent() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(&config_path, "[run]\n").unwrap_or_else(|e| panic!("{e}"));

        let profile =
            super::read_configured_profile(&config_path).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(profile, None);
    }
}
