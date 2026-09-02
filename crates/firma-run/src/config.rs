use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use firma_config_loader::AgentProfile;
use firma_config_schema::secret_provider::SecretProviderPatch;
use firma_core::SecretMatcher;
use firma_runtime_state::RuntimeLayout;
use firma_secret_provider::IntegrationSpec;
use serde::Serialize;

pub use firma_config_schema::run::SandboxIdentityMode;
use firma_config_schema::run::{
    BackendKind as SchemaBackendKind, CommandMediatorPatch, FileConfig, SeccompPolicyPatch,
};
pub(crate) use firma_config_schema::run::{
    CaTrustMode, CapabilityLeasePatch, CapabilitySourcePatch, CommandMediatorHitlMode,
    ExecutableLaunchPolicyPatch, MountPatch, NetworkPolicyPatch, ProfilePatch, SeccompRuntimeMode,
};

use crate::backend::BackendKind;
use crate::backend::platform::detect_wsl;
use crate::error::RunError;
use crate::profile::built_in_profile;
use crate::runtime::RunInput;

fn backend_supports_structural_network(backend: BackendKind) -> bool {
    matches!(backend, BackendKind::Bwrap)
}

impl From<SchemaBackendKind> for BackendKind {
    fn from(backend: SchemaBackendKind) -> Self {
        match backend {
            SchemaBackendKind::Bwrap => Self::Bwrap,
            SchemaBackendKind::Vz => Self::Vz,
            SchemaBackendKind::Wsl2 => Self::Wsl2,
            SchemaBackendKind::Firecracker => Self::Firecracker,
        }
    }
}

impl From<BackendKind> for SchemaBackendKind {
    fn from(backend: BackendKind) -> Self {
        match backend {
            BackendKind::Bwrap => Self::Bwrap,
            BackendKind::Vz => Self::Vz,
            BackendKind::Wsl2 => Self::Wsl2,
            BackendKind::Firecracker => Self::Firecracker,
        }
    }
}

/// Resolved runtime profile after combining built-in defaults, optional file
/// config, and CLI overrides.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedProfile {
    pub id: String,
    pub backend: BackendKind,
    pub(crate) sidecar_endpoint: SidecarEndpoint,
    pub(crate) sidecar_selection: crate::sidecar::SidecarSelection,
    pub env_passthrough: BTreeSet<String>,
    pub env_set: BTreeMap<String, String>,
    pub(crate) mounts: Vec<MountSpec>,
    pub(crate) seccomp_policy: Option<SeccompPolicyConfig>,
    pub(crate) network: NetworkPolicy,
    pub(crate) identity_mode: SandboxIdentityMode,
    pub capability: CapabilityLeaseConfig,
    pub(crate) sidecar_local_exec: Option<CommandMediatorConfig>,
    pub(crate) executable_policies: BTreeMap<String, ExecutableLaunchPolicy>,
    /// Resolved secret-provider integrations: CLI vault tools keyed by binary
    /// basename, HTTP vaults keyed by `provider_id`. A CLI entry activates a
    /// secret-mediation shim for that binary (stdio routed through the
    /// firma-run broker); an HTTP entry is mirrored into the autostarted
    /// Sidecar's own config so it can intercept MITM'd responses from that
    /// vault. The map value is the fully resolved
    /// [`IntegrationSpec`](firma_secret_provider::IntegrationSpec) — a
    /// built-in looked up by name (CLI only), or a custom spec defined
    /// inline. An entry being present here is itself the authorization to
    /// intercept — no separate policy check gates it; see the secrets design
    /// doc. Merged across `[run.defaults]` and the active profile; entries
    /// defined later win on name collision (profile overrides defaults,
    /// custom overrides built-in).
    ///
    /// This is the canonical definition of secret-provider authorization and
    /// merge semantics; other `secret_providers` / `http_secret_providers`
    /// fields reference it via intra-doc links rather than duplicating it.
    pub(crate) secret_providers: BTreeMap<String, IntegrationSpec<SecretMatcher>>,
    /// When `true`, the autostarted sidecar is configured in HTTP proxy
    /// interceptor mode (TCP listener). When `false`, UDS interceptor mode.
    /// Set for profiles whose agent tool uses standard HTTP proxy env vars.
    pub(crate) use_http_proxy_sidecar: bool,
    /// When `true`, allow non-structural (proxy-only) backends to run without
    /// failing closed. Profile layers replace lower explicit values, the CLI
    /// `--allow-non-structural` flag enables it at highest profile precedence,
    /// and `FIRMA_RUN_ALLOW_NON_STRUCTURAL` remains a post-resolution
    /// enable-only override.
    pub(crate) allow_non_structural: bool,
    /// How the sandbox CA trust store is assembled (sole firma-ca vs. appended
    /// to system roots).
    pub(crate) ca_trust_mode: CaTrustMode,
}

impl ResolvedProfile {
    /// Validate resolved values before execution starts.
    ///
    /// # Errors
    ///
    /// Returns an error when resolved profile values violate runtime
    /// invariants (invalid ids, lease settings, or mount paths).
    fn validate(&self) -> Result<(), RunError> {
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

        if self.capability.grace.is_zero() {
            return Err(RunError::ConfigValidation(
                "capability.grace must be > 0".to_string(),
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
            if self.backend != BackendKind::Bwrap {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_policy is only supported with backend 'bwrap', got '{backend}'",
                    backend = self.backend
                )));
            }
        }

        if let Some(mediator) = &self.sidecar_local_exec {
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
                "{REQUIRE_LOCAL_EXEC_GOVERNANCE_ENV}=true requires [run.profiles.<id>.sidecar_local_exec] configuration"
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
    /// Host path exposed by the mount.
    pub(crate) source: PathBuf,
    /// Path where the backend exposes `source` inside the sandbox or guest.
    pub(crate) target: PathBuf,
    /// Whether the backend must prevent writes through the mounted path.
    pub(crate) read_only: bool,
}

/// Network policy toggles used by backend implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkPolicy {
    pub enforce_network_namespace: bool,
    pub fail_closed: bool,
}

/// Capability lease refresh settings.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapabilityLeaseConfig {
    pub source: CapabilitySource,
    /// Raw Ed25519 public key used to verify Authority-issued capabilities.
    pub public_key_path: Option<PathBuf>,
    pub refresh_ratio: f64,
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub grace: Duration,
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
    pub(crate) const fn grace(&self) -> Duration {
        self.grace
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
    pub(crate) enforce_wrapper_defaults: bool,
    pub(crate) sandbox_mode: Option<String>,
    pub(crate) approval_policy: Option<String>,
    pub(crate) config_overrides: BTreeMap<String, String>,
}

/// Runtime command mediation settings for governed local execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandMediatorConfig {
    pub(crate) endpoint: CommandMediatorEndpoint,
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub(crate) timeout: Duration,
    pub(crate) hitl_mode: CommandMediatorHitlMode,
    /// Maximum total wall-clock time `firma-run` will block waiting for a
    /// human to approve a `pending_hitl` token. Applies only when
    /// `hitl_mode = "async_token"`. Fail-closed once exceeded.
    /// Default: 5 minutes.
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub(crate) hitl_max_wait: Duration,
    pub(crate) enforce_known_executables: bool,
    pub(crate) allowed_executables: BTreeSet<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommandMediatorEndpoint {
    Tcp { addr: SocketAddr },
    Unix { path: PathBuf },
}

/// Seccomp policy compilation settings for Linux bwrap backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeccompPolicyConfig {
    pub(crate) source_policy_path: PathBuf,
    pub(crate) artifact_dir: PathBuf,
    pub(crate) runtime_mode: SeccompRuntimeMode,
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

/// Layered merge for `[run]` profile patches, where `higher` wins over the
/// lower layer. This is resolution behavior over the schema representation, so
/// it lives in `firma-run` rather than `firma-config-schema`.
trait Merge {
    fn merge(self, higher: Self) -> Self;
}

impl Merge for NetworkPolicyPatch {
    fn merge(self, higher: Self) -> Self {
        Self {
            enforce_network_namespace: higher
                .enforce_network_namespace
                .or(self.enforce_network_namespace),
            fail_closed: higher.fail_closed.or(self.fail_closed),
        }
    }
}

impl Merge for SeccompPolicyPatch {
    fn merge(self, higher: Self) -> Self {
        Self {
            source_policy_path: higher.source_policy_path.or(self.source_policy_path),
            artifact_dir: higher.artifact_dir.or(self.artifact_dir),
            runtime_mode: higher.runtime_mode.or(self.runtime_mode),
        }
    }
}

impl Merge for CommandMediatorPatch {
    fn merge(self, higher: Self) -> Self {
        Self {
            endpoint: higher.endpoint.or(self.endpoint),
            timeout: higher.timeout.or(self.timeout),
            hitl_mode: higher.hitl_mode.or(self.hitl_mode),
            hitl_max_wait: higher.hitl_max_wait.or(self.hitl_max_wait),
            enforce_known_executables: higher
                .enforce_known_executables
                .or(self.enforce_known_executables),
            allowed_executables: higher.allowed_executables.or(self.allowed_executables),
        }
    }
}

impl Merge for ExecutableLaunchPolicyPatch {
    fn merge(self, higher: Self) -> Self {
        let config_overrides = match higher.config_overrides {
            Some(higher) if higher.is_empty() => Some(higher),
            Some(higher) => {
                let mut merged = self.config_overrides.unwrap_or_default();
                merged.extend(higher);
                Some(merged)
            }
            None => self.config_overrides,
        };
        Self {
            enforce_wrapper_defaults: higher
                .enforce_wrapper_defaults
                .or(self.enforce_wrapper_defaults),
            sandbox_mode: higher.sandbox_mode.or(self.sandbox_mode),
            approval_policy: higher.approval_policy.or(self.approval_policy),
            config_overrides,
        }
    }
}

impl Merge for CapabilityLeasePatch {
    fn merge(self, higher: Self) -> Self {
        Self {
            source: higher.source.or(self.source),
            public_key_path: higher.public_key_path.or(self.public_key_path),
            refresh_ratio: higher.refresh_ratio.or(self.refresh_ratio),
            grace: higher.grace.or(self.grace),
            requested_actions: higher.requested_actions.or(self.requested_actions),
        }
    }
}

impl Merge for ProfilePatch {
    fn merge(self, higher: Self) -> Self {
        let env_set = match higher.env_set {
            Some(higher) if higher.is_empty() => Some(higher),
            Some(higher) => {
                let mut merged = self.env_set.unwrap_or_default();
                merged.extend(higher);
                Some(merged)
            }
            None => self.env_set,
        };
        let executable_policies = match higher.executable_policies {
            Some(higher) if higher.is_empty() => Some(higher),
            Some(higher) => {
                let mut merged = self.executable_policies.unwrap_or_default();
                for (executable, higher_policy) in higher {
                    let policy = if let Some(lower) = merged.remove(&executable) {
                        lower.merge(higher_policy)
                    } else {
                        higher_policy
                    };
                    merged.insert(executable, policy);
                }
                Some(merged)
            }
            None => self.executable_policies,
        };

        Self {
            backend: higher.backend.or(self.backend),
            sidecar_endpoint: higher.sidecar_endpoint.or(self.sidecar_endpoint),
            seccomp_policy: match (self.seccomp_policy, higher.seccomp_policy) {
                (Some(lower), Some(higher)) => Some(lower.merge(higher)),
                (lower, higher) => higher.or(lower),
            },
            env_passthrough: higher.env_passthrough.or(self.env_passthrough),
            env_set,
            mounts: higher.mounts.or(self.mounts),
            network: match (self.network, higher.network) {
                (Some(lower), Some(higher)) => Some(lower.merge(higher)),
                (lower, higher) => higher.or(lower),
            },
            identity_mode: higher.identity_mode.or(self.identity_mode),
            capability: match (self.capability, higher.capability) {
                (Some(lower), Some(higher)) => Some(lower.merge(higher)),
                (lower, higher) => higher.or(lower),
            },
            sidecar_local_exec: match (self.sidecar_local_exec, higher.sidecar_local_exec) {
                (Some(lower), Some(higher)) => Some(lower.merge(higher)),
                (lower, higher) => higher.or(lower),
            },
            executable_policies,
            use_http_proxy_sidecar: higher
                .use_http_proxy_sidecar
                .or(self.use_http_proxy_sidecar),
            allow_non_structural: higher.allow_non_structural.or(self.allow_non_structural),
            mask_home_paths: higher.mask_home_paths.or(self.mask_home_paths),
            ca_trust_mode: higher.ca_trust_mode.or(self.ca_trust_mode),
            secret_providers: match (self.secret_providers, higher.secret_providers) {
                // Additive across layers (like `env_passthrough`); the later
                // (higher) entries come last so they win on name collision in
                // `resolve_secret_providers`.
                (Some(mut lower), Some(higher)) => {
                    lower.extend(higher);
                    Some(lower)
                }
                (lower, higher) => higher.or(lower),
            },
        }
    }
}

/// Resolve profile configuration for a run invocation.
///
/// # Errors
///
/// Returns an error when profile resolution fails due to invalid inputs,
/// parse errors, or resulting validation failures.
pub fn resolve_profile(args: &RunInput) -> Result<ResolvedProfile, RunError> {
    let runtime_layout = resolved_runtime_layout();
    resolve_profile_with_layout(args, &runtime_layout)
}

#[expect(
    clippy::too_many_lines,
    reason = "sequential profile resolution (patch merge + endpoint/selection + network + capability) reads more clearly inline"
)]
pub(crate) fn resolve_profile_with_layout(
    args: &RunInput,
    runtime_layout: &RuntimeLayout,
) -> Result<ResolvedProfile, RunError> {
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

    let configured_backend = patch.backend.map(BackendKind::from);
    let backend = resolve_backend(configured_backend);

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
        .unwrap_or_default()
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .collect::<BTreeSet<_>>();

    let secret_providers = resolve_secret_providers(patch.secret_providers)?;

    let mut env_set = patch.env_set.unwrap_or_default();
    if let Some(paths) = patch.mask_home_paths {
        env_set.insert(
            "FIRMA_RUN_BWRAP_MASK_HOME_PATHS".to_string(),
            paths
                .iter()
                .map(|path| path.to_string_lossy())
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    let mounts = patch
        .mounts
        .unwrap_or_default()
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

    let executable_policies = patch
        .executable_policies
        .unwrap_or_default()
        .into_iter()
        .map(|(executable, policy)| (executable, resolve_executable_policy(policy)))
        .collect();

    let seccomp_policy = patch
        .seccomp_policy
        .map(seccomp_policy_from_patch)
        .transpose()?
        .or(default_managed_seccomp_policy(
            runtime_layout,
            &profile_id,
            backend,
        )?);
    let resolved = ResolvedProfile {
        id: profile_id,
        backend,
        sidecar_endpoint,
        sidecar_selection,
        env_passthrough,
        env_set,
        mounts,
        seccomp_policy,
        network,
        identity_mode,
        capability,
        sidecar_local_exec,
        executable_policies,
        secret_providers,
        use_http_proxy_sidecar: patch.use_http_proxy_sidecar.unwrap_or(false),
        allow_non_structural: patch.allow_non_structural.unwrap_or(false),
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
        backend: args.backend.map(SchemaBackendKind::from),
        sidecar_endpoint: None,
        seccomp_policy: None,
        env_passthrough: None,
        env_set: None,
        mounts: None,
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
                public_key_path: None,
                refresh_ratio: None,
                grace: None,
                requested_actions: None,
            }),
        sidecar_local_exec: None,
        executable_policies: None,
        secret_providers: Vec::new(),
        use_http_proxy_sidecar: None,
        allow_non_structural: args.allow_non_structural.then_some(true),
        mask_home_paths: None,
        ca_trust_mode: None,
    }
}

/// Resolve the merged `secret_providers` patch entries into the final
/// map (CLI entries keyed by binary basename, HTTP entries keyed by
/// `provider_id`). Entries are processed in order, so a later entry (a
/// higher-priority profile, or a custom spec appearing after a bare-name
/// reference) wins on name collision.
///
/// # Errors
///
/// Returns [`RunError::ConfigValidation`] if a bare-string entry does not name
/// a known built-in integration.
fn resolve_secret_providers(
    patch: Option<Vec<SecretProviderPatch>>,
) -> Result<BTreeMap<String, IntegrationSpec<SecretMatcher>>, RunError> {
    let Some(patch) = patch else {
        return Ok(BTreeMap::new());
    };
    let builtins = firma_secret_provider::IntegrationRegistry::with_builtins();
    let mut resolved = BTreeMap::new();
    for entry in patch {
        match entry {
            SecretProviderPatch::Named(name) => {
                let name = name.trim().to_string();
                if name.is_empty() {
                    continue;
                }
                let spec = builtins.for_binary(&name).cloned().ok_or_else(|| {
                    RunError::ConfigValidation(format!(
                        "unknown secret provider '{name}'; no built-in integration by that name \
                         — provide a full spec to define a custom one"
                    ))
                })?;
                resolved.insert(name, IntegrationSpec::Cli(spec));
            }
            SecretProviderPatch::Custom(spec) => {
                let spec = IntegrationSpec::try_from(*spec)?;
                // Cli specs are indexed by binary name, Http specs are indexed by provider id
                let name = match &spec {
                    IntegrationSpec::Cli(cli) => cli.binary_name().to_owned(),
                    IntegrationSpec::Http(http) => http.provider_id.clone(),
                };
                resolved.insert(name, spec);
            }
        }
    }
    Ok(resolved)
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
        config_overrides: policy.config_overrides.unwrap_or_default(),
    }
}

fn capability_from_patch(patch: CapabilityLeasePatch) -> CapabilityLeaseConfig {
    let source = match patch.source {
        Some(CapabilitySourcePatch::File { path }) => CapabilitySource::File { path },
        Some(CapabilitySourcePatch::Disabled) | None => CapabilitySource::Disabled,
    };

    CapabilityLeaseConfig {
        source,
        public_key_path: patch.public_key_path,
        refresh_ratio: patch.refresh_ratio.unwrap_or(0.60),
        grace: patch.grace.unwrap_or(Duration::from_secs(30)),
        requested_actions: patch
            .requested_actions
            .unwrap_or_else(CapabilityLeaseConfig::default_requested_actions),
    }
}

fn default_capability_config() -> CapabilityLeaseConfig {
    CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        public_key_path: None,
        refresh_ratio: 0.60,
        grace: Duration::from_secs(30),
        requested_actions: CapabilityLeaseConfig::default_requested_actions(),
    }
}

fn seccomp_policy_from_patch(patch: SeccompPolicyPatch) -> Result<SeccompPolicyConfig, RunError> {
    let source_policy_path = patch.source_policy_path.ok_or_else(|| {
        RunError::ConfigValidation(
            "seccomp_policy.source_policy_path is required after profile merging".to_string(),
        )
    })?;
    let artifact_dir = patch.artifact_dir.ok_or_else(|| {
        RunError::ConfigValidation(
            "seccomp_policy.artifact_dir is required after profile merging".to_string(),
        )
    })?;
    Ok(SeccompPolicyConfig {
        source_policy_path,
        artifact_dir,
        runtime_mode: patch
            .runtime_mode
            .unwrap_or(SeccompRuntimeMode::CompileOnLaunch),
    })
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
    let allowed_executables =
        canonicalize_allowed_executables(patch.allowed_executables.as_deref().unwrap_or_default())?;
    Ok(CommandMediatorConfig {
        endpoint,
        timeout: patch
            .timeout
            .map_or(Duration::from_millis(500), |timeout| timeout.duration()),
        hitl_mode: patch.hitl_mode.unwrap_or(CommandMediatorHitlMode::SyncWait),
        hitl_max_wait: patch
            .hitl_max_wait
            .map_or(Duration::from_mins(5), |timeout| timeout.duration()),
        enforce_known_executables: patch.enforce_known_executables.unwrap_or(false),
        allowed_executables,
    })
}

fn canonicalize_allowed_executables(paths: &[PathBuf]) -> Result<BTreeSet<PathBuf>, RunError> {
    paths
        .iter()
        .map(|path| {
            if !path.is_absolute() {
                return Err(RunError::ConfigValidation(format!(
                    "sidecar_local_exec.allowed_executables entries must be absolute paths: {}",
                    path.display()
                )));
            }
            let canonical = std::fs::canonicalize(path).map_err(|error| {
                RunError::ConfigValidation(format!(
                    "sidecar_local_exec.allowed_executables entry could not be canonicalized ({}): {error}",
                    path.display()
                ))
            })?;
            if !canonical.is_file() {
                return Err(RunError::ConfigValidation(format!(
                    "sidecar_local_exec.allowed_executables entries must point to existing regular files: {}",
                    path.display()
                )));
            }
            Ok(canonical)
        })
        .collect()
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
    runtime_layout: &RuntimeLayout,
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
        .map_or_else(
            || ensure_managed_policy_path(runtime_layout, profile_id),
            PathBuf::from,
        );

    let artifact_dir = std::env::var(MANAGED_ARTIFACT_DIR_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or_else(
            || default_managed_artifact_dir(runtime_layout),
            PathBuf::from,
        );

    let runtime_mode = std::env::var(MANAGED_RUNTIME_MODE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_managed_runtime_mode(&value))
        .transpose()?
        .unwrap_or(SeccompRuntimeMode::CompileOnLaunch);

    Ok(Some(SeccompPolicyConfig {
        source_policy_path,
        artifact_dir,
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
fn ensure_managed_policy_path(runtime_layout: &RuntimeLayout, profile_id: &str) -> PathBuf {
    let dir = runtime_layout.root().join("seccomp");
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

fn default_managed_artifact_dir(runtime_layout: &RuntimeLayout) -> PathBuf {
    let dir = runtime_layout.root().join("seccomp-artifacts");
    tracing::debug!(path = %dir.display(), "seccomp artifact dir");
    dir
}

fn resolved_runtime_layout() -> RuntimeLayout {
    RuntimeLayout::resolve(None).unwrap_or_else(|error| {
        let fallback = std::env::temp_dir().join("firma");
        tracing::warn!(%error, path = %fallback.display(), "runtime layout unavailable; using temporary fallback");
        RuntimeLayout::from_root(fallback)
    })
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
    let absolute_path = std::path::absolute(path).map_err(|reason| RunError::ConfigParse {
        path: path.to_path_buf(),
        reason: format!("failed to resolve config path: {reason}"),
    })?;
    let config = firma_config_loader::FirmaConfig::load(&absolute_path).map_err(|reason| {
        // FirmaConfig prefixes the path; strip it to avoid doubling in the
        // RunError::ConfigParse display ("{path}: {reason}").
        let prefix = format!("{}: ", absolute_path.display());
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
    let mut parsed = config.section::<FileConfig>("run").map_err(|reason| {
        let prefix = format!("{}: ", absolute_path.display());
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
    let Some(config_dir) = absolute_path.parent() else {
        return Err(RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: "resolved config path has no containing directory".to_string(),
        });
    };
    rebase_file_paths(&mut parsed, config_dir);

    let profile_patch = parsed.profiles.get(profile).cloned().unwrap_or_default();
    Ok(parsed.defaults.merge(profile_patch))
}

fn rebase_file_paths(config: &mut FileConfig, config_dir: &Path) {
    rebase_profile_paths(&mut config.defaults, config_dir);
    for profile in config.profiles.values_mut() {
        rebase_profile_paths(profile, config_dir);
    }
}

fn rebase_profile_paths(profile: &mut ProfilePatch, config_dir: &Path) {
    if let Some(mounts) = &mut profile.mounts {
        for mount in mounts {
            rebase_path(&mut mount.source, config_dir);
        }
    }
    if let Some(seccomp) = &mut profile.seccomp_policy {
        if let Some(path) = &mut seccomp.source_policy_path {
            rebase_path(path, config_dir);
        }
        if let Some(path) = &mut seccomp.artifact_dir {
            rebase_path(path, config_dir);
        }
    }
    if let Some(capability) = &mut profile.capability {
        if let Some(CapabilitySourcePatch::File { path }) = &mut capability.source {
            rebase_path(path, config_dir);
        }
        if let Some(path) = &mut capability.public_key_path {
            rebase_path(path, config_dir);
        }
    }
}

fn rebase_path(path: &mut PathBuf, config_dir: &Path) {
    if path.is_relative() {
        *path = config_dir.join(&*path);
    }
}

/// Read `[run].profile` from `firma.toml`, if present.
///
/// # Errors
///
/// Returns an error when the file cannot be read or the `[run]` section
/// cannot be parsed as `FileConfig`.
pub fn read_configured_profile(path: &Path) -> Result<Option<String>, RunError> {
    let config = firma_config_loader::FirmaConfig::load(path).map_err(|reason| {
        let prefix = format!("{}: ", path.display());
        let reason = reason.to_string();
        let reason = reason.strip_prefix(&prefix).unwrap_or(&reason).to_string();
        RunError::ConfigParse {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    let parsed = config
        .section::<FileConfig>("run")
        .map_err(|reason| RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: reason.to_string(),
        })?;
    Ok(parsed.profile)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use firma_config_loader::CONFIG_FILE_NAME;
    use firma_config_schema::utils::NonZeroDuration;
    use firma_core::SecretMatcher;
    use firma_secret_provider::{MatcherRule, spec::cli::CommandAndMatcher};
    use pretty_assertions::assert_eq;

    use crate::runtime::RunInput;

    use super::{
        BackendKind, CapabilityLeaseConfig, CapabilityLeasePatch, CapabilitySource,
        CapabilitySourcePatch, CommandMediatorHitlMode, CommandMediatorPatch,
        ExecutableLaunchPolicyPatch, FileConfig, Merge, MountPatch, NetworkPolicyPatch,
        ProfilePatch, SandboxIdentityMode, SeccompPolicyPatch, SeccompRuntimeMode,
        capability_from_patch, cli_profile_patch, rebase_file_paths, resolve_profile,
    };

    #[cfg(target_os = "linux")]
    use crate::backend::platform::WslKind;
    use crate::error::RunError;

    fn lease_patch(requested_actions: Option<Vec<String>>) -> CapabilityLeasePatch {
        CapabilityLeasePatch {
            source: Some(super::CapabilitySourcePatch::Disabled),
            public_key_path: None,
            refresh_ratio: None,
            grace: None,
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
    fn file_paths_rebase_for_defaults_and_every_profile_only_where_config_relative() {
        let mut config: FileConfig = toml::from_str(
            r#"
            [[defaults.mounts]]
            source = "workspace"
            target = "/sandbox/workspace"

            [defaults.seccomp_policy]
            source_policy_path = "seccomp/policy.toml"
            artifact_dir = "seccomp/artifacts"

            [defaults.capability]
            public_key_path = "keys/authority.pub"

            [profiles.unselected]
            mask_home_paths = [".ssh"]

            [[profiles.unselected.mounts]]
            source = "other-workspace"
            target = "/sandbox/other"

            [profiles.unselected.capability.source]
            kind = "file"
            path = "capabilities/unselected.toml"

            [profiles.unselected.sidecar_local_exec]
            allowed_executables = ["/usr/bin/bash"]
            "#,
        )
        .unwrap();

        rebase_file_paths(&mut config, std::path::Path::new("/cfg"));

        assert_eq!(
            config.defaults.mounts.as_ref().unwrap()[0].source,
            PathBuf::from("/cfg/workspace")
        );
        assert_eq!(
            config.defaults.mounts.as_ref().unwrap()[0].target,
            PathBuf::from("/sandbox/workspace")
        );
        assert!(!config.defaults.mounts.as_ref().unwrap()[0].read_only);
        let seccomp = config.defaults.seccomp_policy.as_ref().unwrap();
        assert_eq!(
            seccomp.source_policy_path,
            Some(PathBuf::from("/cfg/seccomp/policy.toml"))
        );
        assert_eq!(
            seccomp.artifact_dir,
            Some(PathBuf::from("/cfg/seccomp/artifacts"))
        );
        assert_eq!(
            config
                .defaults
                .capability
                .as_ref()
                .and_then(|capability| capability.public_key_path.as_ref()),
            Some(&PathBuf::from("/cfg/keys/authority.pub"))
        );
        let unselected = &config.profiles["unselected"];
        assert_eq!(
            unselected.mounts.as_ref().unwrap()[0].source,
            PathBuf::from("/cfg/other-workspace")
        );
        match unselected
            .capability
            .as_ref()
            .and_then(|capability| capability.source.as_ref())
        {
            Some(CapabilitySourcePatch::File { path }) => {
                assert_eq!(path, &PathBuf::from("/cfg/capabilities/unselected.toml"));
            }
            other => panic!("expected file capability source, got {other:?}"),
        }
        assert_eq!(
            unselected.mask_home_paths,
            Some(vec![PathBuf::from(".ssh")])
        );
        assert_eq!(
            unselected
                .sidecar_local_exec
                .as_ref()
                .and_then(|mediator| mediator.allowed_executables.as_ref()),
            Some(&vec![PathBuf::from("/usr/bin/bash")])
        );
    }

    #[test]
    fn allowed_executable_parent_alias_is_stored_canonically() {
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        let nested = bin_dir.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let executable = bin_dir.join("agent");
        fs::write(&executable, "test executable").unwrap();
        let alias = nested.join("..").join("agent");

        let allowed = super::canonicalize_allowed_executables(&[alias]).unwrap();

        assert_eq!(
            allowed,
            BTreeSet::from([fs::canonicalize(executable).unwrap()])
        );
    }

    #[cfg(unix)]
    #[test]
    fn allowed_executable_symlink_is_stored_canonically() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("agent");
        let alias = dir.path().join("agent-alias");
        fs::write(&executable, "test executable").unwrap();
        symlink(&executable, &alias).unwrap();

        let allowed = super::canonicalize_allowed_executables(&[alias]).unwrap();

        assert_eq!(
            allowed,
            BTreeSet::from([fs::canonicalize(executable).unwrap()])
        );
    }

    #[test]
    fn allowed_executable_must_be_absolute_and_resolvable() {
        let relative = super::canonicalize_allowed_executables(&[PathBuf::from("bin/agent")])
            .expect_err("relative path must fail");
        assert!(relative.to_string().contains("must be absolute paths"));

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("agent");
        fs::write(&executable, "test executable").unwrap();
        let empty = super::canonicalize_allowed_executables(&[PathBuf::new(), executable])
            .expect_err("empty path must fail even when another entry is valid");
        assert!(empty.to_string().contains("must be absolute paths"));

        let missing = dir.path().join("missing-agent");
        let unresolved = super::canonicalize_allowed_executables(&[missing])
            .expect_err("missing path must fail");
        assert!(
            unresolved
                .to_string()
                .contains("could not be canonicalized")
        );
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
    fn capability_patch_empty_actions_remain_explicitly_empty() {
        let resolved = capability_from_patch(lease_patch(Some(Vec::new())));
        assert!(resolved.requested_actions.is_empty());
    }

    #[test]
    fn capability_empty_actions_replace_lower_actions_and_survive_file_resolution() {
        let merged = lease_patch(Some(vec!["filesystem.read".to_string()]))
            .merge(lease_patch(Some(Vec::new())));
        assert_eq!(merged.requested_actions, Some(Vec::new()));

        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(
            &config_path,
            r"
            [run.profiles.generic.capability]
            requested_actions = []
            ",
        )
        .unwrap();
        let mut run_args = args("generic");
        run_args.config = Some(config_path);

        let resolved = resolve_profile(&run_args).unwrap();
        assert!(resolved.capability.requested_actions.is_empty());
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
        let capability_path = tmpdir.path().join("capability.token");

        let toml = format!(
            r#"
[run.defaults]
sidecar_endpoint = "tcp://127.0.0.1:18080"

[run.profiles.codex]
backend = "bwrap"
identity_mode = "host_user"
env_passthrough = ["HOME"]

[run.profiles.codex.capability.source]
kind = "file"
path = '{}'
"#,
            capability_path.display()
        );
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
                path: capability_path
            }
        );
    }

    #[test]
    fn secret_providers_merge_across_defaults_and_profile() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);

        let toml = r#"
[run.defaults]
secret_providers = ["bws", "  "]

[run.profiles.codex]
secret_providers = ["op"]
"#;
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);

        let resolved = resolve_profile(&run_args).unwrap();
        // Defaults and profile are additive; blank entries are dropped.
        assert!(resolved.secret_providers.contains_key("bws"));
        assert!(resolved.secret_providers.contains_key("op"));
        assert!(!resolved.secret_providers.contains_key(""));
    }

    #[test]
    fn secret_providers_default_to_empty() {
        let resolved = resolve_profile(&args("codex")).unwrap();
        assert!(resolved.secret_providers.is_empty());
    }

    #[test]
    fn secret_providers_named_entry_unknown_builtin_errors() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        let toml = r#"
[run.defaults]
secret_providers = ["not-a-real-integration"]
"#;
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);

        let err = resolve_profile(&run_args).unwrap_err();
        assert!(matches!(err, RunError::ConfigValidation(_)));
    }

    #[test]
    fn secret_providers_custom_spec_overrides_builtin_of_same_name() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        let toml = r#"
[run.defaults]
secret_providers = [
    "bws",
    {
        type = "cli",
        binary_name = "bws",
        provider_id = "bitwarden",
        credential_env_vars = [],
        stripped_options = [],
        matchers = [
            {
                type = "sensitive_command",
                argv = ["secret", "list"],
                match = "prefix",
                matcher = {
                    type = "regex",
                    pattern = "(?P<name>.+)=(?P<value>.+)"
                }
            }
        ]
    },
]
"#;
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);

        let resolved = resolve_profile(&run_args).unwrap();
        let spec = resolved.secret_providers.get("bws").unwrap();
        std::assert_matches!(
            spec.as_cli()
                .expect("bws entry must resolve to a CLI spec")
                .matchers()[0],
            MatcherRule::SensitiveCommand(CommandAndMatcher {
                matcher: SecretMatcher::Regex { .. },
                ..
            })
        );
    }

    #[test]
    fn secret_providers_http_entry_resolves_by_provider_id() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        let toml = r#"
[run.defaults]
secret_providers = [
    {
        type = "http",
        provider_id = "aws-secrets-manager",
        host = "secretsmanager.*.amazonaws.com",
        matchers = [
            {
                type = "sensitive_command",
                path = "/get",
                matcher = {
                    type = "json",
                    record_path = "$",
                    value_path = "$.SecretString",
                    name = { source = "path", path = "$.Name" }
                }
            }
        ]
    },
]
"#;
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);

        let resolved = resolve_profile(&run_args).unwrap();
        let spec = resolved
            .secret_providers
            .get("aws-secrets-manager")
            .expect("http provider keyed by provider_id")
            .as_http()
            .expect("must resolve to an HTTP spec");
        assert_eq!(spec.host, "secretsmanager.*.amazonaws.com");
        assert_eq!(spec.provider_id, "aws-secrets-manager");
    }

    #[test]
    fn secret_providers_http_entry_missing_type_tag_fails_closed() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        let toml = r#"
[run.defaults]
secret_providers = [
    { provider_id = "aws-secrets-manager", host = "secretsmanager.*.amazonaws.com", matcher = { type = "json", value_path = "$.SecretString", name_path = "$.Name" } },
]
"#;
        fs::write(&config_path, toml).unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);

        let err = resolve_profile(&run_args).unwrap_err();
        assert!(matches!(err, RunError::ConfigParse { .. }));
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
    fn profile_boolean_merge_distinguishes_absent_false_and_true() {
        for lower in [None, Some(false), Some(true)] {
            for higher in [None, Some(false), Some(true)] {
                let merged = ProfilePatch {
                    use_http_proxy_sidecar: lower,
                    allow_non_structural: lower,
                    ..ProfilePatch::default()
                }
                .merge(ProfilePatch {
                    use_http_proxy_sidecar: higher,
                    allow_non_structural: higher,
                    ..ProfilePatch::default()
                });

                assert_eq!(merged.use_http_proxy_sidecar, higher.or(lower));
                assert_eq!(merged.allow_non_structural, higher.or(lower));
            }
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one aggregate contract trace keeps every layer and patch shape visible together"
    )]
    fn four_layer_merge_contract_is_total_and_shape_aware() {
        struct StageExpectation {
            name: &'static str,
            backend: Option<firma_config_schema::run::BackendKind>,
            allow_non_structural: Option<bool>,
            use_http_proxy_sidecar: Option<bool>,
            identity_mode: Option<SandboxIdentityMode>,
            capability_file: Option<&'static str>,
        }

        fn capability_file(patch: &ProfilePatch) -> Option<&std::path::Path> {
            match patch
                .capability
                .as_ref()
                .and_then(|capability| capability.source.as_ref())
            {
                Some(CapabilitySourcePatch::File { path }) => Some(path),
                Some(CapabilitySourcePatch::Disabled) | None => None,
            }
        }

        let file: FileConfig = toml::from_str(
            r#"
            [defaults]
            backend = "vz"
            sidecar_endpoint = "unix:///defaults/sidecar.sock"
            env_passthrough = ["DEFAULT_ONLY"]
            mounts = [{ source = "/defaults/source", target = "/defaults/target", read_only = true }]
            identity_mode = "host_user"
            use_http_proxy_sidecar = true
            allow_non_structural = true
            mask_home_paths = [".defaults"]
            ca_trust_mode = "append_system_roots"

            [defaults.env_set]
            DEFAULT_ONLY = "preserved"
            SHARED = "defaults"

            [defaults.network]
            enforce_network_namespace = true
            fail_closed = true

            [defaults.seccomp_policy]
            source_policy_path = "/defaults/seccomp.toml"
            artifact_dir = "/defaults/artifacts"
            runtime_mode = "compile_on_launch"

            [defaults.capability]
            public_key_path = "/defaults/authority.pub"
            refresh_ratio = 0.7
            grace = "45s"
            requested_actions = ["filesystem.read"]

            [defaults.capability.source]
            kind = "file"
            path = "/defaults/capability.toml"

            [defaults.sidecar_local_exec]
            endpoint = "unix:///defaults/local-exec.sock"
            timeout = "2s"
            hitl_mode = "sync_wait"
            hitl_max_wait = "4m"
            enforce_known_executables = true
            allowed_executables = ["/defaults/agent"]

            [defaults.executable_policies.codex]
            enforce_wrapper_defaults = true
            sandbox_mode = "defaults-sandbox"
            approval_policy = "defaults-approval"

            [defaults.executable_policies.codex.config_overrides]
            defaults = "preserved"
            shared = "defaults"

            [profiles.generic]
            backend = "wsl2"
            env_passthrough = []
            mounts = [{ source = "/selected/source", target = "/selected/target", read_only = false }]
            identity_mode = "sandbox_user"
            use_http_proxy_sidecar = false
            allow_non_structural = false
            mask_home_paths = []
            ca_trust_mode = "sole"
            env_set = { SELECTED_ONLY = "present", SHARED = "selected" }
            seccomp_policy = { runtime_mode = "precompiled_only" }
            network = { fail_closed = false }
            capability = { source = { kind = "disabled" }, requested_actions = [] }
            sidecar_local_exec = { hitl_mode = "async_token", enforce_known_executables = false, allowed_executables = [] }
            executable_policies = { codex = { enforce_wrapper_defaults = false, approval_policy = "selected-approval", config_overrides = { selected = "present", shared = "selected" } } }
            "#,
        )
        .unwrap();

        let built_in = crate::profile::built_in_profile("generic").unwrap();
        let defaults = file.defaults;
        let selected = file.profiles["generic"].clone();
        let mut run_args = args("generic");
        run_args.backend = Some(BackendKind::Bwrap);
        run_args.capability_file = Some(PathBuf::from("/cli/capability.toml"));
        run_args.identity_mode = Some(SandboxIdentityMode::SandboxUser);
        run_args.preserve_host_user = true;
        run_args.allow_non_structural = true;
        let cli = cli_profile_patch(&run_args);

        let after_defaults = built_in.clone().merge(defaults);
        let after_selected = after_defaults.clone().merge(selected);
        let after_cli = after_selected.clone().merge(cli);
        let stages = [
            (
                built_in,
                StageExpectation {
                    name: "built-in",
                    backend: None,
                    allow_non_structural: Some(false),
                    use_http_proxy_sidecar: Some(true),
                    identity_mode: None,
                    capability_file: None,
                },
            ),
            (
                after_defaults,
                StageExpectation {
                    name: "defaults",
                    backend: Some(firma_config_schema::run::BackendKind::Vz),
                    allow_non_structural: Some(true),
                    use_http_proxy_sidecar: Some(true),
                    identity_mode: Some(SandboxIdentityMode::HostUser),
                    capability_file: Some("/defaults/capability.toml"),
                },
            ),
            (
                after_selected,
                StageExpectation {
                    name: "selected profile",
                    backend: Some(firma_config_schema::run::BackendKind::Wsl2),
                    allow_non_structural: Some(false),
                    use_http_proxy_sidecar: Some(false),
                    identity_mode: Some(SandboxIdentityMode::SandboxUser),
                    capability_file: None,
                },
            ),
            (
                after_cli.clone(),
                StageExpectation {
                    name: "CLI",
                    backend: Some(firma_config_schema::run::BackendKind::Bwrap),
                    allow_non_structural: Some(true),
                    use_http_proxy_sidecar: Some(false),
                    identity_mode: Some(SandboxIdentityMode::HostUser),
                    capability_file: Some("/cli/capability.toml"),
                },
            ),
        ];

        for (patch, expected) in stages {
            assert_eq!(patch.backend, expected.backend, "{} backend", expected.name);
            assert_eq!(
                patch.allow_non_structural, expected.allow_non_structural,
                "{} allow_non_structural",
                expected.name
            );
            assert_eq!(
                patch.use_http_proxy_sidecar, expected.use_http_proxy_sidecar,
                "{} use_http_proxy_sidecar",
                expected.name
            );
            assert_eq!(
                patch.identity_mode, expected.identity_mode,
                "{} identity_mode",
                expected.name
            );
            assert_eq!(
                capability_file(&patch),
                expected.capability_file.map(std::path::Path::new),
                "{} capability source",
                expected.name
            );
        }

        assert_eq!(
            after_cli.sidecar_endpoint.as_deref(),
            Some("unix:///defaults/sidecar.sock")
        );
        assert!(
            after_cli
                .env_passthrough
                .as_ref()
                .is_some_and(Vec::is_empty)
        );
        let env_set = after_cli.env_set.as_ref().unwrap();
        assert_eq!(
            env_set.get("DEFAULT_ONLY").map(String::as_str),
            Some("preserved")
        );
        assert_eq!(env_set.get("SHARED").map(String::as_str), Some("selected"));
        assert_eq!(
            env_set.get("SELECTED_ONLY").map(String::as_str),
            Some("present")
        );
        let mounts = after_cli.mounts.as_ref().unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].source, PathBuf::from("/selected/source"));
        assert_eq!(mounts[0].target, PathBuf::from("/selected/target"));
        assert!(!mounts[0].read_only);

        let network = after_cli.network.as_ref().unwrap();
        assert_eq!(network.enforce_network_namespace, Some(true));
        assert_eq!(network.fail_closed, Some(false));
        let seccomp = after_cli.seccomp_policy.as_ref().unwrap();
        assert_eq!(
            seccomp.source_policy_path,
            Some(PathBuf::from("/defaults/seccomp.toml"))
        );
        assert_eq!(
            seccomp.artifact_dir,
            Some(PathBuf::from("/defaults/artifacts"))
        );
        assert_eq!(
            seccomp.runtime_mode,
            Some(SeccompRuntimeMode::PrecompiledOnly)
        );

        let capability = after_cli.capability.as_ref().unwrap();
        assert_eq!(
            capability.public_key_path,
            Some(PathBuf::from("/defaults/authority.pub"))
        );
        assert_eq!(capability.refresh_ratio, Some(0.7));
        assert_eq!(capability.grace, Some(Duration::from_secs(45)));
        assert_eq!(capability.requested_actions, Some(Vec::new()));

        let mediator = after_cli.sidecar_local_exec.as_ref().unwrap();
        assert_eq!(
            mediator.endpoint.as_deref(),
            Some("unix:///defaults/local-exec.sock")
        );
        assert_eq!(
            mediator.timeout.map(|timeout| timeout.duration()),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            mediator.hitl_mode,
            Some(CommandMediatorHitlMode::AsyncToken)
        );
        assert_eq!(
            mediator.hitl_max_wait.map(|timeout| timeout.duration()),
            Some(Duration::from_mins(4))
        );
        assert_eq!(mediator.enforce_known_executables, Some(false));
        assert!(
            mediator
                .allowed_executables
                .as_ref()
                .is_some_and(Vec::is_empty)
        );

        let codex = &after_cli.executable_policies.as_ref().unwrap()["codex"];
        assert_eq!(codex.enforce_wrapper_defaults, Some(false));
        assert_eq!(codex.sandbox_mode.as_deref(), Some("defaults-sandbox"));
        assert_eq!(codex.approval_policy.as_deref(), Some("selected-approval"));
        assert_eq!(
            codex.config_overrides,
            Some(BTreeMap::from([
                ("defaults".to_string(), "preserved".to_string()),
                ("selected".to_string(), "present".to_string()),
                ("shared".to_string(), "selected".to_string()),
            ]))
        );
        assert_eq!(after_cli.mask_home_paths, Some(Vec::new()));
        assert_eq!(after_cli.ca_trust_mode, Some(super::CaTrustMode::Sole));

        assert_profile_patch_contract_inventory(after_cli);
        assert_capability_source_variant_inventory(CapabilitySourcePatch::Disabled);
        assert_capability_source_variant_inventory(CapabilitySourcePatch::File {
            path: PathBuf::from("/inventory"),
        });
    }

    fn assert_profile_patch_contract_inventory(patch: ProfilePatch) {
        let ProfilePatch {
            backend: _,
            sidecar_endpoint: _,
            seccomp_policy,
            env_passthrough: _,
            env_set: _,
            mounts,
            network,
            identity_mode: _,
            capability,
            sidecar_local_exec,
            executable_policies,
            use_http_proxy_sidecar,
            allow_non_structural,
            mask_home_paths,
            ca_trust_mode,
            secret_providers,
        } = patch;

        for MountPatch {
            source,
            target,
            read_only,
        } in mounts.unwrap_or_default()
        {
            let _ = (source, target, read_only);
        }
        if let Some(NetworkPolicyPatch {
            enforce_network_namespace,
            fail_closed,
        }) = network
        {
            let _ = (enforce_network_namespace, fail_closed);
        }
        if let Some(SeccompPolicyPatch {
            source_policy_path,
            artifact_dir,
            runtime_mode,
        }) = seccomp_policy
        {
            let _ = (source_policy_path, artifact_dir, runtime_mode);
        }
        if let Some(CapabilityLeasePatch {
            source,
            public_key_path,
            refresh_ratio,
            grace,
            requested_actions,
        }) = capability
        {
            let _ = (
                source,
                public_key_path,
                refresh_ratio,
                grace,
                requested_actions,
            );
        }
        if let Some(CommandMediatorPatch {
            endpoint,
            timeout,
            hitl_mode,
            hitl_max_wait,
            enforce_known_executables,
            allowed_executables,
        }) = sidecar_local_exec
        {
            let _ = (
                endpoint,
                timeout,
                hitl_mode,
                hitl_max_wait,
                enforce_known_executables,
                allowed_executables,
            );
        }
        for ExecutableLaunchPolicyPatch {
            enforce_wrapper_defaults,
            sandbox_mode,
            approval_policy,
            config_overrides,
        } in executable_policies.unwrap_or_default().into_values()
        {
            let _ = (
                enforce_wrapper_defaults,
                sandbox_mode,
                approval_policy,
                config_overrides,
            );
        }
    }

    fn assert_capability_source_variant_inventory(source: CapabilitySourcePatch) {
        match source {
            CapabilitySourcePatch::Disabled => {}
            CapabilitySourcePatch::File { path } => {
                let _ = path;
            }
        }
    }

    #[test]
    fn top_level_collection_merge_obeys_each_shape_contract() {
        let lower = ProfilePatch {
            env_passthrough: Some(vec!["LOWER".to_string()]),
            env_set: Some(BTreeMap::from([
                ("LOWER".to_string(), "preserved".to_string()),
                ("SHARED".to_string(), "lower".to_string()),
            ])),
            mounts: Some(vec![MountPatch {
                source: PathBuf::from("/lower"),
                target: PathBuf::from("/workspace"),
                read_only: true,
            }]),
            ..ProfilePatch::default()
        };

        let inherited = lower.clone().merge(ProfilePatch::default());
        assert_eq!(inherited.env_passthrough, lower.env_passthrough);
        assert_eq!(inherited.env_set, lower.env_set);
        assert_eq!(
            inherited.mounts.as_ref().map(|mounts| &mounts[0].source),
            Some(&PathBuf::from("/lower"))
        );

        let replaced = lower.clone().merge(ProfilePatch {
            env_passthrough: Some(vec!["HIGHER".to_string()]),
            env_set: Some(BTreeMap::from([
                ("HIGHER".to_string(), "added".to_string()),
                ("SHARED".to_string(), "higher".to_string()),
            ])),
            mounts: Some(vec![MountPatch {
                source: PathBuf::from("/higher"),
                target: PathBuf::from("/workspace"),
                read_only: false,
            }]),
            ..ProfilePatch::default()
        });
        assert_eq!(replaced.env_passthrough, Some(vec!["HIGHER".to_string()]));
        assert_eq!(
            replaced.env_set,
            Some(BTreeMap::from([
                ("HIGHER".to_string(), "added".to_string()),
                ("LOWER".to_string(), "preserved".to_string()),
                ("SHARED".to_string(), "higher".to_string()),
            ]))
        );
        assert_eq!(
            replaced.mounts.as_ref().map(|mounts| &mounts[0].source),
            Some(&PathBuf::from("/higher"))
        );

        let cleared = lower.merge(ProfilePatch {
            env_passthrough: Some(Vec::new()),
            env_set: Some(BTreeMap::new()),
            mounts: Some(Vec::new()),
            ..ProfilePatch::default()
        });
        assert_eq!(cleared.env_passthrough, Some(Vec::new()));
        assert_eq!(cleared.env_set, Some(BTreeMap::new()));
        assert!(cleared.mounts.as_ref().is_some_and(Vec::is_empty));
    }

    #[test]
    fn network_and_seccomp_patches_merge_field_by_field() {
        let merged = ProfilePatch {
            network: Some(NetworkPolicyPatch {
                enforce_network_namespace: Some(true),
                fail_closed: Some(true),
            }),
            seccomp_policy: Some(SeccompPolicyPatch {
                source_policy_path: Some(PathBuf::from("/policy/lower.toml")),
                artifact_dir: Some(PathBuf::from("/artifacts/lower")),
                runtime_mode: Some(SeccompRuntimeMode::CompileOnLaunch),
            }),
            ..ProfilePatch::default()
        }
        .merge(ProfilePatch {
            network: Some(NetworkPolicyPatch {
                enforce_network_namespace: Some(false),
                fail_closed: None,
            }),
            seccomp_policy: Some(SeccompPolicyPatch {
                source_policy_path: None,
                artifact_dir: Some(PathBuf::from("/artifacts/higher")),
                runtime_mode: Some(SeccompRuntimeMode::PrecompiledOnly),
            }),
            ..ProfilePatch::default()
        });

        let network = merged.network.unwrap();
        assert_eq!(network.enforce_network_namespace, Some(false));
        assert_eq!(network.fail_closed, Some(true));
        let seccomp = merged.seccomp_policy.unwrap();
        assert_eq!(
            seccomp.source_policy_path,
            Some(PathBuf::from("/policy/lower.toml"))
        );
        assert_eq!(
            seccomp.artifact_dir,
            Some(PathBuf::from("/artifacts/higher"))
        );
        assert_eq!(
            seccomp.runtime_mode,
            Some(SeccompRuntimeMode::PrecompiledOnly)
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "bwrap-only")]
    fn file_network_and_seccomp_layers_preserve_lower_siblings() {
        let tmpdir = tempfile::tempdir().unwrap();
        fs::write(
            tmpdir.path().join("policy.toml"),
            "default_action = \"allow\"\n",
        )
        .unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(
            &config_path,
            r#"
            [run.defaults.network]
            enforce_network_namespace = false
            fail_closed = false

            [run.defaults.seccomp_policy]
            source_policy_path = "policy.toml"
            artifact_dir = "artifacts"

            [run.profiles.generic.network]
            fail_closed = true

            [run.profiles.generic.seccomp_policy]
            runtime_mode = "precompiled_only"
            "#,
        )
        .unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();

        assert!(!resolved.network.enforce_network_namespace);
        assert!(resolved.network.fail_closed);
        let seccomp = resolved.seccomp_policy.unwrap();
        assert_eq!(
            seccomp.source_policy_path,
            tmpdir.path().join("policy.toml")
        );
        assert_eq!(seccomp.artifact_dir, tmpdir.path().join("artifacts"));
        assert_eq!(seccomp.runtime_mode, SeccompRuntimeMode::PrecompiledOnly);
    }

    #[test]
    fn incomplete_final_seccomp_patch_reports_missing_field() {
        for (body, missing) in [
            (
                r#"
                [run.profiles.generic.seccomp_policy]
                runtime_mode = "precompiled_only"
                "#,
                "seccomp_policy.source_policy_path",
            ),
            (
                r#"
                [run.profiles.generic.seccomp_policy]
                source_policy_path = "policy.toml"
                "#,
                "seccomp_policy.artifact_dir",
            ),
        ] {
            let tmpdir = tempfile::tempdir().unwrap();
            let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
            fs::write(&config_path, body).unwrap();
            let mut run_args = args("generic");
            run_args.config = Some(config_path);

            let error = resolve_profile(&run_args).expect_err("incomplete seccomp must fail");
            assert!(
                error.to_string().contains(missing),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn command_mediator_patch_merges_siblings_and_replaces_allowlist() {
        let merged = CommandMediatorPatch {
            endpoint: Some("unix:///run/firma/tools.sock".to_string()),
            timeout: Some(NonZeroDuration::try_from(Duration::from_secs(1)).unwrap()),
            hitl_mode: Some(CommandMediatorHitlMode::SyncWait),
            hitl_max_wait: Some(NonZeroDuration::try_from(Duration::from_mins(5)).unwrap()),
            enforce_known_executables: Some(true),
            allowed_executables: Some(vec![PathBuf::from("/usr/bin/lower")]),
        }
        .merge(CommandMediatorPatch {
            endpoint: None,
            timeout: None,
            hitl_mode: Some(CommandMediatorHitlMode::AsyncToken),
            hitl_max_wait: Some(NonZeroDuration::try_from(Duration::from_mins(2)).unwrap()),
            enforce_known_executables: Some(false),
            allowed_executables: Some(Vec::new()),
        });

        assert_eq!(
            merged.endpoint.as_deref(),
            Some("unix:///run/firma/tools.sock")
        );
        assert_eq!(
            merged.timeout.map(|timeout| timeout.duration()),
            Some(Duration::from_secs(1))
        );
        assert_eq!(merged.hitl_mode, Some(CommandMediatorHitlMode::AsyncToken));
        assert_eq!(
            merged.hitl_max_wait.map(|timeout| timeout.duration()),
            Some(Duration::from_mins(2))
        );
        assert_eq!(merged.enforce_known_executables, Some(false));
        assert!(
            merged
                .allowed_executables
                .as_ref()
                .is_some_and(Vec::is_empty)
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_mediator_file_layers_merge_and_empty_allowlist_clears() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(
            &config_path,
            r#"
            [run.defaults]
            sidecar_endpoint = "unix:///run/firma/sidecar.sock"

            [run.defaults.sidecar_local_exec]
            timeout = "1s"
            hitl_mode = "sync_wait"
            hitl_max_wait = "5m"
            enforce_known_executables = true
            allowed_executables = ["/lower/will-be-cleared"]

            [run.profiles.generic.sidecar_local_exec]
            hitl_mode = "async_token"
            enforce_known_executables = false
            allowed_executables = []
            "#,
        )
        .unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();
        let mediator = resolved.sidecar_local_exec.unwrap();

        assert_eq!(mediator.timeout, Duration::from_secs(1));
        assert_eq!(mediator.hitl_mode, CommandMediatorHitlMode::AsyncToken);
        assert_eq!(mediator.hitl_max_wait, Duration::from_mins(5));
        assert!(!mediator.enforce_known_executables);
        assert!(mediator.allowed_executables.is_empty());
    }

    #[test]
    fn executable_policy_maps_merge_entries_fields_and_config_keys() {
        let lower = ProfilePatch {
            executable_policies: Some(BTreeMap::from([
                (
                    "codex".to_string(),
                    ExecutableLaunchPolicyPatch {
                        enforce_wrapper_defaults: Some(true),
                        sandbox_mode: Some("workspace-write".to_string()),
                        approval_policy: Some("on-request".to_string()),
                        config_overrides: Some(BTreeMap::from([
                            ("lower".to_string(), "preserved".to_string()),
                            ("shared".to_string(), "lower".to_string()),
                        ])),
                    },
                ),
                (
                    "other".to_string(),
                    ExecutableLaunchPolicyPatch {
                        enforce_wrapper_defaults: Some(true),
                        sandbox_mode: None,
                        approval_policy: None,
                        config_overrides: None,
                    },
                ),
            ])),
            ..ProfilePatch::default()
        };
        let merged = lower.clone().merge(ProfilePatch {
            executable_policies: Some(BTreeMap::from([(
                "codex".to_string(),
                ExecutableLaunchPolicyPatch {
                    enforce_wrapper_defaults: Some(false),
                    sandbox_mode: None,
                    approval_policy: Some("never".to_string()),
                    config_overrides: Some(BTreeMap::from([
                        ("higher".to_string(), "added".to_string()),
                        ("shared".to_string(), "higher".to_string()),
                    ])),
                },
            )])),
            ..ProfilePatch::default()
        });

        let policies = merged.executable_policies.as_ref().unwrap();
        assert!(policies.contains_key("other"));
        let codex = &policies["codex"];
        assert_eq!(codex.enforce_wrapper_defaults, Some(false));
        assert_eq!(codex.sandbox_mode.as_deref(), Some("workspace-write"));
        assert_eq!(codex.approval_policy.as_deref(), Some("never"));
        assert_eq!(
            codex.config_overrides,
            Some(BTreeMap::from([
                ("higher".to_string(), "added".to_string()),
                ("lower".to_string(), "preserved".to_string()),
                ("shared".to_string(), "higher".to_string()),
            ]))
        );

        let cleared = lower.merge(ProfilePatch {
            executable_policies: Some(BTreeMap::new()),
            ..ProfilePatch::default()
        });
        assert!(
            cleared
                .executable_policies
                .as_ref()
                .is_some_and(BTreeMap::is_empty)
        );
    }

    #[test]
    fn executable_policy_file_layer_partially_overrides_built_in_entry() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(
            &config_path,
            r#"
            [run.profiles.codex.executable_policies.codex]
            enforce_wrapper_defaults = false

            [run.profiles.codex.executable_policies.codex.config_overrides]
            custom = "higher"
            "#,
        )
        .unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();
        let policy = &resolved.executable_policies["codex"];

        assert!(!policy.enforce_wrapper_defaults);
        assert!(policy.sandbox_mode.is_some());
        assert_eq!(policy.approval_policy.as_deref(), Some("never"));
        assert_eq!(
            policy.config_overrides.get("custom").map(String::as_str),
            Some("higher")
        );
        assert_eq!(
            policy
                .config_overrides
                .get("shell_environment_policy.inherit")
                .map(String::as_str),
            Some("all")
        );
    }

    #[test]
    fn explicit_empty_executable_policy_map_clears_built_in_entries() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(&config_path, "[run.profiles.codex.executable_policies]\n").unwrap();

        let mut run_args = args("codex");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();

        assert!(resolved.executable_policies.is_empty());
    }

    #[test]
    fn explicit_empty_top_level_collections_clear_built_in_values() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(
            &config_path,
            r"
            [run.profiles.generic]
            env_passthrough = []
            mounts = []

            [run.profiles.generic.env_set]
            ",
        )
        .unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();

        assert!(resolved.env_passthrough.is_empty());
        assert!(resolved.env_set.is_empty());
        assert!(resolved.mounts.is_empty());
    }

    #[test]
    fn profile_booleans_follow_file_layers_and_cli_precedence() {
        let tmpdir = tempfile::tempdir().unwrap();
        let config_path = tmpdir.path().join(CONFIG_FILE_NAME);
        fs::write(
            &config_path,
            r"
            [run.defaults]
            use_http_proxy_sidecar = false
            allow_non_structural = true

            [run.profiles.generic]
            allow_non_structural = false
            ",
        )
        .unwrap();

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        run_args.allow_non_structural = false;

        let resolved = resolve_profile(&run_args).unwrap();
        assert!(!resolved.use_http_proxy_sidecar);
        assert!(!resolved.allow_non_structural);

        run_args.allow_non_structural = true;
        let cli_resolved = resolve_profile(&run_args).unwrap();
        assert!(cli_resolved.allow_non_structural);
        assert!(!cli_resolved.use_http_proxy_sidecar);
    }

    #[test]
    fn unsupplied_enable_only_cli_boolean_is_absent() {
        let mut run_args = args("generic");
        run_args.allow_non_structural = false;
        let absent = cli_profile_patch(&run_args);
        assert_eq!(absent.allow_non_structural, None);
        assert_eq!(absent.use_http_proxy_sidecar, None);

        run_args.allow_non_structural = true;
        assert_eq!(
            cli_profile_patch(&run_args).allow_non_structural,
            Some(true)
        );
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
timeout = "700ms"
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
        assert_eq!(mediator.timeout, Duration::from_millis(700));
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
timeout = "500ms"
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
timeout = "500ms"
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
        let allowed_codex = tmpdir.path().join("codex");
        let allowed_claude = tmpdir.path().join("claude");
        let allowed_bash = tmpdir.path().join("bash");
        for path in [&allowed_codex, &allowed_claude, &allowed_bash] {
            fs::write(path, "test executable").unwrap();
        }
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
timeout = "800ms"
hitl_mode = "async_token"
enforce_known_executables = true
allowed_executables = ['{}', '{}', '{}']
"#,
            policy_path.display(),
            artifact_dir.display(),
            allowed_codex.display(),
            allowed_claude.display(),
            allowed_bash.display()
        );
        fs::write(&config_path, toml).unwrap();
        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap();
        let mediator = resolved.sidecar_local_exec.unwrap();
        assert!(mediator.enforce_known_executables);
        assert!(
            mediator
                .allowed_executables
                .contains(&fs::canonicalize(allowed_codex).unwrap())
        );
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
timeout = "700ms"
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
