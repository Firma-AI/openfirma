use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
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
    pub env_passthrough: BTreeSet<String>,
    pub env_set: BTreeMap<String, String>,
    pub mounts: Vec<MountSpec>,
    pub seccomp_bpf_path: Option<PathBuf>,
    pub seccomp_managed: Option<ManagedSeccompPolicyConfig>,
    pub allowed_domains: Vec<String>,
    pub network: NetworkPolicy,
    pub identity_mode: SandboxIdentityMode,
    pub capability: CapabilityLeaseConfig,
    pub executable_policies: BTreeMap<String, ExecutableLaunchPolicy>,
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

        if let Some(path) = &self.seccomp_bpf_path {
            if !path.is_absolute() {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_bpf_path must be absolute: {}",
                    path.display()
                )));
            }
            if !path.is_file() {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_bpf_path must point to an existing file: {}",
                    path.display()
                )));
            }
            if self.backend != BackendKind::Bwrap {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_bpf_path is only supported with backend 'bwrap', got '{backend}'",
                    backend = self.backend
                )));
            }
        }

        if self.seccomp_bpf_path.is_some() && self.seccomp_managed.is_some() {
            return Err(RunError::ConfigValidation(
                "seccomp_bpf_path and seccomp_managed are mutually exclusive".to_string(),
            ));
        }

        if let Some(managed) = &self.seccomp_managed {
            if !managed.source_policy_path.is_absolute() {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_managed.source_policy_path must be absolute: {}",
                    managed.source_policy_path.display()
                )));
            }
            if !managed.source_policy_path.is_file() {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_managed.source_policy_path must point to an existing file: {}",
                    managed.source_policy_path.display()
                )));
            }
            if !managed.artifact_dir.is_absolute() {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_managed.artifact_dir must be absolute: {}",
                    managed.artifact_dir.display()
                )));
            }
            if self.backend != BackendKind::Bwrap {
                return Err(RunError::ConfigValidation(format!(
                    "seccomp_managed is only supported with backend 'bwrap', got '{backend}'",
                    backend = self.backend
                )));
            }
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

/// Managed seccomp policy compilation settings for Linux bwrap backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedSeccompPolicyConfig {
    pub source_policy_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub verify_checksum: bool,
}

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
    pub(crate) seccomp_bpf_path: Option<PathBuf>,
    pub(crate) seccomp_managed: Option<ManagedSeccompPolicyPatch>,
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
    #[serde(default)]
    pub(crate) executable_policies: BTreeMap<String, ExecutableLaunchPolicyPatch>,
    #[serde(default)]
    pub(crate) codex_cli: Option<ExecutableLaunchPolicyPatch>,
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
pub(crate) struct ManagedSeccompPolicyPatch {
    pub(crate) source_policy_path: PathBuf,
    pub(crate) artifact_dir: PathBuf,
    pub(crate) verify_checksum: Option<bool>,
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
            seccomp_bpf_path: higher.seccomp_bpf_path.or(self.seccomp_bpf_path),
            seccomp_managed: higher.seccomp_managed.or(self.seccomp_managed),
            env_passthrough,
            env_set,
            mounts,
            allowed_domains,
            network: higher.network.or(self.network),
            identity_mode: higher.identity_mode.or(self.identity_mode),
            capability: higher.capability.or(self.capability),
            executable_policies,
            codex_cli: higher.codex_cli.or(self.codex_cli),
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
    let mut patch = built_in_profile(&args.profile)?;

    if let Some(path) = &args.config {
        let file_patch = read_config(path, &args.profile)?;
        patch = patch.merge(file_patch);
    }

    let cli_patch = cli_profile_patch(args);
    patch = patch.merge(cli_patch);

    let backend = patch
        .backend
        .unwrap_or_else(BackendKind::default_for_current_host);

    let sidecar_endpoint_value = patch.sidecar_endpoint.as_deref().map_or_else(
        || {
            std::env::var("FIRMA_SIDECAR_ENDPOINT")
                .unwrap_or_else(|_| "tcp://127.0.0.1:8080".to_string())
        },
        ToOwned::to_owned,
    );
    let sidecar_endpoint = sidecar_endpoint_value
        .parse::<SidecarEndpoint>()
        .map_err(RunError::ConfigValidation)?;

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

    let resolved = ResolvedProfile {
        id: args.profile.clone(),
        backend,
        sidecar_endpoint,
        env_passthrough,
        env_set: patch.env_set,
        mounts,
        seccomp_bpf_path: patch.seccomp_bpf_path,
        seccomp_managed: patch.seccomp_managed.map(managed_seccomp_from_patch),
        allowed_domains: patch.allowed_domains,
        network,
        identity_mode,
        capability,
        executable_policies,
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

fn cli_profile_patch(args: &RunInput) -> ProfilePatch {
    ProfilePatch {
        backend: args.backend,
        sidecar_endpoint: args.sidecar_endpoint.clone(),
        seccomp_bpf_path: None,
        seccomp_managed: None,
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
        executable_policies: BTreeMap::new(),
        codex_cli: None,
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

fn managed_seccomp_from_patch(patch: ManagedSeccompPolicyPatch) -> ManagedSeccompPolicyConfig {
    ManagedSeccompPolicyConfig {
        source_policy_path: patch.source_policy_path,
        artifact_dir: patch.artifact_dir,
        verify_checksum: patch.verify_checksum.unwrap_or(true),
    }
}

fn read_config(path: &Path, profile: &str) -> Result<ProfilePatch, RunError> {
    let content = std::fs::read_to_string(path).map_err(|error| RunError::ConfigParse {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;

    let ext = path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    let parsed = if ext == "yaml" || ext == "yml" {
        serde_yaml::from_str::<FileConfig>(&content).map_err(|error| RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?
    } else {
        toml::from_str::<FileConfig>(&content).map_err(|error| RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?
    };

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
        BackendKind, CapabilitySource, SandboxIdentityMode, SidecarEndpoint, resolve_profile,
    };

    fn args(profile: &str) -> RunInput {
        RunInput {
            profile: profile.to_string(),
            config: None,
            backend: None,
            sidecar_endpoint: None,
            capability_file: None,
            identity_mode: None,
            preserve_host_user: false,
            print_effective_config: false,
            sidecar_mode: crate::runtime::SidecarMode::Auto,
            no_autostart: false,
            sidecar_template_path: None,
            sidecar_startup_timeout_secs: 10,
            command: vec!["echo".to_string(), "ok".to_string()],
            authority_cli: crate::authority::AuthorityCli::Unset,
            authority_profile: firma_authority::DEFAULT_PROFILE.to_string(),
            user_config_path: None,
        }
    }

    #[test]
    fn resolves_generic_defaults() {
        let resolved = resolve_profile(&args("generic")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved.id, "generic");
        assert_eq!(resolved.backend, BackendKind::default_for_current_host());
        assert_eq!(
            resolved.sidecar_endpoint,
            SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}"))
            }
        );
        assert_eq!(resolved.identity_mode, SandboxIdentityMode::SandboxUser);
    }

    #[test]
    fn yaml_config_overrides_profile() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let config_path = tmpdir.path().join("firma-run.yaml");

        let seccomp_path = tmpdir.path().join("seccomp.bpf");
        fs::write(&seccomp_path, [0_u8; 8]).unwrap_or_else(|e| panic!("{e}"));

        let yaml = format!(
            r#"
defaults:
  sidecar_endpoint: "tcp://127.0.0.1:18080"
profiles:
  codex:
    backend: bwrap
    seccomp_bpf_path: {}
    identity_mode: host_user
    env_passthrough:
      - HOME
    capability:
      kind: file
      path: /tmp/capability.token
"#,
            seccomp_path.display()
        );
        fs::write(&config_path, yaml).unwrap_or_else(|e| panic!("{e}"));

        let mut run_args = args("codex");
        run_args.config = Some(config_path);

        let resolved = resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved.backend, BackendKind::Bwrap);
        assert_eq!(resolved.seccomp_bpf_path, Some(seccomp_path));
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
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let config_path = tmpdir.path().join("firma-run.toml");
        let toml = r#"
[profiles.codex.codex_cli]
enforce_wrapper_defaults = true
sandbox_mode = "workspace-write"
approval_policy = "never"
"#;
        fs::write(&config_path, toml).unwrap_or_else(|e| panic!("{e}"));

        let mut run_args = args("codex");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));

        let policy = resolved
            .executable_policies
            .get("codex")
            .unwrap_or_else(|| panic!("missing codex executable policy"));
        assert!(policy.enforce_wrapper_defaults);
        assert_eq!(policy.sandbox_mode.as_deref(), Some("workspace-write"));
        assert_eq!(policy.approval_policy.as_deref(), Some("never"));
    }

    #[test]
    fn preserve_host_user_cli_overrides_profile_identity_mode() {
        let mut run_args = args("generic");
        run_args.identity_mode = Some(SandboxIdentityMode::SandboxUser);
        run_args.preserve_host_user = true;

        let resolved = resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved.identity_mode, SandboxIdentityMode::HostUser);
    }

    #[test]
    fn resolves_claude_code_profile() {
        let resolved = resolve_profile(&args("claude-code")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved.id, "claude-code");
        assert!(resolved.env_passthrough.contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn structural_network_defaults_to_true_for_bwrap_backend() {
        let mut run_args = args("generic");
        run_args.backend = Some(BackendKind::Bwrap);

        let resolved = resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));
        assert!(resolved.network.enforce_network_namespace);
        assert!(resolved.network.fail_closed);
    }

    #[test]
    fn structural_network_defaults_to_false_for_non_bwrap_backends() {
        let mut run_args = args("generic");
        run_args.backend = Some(BackendKind::Vz);

        let resolved = resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));
        assert!(!resolved.network.enforce_network_namespace);
        assert!(resolved.network.fail_closed);
    }

    #[test]
    fn structural_network_true_on_non_bwrap_backend_is_rejected() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let config_path = tmpdir.path().join("firma-run.toml");
        let toml = r#"
[profiles.generic]
backend = "vz"

[profiles.generic.network]
enforce_network_namespace = true
fail_closed = true
"#;
        fs::write(&config_path, toml).unwrap_or_else(|e| panic!("{e}"));

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
    fn seccomp_bpf_path_rejected_for_non_bwrap_backend() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let seccomp_path = tmpdir.path().join("seccomp.bpf");
        fs::write(&seccomp_path, [0_u8; 8]).unwrap_or_else(|e| panic!("{e}"));

        let config_path = tmpdir.path().join("firma-run.toml");
        // TOML literal string (single quotes) keeps backslashes verbatim so
        // Windows paths like `C:\Users\...` parse without escape interpretation.
        let toml = format!(
            r#"
[profiles.generic]
backend = "vz"
seccomp_bpf_path = '{}'
"#,
            seccomp_path.display()
        );
        fs::write(&config_path, toml).unwrap_or_else(|e| panic!("{e}"));

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let err =
            resolve_profile(&run_args).expect_err("expected seccomp backend validation error");
        assert!(
            err.to_string()
                .contains("seccomp_bpf_path is only supported with backend 'bwrap'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn seccomp_managed_resolves_when_configured_for_bwrap() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
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
        .unwrap_or_else(|e| panic!("{e}"));
        let artifact_dir = tmpdir.path().join("artifacts");

        let config_path = tmpdir.path().join("firma-run.toml");
        let toml = format!(
            r#"
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_managed]
source_policy_path = '{}'
artifact_dir = '{}'
verify_checksum = true
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap_or_else(|e| panic!("{e}"));

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let resolved = resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));
        assert!(resolved.seccomp_managed.is_some());
    }

    #[test]
    fn seccomp_managed_rejected_for_non_bwrap_backend() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
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
        .unwrap_or_else(|e| panic!("{e}"));
        let artifact_dir = tmpdir.path().join("artifacts");

        let config_path = tmpdir.path().join("firma-run.toml");
        let toml = format!(
            r#"
[profiles.generic]
backend = "vz"

[profiles.generic.seccomp_managed]
source_policy_path = '{}'
artifact_dir = '{}'
"#,
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap_or_else(|e| panic!("{e}"));

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let err = resolve_profile(&run_args).expect_err("expected backend validation error");
        assert!(
            err.to_string()
                .contains("seccomp_managed is only supported with backend 'bwrap'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn seccomp_managed_and_legacy_path_are_mutually_exclusive() {
        let tmpdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
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
        .unwrap_or_else(|e| panic!("{e}"));
        let artifact_dir = tmpdir.path().join("artifacts");
        let seccomp_path = tmpdir.path().join("legacy.bpf");
        fs::write(&seccomp_path, [0_u8; 8]).unwrap_or_else(|e| panic!("{e}"));

        let config_path = tmpdir.path().join("firma-run.toml");
        let toml = format!(
            r#"
[profiles.generic]
backend = "bwrap"
seccomp_bpf_path = '{}'

[profiles.generic.seccomp_managed]
source_policy_path = '{}'
artifact_dir = '{}'
"#,
            seccomp_path.display(),
            policy_path.display(),
            artifact_dir.display()
        );
        fs::write(&config_path, toml).unwrap_or_else(|e| panic!("{e}"));

        let mut run_args = args("generic");
        run_args.config = Some(config_path);
        let err = resolve_profile(&run_args).expect_err("expected mutual exclusivity error");
        assert!(
            err.to_string()
                .contains("seccomp_bpf_path and seccomp_managed are mutually exclusive"),
            "unexpected error: {err}"
        );
    }
}
