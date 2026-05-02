use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::args::RunArgs;
use crate::backend::BackendKind;
use crate::error::RunError;
use crate::profile::built_in_profile;

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
    pub allowed_domains: Vec<String>,
    pub network: NetworkPolicy,
    pub identity_mode: SandboxIdentityMode,
    pub capability: CapabilityLeaseConfig,
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
            env_passthrough,
            env_set,
            mounts,
            allowed_domains,
            network: higher.network.or(self.network),
            identity_mode: higher.identity_mode.or(self.identity_mode),
            capability: higher.capability.or(self.capability),
        }
    }
}

/// Resolve profile configuration for a run invocation.
///
/// # Errors
///
/// Returns an error when profile resolution fails due to invalid inputs,
/// parse errors, or resulting validation failures.
pub fn resolve_profile(args: &RunArgs) -> Result<ResolvedProfile, RunError> {
    let mut patch = built_in_profile(&args.profile)?;

    if let Some(path) = &args.config {
        let file_patch = read_config(path, &args.profile)?;
        patch = patch.merge(file_patch);
    }

    let cli_patch = ProfilePatch {
        backend: args.backend.map(Into::into),
        sidecar_endpoint: args.sidecar_endpoint.clone(),
        seccomp_bpf_path: None,
        env_passthrough: Vec::new(),
        env_set: BTreeMap::new(),
        mounts: Vec::new(),
        allowed_domains: Vec::new(),
        network: None,
        identity_mode: if args.preserve_host_user {
            Some(SandboxIdentityMode::HostUser)
        } else {
            args.identity_mode.map(Into::into)
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
    };
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

    let resolved = ResolvedProfile {
        id: args.profile.clone(),
        backend,
        sidecar_endpoint,
        env_passthrough,
        env_set: patch.env_set,
        mounts,
        seccomp_bpf_path: patch.seccomp_bpf_path,
        allowed_domains: patch.allowed_domains,
        network,
        identity_mode,
        capability,
    };

    resolved.validate()?;
    Ok(resolved)
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

    use crate::args::RunArgs;

    use super::{
        BackendKind, CapabilitySource, SandboxIdentityMode, SidecarEndpoint, resolve_profile,
    };

    fn args(profile: &str) -> RunArgs {
        RunArgs {
            profile: profile.to_string(),
            config: None,
            backend: None,
            sidecar_endpoint: None,
            capability_file: None,
            identity_mode: None,
            preserve_host_user: false,
            print_effective_config: false,
            command: vec!["echo".to_string(), "ok".to_string()],
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
    fn preserve_host_user_cli_overrides_profile_identity_mode() {
        let mut run_args = args("generic");
        run_args.identity_mode = Some(crate::args::IdentityModeOverride::SandboxUser);
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
        run_args.backend = Some(crate::args::BackendOverride::Bwrap);

        let resolved = resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));
        assert!(resolved.network.enforce_network_namespace);
        assert!(resolved.network.fail_closed);
    }

    #[test]
    fn structural_network_defaults_to_false_for_non_bwrap_backends() {
        let mut run_args = args("generic");
        run_args.backend = Some(crate::args::BackendOverride::Vz);

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
        let toml = format!(
            r#"
[profiles.generic]
backend = "vz"
seccomp_bpf_path = "{}"
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
}
