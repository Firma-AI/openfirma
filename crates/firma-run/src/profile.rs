use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::config::{
    CapabilityLeasePatch, CapabilitySourcePatch, ExecutableLaunchPolicyPatch, MountPatch,
    NetworkPolicyPatch, ProfilePatch,
};
use crate::error::RunError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuiltInProfileId {
    Generic,
    Codex,
    ClaudeCode,
}

impl BuiltInProfileId {
    #[must_use]
    pub(crate) fn from_str(profile: &str) -> Option<Self> {
        match profile {
            "generic" => Some(Self::Generic),
            "codex" => Some(Self::Codex),
            "claude-code" => Some(Self::ClaudeCode),
            _ => None,
        }
    }
}

/// Returns built-in profile patch for a given profile id.
pub(crate) fn built_in_profile(profile: &str) -> Result<ProfilePatch, RunError> {
    match BuiltInProfileId::from_str(profile) {
        Some(BuiltInProfileId::Generic) => Ok(generic_profile()),
        Some(BuiltInProfileId::Codex) => Ok(codex_profile()),
        Some(BuiltInProfileId::ClaudeCode) => Ok(claude_code_profile()),
        None => Err(RunError::ConfigValidation(format!(
            "unknown profile '{profile}'; supported profiles: generic, codex, claude-code"
        ))),
    }
}

fn generic_profile() -> ProfilePatch {
    let mut env_set = BTreeMap::new();
    env_set.insert("FIRMA_RUN_PROFILE".to_string(), "generic".to_string());
    env_set.insert(
        "FIRMA_RUN_BWRAP_RUNTIME_HOME".to_string(),
        "false".to_string(),
    );
    // On macOS (vz) and WSL2 backends, structural network-namespace confinement is
    // unavailable; enforcement is proxy-based. Clear NO_PROXY so host env cannot
    // accidentally route traffic around the HTTP proxy Sidecar.
    env_set.insert("NO_PROXY".to_string(), String::new());
    env_set.insert("no_proxy".to_string(), String::new());

    ProfilePatch {
        backend: None,
        sidecar_endpoint: None,
        seccomp_policy: None,
        env_passthrough: vec!["HOME".to_string(), "PATH".to_string(), "TERM".to_string()],
        env_set,
        mounts: vec![MountPatch {
            source: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            target: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            read_only: false,
        }],
        allowed_domains: Vec::new(),
        network: Some(NetworkPolicyPatch {
            // Structural confinement default is backend-aware and resolved later.
            enforce_network_namespace: None,
            fail_closed: Some(true),
        }),
        identity_mode: None,
        capability: Some(CapabilityLeasePatch {
            source: Some(CapabilitySourcePatch::Disabled),
            kind: None,
            path: None,
            refresh_ratio: Some(0.60),
            grace_seconds: Some(30),
        }),
        sidecar_local_exec: None,
        executable_policies: BTreeMap::new(),
        codex_cli: None,
        use_http_proxy_sidecar: true,
        allow_non_structural: false,
        mask_home_paths: None,
    }
}

fn codex_profile() -> ProfilePatch {
    let mut base = generic_profile();
    base.env_set
        .insert("FIRMA_RUN_PROFILE".to_string(), "codex".to_string());
    base.env_passthrough.extend([
        "OPENAI_API_KEY".to_string(),
        "ANTHROPIC_API_KEY".to_string(),
        "CODEX_HOME".to_string(),
    ]);
    base.executable_policies.insert(
        "codex".to_string(),
        ExecutableLaunchPolicyPatch {
            enforce_wrapper_defaults: Some(true),
            sandbox_mode: Some("workspace-write".to_string()),
            approval_policy: Some("never".to_string()),
            config_overrides: BTreeMap::from([
                (
                    "sandbox_workspace_write.network_access".to_string(),
                    "true".to_string(),
                ),
                (
                    "shell_environment_policy.inherit".to_string(),
                    "all".to_string(),
                ),
            ]),
        },
    );
    base
}

fn claude_code_profile() -> ProfilePatch {
    let mut base = generic_profile();
    base.env_set
        .insert("FIRMA_RUN_PROFILE".to_string(), "claude-code".to_string());
    base.env_set.insert(
        "FIRMA_RUN_BWRAP_ROOTFS_MODE".to_string(),
        "readonly".to_string(),
    );
    base.env_set.insert(
        "FIRMA_RUN_BWRAP_MASK_HOME_PATHS".to_string(),
        crate::backend::DEFAULT_SENSITIVE_HOME_SUFFIXES.join(","),
    );
    base.env_passthrough.extend([
        "ANTHROPIC_API_KEY".to_string(),
        "ANTHROPIC_AUTH_TOKEN".to_string(),
        "ANTHROPIC_BASE_URL".to_string(),
        "CLAUDE_CODE_USE_VERTEX".to_string(),
        "CLAUDE_CODE_USE_BEDROCK".to_string(),
    ]);
    base.use_http_proxy_sidecar = true;
    base
}
