use std::collections::BTreeMap;
use std::path::PathBuf;

use firma_config::AgentProfile;

use crate::config::{
    CapabilityLeasePatch, CapabilitySourcePatch, ExecutableLaunchPolicyPatch, MountPatch,
    NetworkPolicyPatch, ProfilePatch,
};
use crate::error::RunError;

/// Returns built-in profile patch for a given profile id.
pub(crate) fn built_in_profile(profile: &str) -> Result<ProfilePatch, RunError> {
    match AgentProfile::from_name(profile) {
        Some(AgentProfile::Generic) => Ok(generic_profile()),
        Some(AgentProfile::Codex) => Ok(codex_profile()),
        Some(AgentProfile::ClaudeCode) => Ok(claude_code_profile()),
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

fn nested_bwrap_restricted() -> bool {
    if std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .is_ok_and(|s| s.trim() == "0")
    {
        return true;
    }
    std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .is_ok_and(|s| s.trim() == "1")
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

    // When nested bwrap is restricted (Ubuntu, Debian ≥12, hardened kernels),
    // codex's internal bwrap sandbox cannot run inside firma's outer sandbox.
    // danger-full-access disables codex's internal sandbox; firma's outer
    // sandbox provides equivalent isolation. Elsewhere keep workspace-write.
    let (sandbox_mode, config_overrides) = if nested_bwrap_restricted() {
        (
            "danger-full-access".to_string(),
            BTreeMap::from([(
                "shell_environment_policy.inherit".to_string(),
                "all".to_string(),
            )]),
        )
    } else {
        (
            "workspace-write".to_string(),
            BTreeMap::from([
                (
                    "sandbox_workspace_write.network_access".to_string(),
                    "true".to_string(),
                ),
                (
                    "shell_environment_policy.inherit".to_string(),
                    "all".to_string(),
                ),
            ]),
        )
    };

    base.executable_policies.insert(
        "codex".to_string(),
        ExecutableLaunchPolicyPatch {
            enforce_wrapper_defaults: Some(true),
            sandbox_mode: Some(sandbox_mode),
            approval_policy: Some("never".to_string()),
            config_overrides,
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
