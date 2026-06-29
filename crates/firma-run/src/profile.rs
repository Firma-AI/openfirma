use std::collections::BTreeMap;
use std::path::PathBuf;

use firma_config_loader::AgentProfile;

use crate::config::{
    CaTrustMode, CapabilityLeasePatch, CapabilitySourcePatch, ExecutableLaunchPolicyPatch,
    MountPatch, NetworkPolicyPatch, ProfilePatch,
};
use crate::error::RunError;

/// Returns built-in profile patch for a given profile id.
pub(crate) fn built_in_profile(profile: &str) -> Result<ProfilePatch, RunError> {
    match AgentProfile::from_name(profile) {
        Some(AgentProfile::Generic) => Ok(generic_profile()),
        Some(AgentProfile::Codex) => Ok(codex_profile()),
        Some(AgentProfile::ClaudeCode) => Ok(claude_code_profile()),
        Some(AgentProfile::Copilot) => Ok(copilot_profile()),
        None => Err(RunError::ConfigValidation(format!(
            "unknown profile '{profile}'; supported profiles: generic, codex, claude-code, copilot"
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
        ca_trust_mode: None,
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

    // When nested bwrap is restricted (Ubuntu, Debian ≥12, hardened kernels),
    // codex's internal bwrap sandbox cannot run inside firma's outer sandbox.
    // danger-full-access disables codex's internal sandbox; firma's outer
    // sandbox provides equivalent isolation. Elsewhere keep workspace-write.
    base.executable_policies.insert(
        "codex".to_string(),
        codex_executable_policy(crate::backend::platform::nested_userns_restricted()),
    );
    base
}

fn codex_executable_policy(restricted: bool) -> ExecutableLaunchPolicyPatch {
    let (sandbox_mode, config_overrides) = if restricted {
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
    ExecutableLaunchPolicyPatch {
        enforce_wrapper_defaults: Some(true),
        sandbox_mode: Some(sandbox_mode),
        approval_policy: Some("never".to_string()),
        config_overrides,
    }
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

fn copilot_profile() -> ProfilePatch {
    let mut base = generic_profile();
    base.env_set
        .insert("FIRMA_RUN_PROFILE".to_string(), "copilot".to_string());
    // Copilot authenticates to GitHub via env-provided tokens; the SQLite
    // session store lives on the per-session runtime home (no host persistence).
    base.env_passthrough.extend([
        "GITHUB_TOKEN".to_string(),
        "GH_TOKEN".to_string(),
        "GH_COPILOT_TOKEN".to_string(),
    ]);
    // Copilot reaches real (non-MITM'd) GitHub hosts, so the sandbox CA store
    // must contain the system roots in addition to firma-ca. The copilot managed
    // seccomp baseline (config.rs) permits filesystem.delete for SQLite.
    base.ca_trust_mode = Some(CaTrustMode::AppendSystemRoots);
    base.use_http_proxy_sidecar = true;
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copilot_profile_sets_append_ca_and_github_env() {
        let patch = built_in_profile("copilot").unwrap();
        assert_eq!(patch.ca_trust_mode, Some(CaTrustMode::AppendSystemRoots));
        assert!(patch.env_passthrough.contains(&"GITHUB_TOKEN".to_string()));
        assert_eq!(
            patch.env_set.get("FIRMA_RUN_PROFILE"),
            Some(&"copilot".to_string())
        );
    }

    #[test]
    fn codex_policy_workspace_write_includes_network_access() {
        let policy = codex_executable_policy(false);
        assert_eq!(policy.sandbox_mode, Some("workspace-write".to_string()));
        assert_eq!(
            policy
                .config_overrides
                .get("sandbox_workspace_write.network_access"),
            Some(&"true".to_string())
        );
        assert_eq!(
            policy
                .config_overrides
                .get("shell_environment_policy.inherit"),
            Some(&"all".to_string())
        );
    }

    #[test]
    fn codex_policy_danger_full_access_omits_network_access() {
        let policy = codex_executable_policy(true);
        assert_eq!(policy.sandbox_mode, Some("danger-full-access".to_string()));
        assert!(
            !policy
                .config_overrides
                .contains_key("sandbox_workspace_write.network_access")
        );
        assert_eq!(
            policy
                .config_overrides
                .get("shell_environment_policy.inherit"),
            Some(&"all".to_string())
        );
    }
}
