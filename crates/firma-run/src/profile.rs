use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::config::{
    CapabilityLeasePatch, CapabilitySourcePatch, MountPatch, NetworkPolicyPatch, ProfilePatch,
};
use crate::error::RunError;

/// Returns built-in profile patch for a given profile id.
pub(crate) fn built_in_profile(profile: &str) -> Result<ProfilePatch, RunError> {
    match profile {
        "generic" => Ok(generic_profile()),
        "codex" => Ok(codex_profile()),
        other => Err(RunError::ConfigValidation(format!(
            "unknown profile '{other}'; supported profiles: generic, codex"
        ))),
    }
}

fn generic_profile() -> ProfilePatch {
    let mut env_set = BTreeMap::new();
    env_set.insert("FIRMA_RUN_PROFILE".to_string(), "generic".to_string());

    ProfilePatch {
        backend: None,
        sidecar_endpoint: Some("tcp://127.0.0.1:8080".to_string()),
        env_passthrough: vec!["HOME".to_string(), "PATH".to_string(), "TERM".to_string()],
        env_set,
        mounts: vec![MountPatch {
            source: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            target: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            read_only: false,
        }],
        allowed_domains: Vec::new(),
        network: Some(NetworkPolicyPatch {
            enforce_network_namespace: Some(true),
            fail_closed: Some(true),
        }),
        capability: Some(CapabilityLeasePatch {
            source: Some(CapabilitySourcePatch::Disabled),
            kind: None,
            path: None,
            refresh_ratio: Some(0.60),
            grace_seconds: Some(30),
        }),
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
    base
}
