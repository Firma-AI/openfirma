use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

use serde::Serialize;

use crate::args::RunArgs;
use crate::backend::{LaunchSpec, PrepareRequest, build_backend};
use crate::capability::CapabilityLeaseManager;
use crate::config::{CapabilitySource, ResolvedProfile, SidecarEndpoint, resolve_profile};
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::routing::prepare_network_runtime;
use crate::supervisor::wait_with_signal_forwarding;

/// Execute `firma run`.
///
/// # Errors
///
/// Returns an error when config resolution, backend lifecycle operations, or
/// wrapped process supervision fails.
pub fn execute_run(args: &RunArgs) -> Result<i32, RunError> {
    if args.command.is_empty() {
        return Err(RunError::MissingCommand);
    }

    let profile = resolve_profile(args)?;
    if args.print_effective_config {
        print_effective_config(&profile)?;
    }

    let identity = RunIdentity::new(profile.id.clone());
    tracing::info!(
        sandbox_id = %identity.sandbox_id,
        session_id = %identity.session_id,
        profile = %identity.profile,
        backend = %profile.backend,
        "starting firma run"
    );
    if profile.id == "claude-code" && profile.backend != crate::backend::BackendKind::Bwrap {
        tracing::warn!(
            profile = %profile.id,
            backend = %profile.backend,
            "claude-code profile is running in compatibility mode; full Linux structural confinement guarantees require backend=bwrap"
        );
    }

    let lease = CapabilityLeaseManager::new(&profile.capability)?;

    let working_dir = std::env::current_dir().map_err(|error| {
        RunError::Internal(format!("failed to read current directory: {error}"))
    })?;

    let backend = build_backend(profile.backend);
    let mut handle = Some(backend.prepare(&PrepareRequest {
        identity: identity.clone(),
        profile: profile.clone(),
        working_dir: working_dir.clone(),
    })?);

    let run_result = (|| {
        let handle_ref = handle
            .as_ref()
            .ok_or_else(|| RunError::Internal("sandbox handle missing".to_string()))?;

        let proof = backend.enforce_network(handle_ref, &profile.network)?;
        backend.verify_fail_closed(handle_ref, &proof)?;

        tracing::info!(
            structural = proof.structural,
            fail_closed = proof.fail_closed,
            detail = %proof.detail,
            "backend network enforcement proof"
        );

        let network_runtime = prepare_network_runtime(handle_ref, &profile.sidecar_endpoint)?;
        let env = build_execution_env(&profile, &identity, &lease, network_runtime.env_overrides());

        let executable = args
            .command
            .first()
            .cloned()
            .ok_or(RunError::MissingCommand)?;
        let launch_args = maybe_apply_executable_policy(
            &profile,
            &executable,
            args.command.iter().skip(1).cloned().collect(),
        );
        let launch_args =
            maybe_apply_claude_settings(handle_ref, &profile, &executable, launch_args)?;
        let launch = LaunchSpec {
            executable,
            args: launch_args,
            cwd: working_dir,
            env,
            identity_mode: profile.identity_mode,
        };

        let child = backend.start_agent(handle_ref, &launch)?;
        wait_with_signal_forwarding(child)
    })();

    let teardown_result = if let Some(real_handle) = handle.take() {
        backend.teardown(real_handle)
    } else {
        Ok(())
    };

    match (run_result, teardown_result) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(run_error), Err(teardown_error)) => Err(RunError::Internal(format!(
            "run failed: {run_error}; teardown failed: {teardown_error}"
        ))),
    }
}

fn maybe_apply_executable_policy(
    profile: &ResolvedProfile,
    executable: &str,
    args: Vec<String>,
) -> Vec<String> {
    let executable = std::path::Path::new(executable)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_string();
    let Some(policy) = profile.executable_policies.get(&executable) else {
        return args;
    };
    if !policy.enforce_wrapper_defaults {
        return args;
    }

    let has_sandbox = args.iter().any(|arg| arg == "--sandbox" || arg == "-s");
    let has_approval = args
        .iter()
        .any(|arg| arg == "--ask-for-approval" || arg == "-a");

    let mut merged = Vec::with_capacity(args.len() + 4);
    let mut injected_sandbox_mode: Option<String> = None;
    let mut injected_approval_policy: Option<String> = None;
    let mut injected_config_overrides: Vec<String> = Vec::new();
    if !has_sandbox && let Some(mode) = &policy.sandbox_mode {
        merged.push("--sandbox".to_string());
        merged.push(mode.clone());
        injected_sandbox_mode = Some(mode.clone());
    }
    if !has_approval && let Some(mode) = &policy.approval_policy {
        merged.push("--ask-for-approval".to_string());
        merged.push(mode.clone());
        injected_approval_policy = Some(mode.clone());
    }
    for (key, value) in &policy.config_overrides {
        if !has_config_override(&args, key) {
            merged.push("--config".to_string());
            merged.push(format!("{key}={value}"));
            injected_config_overrides.push(format!("{key}={value}"));
        }
    }
    merged.extend(args);
    if injected_sandbox_mode.is_some()
        || injected_approval_policy.is_some()
        || !injected_config_overrides.is_empty()
    {
        tracing::info!(
            executable = %executable,
            injected_sandbox_mode = ?injected_sandbox_mode,
            injected_approval_policy = ?injected_approval_policy,
            injected_config_overrides = ?injected_config_overrides,
            "applied executable wrapper defaults for governed execution"
        );
    }
    merged
}

fn has_config_override(args: &[String], key: &str) -> bool {
    for i in 0..args.len() {
        let arg = &args[i];
        if arg == "--config" || arg == "-c" {
            if let Some(next) = args.get(i + 1)
                && config_item_matches_key(next, key)
            {
                return true;
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("--config=")
            && config_item_matches_key(value, key)
        {
            return true;
        }
    }
    false
}

fn config_item_matches_key(item: &str, key: &str) -> bool {
    item.split_once('=').is_some_and(|(k, _)| k.trim() == key)
}

fn build_execution_env(
    profile: &ResolvedProfile,
    identity: &RunIdentity,
    lease: &CapabilityLeaseManager,
    network_overrides: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    for key in &profile.env_passthrough {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.clone(), value);
        }
    }

    env.extend(profile.env_set.clone());
    env.extend(identity.env_pairs());

    match &profile.sidecar_endpoint {
        SidecarEndpoint::Tcp { addr } => {
            env.insert("HTTP_PROXY".to_string(), format!("http://{addr}"));
            env.insert("HTTPS_PROXY".to_string(), format!("http://{addr}"));
            env.insert("http_proxy".to_string(), format!("http://{addr}"));
            env.insert("https_proxy".to_string(), format!("http://{addr}"));
            env.insert("ALL_PROXY".to_string(), format!("http://{addr}"));
            env.insert("all_proxy".to_string(), format!("http://{addr}"));
        }
        SidecarEndpoint::Unix { path } => {
            env.insert(
                "FIRMA_SIDECAR_UNIX_SOCKET".to_string(),
                path.display().to_string(),
            );
        }
    }

    if let Some(ca_cert_path) = resolve_sidecar_ca_cert_path() {
        inject_sidecar_ca_trust_env(&mut env, &ca_cert_path);
    }

    env.extend(network_overrides.clone());

    let attr_headers = build_attribution_headers(profile, identity);
    env.insert(
        "FIRMA_RUN_ATTR_HEADERS_JSON".to_string(),
        serde_json::to_string(&attr_headers).unwrap_or_else(|_| "{}".to_string()),
    );

    if let Some(seccomp_path) = &profile.seccomp_bpf_path {
        env.insert(
            "FIRMA_RUN_SECCOMP_BPF_PATH".to_string(),
            seccomp_path.display().to_string(),
        );
    }

    if let Some(token) = lease.token() {
        env.insert("FIRMA_CAPABILITY_TOKEN".to_string(), token);
    }

    if let CapabilitySource::File { path } = &profile.capability.source {
        env.insert(
            "FIRMA_CAPABILITY_FILE".to_string(),
            path.display().to_string(),
        );
    }

    env
}

fn build_attribution_headers(
    profile: &ResolvedProfile,
    identity: &RunIdentity,
) -> BTreeMap<String, String> {
    let mut headers = identity.attribution_headers();
    let runtime_user = std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("USERNAME").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .unwrap_or_else(|| "unknown".to_string());

    headers.insert("x-firma-agent".to_string(), profile.id.clone());
    headers.insert("x-firma-user".to_string(), runtime_user);
    headers
}

fn maybe_apply_claude_settings(
    handle: &crate::backend::SandboxHandle,
    profile: &ResolvedProfile,
    executable: &str,
    args: Vec<String>,
) -> Result<Vec<String>, RunError> {
    if profile.id != "claude-code" {
        return Ok(args);
    }

    let executable = std::path::Path::new(executable)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    if executable != "claude" {
        return Ok(args);
    }

    // Respect user-provided settings path/JSON if already present.
    if args.iter().any(|arg| arg == "--settings") {
        return Ok(args);
    }

    let settings_path = handle.runtime_dir.join("claude-settings.json");
    let settings_json = serde_json::json!({
        "sandbox": {
            "autoAllowBashIfSandboxed": true
        }
    });
    let serialized = serde_json::to_vec_pretty(&settings_json).map_err(|error| {
        RunError::Internal(format!(
            "failed to serialize Claude settings payload: {error}"
        ))
    })?;
    std::fs::write(&settings_path, serialized).map_err(|error| {
        RunError::Internal(format!(
            "failed to write Claude settings file {}: {error}",
            settings_path.display()
        ))
    })?;

    let mut merged = Vec::with_capacity(args.len() + 2);
    merged.push("--settings".to_string());
    merged.push(settings_path.display().to_string());
    merged.extend(args);
    Ok(merged)
}

fn inject_sidecar_ca_trust_env(env: &mut BTreeMap<String, String>, ca_cert_path: &Path) {
    let path = ca_cert_path.display().to_string();
    env.insert("FIRMA_SIDECAR_CA_CERT_PATH".to_string(), path.clone());
    // Python / OpenSSL ecosystem.
    env.insert("REQUESTS_CA_BUNDLE".to_string(), path.clone());
    env.insert("SSL_CERT_FILE".to_string(), path.clone());
    env.insert("CURL_CA_BUNDLE".to_string(), path.clone());
    // Node.js ecosystem.
    env.insert("NODE_EXTRA_CA_CERTS".to_string(), path.clone());
    // Git/libcurl callers.
    env.insert("GIT_SSL_CAINFO".to_string(), path);
}

fn resolve_sidecar_ca_cert_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("FIRMA_SIDECAR_CA_CERT_PATH")
        && !explicit.trim().is_empty()
    {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }

    if let Ok(ca_dir) = std::env::var("FIRMA_SIDECAR_CA_DIR")
        && !ca_dir.trim().is_empty()
    {
        let path = PathBuf::from(ca_dir).join("firma-ca.crt");
        if path.is_file() {
            return Some(path);
        }
    }

    let cwd_candidate = std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join("firma-ca").join("firma-ca.crt"));
    let default_candidates = [
        cwd_candidate,
        Some(PathBuf::from("/etc/firma/ca/firma-ca.crt")),
        Some(PathBuf::from("/var/lib/firma/ca/firma-ca.crt")),
    ];

    default_candidates
        .into_iter()
        .flatten()
        .find(|candidate| candidate.is_file())
}

fn print_effective_config(profile: &ResolvedProfile) -> Result<(), RunError> {
    #[derive(Serialize)]
    struct Snapshot<'a> {
        profile: &'a ResolvedProfile,
        working_dir: PathBuf,
    }

    let snapshot = Snapshot {
        profile,
        working_dir: std::env::current_dir().map_err(|error| {
            RunError::Internal(format!(
                "failed to resolve working dir for snapshot: {error}"
            ))
        })?,
    };

    let json = serde_json::to_string_pretty(&snapshot)
        .map_err(|error| RunError::Internal(format!("snapshot serialization failed: {error}")))?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;

    use crate::config::{
        CapabilityLeaseConfig, CapabilitySource, ExecutableLaunchPolicy, MountSpec, NetworkPolicy,
        ResolvedProfile, SandboxIdentityMode, SidecarEndpoint,
    };

    use super::{RunIdentity, build_execution_env};

    #[test]
    fn execution_env_includes_identity_and_proxy() {
        let profile = ResolvedProfile {
            id: "generic".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::<MountSpec>::new(),
            seccomp_bpf_path: None,
            allowed_domains: Vec::new(),
            network: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
            identity_mode: SandboxIdentityMode::SandboxUser,
            capability: CapabilityLeaseConfig {
                source: CapabilitySource::Disabled,
                refresh_ratio: 0.60,
                grace_seconds: 30,
            },
            executable_policies: BTreeMap::new(),
        };

        let identity = RunIdentity::new("generic");
        let lease = crate::capability::CapabilityLeaseManager::new(&profile.capability)
            .unwrap_or_else(|e| panic!("{e}"));

        let env = build_execution_env(&profile, &identity, &lease, &BTreeMap::default());
        assert!(env.contains_key("HTTP_PROXY"));
        assert_eq!(env.get("FIRMA_RUN_PROFILE"), Some(&"generic".to_string()));
        let headers_json = env
            .get("FIRMA_RUN_ATTR_HEADERS_JSON")
            .unwrap_or_else(|| panic!("missing FIRMA_RUN_ATTR_HEADERS_JSON"));
        let headers: BTreeMap<String, String> =
            serde_json::from_str(headers_json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(headers.get("x-firma-agent"), Some(&"generic".to_string()));
        assert!(headers.contains_key("x-firma-session-id"));
    }

    #[test]
    fn capability_file_is_exported_when_file_source_is_used() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let token_path = tempdir.path().join("cap.token");
        fs::write(&token_path, "token").unwrap_or_else(|e| panic!("{e}"));

        let profile = ResolvedProfile {
            id: "generic".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_bpf_path: None,
            allowed_domains: Vec::new(),
            network: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
            identity_mode: SandboxIdentityMode::SandboxUser,
            capability: CapabilityLeaseConfig {
                source: CapabilitySource::File {
                    path: token_path.clone(),
                },
                refresh_ratio: 0.60,
                grace_seconds: 30,
            },
            executable_policies: BTreeMap::new(),
        };

        let identity = RunIdentity::new("generic");
        let lease = crate::capability::CapabilityLeaseManager::new(&profile.capability)
            .unwrap_or_else(|e| panic!("{e}"));

        let env = build_execution_env(&profile, &identity, &lease, &BTreeMap::default());
        assert_eq!(
            env.get("FIRMA_CAPABILITY_FILE"),
            Some(&token_path.display().to_string())
        );
        assert_eq!(
            env.get("FIRMA_CAPABILITY_TOKEN"),
            Some(&"token".to_string())
        );
    }

    #[test]
    fn seccomp_bpf_path_is_exported_when_configured() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let seccomp_path = tempdir.path().join("seccomp.bpf");
        fs::write(&seccomp_path, [0_u8; 8]).unwrap_or_else(|e| panic!("{e}"));

        let profile = ResolvedProfile {
            id: "generic".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_bpf_path: Some(seccomp_path.clone()),
            allowed_domains: Vec::new(),
            network: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
            identity_mode: SandboxIdentityMode::SandboxUser,
            capability: CapabilityLeaseConfig {
                source: CapabilitySource::Disabled,
                refresh_ratio: 0.60,
                grace_seconds: 30,
            },
            executable_policies: BTreeMap::new(),
        };

        let identity = RunIdentity::new("generic");
        let lease = crate::capability::CapabilityLeaseManager::new(&profile.capability)
            .unwrap_or_else(|e| panic!("{e}"));
        let env = build_execution_env(&profile, &identity, &lease, &BTreeMap::default());

        assert_eq!(
            env.get("FIRMA_RUN_SECCOMP_BPF_PATH"),
            Some(&seccomp_path.display().to_string())
        );
    }

    #[test]
    fn injects_sidecar_ca_trust_env_vars() {
        let mut env = BTreeMap::new();
        let cert_path = PathBuf::from("/tmp/firma-ca/firma-ca.crt");
        super::inject_sidecar_ca_trust_env(&mut env, &cert_path);

        let expected = cert_path.display().to_string();
        assert_eq!(env.get("FIRMA_SIDECAR_CA_CERT_PATH"), Some(&expected));
        assert_eq!(env.get("REQUESTS_CA_BUNDLE"), Some(&expected));
        assert_eq!(env.get("SSL_CERT_FILE"), Some(&expected));
        assert_eq!(env.get("CURL_CA_BUNDLE"), Some(&expected));
        assert_eq!(env.get("NODE_EXTRA_CA_CERTS"), Some(&expected));
        assert_eq!(env.get("GIT_SSL_CAINFO"), Some(&expected));
    }

    #[test]
    fn codex_policy_injects_defaults_when_missing() {
        let profile = ResolvedProfile {
            id: "codex".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_bpf_path: None,
            allowed_domains: Vec::new(),
            network: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
            identity_mode: SandboxIdentityMode::SandboxUser,
            capability: CapabilityLeaseConfig {
                source: CapabilitySource::Disabled,
                refresh_ratio: 0.60,
                grace_seconds: 30,
            },
            executable_policies: BTreeMap::from([(
                "codex".to_string(),
                ExecutableLaunchPolicy {
                    enforce_wrapper_defaults: true,
                    sandbox_mode: Some("workspace-write".to_string()),
                    approval_policy: Some("never".to_string()),
                    config_overrides: BTreeMap::from([(
                        "sandbox_workspace_write.network_access".to_string(),
                        "true".to_string(),
                    )]),
                },
            )]),
        };

        let args = super::maybe_apply_executable_policy(
            &profile,
            "codex",
            vec!["exec".to_string(), "hello".to_string()],
        );
        assert_eq!(
            args,
            vec![
                "--sandbox".to_string(),
                "workspace-write".to_string(),
                "--ask-for-approval".to_string(),
                "never".to_string(),
                "--config".to_string(),
                "sandbox_workspace_write.network_access=true".to_string(),
                "exec".to_string(),
                "hello".to_string()
            ]
        );
    }

    #[test]
    fn codex_policy_respects_explicit_cli_flags() {
        let profile = ResolvedProfile {
            id: "codex".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_bpf_path: None,
            allowed_domains: Vec::new(),
            network: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
            identity_mode: SandboxIdentityMode::SandboxUser,
            capability: CapabilityLeaseConfig {
                source: CapabilitySource::Disabled,
                refresh_ratio: 0.60,
                grace_seconds: 30,
            },
            executable_policies: BTreeMap::from([(
                "codex".to_string(),
                ExecutableLaunchPolicy {
                    enforce_wrapper_defaults: true,
                    sandbox_mode: Some("workspace-write".to_string()),
                    approval_policy: Some("never".to_string()),
                    config_overrides: BTreeMap::from([(
                        "sandbox_workspace_write.network_access".to_string(),
                        "true".to_string(),
                    )]),
                },
            )]),
        };

        let args = super::maybe_apply_executable_policy(
            &profile,
            "codex",
            vec![
                "--sandbox".to_string(),
                "read-only".to_string(),
                "--ask-for-approval".to_string(),
                "on-request".to_string(),
                "--config".to_string(),
                "sandbox_workspace_write.network_access=true".to_string(),
                "exec".to_string(),
                "hi".to_string(),
            ],
        );
        assert_eq!(
            args,
            vec![
                "--sandbox".to_string(),
                "read-only".to_string(),
                "--ask-for-approval".to_string(),
                "on-request".to_string(),
                "--config".to_string(),
                "sandbox_workspace_write.network_access=true".to_string(),
                "exec".to_string(),
                "hi".to_string(),
            ]
        );
    }

    #[test]
    fn codex_policy_respects_explicit_config_override() {
        let profile = ResolvedProfile {
            id: "codex".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_bpf_path: None,
            allowed_domains: Vec::new(),
            network: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
            identity_mode: SandboxIdentityMode::SandboxUser,
            capability: CapabilityLeaseConfig {
                source: CapabilitySource::Disabled,
                refresh_ratio: 0.60,
                grace_seconds: 30,
            },
            executable_policies: BTreeMap::from([(
                "codex".to_string(),
                ExecutableLaunchPolicy {
                    enforce_wrapper_defaults: true,
                    sandbox_mode: Some("workspace-write".to_string()),
                    approval_policy: Some("never".to_string()),
                    config_overrides: BTreeMap::from([(
                        "sandbox_workspace_write.network_access".to_string(),
                        "true".to_string(),
                    )]),
                },
            )]),
        };

        let args = super::maybe_apply_executable_policy(
            &profile,
            "codex",
            vec![
                "--config".to_string(),
                "sandbox_workspace_write.network_access=false".to_string(),
                "exec".to_string(),
                "hi".to_string(),
            ],
        );
        assert_eq!(
            args,
            vec![
                "--sandbox".to_string(),
                "workspace-write".to_string(),
                "--ask-for-approval".to_string(),
                "never".to_string(),
                "--config".to_string(),
                "sandbox_workspace_write.network_access=false".to_string(),
                "exec".to_string(),
                "hi".to_string(),
            ]
        );
    }
}
