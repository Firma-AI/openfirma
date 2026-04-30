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
        let launch = LaunchSpec {
            executable,
            args: args.command.iter().skip(1).cloned().collect(),
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

    env.insert(
        "FIRMA_RUN_ATTR_HEADERS_JSON".to_string(),
        serde_json::to_string(&identity.attribution_headers()).unwrap_or_else(|_| "{}".to_string()),
    );

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
        CapabilityLeaseConfig, CapabilitySource, MountSpec, NetworkPolicy, ResolvedProfile,
        SandboxIdentityMode, SidecarEndpoint,
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
        };

        let identity = RunIdentity::new("generic");
        let lease = crate::capability::CapabilityLeaseManager::new(&profile.capability)
            .unwrap_or_else(|e| panic!("{e}"));

        let env = build_execution_env(&profile, &identity, &lease, &BTreeMap::default());
        assert!(env.contains_key("HTTP_PROXY"));
        assert_eq!(env.get("FIRMA_RUN_PROFILE"), Some(&"generic".to_string()));
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
}
