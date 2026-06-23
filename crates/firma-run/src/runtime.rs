use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

use crate::backend::{LaunchSpec, PrepareRequest, build_backend};
use crate::capability::CapabilityLeaseManager;
use crate::config::{CapabilitySource, ResolvedProfile, SidecarEndpoint, resolve_profile};
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::mediator::enforce_local_command_governance;
use crate::routing::{AutostartFlags, prepare_network_runtime};
use crate::seccomp::resolve_effective_seccomp;
use crate::sidecar::supervisor::DEFAULT_STARTUP_TIMEOUT_SECS;
use crate::supervisor::wait_with_signal_forwarding;

/// Lib-level input for [`execute_run`]. The CLI layer (in the `firma`
/// host crate) builds this from its `clap`-derived args struct.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "this type intentionally models independent CLI/runtime flags one-to-one"
)]
pub struct RunInput {
    /// Built-in profile id to use.
    pub profile: String,
    /// Optional runtime config path (.toml, .yaml, .yml).
    pub config: Option<PathBuf>,
    /// Override backend selection.
    pub backend: Option<crate::backend::BackendKind>,
    /// CLI value of `--sidecar` (`local` | `<tcp://...|unix:///...>` | unset).
    pub sidecar_cli: crate::sidecar::SidecarCli,
    /// Optional capability token file path for runtime lease refresh.
    pub capability_file: Option<PathBuf>,
    /// Override sandbox identity mode.
    pub identity_mode: Option<crate::config::SandboxIdentityMode>,
    /// Preserve host user identity inside sandbox for compatibility workflows.
    pub preserve_host_user: bool,
    /// Print the resolved effective config as JSON before execution.
    pub print_effective_config: bool,
    /// When set, never autostart — fail with a typed error if the
    /// configured endpoint is unreachable. CI / production safety net.
    pub no_autostart: bool,
    /// Optional explicit template path for the autostarted sidecar config.
    pub sidecar_template_path: Option<PathBuf>,
    /// Seconds to wait for the autostarted sidecar's `ready` line.
    pub sidecar_startup_timeout_secs: u64,
    /// Wrapped command and args.
    pub command: Vec<String>,
    /// CLI value of `--authority` (`local` | `<url>` | unset).
    pub authority_cli: crate::authority::AuthorityCli,
    /// CLI value of `--authority-profile`. Default `developer`.
    pub authority_profile: String,
    /// Optional override of the user-config path. Default
    /// `dirs::config_dir()/firma/firma.toml`. Tests inject a tmp path.
    pub user_config_path: Option<PathBuf>,
    /// When true, allow non-structural (proxy-only) backends without
    /// failing closed. Required for macOS vz and WSL2 backends when
    /// structural enforcement is not available.
    pub allow_non_structural: bool,
    /// When true, inject `mode = "monitor"` into the synthesized sidecar
    /// config, overriding any value in the operator template. Equivalent
    /// to `mode = "monitor"` in firma.toml but scoped to this run only.
    pub monitor_mode: bool,
}

/// Execute `firma run`.
///
/// # Errors
///
/// Returns an error when config resolution, backend lifecycle operations, or
/// wrapped process supervision fails.
#[expect(
    clippy::too_many_lines,
    reason = "step-0 authority resolution + sidecar autostart + sandbox lifecycle are sequential and read more clearly inline"
)]
pub fn execute_run(args: &RunInput) -> Result<i32, RunError> {
    if args.command.is_empty() {
        return Err(RunError::MissingCommand);
    }

    ensure_required_session_identity()?;

    let profile = resolve_profile(args)?;
    if args.print_effective_config {
        print_effective_config(&profile)?;
    }

    let allow_non_structural =
        profile.allow_non_structural || crate::config::env_truthy("FIRMA_RUN_ALLOW_NON_STRUCTURAL");

    let identity = RunIdentity::new(profile.id.clone());
    log_run_start(&identity, &profile);

    let lease = CapabilityLeaseManager::new(&profile.capability)?;
    let working_dir = resolve_working_dir()?;

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

        if !proof.structural && !allow_non_structural {
            return Err(RunError::NonStructuralBackendRequiresOptIn {
                backend: proof.backend.to_string(),
            });
        }

        if proof.structural {
            tracing::info!(
                structural = proof.structural,
                fail_closed = proof.fail_closed,
                network_confinement = ?proof.network_confinement,
                detail = %proof.detail,
                "backend network enforcement proof"
            );
        } else {
            tracing::warn!(
                structural = false,
                mode = "proxy_only",
                enforced = false,
                backend = %proof.backend,
                profile = %profile.id,
                fail_closed = proof.fail_closed,
                network_confinement = ?proof.network_confinement,
                http_proxy_injected = profile.use_http_proxy_sidecar,
                detail = %proof.detail,
                "backend compatibility proof — proxy-only mode; \
                 agent egress is NOT mandatorily confined; \
                 raw sockets, proxy-env-unset children, and clients \
                 ignoring HTTP_PROXY may bypass the Sidecar"
            );
        }

        // Resolve firma.toml: explicit CLI path > env var > walk up from
        // cwd for `.firma/firma.toml`. `None` means no config — zero-config
        // defaults kick in downstream.
        let resolved_user_config = firma_config::SystemDirs::default()
            .resolve_config(args.user_config_path.as_deref())
            .map_err(|error| RunError::ConfigParse {
                path: args
                    .user_config_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("firma.toml")),
                reason: error.to_string(),
            })?;
        let user_config_path: Option<PathBuf> = resolved_user_config.as_ref().map_or_else(
            || {
                tracing::info!("no firma.toml found; using zero-config defaults");
                None
            },
            |resolved| {
                tracing::info!(
                    path = %resolved.config_file().display(),
                    source = ?resolved.source,
                    "loaded firma.toml"
                );
                Some(resolved.config_file().to_path_buf())
            },
        );
        let user_config_dir = resolved_user_config
            .as_ref()
            .map(firma_config::ResolvedConfig::config_dir);
        let sidecar_template_path =
            resolve_sidecar_template_path(args, user_config_path.as_deref());
        let flags = AutostartFlags {
            sidecar_autostart: matches!(
                profile.sidecar_selection,
                crate::sidecar::SidecarSelection::Local
            ),
            no_autostart: args.no_autostart,
            template_path: sidecar_template_path,
            startup_timeout: Duration::from_secs(if args.sidecar_startup_timeout_secs == 0 {
                DEFAULT_STARTUP_TIMEOUT_SECS
            } else {
                args.sidecar_startup_timeout_secs
            }),
            use_http_proxy_sidecar: profile.use_http_proxy_sidecar,
            monitor_mode: args.monitor_mode,
            ..Default::default()
        };
        let firma_exe = std::env::current_exe()
            .map_err(|e| RunError::Internal(format!("resolve current_exe: {e}")))?;
        let runtime_dir = firma_stack::runtime_paths::default_runtime_dir();
        let mut prompt = crate::authority::StdAuthorityPrompt;
        let authority = crate::routing::resolve_authority(
            &identity,
            &runtime_dir,
            &flags,
            &args.authority_cli,
            &args.authority_profile,
            user_config_path.as_deref(),
            user_config_dir.as_deref(),
            &firma_exe,
            &mut prompt,
        )?;

        // When the user supplied their own capability file, `firma run` must
        // not mint a per-session seed during autostart.
        let skip_mint = matches!(profile.capability.source, CapabilitySource::File { .. });
        let network_runtime = prepare_network_runtime(
            handle_ref,
            &proof,
            &profile.sidecar_endpoint,
            &identity,
            &flags,
            authority,
            skip_mint,
        )?;
        let effective_endpoint = network_runtime.sidecar_endpoint().clone();
        let effective_seccomp = resolve_effective_seccomp(&profile)?;
        if let Some(materialized) = &effective_seccomp {
            tracing::info!(
                policy_id = %materialized.metadata.policy_id,
                policy_version = %materialized.metadata.policy_version,
                policy_sha256 = %materialized.metadata.sha256,
                target_arch = %materialized.metadata.target_arch,
                compiler_version = %materialized.metadata.compiler_version,
                seccomp_filter_path = %materialized.bpf_path.display(),
                "resolved managed static seccomp artifact"
            );
        }
        let env = build_execution_env(
            &profile,
            &identity,
            &lease,
            &effective_endpoint,
            network_runtime.env_overrides(),
        );

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
        if let Some(mediator) = &profile.sidecar_local_exec {
            let canonical = resolve_governed_executable(mediator, &executable)?;
            enforce_local_command_governance(mediator, &identity, &canonical, &launch_args)?;
        }
        let launch = LaunchSpec {
            executable,
            args: launch_args,
            cwd: working_dir,
            env,
            seccomp_filter_path: effective_seccomp.as_ref().map(|s| s.bpf_path.clone()),
            identity_mode: profile.identity_mode,
        };

        let child = backend.start_agent(handle_ref, &launch)?;
        wait_with_signal_forwarding(child)
    })();

    let teardown_result = handle
        .take()
        .map_or(Ok(()), |real_handle| backend.teardown(real_handle));

    combine_run_and_teardown_results(run_result, teardown_result)
}

fn resolve_sidecar_template_path(
    args: &RunInput,
    user_config_path: Option<&Path>,
) -> Option<PathBuf> {
    args.sidecar_template_path
        .clone()
        .or_else(|| args.config.clone())
        .or_else(|| {
            user_config_path
                .filter(|p| p.is_file())
                .map(Path::to_path_buf)
        })
}

fn log_run_start(identity: &RunIdentity, profile: &ResolvedProfile) {
    tracing::info!(
        sandbox_id = identity.sandbox_id.compact(),
        session_id = %identity.session_id,
        profile = %identity.profile,
        backend = %profile.backend,
        "starting firma run"
    );
}

fn resolve_working_dir() -> Result<PathBuf, RunError> {
    std::env::current_dir()
        .map_err(|error| RunError::Internal(format!("failed to read current directory: {error}")))
}

fn combine_run_and_teardown_results(
    run_result: Result<i32, RunError>,
    teardown_result: Result<(), RunError>,
) -> Result<i32, RunError> {
    match (run_result, teardown_result) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(run_error), Err(teardown_error)) => Err(RunError::Internal(format!(
            "run failed: {run_error}; teardown failed: {teardown_error}"
        ))),
    }
}

fn ensure_required_session_identity() -> Result<(), RunError> {
    let require = std::env::var("FIRMA_RUN_REQUIRE_SESSION_ID")
        .ok()
        .is_some_and(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        });
    if !require {
        return Ok(());
    }
    let has_session = std::env::var("FIRMA_RUN_SESSION_ID")
        .ok()
        .is_some_and(|v| !v.trim().is_empty());
    if has_session {
        return Ok(());
    }
    Err(RunError::ConfigValidation(
        "FIRMA_RUN_REQUIRE_SESSION_ID is enabled but FIRMA_RUN_SESSION_ID is not set; set a stable session id so capability issuance/seed selection can match runtime attribution".to_string(),
    ))
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

/// Resolve `executable` to its canonical UTF-8 path, enforce the configured
/// allowlist policy, and return the canonical string.
///
/// Combines canonicalization, UTF-8 validation, and allowlist enforcement into
/// a single fail-closed step so no intermediate non-canonical or lossy path
/// can reach the governance call.
fn resolve_governed_executable(
    mediator: &crate::config::CommandMediatorConfig,
    executable: &str,
) -> Result<String, RunError> {
    let canonical_path = std::fs::canonicalize(executable).map_err(|error| {
        RunError::Governance(format!(
            "executable '{executable}' could not be resolved (fail-closed): {error}"
        ))
    })?;

    // OsString::into_string fails (returns Err(OsString)) on non-UTF-8 paths.
    // to_string_lossy would silently mangle the path — unacceptable on a
    // security boundary.
    let canonical = canonical_path.into_os_string().into_string().map_err(|_| {
        RunError::Governance(
            "executable canonical path is not valid UTF-8 (fail-closed)".to_string(),
        )
    })?;

    enforce_known_executable_policy(mediator, &canonical)?;
    Ok(canonical)
}

fn enforce_known_executable_policy(
    mediator: &crate::config::CommandMediatorConfig,
    canonical: &str,
) -> Result<(), RunError> {
    if !mediator.enforce_known_executables {
        return Ok(());
    }

    if mediator.allowed_executables.contains(canonical) {
        return Ok(());
    }

    Err(RunError::Governance(format!(
        "executable '{canonical}' is not in sidecar_local_exec.allowed_executables"
    )))
}

fn build_execution_env(
    profile: &ResolvedProfile,
    identity: &RunIdentity,
    lease: &CapabilityLeaseManager,
    sidecar_endpoint: &SidecarEndpoint,
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

    match sidecar_endpoint {
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

    if let Some(ca_cert_path) = resolve_sidecar_ca_cert_path(network_overrides) {
        inject_sidecar_ca_trust_env(&mut env, &ca_cert_path);
    }

    env.extend(network_overrides.clone());

    let attr_headers = build_attribution_headers(profile, identity);
    env.insert(
        "FIRMA_RUN_ATTR_HEADERS_JSON".to_string(),
        serde_json::to_string(&attr_headers).unwrap_or_else(|_| "{}".to_string()),
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

fn build_attribution_headers(
    _profile: &ResolvedProfile,
    identity: &RunIdentity,
) -> BTreeMap<String, String> {
    identity.full_attribution_headers()
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

fn resolve_sidecar_ca_cert_path(network_overrides: &BTreeMap<String, String>) -> Option<PathBuf> {
    if let Some(explicit) = network_overrides.get("FIRMA_SIDECAR_CA_CERT_PATH")
        && !explicit.trim().is_empty()
    {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }

    if let Some(ca_dir) = network_overrides.get("FIRMA_SIDECAR_CA_DIR")
        && !ca_dir.trim().is_empty()
    {
        let path = PathBuf::from(ca_dir).join("firma-ca.crt");
        if path.is_file() {
            return Some(path);
        }
    }

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
    use crate::backend::SandboxHandle;

    #[test]
    fn execution_env_includes_identity_and_proxy() {
        let profile = ResolvedProfile {
            id: "generic".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            sidecar_selection: crate::sidecar::SidecarSelection::Local,
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::<MountSpec>::new(),
            seccomp_policy: None,
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
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            use_http_proxy_sidecar: false,
            allow_non_structural: false,
        };

        let identity = RunIdentity::new("generic");
        let lease = crate::capability::CapabilityLeaseManager::new(&profile.capability)
            .unwrap_or_else(|e| panic!("{e}"));

        let env = build_execution_env(
            &profile,
            &identity,
            &lease,
            &profile.sidecar_endpoint,
            &BTreeMap::default(),
        );
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
            sidecar_selection: crate::sidecar::SidecarSelection::Local,
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_policy: None,
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
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            use_http_proxy_sidecar: false,
            allow_non_structural: false,
        };

        let identity = RunIdentity::new("generic");
        let lease = crate::capability::CapabilityLeaseManager::new(&profile.capability)
            .unwrap_or_else(|e| panic!("{e}"));

        let env = build_execution_env(
            &profile,
            &identity,
            &lease,
            &profile.sidecar_endpoint,
            &BTreeMap::default(),
        );
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
    fn execution_env_does_not_expose_seccomp_artifact_path() {
        let profile = ResolvedProfile {
            id: "generic".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            sidecar_selection: crate::sidecar::SidecarSelection::Local,
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_policy: None,
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
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            use_http_proxy_sidecar: false,
            allow_non_structural: false,
        };

        let identity = RunIdentity::new("generic");
        let lease = crate::capability::CapabilityLeaseManager::new(&profile.capability)
            .unwrap_or_else(|e| panic!("{e}"));
        let env = build_execution_env(
            &profile,
            &identity,
            &lease,
            &profile.sidecar_endpoint,
            &BTreeMap::default(),
        );

        assert!(
            env.keys().all(|key| !key.starts_with("FIRMA_RUN_SECCOMP_")),
            "runtime env must not expose legacy seccomp-path env vars"
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
            sidecar_selection: crate::sidecar::SidecarSelection::Local,
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_policy: None,
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
            sidecar_local_exec: None,
            use_http_proxy_sidecar: true,
            allow_non_structural: false,
            executable_policies: BTreeMap::from([(
                "codex".to_string(),
                ExecutableLaunchPolicy {
                    enforce_wrapper_defaults: true,
                    sandbox_mode: Some("danger-full-access".to_string()),
                    approval_policy: Some("never".to_string()),
                    config_overrides: BTreeMap::from([(
                        "shell_environment_policy.inherit".to_string(),
                        "all".to_string(),
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
                "danger-full-access".to_string(),
                "--ask-for-approval".to_string(),
                "never".to_string(),
                "--config".to_string(),
                "shell_environment_policy.inherit=all".to_string(),
                "exec".to_string(),
                "hello".to_string()
            ]
        );
    }

    #[test]
    fn execution_env_clears_no_proxy_in_tcp_mode() {
        // NO_PROXY="" comes from the generic profile's env_set (inherited by all
        // built-in profiles), not from hardcoded runtime logic. The test reflects
        // this by including it in the profile.
        let profile = ResolvedProfile {
            id: "codex".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            sidecar_selection: crate::sidecar::SidecarSelection::Local,
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::from([
                ("NO_PROXY".to_string(), String::new()),
                ("no_proxy".to_string(), String::new()),
            ]),
            mounts: Vec::new(),
            seccomp_policy: None,
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
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            use_http_proxy_sidecar: true,
            allow_non_structural: false,
        };
        let identity = RunIdentity::new("codex");
        let lease = crate::capability::CapabilityLeaseManager::new(&profile.capability)
            .unwrap_or_else(|e| panic!("{e}"));
        let env = build_execution_env(
            &profile,
            &identity,
            &lease,
            &profile.sidecar_endpoint,
            &BTreeMap::default(),
        );
        assert_eq!(env.get("NO_PROXY"), Some(&String::new()));
        assert_eq!(env.get("no_proxy"), Some(&String::new()));
    }

    #[test]
    fn codex_policy_respects_explicit_cli_flags() {
        let profile = ResolvedProfile {
            id: "codex".to_string(),
            backend: crate::backend::BackendKind::Bwrap,
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:8080".parse().unwrap_or_else(|e| panic!("{e}")),
            },
            sidecar_selection: crate::sidecar::SidecarSelection::Local,
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_policy: None,
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
            sidecar_local_exec: None,
            use_http_proxy_sidecar: true,
            allow_non_structural: false,
            executable_policies: BTreeMap::from([(
                "codex".to_string(),
                ExecutableLaunchPolicy {
                    enforce_wrapper_defaults: true,
                    sandbox_mode: Some("danger-full-access".to_string()),
                    approval_policy: Some("never".to_string()),
                    config_overrides: BTreeMap::from([(
                        "shell_environment_policy.inherit".to_string(),
                        "all".to_string(),
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
                "shell_environment_policy.inherit=none".to_string(),
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
                "shell_environment_policy.inherit=none".to_string(),
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
            sidecar_selection: crate::sidecar::SidecarSelection::Local,
            env_passthrough: BTreeSet::default(),
            env_set: BTreeMap::default(),
            mounts: Vec::new(),
            seccomp_policy: None,
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
            sidecar_local_exec: None,
            use_http_proxy_sidecar: true,
            allow_non_structural: false,
            executable_policies: BTreeMap::from([(
                "codex".to_string(),
                ExecutableLaunchPolicy {
                    enforce_wrapper_defaults: true,
                    sandbox_mode: Some("danger-full-access".to_string()),
                    approval_policy: Some("never".to_string()),
                    config_overrides: BTreeMap::from([(
                        "shell_environment_policy.inherit".to_string(),
                        "all".to_string(),
                    )]),
                },
            )]),
        };

        let args = super::maybe_apply_executable_policy(
            &profile,
            "codex",
            vec![
                "--config".to_string(),
                "shell_environment_policy.inherit=none".to_string(),
                "exec".to_string(),
                "hi".to_string(),
            ],
        );
        assert_eq!(
            args,
            vec![
                "--sandbox".to_string(),
                "danger-full-access".to_string(),
                "--ask-for-approval".to_string(),
                "never".to_string(),
                "--config".to_string(),
                "shell_environment_policy.inherit=none".to_string(),
                "exec".to_string(),
                "hi".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_sidecar_template_prefers_explicit_sidecar_config() {
        let args = super::RunInput {
            profile: "codex".to_string(),
            config: Some(PathBuf::from("/tmp/from-run-config.toml")),
            backend: None,
            sidecar_cli: crate::sidecar::SidecarCli::Unset,
            capability_file: None,
            identity_mode: None,
            preserve_host_user: false,
            print_effective_config: false,
            no_autostart: false,
            sidecar_template_path: Some(PathBuf::from("/tmp/from-sidecar-config.toml")),
            sidecar_startup_timeout_secs: 10,
            command: vec!["codex".to_string()],
            authority_cli: crate::authority::AuthorityCli::Unset,
            authority_profile: firma_authority::DEFAULT_PROFILE.to_string(),
            user_config_path: None,
            allow_non_structural: true,
            monitor_mode: false,
        };
        let resolved = super::resolve_sidecar_template_path(
            &args,
            Some(PathBuf::from("/tmp/user.toml").as_path()),
        );
        assert_eq!(
            resolved,
            Some(PathBuf::from("/tmp/from-sidecar-config.toml"))
        );
    }

    #[test]
    fn resolve_sidecar_template_falls_back_to_user_config_when_present() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let user_cfg = tmp.path().join("firma.toml");
        fs::write(&user_cfg, "[sidecar]\n").unwrap_or_else(|e| panic!("{e}"));

        let args = super::RunInput {
            profile: "codex".to_string(),
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
            command: vec!["codex".to_string()],
            authority_cli: crate::authority::AuthorityCli::Unset,
            authority_profile: firma_authority::DEFAULT_PROFILE.to_string(),
            user_config_path: None,
            allow_non_structural: true,
            monitor_mode: false,
        };
        let resolved = super::resolve_sidecar_template_path(&args, Some(user_cfg.as_path()));
        assert_eq!(resolved, Some(user_cfg));
    }

    #[test]
    fn enforce_network_proof_is_structural_for_bwrap() {
        let backend = crate::backend::build_backend(crate::backend::BackendKind::Bwrap);
        let handle = SandboxHandle {
            backend: crate::backend::BackendKind::Bwrap,
            runtime_dir: PathBuf::from("/tmp/firma-test"),
            identity: RunIdentity::new("generic"),
            mounts: vec![],
            network_policy: NetworkPolicy {
                enforce_network_namespace: true,
                fail_closed: true,
            },
        };
        let proof = backend
            .enforce_network(&handle, &handle.network_policy)
            .unwrap();
        assert!(
            proof.structural,
            "bwrap backend must report structural=true"
        );
    }

    #[test]
    fn enforce_network_proof_is_non_structural_for_vz() {
        let backend = crate::backend::build_backend(crate::backend::BackendKind::Vz);
        let handle = SandboxHandle {
            backend: crate::backend::BackendKind::Vz,
            runtime_dir: PathBuf::from("/tmp/firma-test"),
            identity: RunIdentity::new("generic"),
            mounts: vec![],
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let result = backend.enforce_network(&handle, &handle.network_policy);
        if cfg!(target_os = "macos") {
            let proof = result.unwrap();
            if crate::config::env_truthy("FIRMA_RUN_VZ_GUEST")
                || crate::config::env_truthy("FIRMA_RUN_VZ_STRUCTURAL_NETWORK")
            {
                assert!(
                    proof.structural,
                    "vz backend must report structural=true when macOS structural mode is enabled"
                );
            } else {
                assert!(
                    !proof.structural,
                    "vz backend must report structural=false by default"
                );
            }
        }
    }

    #[test]
    fn enforce_network_proof_is_non_structural_for_wsl2() {
        let backend = crate::backend::build_backend(crate::backend::BackendKind::Wsl2);
        let handle = SandboxHandle {
            backend: crate::backend::BackendKind::Wsl2,
            runtime_dir: PathBuf::from("/tmp/firma-test"),
            identity: RunIdentity::new("generic"),
            mounts: vec![],
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let result = backend.enforce_network(&handle, &handle.network_policy);
        if cfg!(target_os = "linux") || cfg!(target_os = "windows") {
            let proof = result.unwrap();
            assert!(
                !proof.structural,
                "wsl2 backend must report structural=false"
            );
        }
    }

    #[test]
    fn generic_profile_keeps_use_http_proxy_sidecar_on_non_structural_backend() {
        let run_args = super::RunInput {
            profile: "generic".to_string(),
            config: None,
            backend: Some(non_bwrap_backend_for_current_host()),
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
        };
        let resolved = crate::config::resolve_profile(&run_args).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            resolved.use_http_proxy_sidecar,
            "generic profile must keep use_http_proxy_sidecar=true on non-structural backend"
        );
    }

    fn non_bwrap_backend_for_current_host() -> crate::backend::BackendKind {
        #[cfg(target_os = "linux")]
        {
            return crate::backend::BackendKind::Firecracker;
        }
        #[cfg(target_os = "macos")]
        {
            return crate::backend::BackendKind::Vz;
        }
        #[cfg(target_os = "windows")]
        {
            return crate::backend::BackendKind::Wsl2;
        }
        #[expect(
            unreachable_code,
            reason = "fallback satisfies exhaustive return typing after cfg-gated platform branches"
        )]
        crate::backend::BackendKind::Firecracker
    }
}
