use std::{
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use firma_runtime_state::runtime_paths::{default_runtime_dir, run_entry_from};
use serde::Serialize;

use crate::backend::{LaunchSpec, PrepareRequest, build_backend};
use crate::capability::read_capability_token;
use crate::config::{
    CaTrustMode, CapabilitySource, ResolvedProfile, SidecarEndpoint, resolve_profile,
};
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::mediator::enforce_local_command_governance;
use crate::routing::{AutostartFlags, ResolveAuthorityRequest, prepare_network_runtime};
use crate::seccomp::resolve_effective_seccomp;
use crate::sidecar::supervisor::DEFAULT_STARTUP_TIMEOUT_SECS;
use crate::supervisor::wait_with_signal_forwarding;

#[doc(hidden)]
pub mod vscode;

/// Secret-mediation shim injection (Unix/bwrap). Wires the broker + shim mounts
/// into a launch when the profile lists `secret_providers`.
mod secret_shims;

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
    /// Optional operator-supplied capability token file, injected into the
    /// agent environment at launch (bring-your-own token).
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
    /// the default config discovery path. Tests inject a tmp path.
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

/// Callbacks fired around the tty-handoff to the wrapped agent. Both hooks are
/// optional; the default is a no-op on each.
#[derive(Clone, Copy, Default)]
pub struct LaunchHooks<'a> {
    /// Invoked immediately after the agent process is spawned and owns the
    /// terminal, before the supervisor blocks waiting on it. Receives the
    /// per-run marker directory.
    pub on_agent_launch: Option<&'a (dyn Fn(&Path) + Sync)>,
    /// Invoked once the agent has been reaped, before teardown runs.
    pub on_agent_exit: Option<&'a (dyn Fn() + Sync)>,
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
pub fn execute_run(args: &RunInput, hooks: &LaunchHooks<'_>) -> Result<i32, RunError> {
    if args.command.is_empty() {
        return Err(RunError::MissingCommand);
    }

    crate::identity::reject_reserved_sandbox_id_environment()?;

    ensure_required_session_identity()?;

    let config_override = args.user_config_path.as_deref().or(args.config.as_deref());
    let resolved_user_config = firma_config_loader::ConfigResolver::default()
        .resolve_config(config_override)
        .map_err(|error| RunError::ConfigParse {
            path: error.path.clone(),
            reason: error.to_string(),
        })?;
    let user_config_path = resolved_user_config
        .as_ref()
        .map(firma_config_loader::ResolvedConfig::config_file)
        .map(Path::to_path_buf);
    let user_config_dir = resolved_user_config
        .as_ref()
        .map(firma_config_loader::ResolvedConfig::config_dir);
    let agent_id = user_config_path.as_deref().map_or_else(
        || {
            Err(RunError::MissingAgentId {
                path: PathBuf::from("firma.toml"),
            })
        },
        crate::identity::read_configured_agent_id,
    )?;

    let profile = resolve_profile(args)?;
    let identity = RunIdentity::new(agent_id, profile.id.clone());
    if args.print_effective_config {
        print_effective_config(&identity, &profile)?;
    }

    let allow_non_structural =
        profile.allow_non_structural || crate::config::env_truthy("FIRMA_RUN_ALLOW_NON_STRUCTURAL");

    log_run_start(&identity, &profile);

    let capability_token = read_capability_token(&profile.capability.source)?;
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

        let sidecar_template_path = resolve_sidecar_template_path(
            args.sidecar_template_path.as_deref(),
            user_config_path.as_deref(),
        );
        let mut flags = AutostartFlags {
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
        // When the user supplies --capability-file, thread the path into the
        // autostart flags so the sidecar loads it as a capability seed.
        // prepare_network_runtime does not mint for a File source, so it leaves
        // this path untouched.
        if let CapabilitySource::File { ref path } = profile.capability.source {
            flags.capability_seed_path = Some(path.clone());
        }
        let firma_exe = env::current_exe()
            .map_err(|e| RunError::Internal(format!("resolve current_exe: {e}")))?;

        // Pre-bind the secret gateway before the Sidecar starts so the Sidecar
        // can read its address from FIRMA_SECRET_GATEWAY_ADDR at startup.
        let gateway_binding = secret_shims::pre_bind_gateway(handle_ref, &profile)?;
        flags.secret_gateway_addr = gateway_binding.as_ref().map(|b| b.addr.clone());
        flags.http_secret_providers = profile
            .secret_providers
            .values()
            .filter_map(firma_secret_provider::IntegrationSpec::as_http)
            .cloned()
            .collect();

        let runtime_dir = firma_runtime_state::runtime_paths::default_runtime_dir();
        let mut prompt = crate::authority::StdAuthorityPrompt;
        let authority = crate::routing::resolve_authority(
            ResolveAuthorityRequest {
                identity: &identity,
                runtime_dir: &runtime_dir,
                flags: &flags,
                cli: &args.authority_cli,
                profile_name: &args.authority_profile,
                user_config_path: user_config_path.as_deref(),
                user_config_dir: user_config_dir.as_deref(),
                firma_exe: &firma_exe,
                capability_public_key_path: profile.capability.public_key_path.as_deref(),
                working_dir: &working_dir,
            },
            &mut prompt,
        )?;

        let network_runtime = prepare_network_runtime(
            handle_ref,
            &proof,
            &profile.sidecar_endpoint,
            &identity,
            &flags,
            authority,
            &profile.capability,
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
        let mut env = build_execution_env(
            &profile,
            &identity,
            capability_token.as_deref(),
            &effective_endpoint,
            network_runtime.env_overrides(),
        );

        let mut executable = args
            .command
            .first()
            .cloned()
            .ok_or(RunError::MissingCommand)?;
        let launch_args = maybe_apply_executable_policy(
            &profile,
            &executable,
            args.command.iter().skip(1).cloned().collect(),
        );
        let mut launch_args =
            maybe_apply_claude_settings(handle_ref, &profile, &executable, launch_args)?;
        let vscode_state_dir = if vscode::should_apply_vscode_shim(&profile, &executable) {
            let state_dir = vscode::resolve_vscode_state_dir(
                user_config_path.as_deref(),
                &handle_ref.runtime_dir,
            )?;
            let prepared = vscode::prepare_vscode_shim(
                &handle_ref.runtime_dir,
                &state_dir,
                &executable,
                launch_args,
                &mut env,
                env::var_os("PATH").as_deref(),
            )?;
            executable = prepared.executable.display().to_string();
            launch_args = prepared.args;
            Some(state_dir)
        } else {
            None
        };
        if let Some(mediator) = &profile.sidecar_local_exec {
            let canonical = resolve_governed_executable(mediator, &executable)?;
            enforce_local_command_governance(mediator, &identity, &canonical, &launch_args)?;
        }
        if let Some(state_dir) = vscode_state_dir {
            let handle_mut = handle
                .as_mut()
                .ok_or_else(|| RunError::Internal("sandbox handle missing".to_string()))?;
            vscode::ensure_vscode_state_mount(handle_mut, &state_dir);
        }
        // Start the broker and serve the pre-bound gateway. Shim bind-mounts
        // and env vars are applied to the sandbox handle when one is present.
        secret_shims::prepare(
            &mut handle,
            &profile,
            &identity,
            &mut env,
            &firma_exe,
            env::var_os("PATH").as_deref(),
            gateway_binding,
        )?;
        let launch = LaunchSpec {
            executable,
            args: launch_args,
            cwd: working_dir,
            env,
            sidecar_endpoint: effective_endpoint,
            seccomp_filter_path: effective_seccomp.as_ref().map(|s| s.bpf_path.clone()),
            identity_mode: profile.identity_mode,
        };

        let child = {
            let handle_ref = handle
                .as_ref()
                .ok_or_else(|| RunError::Internal("sandbox handle missing".to_string()))?;
            backend.start_agent(handle_ref, &launch)?
        };
        // Per-run marker dir under the persistent runtime root, alongside
        // `sidecar.log` / `authority.log`. The caller redirects its foreground
        // logs here while the agent's TUI owns the terminal.
        let marker_dir = run_entry_from(&default_runtime_dir(), &identity.sandbox_id);
        if let Some(hook) = hooks.on_agent_launch {
            hook(&marker_dir);
        }
        let wait_result = wait_with_signal_forwarding(child, backend.kind());
        if let Some(hook) = hooks.on_agent_exit {
            hook();
        }
        wait_result
    })();

    let teardown_result = handle
        .take()
        .map_or(Ok(()), |real_handle| backend.teardown(real_handle));

    combine_run_and_teardown_results(run_result, teardown_result)
}

fn resolve_sidecar_template_path(
    sidecar_template_path: Option<&Path>,
    user_config_path: Option<&Path>,
) -> Option<PathBuf> {
    sidecar_template_path.map(Path::to_path_buf).or_else(|| {
        user_config_path
            .filter(|p| p.is_file())
            .map(Path::to_path_buf)
    })
}

fn log_run_start(identity: &RunIdentity, profile: &ResolvedProfile) {
    tracing::info!(
        sandbox_id = %identity.sandbox_id,
        session_id = %identity.session_id,
        agent_id = %identity.agent_id,
        profile = %identity.execution_profile,
        backend = %profile.backend,
        "starting firma run"
    );
}

fn resolve_working_dir() -> Result<PathBuf, RunError> {
    env::current_dir()
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
    let require = env::var("FIRMA_RUN_REQUIRE_SESSION_ID")
        .ok()
        .is_some_and(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        });
    if !require {
        return Ok(());
    }
    let has_session = env::var("FIRMA_RUN_SESSION_ID")
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
    let executable = Path::new(executable)
        .file_name()
        .and_then(OsStr::to_str)
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

fn resolve_host_executable(
    executable: &str,
    host_path: Option<&OsStr>,
) -> Result<PathBuf, RunError> {
    let candidate = PathBuf::from(executable);
    if candidate
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return require_file(candidate, executable);
    }

    let path_value = host_path
        .map(OsString::from)
        .or_else(|| env::var_os("PATH"))
        .ok_or_else(|| {
            RunError::ConfigValidation(format!(
                "cannot resolve executable '{executable}' because host PATH is not set"
            ))
        })?;
    for dir in env::split_paths(&path_value) {
        for candidate in executable_search_candidates(&dir, executable) {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(RunError::ConfigValidation(format!(
        "cannot resolve executable '{executable}' on host PATH"
    )))
}

fn require_file(candidate: PathBuf, executable: &str) -> Result<PathBuf, RunError> {
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(RunError::ConfigValidation(format!(
            "cannot resolve executable '{executable}' at {}",
            candidate.display()
        )))
    }
}

#[cfg(windows)]
fn executable_search_candidates(dir: &Path, executable: &str) -> Vec<PathBuf> {
    let direct = dir.join(executable);
    if Path::new(executable).extension().is_some() {
        return vec![direct];
    }

    let mut candidates = vec![direct];
    let path_ext = env::var_os("PATHEXT").map_or_else(
        || ".COM;.EXE;.BAT;.CMD".to_string(),
        |value| value.to_string_lossy().into_owned(),
    );
    candidates.extend(
        path_ext
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(|extension| dir.join(format!("{executable}{extension}"))),
    );
    candidates
}

#[cfg(not(windows))]
fn executable_search_candidates(dir: &Path, executable: &str) -> Vec<PathBuf> {
    vec![dir.join(executable)]
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
    let canonical_path = fs::canonicalize(executable).map_err(|error| {
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
    capability_token: Option<&str>,
    sidecar_endpoint: &SidecarEndpoint,
    network_overrides: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    for key in &profile.env_passthrough {
        if let Ok(value) = env::var(key) {
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
        let effective = match profile.ca_trust_mode {
            CaTrustMode::AppendSystemRoots => {
                build_appended_ca_bundle(&ca_cert_path).unwrap_or(ca_cert_path)
            }
            CaTrustMode::Sole => ca_cert_path,
        };
        inject_sidecar_ca_trust_env(&mut env, &effective);
    }

    env.extend(network_overrides.clone());

    let attr_headers = build_attribution_headers(profile, identity);
    env.insert(
        "FIRMA_RUN_ATTR_HEADERS_JSON".to_string(),
        serde_json::to_string(&attr_headers).unwrap_or_else(|_| "{}".to_string()),
    );

    if let Some(token) = capability_token {
        env.insert("FIRMA_CAPABILITY_TOKEN".to_string(), token.to_string());
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

    let executable = Path::new(executable)
        .file_name()
        .and_then(OsStr::to_str)
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
    fs::write(&settings_path, serialized).map_err(|error| {
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

/// Common Linux system CA bundle locations, probed in order.
const SYSTEM_CA_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// Build `firma-ca-bundle.crt` next to `firma_ca_path`, containing the first
/// discovered system root bundle followed by the firma CA. Returns `None`
/// (caller falls back to sole firma-ca) when no system bundle is found or the
/// write fails.
fn build_appended_ca_bundle(firma_ca_path: &Path) -> Option<PathBuf> {
    let roots: Vec<PathBuf> = SYSTEM_CA_BUNDLE_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .collect();
    build_appended_ca_bundle_with_roots(firma_ca_path, &roots)
}

/// Testable core of [`build_appended_ca_bundle`]: takes explicit candidate root
/// paths and concatenates the first existing one with the firma CA.
fn build_appended_ca_bundle_with_roots(firma_ca_path: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    let system_roots = roots.iter().find(|p| p.is_file())?;
    let mut bundle = match fs::read(system_roots) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, path = %system_roots.display(), "failed to read system CA bundle; using sole firma-ca");
            return None;
        }
    };
    let firma_ca = match fs::read(firma_ca_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, path = %firma_ca_path.display(), "failed to read firma-ca; using sole firma-ca");
            return None;
        }
    };
    if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(&firma_ca);
    let bundle_path = firma_ca_path.with_file_name("firma-ca-bundle.crt");
    if let Err(error) = fs::write(&bundle_path, &bundle) {
        tracing::warn!(%error, path = %bundle_path.display(), "failed to write combined CA bundle; using sole firma-ca");
        return None;
    }
    Some(bundle_path)
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

    if let Ok(explicit) = env::var("FIRMA_SIDECAR_CA_CERT_PATH")
        && !explicit.trim().is_empty()
    {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }

    if let Ok(ca_dir) = env::var("FIRMA_SIDECAR_CA_DIR")
        && !ca_dir.trim().is_empty()
    {
        let path = PathBuf::from(ca_dir).join("firma-ca.crt");
        if path.is_file() {
            return Some(path);
        }
    }

    let cwd_candidate = env::current_dir()
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

fn print_effective_config(
    identity: &RunIdentity,
    profile: &ResolvedProfile,
) -> Result<(), RunError> {
    #[derive(Serialize)]
    struct Snapshot<'a> {
        agent_id: &'a firma_core::AgentId,
        execution_profile: &'a str,
        profile: &'a ResolvedProfile,
        working_dir: PathBuf,
    }

    let snapshot = Snapshot {
        agent_id: &identity.agent_id,
        execution_profile: &identity.execution_profile,
        profile,
        working_dir: env::current_dir().map_err(|error| {
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
    use std::path::{Path, PathBuf};

    use firma_config_loader::CONFIG_FILE_NAME;

    use crate::config::{
        CapabilityLeaseConfig, CapabilitySource, ExecutableLaunchPolicy, MountSpec, NetworkPolicy,
        ResolvedProfile, SandboxIdentityMode, SidecarEndpoint,
    };

    use super::{RunIdentity, build_execution_env};
    use crate::backend::SandboxHandle;

    #[test]
    fn appended_ca_bundle_concatenates_system_roots_and_firma_ca() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let system = dir.path().join("system-roots.pem");
        fs::write(&system, b"-----SYSTEM ROOT-----\n").unwrap_or_else(|e| panic!("{e}"));
        let firma_ca = dir.path().join("firma-ca.crt");
        fs::write(&firma_ca, b"-----FIRMA CA-----\n").unwrap_or_else(|e| panic!("{e}"));

        let bundle =
            super::build_appended_ca_bundle_with_roots(&firma_ca, std::slice::from_ref(&system))
                .unwrap_or_else(|| panic!("bundle should be built"));
        assert_eq!(bundle, dir.path().join("firma-ca-bundle.crt"));
        let body = fs::read_to_string(&bundle).unwrap_or_else(|e| panic!("{e}"));
        assert!(body.contains("SYSTEM ROOT"));
        assert!(body.contains("FIRMA CA"));
    }

    #[test]
    fn appended_ca_bundle_falls_back_when_no_system_roots() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let firma_ca = dir.path().join("firma-ca.crt");
        fs::write(&firma_ca, b"-----FIRMA CA-----\n").unwrap_or_else(|e| panic!("{e}"));
        let missing = dir.path().join("does-not-exist.pem");
        assert!(super::build_appended_ca_bundle_with_roots(&firma_ca, &[missing]).is_none());
    }

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
                public_key_path: None,
                refresh_ratio: 0.60,
                grace_seconds: 30,
                requested_actions: CapabilityLeaseConfig::default_requested_actions(),
            },
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            secret_providers: BTreeMap::new(),
            use_http_proxy_sidecar: false,
            allow_non_structural: false,
            ca_trust_mode: crate::config::CaTrustMode::Sole,
        };

        let identity = RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let capability_token = crate::capability::read_capability_token(&profile.capability.source)
            .unwrap_or_else(|e| panic!("{e}"));

        let env = build_execution_env(
            &profile,
            &identity,
            capability_token.as_deref(),
            &profile.sidecar_endpoint,
            &BTreeMap::default(),
        );
        assert!(env.contains_key("HTTP_PROXY"));
        assert_eq!(
            env.get("FIRMA_AGENT_ID"),
            Some(&crate::identity::test_agent_id().to_string())
        );
        assert_eq!(env.get("FIRMA_RUN_PROFILE"), Some(&"generic".to_string()));
        let headers_json = env
            .get("FIRMA_RUN_ATTR_HEADERS_JSON")
            .unwrap_or_else(|| panic!("missing FIRMA_RUN_ATTR_HEADERS_JSON"));
        let headers: BTreeMap<String, String> =
            serde_json::from_str(headers_json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            headers.get("x-firma-agent"),
            Some(&crate::identity::test_agent_id().to_string())
        );
        assert_eq!(headers.get("x-firma-profile"), Some(&"generic".to_string()));
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
                public_key_path: None,
                refresh_ratio: 0.60,
                grace_seconds: 30,
                requested_actions: CapabilityLeaseConfig::default_requested_actions(),
            },
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            secret_providers: BTreeMap::new(),
            use_http_proxy_sidecar: false,
            allow_non_structural: false,
            ca_trust_mode: crate::config::CaTrustMode::Sole,
        };

        let identity = RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let capability_token = crate::capability::read_capability_token(&profile.capability.source)
            .unwrap_or_else(|e| panic!("{e}"));

        let env = build_execution_env(
            &profile,
            &identity,
            capability_token.as_deref(),
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
                public_key_path: None,
                refresh_ratio: 0.60,
                grace_seconds: 30,
                requested_actions: CapabilityLeaseConfig::default_requested_actions(),
            },
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            secret_providers: BTreeMap::new(),
            use_http_proxy_sidecar: false,
            allow_non_structural: false,
            ca_trust_mode: crate::config::CaTrustMode::Sole,
        };

        let identity = RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let capability_token = crate::capability::read_capability_token(&profile.capability.source)
            .unwrap_or_else(|e| panic!("{e}"));
        let env = build_execution_env(
            &profile,
            &identity,
            capability_token.as_deref(),
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
    fn ca_trust_mode_selects_appended_bundle_at_injection_site() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let ca_cert = dir.path().join("firma-ca.crt");
        fs::write(&ca_cert, b"-----FIRMA CA-----\n").unwrap_or_else(|e| panic!("{e}"));

        let make_profile = |mode: crate::config::CaTrustMode| ResolvedProfile {
            id: "copilot".to_string(),
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
                public_key_path: None,
                refresh_ratio: 0.60,
                grace_seconds: 30,
                requested_actions: CapabilityLeaseConfig::default_requested_actions(),
            },
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            secret_providers: BTreeMap::new(),
            use_http_proxy_sidecar: false,
            allow_non_structural: false,
            ca_trust_mode: mode,
        };

        // Route resolve_sidecar_ca_cert_path to our temp firma-ca via the
        // network override. `env.extend(network_overrides)` later clobbers the
        // injected FIRMA_SIDECAR_CA_CERT_PATH, so assert on a sibling var
        // (SSL_CERT_FILE) which reflects the effective, mode-selected path.
        let mut overrides = BTreeMap::new();
        overrides.insert(
            "FIRMA_SIDECAR_CA_CERT_PATH".to_string(),
            ca_cert.display().to_string(),
        );

        let identity = RunIdentity::new(crate::identity::test_agent_id(), "copilot");
        let capability_token = crate::capability::read_capability_token(
            &make_profile(crate::config::CaTrustMode::Sole)
                .capability
                .source,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let sole_profile = make_profile(crate::config::CaTrustMode::Sole);
        let sole_env = build_execution_env(
            &sole_profile,
            &identity,
            capability_token.as_deref(),
            &sole_profile.sidecar_endpoint,
            &overrides,
        );
        // Sole mode always injects the raw firma-ca path, never a bundle.
        assert_eq!(
            sole_env.get("SSL_CERT_FILE"),
            Some(&ca_cert.display().to_string())
        );

        let append_profile = make_profile(crate::config::CaTrustMode::AppendSystemRoots);
        let append_env = build_execution_env(
            &append_profile,
            &identity,
            capability_token.as_deref(),
            &append_profile.sidecar_endpoint,
            &overrides,
        );
        let bundle_path = ca_cert.with_file_name("firma-ca-bundle.crt");
        let system_roots_present = super::SYSTEM_CA_BUNDLE_CANDIDATES
            .iter()
            .any(|p| Path::new(p).is_file());
        if system_roots_present {
            // A system bundle exists: AppendSystemRoots must point at the
            // generated sibling bundle, and it must contain the firma CA.
            assert_eq!(
                append_env.get("SSL_CERT_FILE"),
                Some(&bundle_path.display().to_string())
            );
            let body = fs::read_to_string(&bundle_path).unwrap_or_else(|e| panic!("{e}"));
            assert!(body.contains("FIRMA CA"));
            assert_ne!(
                append_env.get("SSL_CERT_FILE"),
                sole_env.get("SSL_CERT_FILE")
            );
        } else {
            // No system bundle on this host: AppendSystemRoots falls back to
            // the sole firma-ca path, matching Sole mode.
            assert_eq!(
                append_env.get("SSL_CERT_FILE"),
                Some(&ca_cert.display().to_string())
            );
        }
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
                public_key_path: None,
                refresh_ratio: 0.60,
                grace_seconds: 30,
                requested_actions: CapabilityLeaseConfig::default_requested_actions(),
            },
            sidecar_local_exec: None,
            secret_providers: BTreeMap::new(),
            use_http_proxy_sidecar: true,
            allow_non_structural: false,
            ca_trust_mode: crate::config::CaTrustMode::Sole,
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
                public_key_path: None,
                refresh_ratio: 0.60,
                grace_seconds: 30,
                requested_actions: CapabilityLeaseConfig::default_requested_actions(),
            },
            sidecar_local_exec: None,
            executable_policies: BTreeMap::new(),
            secret_providers: BTreeMap::new(),
            use_http_proxy_sidecar: true,
            allow_non_structural: false,
            ca_trust_mode: crate::config::CaTrustMode::Sole,
        };
        let identity = RunIdentity::new(crate::identity::test_agent_id(), "codex");
        let capability_token = crate::capability::read_capability_token(&profile.capability.source)
            .unwrap_or_else(|e| panic!("{e}"));
        let env = build_execution_env(
            &profile,
            &identity,
            capability_token.as_deref(),
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
                public_key_path: None,
                refresh_ratio: 0.60,
                grace_seconds: 30,
                requested_actions: CapabilityLeaseConfig::default_requested_actions(),
            },
            sidecar_local_exec: None,
            secret_providers: BTreeMap::new(),
            use_http_proxy_sidecar: true,
            allow_non_structural: false,
            ca_trust_mode: crate::config::CaTrustMode::Sole,
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
                public_key_path: None,
                refresh_ratio: 0.60,
                grace_seconds: 30,
                requested_actions: CapabilityLeaseConfig::default_requested_actions(),
            },
            sidecar_local_exec: None,
            secret_providers: BTreeMap::new(),
            use_http_proxy_sidecar: true,
            allow_non_structural: false,
            ca_trust_mode: crate::config::CaTrustMode::Sole,
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
    fn vscode_shim_creates_runtime_wrapper_and_prepends_path() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let host_bin = tmp.path().join("host-bin");
        fs::create_dir(&host_bin).unwrap_or_else(|e| panic!("{e}"));
        let real_code = host_bin.join("code");
        fs::write(&real_code, "#!/bin/sh\nexit 0\n").unwrap_or_else(|e| panic!("{e}"));

        let mut env = BTreeMap::from([("PATH".to_string(), host_bin.display().to_string())]);
        let state_dir = tmp.path().join(".firma").join("vscode");
        let prepared = super::vscode::prepare_vscode_shim(
            tmp.path(),
            &state_dir,
            "code",
            vec![".".to_string()],
            &mut env,
            Some(host_bin.as_os_str()),
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let shim = super::vscode::vscode_shim_path(&tmp.path().join("bin"));
        assert_eq!(prepared.args, vec![".".to_string()]);
        assert_eq!(prepared.executable, shim);
        assert!(shim.is_file());
        let script = fs::read_to_string(&shim).unwrap_or_else(|e| panic!("{e}"));
        assert!(script.contains("--no-sandbox"));
        assert!(script.contains("--wait"));
        assert!(script.contains("--new-window"));
        assert!(script.contains("--user-data-dir"));
        assert!(script.contains("--extensions-dir"));
        assert!(script.contains(&real_code.display().to_string()));
        assert_eq!(
            env.get("FIRMA_RUN_VSCODE_USER_DATA_DIR"),
            Some(&state_dir.join("user-data").display().to_string())
        );
        assert_eq!(
            env.get("FIRMA_RUN_VSCODE_EXTENSIONS_DIR"),
            Some(&state_dir.join("extensions").display().to_string())
        );
        let settings_path = state_dir
            .join("user-data")
            .join("User")
            .join("settings.json");
        let settings = fs::read_to_string(&settings_path).unwrap_or_else(|e| panic!("{e}"));
        let parsed: serde_json::Value =
            serde_json::from_str(&settings).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parsed.get("github-authentication.preferDeviceCodeFlow"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(
            env.get("PATH")
                .is_some_and(|path| path.starts_with(&tmp.path().join("bin").display().to_string()))
        );
        assert_eq!(
            env.get("TMPDIR"),
            Some(
                &tmp.path()
                    .join("vscode")
                    .join("xdg-runtime")
                    .display()
                    .to_string()
            )
        );
        assert_eq!(
            env.get("XDG_RUNTIME_DIR"),
            Some(
                &tmp.path()
                    .join("vscode")
                    .join("xdg-runtime")
                    .display()
                    .to_string()
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn vscode_shim_invokes_fake_code_with_managed_contract() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let host_bin = tmp.path().join("host-bin");
        fs::create_dir(&host_bin).unwrap_or_else(|e| panic!("{e}"));
        let real_code = host_bin.join("code");
        let record_path = tmp.path().join("vscode-invocation.txt");
        fs::write(
            &real_code,
            "#!/bin/sh\n\
             set -eu\n\
             {\n\
             printf 'USER_DATA=%s\\n' \"$FIRMA_RUN_VSCODE_USER_DATA_DIR\"\n\
             printf 'EXTENSIONS=%s\\n' \"$FIRMA_RUN_VSCODE_EXTENSIONS_DIR\"\n\
             i=0\n\
             for arg in \"$@\"; do\n\
             printf 'ARG_%s=%s\\n' \"$i\" \"$arg\"\n\
             i=$((i + 1))\n\
             done\n\
             } > \"$FIRMA_TEST_VSCODE_RECORD\"\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let mut permissions = fs::metadata(&real_code)
            .unwrap_or_else(|e| panic!("{e}"))
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&real_code, permissions).unwrap_or_else(|e| panic!("{e}"));

        let state_dir = tmp.path().join(".firma").join("vscode");
        let mut env = BTreeMap::from([
            ("PATH".to_string(), host_bin.display().to_string()),
            (
                "FIRMA_TEST_VSCODE_RECORD".to_string(),
                record_path.display().to_string(),
            ),
        ]);
        let prepared = super::vscode::prepare_vscode_shim(
            tmp.path(),
            &state_dir,
            "code",
            vec![".".to_string()],
            &mut env,
            Some(host_bin.as_os_str()),
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let output = Command::new(&prepared.executable)
            .args(&prepared.args)
            .env_clear()
            .envs(&env)
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            output.status.success(),
            "shim failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let user_data_dir = state_dir.join("user-data").display().to_string();
        let extensions_dir = state_dir.join("extensions").display().to_string();
        let record = fs::read_to_string(&record_path).unwrap_or_else(|e| panic!("{e}"));
        let expected = [
            format!("USER_DATA={user_data_dir}"),
            format!("EXTENSIONS={extensions_dir}"),
            "ARG_0=--no-sandbox".to_string(),
            "ARG_1=--wait".to_string(),
            "ARG_2=--new-window".to_string(),
            "ARG_3=--user-data-dir".to_string(),
            format!("ARG_4={user_data_dir}"),
            "ARG_5=--extensions-dir".to_string(),
            format!("ARG_6={extensions_dir}"),
            "ARG_7=.".to_string(),
        ]
        .join("\n");
        assert_eq!(record.trim_end(), expected);
    }

    #[test]
    fn vscode_state_dir_uses_config_parent_when_available() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let config_path = tmp.path().join(".firma").join("firma.toml");
        let runtime_dir = tmp.path().join("runtime");

        let state_dir = super::vscode::resolve_vscode_state_dir(Some(&config_path), &runtime_dir)
            .unwrap_or_else(|e| panic!("{e}"));

        assert_eq!(state_dir, tmp.path().join(".firma").join("vscode"));
    }

    #[test]
    fn vscode_state_mount_is_added_once() {
        let state_dir = PathBuf::from("/workspace/.firma/vscode");
        let mut handle = crate::backend::SandboxHandle {
            backend: crate::backend::BackendKind::Bwrap,
            runtime_dir: PathBuf::from("/tmp/firma-run/session"),
            identity: crate::identity::RunIdentity::new(
                crate::identity::test_agent_id(),
                "vscode".to_string(),
            ),
            mounts: Vec::new(),
            network_policy: crate::config::NetworkPolicy {
                enforce_network_namespace: true,
                fail_closed: true,
            },
        };

        super::vscode::ensure_vscode_state_mount(&mut handle, &state_dir);
        super::vscode::ensure_vscode_state_mount(&mut handle, &state_dir);

        assert_eq!(handle.mounts.len(), 1);
        assert_eq!(handle.mounts[0].source, state_dir);
        assert!(!handle.mounts[0].read_only);
    }

    #[test]
    fn vscode_shim_rejects_state_and_window_conflicts() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut env = BTreeMap::new();
        let error = super::vscode::prepare_vscode_shim(
            tmp.path(),
            &tmp.path().join("vscode"),
            "code",
            vec!["--user-data-dir".to_string(), "/tmp/code".to_string()],
            &mut env,
            Some(std::ffi::OsStr::new("/usr/bin")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("--user-data-dir"));

        let error = super::vscode::prepare_vscode_shim(
            tmp.path(),
            &tmp.path().join("vscode"),
            "code",
            vec!["--reuse-window".to_string()],
            &mut env,
            Some(std::ffi::OsStr::new("/usr/bin")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("--reuse-window"));
    }

    #[test]
    fn vscode_host_executable_resolution_uses_supplied_path() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let host_bin = tmp.path().join("host-bin");
        fs::create_dir(&host_bin).unwrap_or_else(|e| panic!("{e}"));
        let real_code = host_bin.join("code");
        fs::write(&real_code, "#!/bin/sh\nexit 0\n").unwrap_or_else(|e| panic!("{e}"));

        let resolved = super::resolve_host_executable("code", Some(host_bin.as_os_str()))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved, real_code);
    }

    #[test]
    fn resolve_sidecar_template_prefers_explicit_sidecar_config() {
        let resolved = super::resolve_sidecar_template_path(
            Some(PathBuf::from("/tmp/from-sidecar-config.toml").as_path()),
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
        let user_cfg = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(&user_cfg, "[sidecar]\n").unwrap_or_else(|e| panic!("{e}"));

        let resolved = super::resolve_sidecar_template_path(None, Some(user_cfg.as_path()));
        assert_eq!(resolved, Some(user_cfg));
    }

    #[test]
    fn enforce_network_proof_is_structural_for_bwrap() {
        let backend = crate::backend::build_backend(crate::backend::BackendKind::Bwrap);
        let handle = SandboxHandle {
            backend: crate::backend::BackendKind::Bwrap,
            runtime_dir: PathBuf::from("/tmp/firma-test"),
            identity: RunIdentity::new(crate::identity::test_agent_id(), "generic"),
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
            identity: RunIdentity::new(crate::identity::test_agent_id(), "generic"),
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
            identity: RunIdentity::new(crate::identity::test_agent_id(), "generic"),
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
