//! Runner for `firma sidecar`.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use firma_sidecar::authority_client::readiness::ReadinessFlag;
use firma_sidecar::startup::CapabilityReloader;
use firma_sidecar::{config, handler, health, startup};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::args::sidecar::{Args, SidecarCommand, StartArgs, StopArgs};
use crate::signal::wait_for_shutdown;

/// Entry point for `firma sidecar [SUBCOMMAND]`.
///
/// # Errors
///
/// Propagates config/startup/runtime errors from the server path, or
/// rendering/probe errors from the status path.
pub async fn run(args: Args) -> anyhow::Result<ExitCode> {
    match args.command {
        Some(SidecarCommand::Status(ref status)) => crate::services::sidecar_status::run(status),
        Some(SidecarCommand::Start(start)) => Ok(run_start(start)),
        Some(SidecarCommand::Stop(stop)) => Ok(run_stop(stop)),
        None => serve(args.serve).await,
    }
}

fn run_start(args: StartArgs) -> ExitCode {
    info!(
        detach = args.detach,
        config = ?args.config,
        state_dir = ?args.state_dir,
        "firma sidecar start invoked"
    );
    let cfg = match firma_stack::resolve_stack_config(args.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(error) => return fail(&format!("config: {error}")),
    };
    let state_dir = match crate::services::config::resolve_state_dir(args.state_dir) {
        Ok(path) => path,
        Err(error) => return fail(&error),
    };
    let mode = if args.detach {
        firma_stack::StartMode::Detached
    } else {
        firma_stack::StartMode::Foreground
    };
    match firma_stack::start(&cfg, &state_dir, mode) {
        Ok(_) => {
            if mode == firma_stack::StartMode::Detached {
                crate::output::ok(format!(
                    "sidecar running, state_dir={}",
                    state_dir.display()
                ));
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!("start: {error}")),
    }
}

fn run_stop(args: StopArgs) -> ExitCode {
    info!(timeout = args.timeout, "firma sidecar stop invoked");
    let state_dir = match crate::services::config::resolve_state_dir(args.state_dir) {
        Ok(path) => path,
        Err(error) => return fail(&error),
    };
    match firma_stack::stop(&state_dir, Duration::from_secs(args.timeout)) {
        // Either path succeeded as long as the call returned. `forced=true`
        // means at least one child needed a hard kill — common when the
        // components hold long-lived gRPC streams that block tonic's
        // graceful shutdown. The sidecar is down either way.
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("stop: {error}")),
    }
}

fn fail(msg: &str) -> ExitCode {
    crate::output::err(format!("sidecar: {msg}"));
    ExitCode::from(2)
}

/// Watch the per-session capability seed so a token re-minted by `firma run` is
/// hot-swapped into Stage 1 without a restart. Returns `None` when hot-reload is
/// disabled. The returned guard stops the watch on drop.
fn spawn_capability_reload(
    config: &config::SidecarConfig,
    pipeline_runtime: &startup::PipelineRuntime,
    exit: &CancellationToken,
) -> anyhow::Result<Option<CapabilityReloader>> {
    if !config.capability_seed.hot_reload {
        return Ok(None);
    }
    Ok(Some(CapabilityReloader::spawn(
        &config.capability_seed,
        Arc::clone(&pipeline_runtime.token_verifier),
        pipeline_runtime.capability_handle.clone(),
        exit.clone(),
    )?))
}

async fn serve(args: crate::args::sidecar::ServeArgs) -> anyhow::Result<ExitCode> {
    debug!("firma sidecar starting");
    let sandbox_id = propagated_sandbox_id()?;

    let resolved = firma_config_loader::ConfigResolver::default()
        .resolve_config(args.config.as_deref())?
        .ok_or_else(|| anyhow::anyhow!("no firma.toml found for `sidecar`"))?;
    info!(
        path = %resolved.config_file().display(),
        source = ?resolved.source,
        "config resolved"
    );
    let config = read_config(&resolved)?;
    debug!("configuration loaded successfully");

    let exit = CancellationToken::new();
    let health_ready = health::readiness_flag();
    let health_server = spawn_health_server(
        args.health_bind_addr,
        exit.clone(),
        Arc::clone(&health_ready),
    )
    .await?;

    debug!("registering signal handlers for graceful shutdown");
    let shutdown_handler = {
        let exit = exit.clone();
        tokio::spawn(async move {
            wait_for_shutdown(exit).await;
        })
    };

    let (audit_payload_tx, audit_payload_rx) = tokio::sync::mpsc::channel(100);
    let audit_event_builder =
        startup::load_audit_event_builder(&config.audit)?.with_sandbox_id(sandbox_id);
    let audit_sink = startup::spawn_audit_sink(
        &config.audit,
        audit_payload_rx,
        audit_event_builder,
        exit.clone(),
    )?;

    // Out-of-band ingest for the `firma run` audit channel (e.g. loopback
    // connections the egress guard blocks at the sandbox boundary). Bound only
    // when `firma run` provisions a control socket; absent in plain daemon
    // mode. Clone the sender before it is moved into the RequestHandler below.
    #[cfg(unix)]
    let run_audit_handle = spawn_run_audit_listener(&audit_payload_tx, &exit);

    let pipeline_runtime = startup::build_pipeline_runtime(&config)?;
    let authority_handle =
        startup::spawn_authority_client(&config, &pipeline_runtime, exit.clone())?;
    let _capability_reload = spawn_capability_reload(&config, &pipeline_runtime, &exit)?;
    let connector_registry = startup::build_connector_registry(&config.connector)?;
    let handler = Arc::new(handler::RequestHandler::new(
        Arc::clone(&pipeline_runtime.pipeline),
        connector_registry,
        audit_payload_tx,
    ));

    debug!(mode = %config.interceptor.mode, "starting interceptor");
    let interceptor = startup::spawn_interceptor(&config, handler, exit.clone())?;

    let local_exec_handle = startup::spawn_local_exec_endpoint(&config, sandbox_id, exit.clone())?;

    let report = build_startup_report(
        resolved.config_file(),
        &config,
        pipeline_runtime.mapping_rules_loaded,
        &interceptor.listen_addr,
    );
    startup::log_pre_ready_sequence(&report);
    emit_operator_routing_hints(&config, &interceptor.listen_addr);

    // Hold `ready` until Authority streams hydrate so the first
    // wrapped-agent call cannot race the readiness gate (FIR-183).
    // `wait_until_fully_ready` returns immediately when no Authority is
    // configured because the pipeline pre-seeds both readiness flags as
    // true in that mode.
    wait_for_streams_ready(&pipeline_runtime, exit.clone()).await;
    startup::log_ready_line();
    health::mark_ready(&health_ready);
    let health_readiness_mirror = spawn_health_readiness_mirror(
        Arc::clone(&health_ready),
        Arc::clone(&pipeline_runtime.readiness),
        exit.clone(),
    );

    let authority_stream_tasks = async {
        if let Some(handle) = authority_handle {
            let _ = tokio::join!(handle.policy_task, handle.revocation_task);
        }
    };
    let local_exec_task = async {
        if let Some(handle) = local_exec_handle {
            let _ = handle.await;
        }
    };
    let run_audit_task = async {
        #[cfg(unix)]
        if let Some(handle) = run_audit_handle {
            let _ = handle.await;
        }
    };
    let _ = tokio::join!(
        audit_sink,
        health_server,
        health_readiness_mirror,
        interceptor.handle,
        shutdown_handler,
        authority_stream_tasks,
        local_exec_task,
        run_audit_task,
    );
    debug!("firma sidecar exiting");

    Ok(ExitCode::SUCCESS)
}

fn propagated_sandbox_id() -> anyhow::Result<Option<firma_runtime_state::SandboxId>> {
    let Some(value) = std::env::var_os("FIRMA_RUN_SANDBOX_ID") else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("FIRMA_RUN_SANDBOX_ID must contain a valid UTF-8 UUID v7"))?;
    value
        .parse()
        .map(Some)
        .map_err(|error| anyhow::anyhow!("invalid FIRMA_RUN_SANDBOX_ID: {error}"))
}

/// Spawns the `firma run` audit-channel listener when `firma run` provisions a
/// control socket via `FIRMA_RUN_AUDIT_SOCK`. Returns `None` in plain daemon
/// mode (no socket configured) or when binding fails — in the latter case the
/// Sidecar still serves traffic, but out-of-band reports (e.g. loopback blocks)
/// go unaudited, so the failure is logged loudly.
#[cfg(unix)]
fn spawn_run_audit_listener(
    audit_payload_tx: &tokio::sync::mpsc::Sender<firma_sidecar::audit::AuditPayload>,
    exit: &CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let socket = std::env::var("FIRMA_RUN_AUDIT_SOCK")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    match firma_sidecar::run_audit::spawn_listener(
        std::path::PathBuf::from(socket),
        audit_payload_tx.clone(),
        exit.clone(),
    ) {
        Ok(handle) => Some(handle),
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to start run-audit listener; out-of-band firma run reports will not be audited"
            );
            None
        }
    }
}

async fn wait_for_streams_ready(runtime: &startup::PipelineRuntime, cancel: CancellationToken) {
    if runtime.readiness.snapshot().fully_ready() {
        return;
    }
    debug!("awaiting authority stream hydration before emitting ready");
    tokio::select! {
        () = runtime.readiness.wait_until_fully_ready() => {}
        () = cancel.cancelled() => {}
    }
}

fn spawn_health_readiness_mirror(
    ready: Arc<std::sync::atomic::AtomicBool>,
    readiness: Arc<ReadinessFlag>,
    exit: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut updates = readiness.subscribe();
        loop {
            if updates.borrow().fully_ready() {
                health::mark_ready(&ready);
            } else {
                health::mark_not_ready(&ready);
            }

            tokio::select! {
                () = exit.cancelled() => return,
                changed = updates.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    })
}

fn build_startup_report<'a>(
    config_path: &'a Path,
    config: &'a config::SidecarConfig,
    mapping_rules: usize,
    interceptor_addr: &str,
) -> startup::StartupReport<'a> {
    let (policy_bundle_version, policy_count) =
        startup::compute_policy_bundle_version(&config.policy.dir)
            .unwrap_or_else(|_| ("00000000".to_string(), 0));
    let authority_endpoint = config
        .authority
        .url
        .clone()
        .unwrap_or_else(|| "(disabled)".to_string());

    startup::StartupReport {
        config_path,
        mapping_rules,
        policy_bundle_version,
        policy_count,
        authority_endpoint,
        connector_hosts: config.connector.hosts.len(),
        connector_default_timeout_ms: config.connector.default_timeout_ms,
        interceptor_addr: interceptor_addr.to_string(),
    }
}

async fn spawn_health_server(
    health_bind_addr: std::net::SocketAddr,
    exit: CancellationToken,
    ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    tracing::debug!("initializing health check server at {}", health_bind_addr);
    let health_server = health::HealthcheckServer::bind(health_bind_addr, exit, ready).await?;
    tracing::debug!("health check server listening at {}", health_bind_addr);
    Ok(tokio::spawn(health_server.serve()))
}

fn emit_operator_routing_hints(config: &config::SidecarConfig, interceptor_addr: &str) {
    if config.interceptor.mode == config::InterceptorMode::HttpProxy {
        let proxy = format!("http://{interceptor_addr}");
        info!(
            proxy = %proxy,
            "http_proxy mode active: clients must route traffic through this proxy for sidecar enforcement/audit"
        );
        info!(
            "set HTTP_PROXY/HTTPS_PROXY/ALL_PROXY or run via firma run wrapper to guarantee coverage"
        );
    }
}

fn read_config(
    resolved: &firma_config_loader::ResolvedConfig,
) -> anyhow::Result<config::SidecarConfig> {
    let body = resolved
        .config
        .section("sidecar")
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
    let mut config: config::SidecarConfig = toml::from_str(&body)?;
    config.rebase_defaults(&resolved.config_dir());
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use firma_sidecar::authority_client::readiness::{ReadinessFlag, ReadinessState};

    use super::*;

    #[tokio::test]
    async fn health_mirror_clears_ready_when_revocation_readiness_is_lost() {
        let ready = health::readiness_flag();
        let (readiness, _view) = ReadinessFlag::new(ReadinessState {
            policy_bundle_ready: true,
            revocation_ready: true,
        });
        let readiness = Arc::new(readiness);
        let cancel = CancellationToken::new();
        let handle = spawn_health_readiness_mirror(
            Arc::clone(&ready),
            Arc::clone(&readiness),
            cancel.clone(),
        );

        assert!(
            wait_for_health(&ready, true).await,
            "health mirror did not mark ready"
        );

        readiness.set_revocation_ready(false);

        assert!(
            wait_for_health(&ready, false).await,
            "health mirror did not clear ready after revocation readiness was lost"
        );

        cancel.cancel();
        assert!(handle.await.is_ok(), "health mirror task panicked");
    }

    async fn wait_for_health(ready: &std::sync::atomic::AtomicBool, expected: bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(200) {
            if ready.load(Ordering::Acquire) == expected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        ready.load(Ordering::Acquire) == expected
    }
}
