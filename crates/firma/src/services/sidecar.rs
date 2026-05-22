//! Runner for `firma sidecar`.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use firma_sidecar::{config, handler, health, startup};
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
    let state_dir = match crate::services::init::resolve_state_dir(args.state_dir) {
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
                println!("firma sidecar running, state_dir={}", state_dir.display());
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!("start: {error}")),
    }
}

fn run_stop(args: StopArgs) -> ExitCode {
    info!(timeout = args.timeout, "firma sidecar stop invoked");
    let state_dir = match crate::services::init::resolve_state_dir(args.state_dir) {
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
    eprintln!("firma sidecar: {msg}");
    ExitCode::from(2)
}

async fn serve(args: crate::args::sidecar::ServeArgs) -> anyhow::Result<ExitCode> {
    debug!("firma sidecar starting");

    let resolved =
        firma_config::resolve_config("sidecar", args.config.as_deref(), &firma_config::SystemDirs)?;
    info!(
        path = %resolved.config_file.display(),
        source = ?resolved.source,
        "config resolved"
    );
    let config = read_config(&resolved)?;
    debug!("configuration loaded successfully");

    let exit = CancellationToken::new();

    debug!(
        "initializing health check server at {}",
        args.health_bind_addr
    );
    let health_server =
        health::HealthcheckServer::bind(args.health_bind_addr, exit.clone()).await?;
    let health_server = tokio::spawn(health_server.serve());
    debug!("health check server listening at {}", args.health_bind_addr);

    debug!("registering signal handlers for graceful shutdown");
    let shutdown_handler = {
        let exit = exit.clone();
        tokio::spawn(async move {
            wait_for_shutdown(exit).await;
        })
    };

    let (audit_payload_tx, audit_payload_rx) = tokio::sync::mpsc::channel(100);
    // Per-run identity stamped on every emitted audit event (FIR-185).
    // Set by `firma run`'s SidecarSupervisor; empty in daemon mode.
    let sandbox_id = std::env::var("FIRMA_RUN_SANDBOX_ID").unwrap_or_default();
    let audit_event_builder =
        startup::load_audit_event_builder(&config.audit)?.with_sandbox_id(sandbox_id);
    let audit_sink = startup::spawn_audit_sink(
        &config.audit,
        audit_payload_rx,
        audit_event_builder,
        exit.clone(),
    )?;

    let ca_cert_pem: Option<Vec<u8>> = if let Some(ref path) = config.authority.ca_cert_path {
        Some(tokio::fs::read(path).await.map_err(|e| {
            anyhow::anyhow!("failed to read authority CA cert {}: {e}", path.display())
        })?)
    } else {
        None
    };

    let preflight = match (&config.preflight, config.policy.authority_url.as_deref()) {
        (Some(pf_config), Some(authority_url)) => {
            Some(startup::run_preflight(pf_config, authority_url, ca_cert_pem.as_deref()).await?)
        }
        (Some(_), None) => {
            anyhow::bail!("[preflight] is configured but policy.authority_url is not set");
        }
        (None, _) => None,
    };

    let pipeline_runtime = startup::build_pipeline_runtime(&config, preflight)?;
    let authority_handle =
        startup::spawn_authority_client(&config, &pipeline_runtime, exit.clone())?;
    let connector_registry = startup::build_connector_registry(&config.connector)?;
    let handler = Arc::new(handler::RequestHandler::new(
        Arc::clone(&pipeline_runtime.pipeline),
        connector_registry,
        audit_payload_tx,
    ));

    debug!(mode = %config.interceptor.mode, "starting interceptor");
    let interceptor = startup::spawn_interceptor(&config, handler, exit.clone())?;

    let local_exec_handle = startup::spawn_local_exec_endpoint(&config, exit.clone())?;

    let report = build_startup_report(
        &resolved.config_file,
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
    let _ = tokio::join!(
        audit_sink,
        health_server,
        interceptor.handle,
        shutdown_handler,
        authority_stream_tasks,
        local_exec_task
    );
    debug!("firma sidecar exiting");

    Ok(ExitCode::SUCCESS)
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
        .policy
        .authority_url
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

fn read_config(resolved: &firma_config::ResolvedConfig) -> anyhow::Result<config::SidecarConfig> {
    let body = firma_config::load_section(&resolved.config_file, "sidecar")
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
    let mut config: config::SidecarConfig = toml::from_str(&body)?;
    config.rebase_defaults(&resolved.config_dir);
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
    Ok(config)
}
