//! Runner for `firma sidecar`.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use firma_sidecar::{config, handler, health, startup};
use tokio_util::sync::CancellationToken;

use crate::args::sidecar::{Args, SidecarCommand};
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
        None => serve(args.serve).await,
    }
}

async fn serve(args: crate::args::sidecar::ServeArgs) -> anyhow::Result<ExitCode> {
    tracing::debug!("firma sidecar starting");

    let resolved =
        firma_config::resolve_config("sidecar", args.config.as_deref(), &firma_config::SystemDirs)?;
    tracing::info!(
        path = %resolved.config_file.display(),
        source = ?resolved.source,
        "config resolved"
    );
    let config = read_config(&resolved)?;
    tracing::debug!("configuration loaded successfully");

    let exit = CancellationToken::new();

    tracing::debug!(
        "initializing health check server at {}",
        args.health_bind_addr
    );
    let health_server =
        health::HealthcheckServer::bind(args.health_bind_addr, exit.clone()).await?;
    let health_server = tokio::spawn(health_server.serve());
    tracing::debug!("health check server listening at {}", args.health_bind_addr);

    tracing::debug!("registering signal handlers for graceful shutdown");
    let shutdown_handler = {
        let exit = exit.clone();
        tokio::spawn(async move {
            wait_for_shutdown(exit).await;
        })
    };

    let (audit_payload_tx, audit_payload_rx) = tokio::sync::mpsc::channel(100);
    let audit_event_builder = startup::load_audit_event_builder(&config.audit)?;
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
        pipeline_runtime.pipeline,
        connector_registry,
        audit_payload_tx,
    ));

    tracing::debug!(mode = %config.interceptor.mode, "starting interceptor");
    let interceptor = startup::spawn_interceptor(&config, handler, exit.clone())?;

    let local_exec_handle = startup::spawn_local_exec_endpoint(&config, exit.clone())?;

    emit_ready_sequence(
        &resolved.config_file,
        &config,
        pipeline_runtime.mapping_rules_loaded,
        &interceptor.listen_addr,
    );
    emit_operator_routing_hints(&config, &interceptor.listen_addr);

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
    tracing::debug!("firma sidecar exiting");

    Ok(ExitCode::SUCCESS)
}

fn emit_ready_sequence(
    config_path: &Path,
    config: &config::SidecarConfig,
    mapping_rules: usize,
    interceptor_addr: &str,
) {
    let (policy_bundle_version, policy_count) =
        startup::compute_policy_bundle_version(&config.policy.dir)
            .unwrap_or_else(|_| ("00000000".to_string(), 0));
    let authority_endpoint = config
        .policy
        .authority_url
        .clone()
        .unwrap_or_else(|| "(disabled)".to_string());

    startup::log_ready_sequence(&startup::StartupReport {
        config_path,
        mapping_rules,
        policy_bundle_version,
        policy_count,
        authority_endpoint,
        connector_hosts: config.connector.hosts.len(),
        connector_default_timeout_ms: config.connector.default_timeout_ms,
        interceptor_addr: interceptor_addr.to_string(),
    });
}

fn emit_operator_routing_hints(config: &config::SidecarConfig, interceptor_addr: &str) {
    if config.interceptor.mode == config::InterceptorMode::HttpProxy {
        let proxy = format!("http://{interceptor_addr}");
        tracing::info!(
            proxy = %proxy,
            "http_proxy mode active: clients must route traffic through this proxy for sidecar enforcement/audit"
        );
        tracing::info!(
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
