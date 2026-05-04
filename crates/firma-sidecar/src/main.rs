use std::path::Path;
use std::sync::Arc;

use clap::Parser as _;
use firma_sidecar::{args, config, handler, health, log, startup};
use tokio::io::AsyncReadExt as _;
use tokio_util::sync::CancellationToken;

use crate::args::Args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    log::init_log(args.log_level, args.log_file.as_deref(), args.log_filter)?;
    tracing::debug!("firma-sidecar starting");

    tracing::debug!("loading configuration from {}", args.config_file.display());
    let config = read_config(&args.config_file).await?;
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
    let sigterm_handler = {
        let exit = exit.clone();
        tokio::spawn(async move {
            handle_sigterm(exit).await;
        })
    };
    tracing::debug!("signal handlers registered");

    let (audit_payload_tx, audit_payload_rx) = tokio::sync::mpsc::channel(100);
    let audit_event_builder = startup::load_audit_event_builder(&config.audit)?;
    let audit_sink = startup::spawn_audit_sink(
        &config.audit,
        audit_payload_rx,
        audit_event_builder,
        exit.clone(),
    )?;

    // Optional pre-flight: call IssueCapability to provision Stage 1 tokens.
    let preflight = match (&config.preflight, config.policy.authority_url.as_deref()) {
        (Some(pf_config), Some(authority_url)) => {
            Some(startup::run_preflight(pf_config, authority_url).await?)
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
    let interceptor_handle = startup::spawn_interceptor(&config, handler, exit.clone())?;

    emit_ready_sequence(
        &args.config_file,
        &config,
        pipeline_runtime.mapping_rules_loaded,
    );
    emit_operator_routing_hints(&config);

    let authority_stream_tasks = async {
        if let Some(handle) = authority_handle {
            let _ = tokio::join!(handle.policy_task, handle.revocation_task);
        }
    };
    let _ = tokio::join!(
        audit_sink,
        health_server,
        interceptor_handle,
        sigterm_handler,
        authority_stream_tasks
    );
    tracing::debug!("firma-sidecar exiting");

    Ok(())
}

/// Build the [`startup::StartupReport`] from runtime state and emit
/// the seven-line contract.
fn emit_ready_sequence(config_path: &Path, config: &config::SidecarConfig, mapping_rules: usize) {
    let (policy_bundle_version, policy_count) =
        startup::compute_policy_bundle_version(&config.policy.dir)
            .unwrap_or_else(|_| ("00000000".to_string(), 0));
    let interceptor_addr = interceptor_addr_display(&config.interceptor);
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
        interceptor_addr,
    });
}

/// Format the interceptor address used in the contract's "interceptor
/// listening" line according to the active mode.
fn interceptor_addr_display(ic: &config::InterceptorConfig) -> String {
    match ic.mode {
        config::InterceptorMode::HttpProxy | config::InterceptorMode::Grpc => {
            ic.listen_addr.to_string()
        }
        #[cfg(unix)]
        config::InterceptorMode::UnixSocket => ic
            .socket_path
            .as_ref()
            .map_or_else(String::new, |p| p.display().to_string()),
    }
}

/// Emit operator hints for common routing/coverage confusion cases.
fn emit_operator_routing_hints(config: &config::SidecarConfig) {
    if config.interceptor.mode == config::InterceptorMode::HttpProxy {
        let proxy = format!("http://{}", config.interceptor.listen_addr);
        tracing::info!(
            proxy = %proxy,
            "http_proxy mode active: clients must route traffic through this proxy for sidecar enforcement/audit"
        );
        tracing::info!(
            "set HTTP_PROXY/HTTPS_PROXY/ALL_PROXY or run via firma-run wrapper to guarantee coverage"
        );
    }
}

/// Handler worker for catching sigterm signals.
///
/// When a SIGTERM signal is caught, the `exit` flag is triggered.
async fn handle_sigterm(exit: CancellationToken) {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("received SIGINT, shutting down");
                }
                _ = sigterm.recv() => {
                    tracing::info!("received SIGTERM, shutting down");
                }
            }
        }
        Err(e) => {
            tracing::warn!("failed to register SIGTERM handler: {e}; falling back to SIGINT only");
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!("failed to listen for SIGINT: {e}");
            } else {
                tracing::info!("received SIGINT, shutting down");
            }
        }
    }

    exit.cancel();
}

/// Read [`config::SidecarConfig`] from the given [`Path`].
async fn read_config(path: &Path) -> anyhow::Result<config::SidecarConfig> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut content = String::new();
    f.read_to_string(&mut content).await?;

    let config: config::SidecarConfig = toml::from_str(&content)?;
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;

    Ok(config)
}
