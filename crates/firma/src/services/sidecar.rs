//! Runner for `firma sidecar`.

use std::{path::Path, process::ExitCode, str::FromStr, sync::Arc, time::Duration};

#[cfg(unix)]
use std::path::PathBuf;

use anyhow::Context as _;
use firma_config_schema::sidecar::InterceptorMode;
use firma_runtime_state::RuntimeLayout;
use firma_secret_provider::{
    MatcherCompiler,
    endpoint::client::ClientEndpoint,
    gateway::client::{GATEWAY_ADDR_ENV, GatewayClient},
};
use firma_sidecar::{
    audit::AuditPayload, authority_client::readiness::ReadinessFlag, composio::ComposioCatalogs,
    config, connector::ConnectorRegistry, handler, health, pipeline::EnforcementPipeline, startup,
    startup::CapabilityReloader,
};
#[cfg(unix)]
use firma_stack::UnixEndpoint;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{
    args::sidecar::{Args, SidecarCommand, StartArgs, StopArgs},
    signal::wait_for_shutdown,
};

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
    runtime_layout: &RuntimeLayout,
    config: &config::SidecarConfig,
    pipeline_runtime: &startup::PipelineRuntime,
    exit: &CancellationToken,
) -> anyhow::Result<Option<CapabilityReloader>> {
    if !config.capability_seed.hot_reload {
        return Ok(None);
    }
    Ok(Some(CapabilityReloader::spawn(
        runtime_layout,
        &config.capability_seed,
        Arc::clone(&pipeline_runtime.token_verifier),
        pipeline_runtime.capability_handle.clone(),
        exit.clone(),
    )?))
}

/// Load the reviewed Composio catalogs compiled into the Sidecar.
///
/// Composio multiplexes every connected app onto two hosts and one URL shape,
/// so the catalogs are what let enforcement see the tool behind a request.
/// Loading them unconditionally keeps that visibility independent of operator
/// configuration.
///
/// # Errors
///
/// Returns an error when a shipped snapshot and its mapping have drifted
/// apart, which fails startup instead of silently leaving Composio traffic
/// classified only by transport.
fn load_composio_catalogs() -> anyhow::Result<Arc<firma_sidecar::composio::ComposioCatalogs>> {
    let catalogs = firma_sidecar::composio::ComposioCatalogs::builtin()
        .map_err(|error| anyhow::anyhow!("failed to load Composio catalogs: {error}"))?;
    debug!(tools = catalogs.len(), "loaded pinned Composio catalogs");
    Ok(Arc::new(catalogs))
}

fn build_request_handler(
    pipeline: Arc<EnforcementPipeline>,
    connector_registry: Arc<ConnectorRegistry>,
    audit_sink_sender: tokio::sync::mpsc::Sender<AuditPayload>,
    composio_catalogs: Arc<ComposioCatalogs>,
    config: &config::SidecarConfig,
) -> anyhow::Result<handler::RequestHandler> {
    let base = handler::RequestHandler::new(pipeline, connector_registry, audit_sink_sender)
        .with_composio_catalogs(composio_catalogs)
        .with_max_decompressed_body_bytes(config.interceptor.max_decompressed_body_bytes());

    let base = if let Ok(addr) = std::env::var(GATEWAY_ADDR_ENV) {
        match ClientEndpoint::from_str(&addr) {
            Ok(ep) => {
                tracing::info!(%addr, "secret gateway configured; placeholder rehydration enabled");
                base.with_gateway_client(GatewayClient::new(ep, config.secret_gateway))
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "invalid secret gateway address \"{addr}\": {err}"
                ));
            }
        }
    } else {
        if !config.http_secret_providers.is_empty() {
            return Err(anyhow::anyhow!(
                "http_secret_providers configured but no secret gateway is available"
            ));
        }
        base
    };

    let http_secret_providers = config
        .http_secret_providers
        .iter()
        .map(|spec| {
            spec.compile().map_err(|err| {
                anyhow::anyhow!(
                    "invalid secret provider config for \"{}\": {err}",
                    spec.provider_id
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if http_secret_providers.is_empty() {
        return Ok(base);
    }

    Ok(base.with_http_secret_providers(http_secret_providers))
}

#[expect(
    clippy::too_many_lines,
    reason = "startup sequencing stays linear so readiness ordering remains auditable"
)]
async fn serve(args: crate::args::sidecar::ServeArgs) -> anyhow::Result<ExitCode> {
    debug!("firma sidecar starting");
    let sandbox_id = propagated_sandbox_id()?;
    let runtime_layout = RuntimeLayout::resolve(None)?;

    let resolved = firma_config_loader::ConfigResolver::default()
        .resolve_config(args.config.as_deref())?
        .ok_or_else(|| anyhow::anyhow!("no firma.toml found for `sidecar`"))?;
    info!(
        path = %resolved.config_file().display(),
        source = ?resolved.source,
        "config resolved"
    );
    let config = read_config(&resolved, args.authority_connect_addr)?;
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

    let pipeline_runtime = startup::build_pipeline_runtime(&runtime_layout, &config)?;
    let authority_handle =
        startup::spawn_authority_client(&config, &pipeline_runtime, exit.clone())?;
    let _capability_reload =
        spawn_capability_reload(&runtime_layout, &config, &pipeline_runtime, &exit)?;
    let connector_registry = startup::build_connector_registry(&config.connector)?;
    let handler = Arc::new(build_request_handler(
        Arc::clone(&pipeline_runtime.pipeline),
        connector_registry,
        audit_payload_tx,
        load_composio_catalogs()?,
        &config,
    )?);

    debug!(mode = %config.interceptor.mode, "starting interceptor");
    let interceptor = startup::spawn_interceptor(&runtime_layout, &config, handler, exit.clone())?;

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
    let health_readiness_mirror = if wait_for_streams_ready(&pipeline_runtime, exit.clone()).await
        == StreamReadinessOutcome::Hydrated
    {
        write_startup_report(
            args.startup_report.as_deref(),
            &config.interceptor,
            &interceptor.listen_addr,
        )?;
        startup::log_ready_line();
        health::mark_ready(&health_ready);
        Some(spawn_health_readiness_mirror(
            Arc::clone(&health_ready),
            Arc::clone(&pipeline_runtime.readiness),
            exit.clone(),
        ))
    } else {
        None
    };

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
    let health_readiness_task = async {
        if let Some(handle) = health_readiness_mirror {
            let _ = handle.await;
        }
    };
    let _ = tokio::join!(
        audit_sink,
        health_server,
        health_readiness_task,
        interceptor.handle,
        shutdown_handler,
        authority_stream_tasks,
        local_exec_task,
        run_audit_task,
    );
    debug!("firma sidecar exiting");

    Ok(ExitCode::SUCCESS)
}

fn write_startup_report(
    path: Option<&Path>,
    interceptor: &config::InterceptorConfig,
    listen_addr: &str,
) -> anyhow::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let endpoint = match interceptor.mode {
        InterceptorMode::HttpProxy | InterceptorMode::Grpc => {
            firma_stack::ComponentEndpoint::Tcp(listen_addr.parse().with_context(|| {
                format!("interceptor reported an invalid TCP listen address: {listen_addr}")
            })?)
        }
        #[cfg(unix)]
        InterceptorMode::UnixSocket => UnixEndpoint::new(PathBuf::from(listen_addr))
            .map(firma_stack::ComponentEndpoint::Unix)
            .map_err(|path| {
                anyhow::anyhow!(
                    "Unix interceptor socket path is invalid: {}",
                    path.display()
                )
            })?,
    };
    firma_stack::publish_startup_report(path, &endpoint)
        .with_context(|| format!("failed to write startup report to {}", path.display()))
}

fn propagated_sandbox_id() -> anyhow::Result<Option<firma_identifiers::SandboxId>> {
    // Per-run identity stamped on every emitted audit event (FIR-185).
    // Set by `firma run`'s prepared Sidecar command; empty in daemon mode.
    let Some(value) = std::env::var_os("FIRMA_RUN_SANDBOX_ID") else {
        return Ok(None);
    };
    let value = value.into_string().map_err(|_| {
        anyhow::anyhow!("FIRMA_RUN_SANDBOX_ID must contain a valid UTF-8 sandbox ID")
    })?;
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
        PathBuf::from(socket),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamReadinessOutcome {
    Hydrated,
    Cancelled,
}

async fn wait_for_streams_ready(
    runtime: &startup::PipelineRuntime,
    cancel: CancellationToken,
) -> StreamReadinessOutcome {
    if cancel.is_cancelled() {
        return StreamReadinessOutcome::Cancelled;
    }
    if runtime.readiness.snapshot().fully_ready() {
        return StreamReadinessOutcome::Hydrated;
    }
    debug!("awaiting authority stream hydration before emitting ready");
    tokio::select! {
        biased;
        () = cancel.cancelled() => StreamReadinessOutcome::Cancelled,
        () = runtime.readiness.wait_until_fully_ready() => StreamReadinessOutcome::Hydrated,
    }
}

fn spawn_health_readiness_mirror(
    ready: Arc<std::sync::atomic::AtomicBool>,
    readiness: Arc<ReadinessFlag>,
    exit: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if exit.is_cancelled() {
            health::mark_not_ready(&ready);
            return;
        }
        let mut updates = readiness.subscribe();
        loop {
            if updates.borrow().fully_ready() {
                health::mark_ready(&ready);
            } else {
                health::mark_not_ready(&ready);
            }

            tokio::select! {
                biased;
                () = exit.cancelled() => {
                    health::mark_not_ready(&ready);
                    return;
                },
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
    if config.interceptor.mode == InterceptorMode::HttpProxy {
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
    authority_connect_addr: Option<std::net::SocketAddr>,
) -> anyhow::Result<config::SidecarConfig> {
    let body = resolved
        .config
        .raw_section("sidecar")
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
    let mut schema: firma_config_schema::sidecar::SidecarConfig = toml::from_str(&body)?;
    if let Some(connect_addr) = authority_connect_addr {
        schema.authority.connect_addr = Some(connect_addr);
    }
    let mut config = config::SidecarConfig::try_from(schema)
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
    config.rebase_defaults(&resolved.config_dir());
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use firma_sidecar::authority_client::readiness::{ReadinessFlag, ReadinessState};

    use super::*;

    #[test]
    fn authority_connect_addr_cli_override_takes_precedence_over_config() {
        let directory = tempfile::tempdir().expect("create config directory");
        let config_path = directory.path().join("firma.toml");
        std::fs::write(
            &config_path,
            "[sidecar.authority]\nurl = 'http://localhost:50051'\nconnect_addr = '127.0.0.1:41000'\n",
        )
        .expect("write config");
        let resolved = firma_config_loader::ConfigResolver::default()
            .resolve_config(Some(&config_path))
            .expect("resolve config")
            .expect("explicit config exists");
        let cli_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42000);

        let config = read_config(&resolved, Some(cli_address)).expect("read config");

        assert_eq!(config.authority.connect_addr, Some(cli_address));
    }

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

        readiness.set_revocation_ready(true);
        assert!(
            wait_for_health(&ready, true).await,
            "health mirror did not restore ready after revocation readiness recovered"
        );

        cancel.cancel();
        assert!(handle.await.is_ok(), "health mirror task panicked");
        assert!(
            !ready.load(Ordering::Acquire),
            "health mirror left health ready after cancellation"
        );
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

    #[test]
    fn build_startup_report_falls_back_when_policy_dir_unreadable_and_authority_disabled() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file, not a directory: `read_dir` fails with a real IO
        // error (not `NotFound`, which `compute_policy_bundle_version`
        // already handles as "no policies"), so the report must fall back
        // to the "00000000"/0 defaults rather than propagating the error.
        let not_a_dir = dir.path().join("not-a-directory");
        std::fs::write(&not_a_dir, b"oops").unwrap();
        let mut cfg = config::SidecarConfig::default();
        cfg.policy.dir = not_a_dir;
        cfg.authority.url = None;

        let config_path = Path::new("firma.toml");
        let report = build_startup_report(config_path, &cfg, 3, "127.0.0.1:9000");

        assert_eq!(report.policy_bundle_version, "00000000");
        assert_eq!(report.policy_count, 0);
        assert_eq!(report.authority_endpoint, "(disabled)");
        assert_eq!(report.mapping_rules, 3);
        assert_eq!(report.connector_hosts, cfg.connector.hosts.len());
        assert_eq!(
            report.connector_default_timeout_ms,
            cfg.connector.default_timeout_ms
        );
        assert_eq!(report.interceptor_addr, "127.0.0.1:9000");
    }

    #[test]
    fn build_startup_report_uses_authority_url_and_computed_policy_bundle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.cedar"),
            b"permit(principal, action, resource);",
        )
        .unwrap();

        let mut cfg = config::SidecarConfig::default();
        cfg.policy.dir = dir.path().to_path_buf();
        cfg.authority.url = Some("https://auth.test:9443".to_string());
        cfg.connector.default_timeout_ms = 5_000;

        let config_path = Path::new("firma.toml");
        let report = build_startup_report(config_path, &cfg, 1, "127.0.0.1:9001");

        assert_eq!(report.authority_endpoint, "https://auth.test:9443");
        assert_eq!(report.policy_count, 1);
        assert_eq!(report.policy_bundle_version.len(), 8);
        assert!(
            report
                .policy_bundle_version
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
        assert_eq!(report.connector_hosts, cfg.connector.hosts.len());
        assert_eq!(report.connector_default_timeout_ms, 5_000);
    }
}
