//! Firma Sidecar — the enforcement layer between an agent and the outside
//! world.
//!
//! Every outbound agent call passes through the Sidecar. It is a single
//! statically-linked binary with no persistent database; all state is
//! in-memory and re-populated from Authority streams on restart.
//!
//! # Architecture
//!
//! ```text
//! agent → interceptor → normalizer → Stage 1 → Stage 2 → connector → external
//! ```
//!
//! - [`interceptor`] — Captures outbound agent traffic before it
//!   reaches the external system (HTTP proxy, gRPC hook, Unix socket).
//! - [`normalizer`] — Intent Normalizer / Envelope Builder.
//!   Deterministically maps raw intercepted events into canonical
//!   `ExecutionEnvelope` instances with a normalized `intent.action_class`.
//! - [`enforcement`] — Two-phase enforcement engine:
//!   - Stage 1 (Capability Validation): token selection, parse, signature
//!     verify, expiry, revocation check.
//!   - Stage 2 (Constraint Enforcement Engine / CEE): scope check, policy
//!     bundle freshness, Cedar policy evaluation.
//! - [`pipeline`] — Orchestrates normalizer + both enforcement stages into
//!   a single `enforce()` entry point. This is the primary public API;
//!   all types needed to construct and inspect the pipeline are re-exported
//!   from here.
//! - [`audit`] — Audit event emitter. Produces a signed event for every
//!   enforcement decision. Supports stdout, file, gRPC, and WAL output
//!   sinks.
//! - [`startup`] — Per-subsystem builders that translate
//!   [`config::SidecarConfig`] into runtime components.

mod args;
mod audit;
mod authority_client;
mod config;
mod connector;
mod credential;
mod enforcement;
mod handler;
mod health;
mod interceptor;
mod log;
mod normalizer;
mod pipeline;
mod startup;

use std::path::Path;
use std::sync::Arc;

use clap::Parser as _;
use tokio::io::AsyncReadExt as _;
use tokio_util::sync::CancellationToken;

use crate::args::Args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    crate::log::init_log(args.log_level, args.log_file.as_deref(), args.log_filter)?;
    tracing::info!("firma-sidecar starting");

    tracing::info!("loading configuration from {}", args.config_file.display());
    let config = read_config(&args.config_file).await?;
    tracing::info!("configuration loaded successfully");

    let exit = CancellationToken::new();

    tracing::debug!(
        "initializing health check server at {}",
        args.health_bind_addr
    );
    let health_server =
        crate::health::HealthcheckServer::bind(args.health_bind_addr, exit.clone()).await?;
    let health_server = tokio::spawn(health_server.serve());
    tracing::info!("health check server listening at {}", args.health_bind_addr);

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

    let pipeline_runtime = startup::build_pipeline_runtime(&config)?;
    let authority_handle =
        startup::spawn_authority_client(&config, &pipeline_runtime, exit.clone())?;
    let connector_registry = startup::build_connector_registry(&config.connector)?;
    let handler = Arc::new(handler::RequestHandler::new(
        pipeline_runtime.pipeline,
        connector_registry,
        audit_payload_tx,
    ));

    tracing::info!(
        mode = %config.interceptor.mode,
        "starting interceptor"
    );
    let interceptor_handle = startup::spawn_interceptor(&config, handler, exit.clone())?;

    tracing::info!("all components initialized; entering main loop");
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
    tracing::info!("firma-sidecar exiting");

    Ok(())
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
