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

mod args;
mod audit;
mod config;
mod enforcement;
mod health;
mod interceptor;
mod log;
mod normalizer;
mod pipeline;

use std::path::Path;
use std::sync::Arc;

use clap::Parser as _;
use tokio::io::AsyncReadExt as _;
use tokio_util::sync::CancellationToken;

use crate::args::Args;
use crate::audit::AuditSink as _;
use crate::audit::sink as audit_sink;
use crate::config::{AuditConfig, InterceptorMode};
use crate::interceptor::Interceptor as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // parse arguments and initialize logging before doing anything else
    let args = Args::parse();
    crate::log::init_log(args.log_level, args.log_file.as_deref(), args.log_filter)?;
    tracing::info!("firma-sidecar starting");

    // parse configuration
    tracing::info!("loading configuration from {}", args.config_file.display());
    let config = read_config(&args.config_file).await?;
    tracing::info!("configuration loaded successfully");

    // setup cancellation
    let exit = CancellationToken::new();

    // setup health check server
    tracing::debug!(
        "initializing health check server at {}",
        args.health_bind_addr
    );
    let health_server =
        crate::health::HealthcheckServer::bind(args.health_bind_addr, exit.clone()).await?;
    let health_server = tokio::spawn(health_server.serve());
    tracing::info!("health check server listening at {}", args.health_bind_addr);

    // setup signal handlers for graceful shutdown
    tracing::debug!("registering signal handlers for graceful shutdown");
    let sigterm_handler = {
        let exit = exit.clone();
        tokio::spawn(async move {
            handle_sigterm(exit).await;
        })
    };
    tracing::debug!("signal handlers registered");

    // setup audit sink
    let (audit_sink_tx, audit_sink_rx) = tokio::sync::mpsc::channel(100);
    let audit_sink = spawn_audit_sink(&config.audit, audit_sink_rx, exit.clone())?;

    // build enforcement pipeline
    let pipeline = build_pipeline(&config, audit_sink_tx)?;

    // run interceptor
    tracing::info!(
        mode = %config.interceptor.mode,
        "starting interceptor"
    );
    let interceptor_handle = spawn_interceptor(&config, pipeline, exit.clone())?;

    tracing::info!("all components initialized; entering main loop");
    // wait for all background tasks to complete
    let _ = tokio::join!(
        audit_sink,
        health_server,
        interceptor_handle,
        sigterm_handler
    );
    tracing::info!("firma-sidecar exiting");

    Ok(())
}

/// Handler worker for catching sigterm signals.
///
/// When a SIGTERM signal is caught, the `exit` flag is trigerred.
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

/// Read [`config::SidecarConfig`] from the given [`Path`]
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

/// Build the [`pipeline::EnforcementPipeline`] from a validated
/// [`config::SidecarConfig`] and the [`tokio::sync::mpsc::Sender`] for audit [`audit::ExecutionEvent`]s.
///
/// Reads the mapping rules file referenced in the config, constructs
/// the action-class registry, normalizer, and both enforcement stages.
///
/// # Errors
///
/// Returns an error when the mapping rules file cannot be read or
/// parsed, or when pipeline components fail to initialize.
fn build_pipeline(
    config: &config::SidecarConfig,
    audit_sink_tx: tokio::sync::mpsc::Sender<audit::ExecutionEvent>,
) -> anyhow::Result<Arc<pipeline::EnforcementPipeline>> {
    // Load mapping rules
    let rules_content =
        std::fs::read_to_string(&config.enforcement.mapping.rules_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read mapping rules from '{}': {e}",
                config.enforcement.mapping.rules_path
            )
        })?;
    let rules_file: config::MappingRulesFile = toml::from_str(&rules_content).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse mapping rules '{}': {e}",
            config.enforcement.mapping.rules_path
        )
    })?;
    rules_file.validate().map_err(|e| {
        anyhow::anyhow!(
            "invalid mapping rules '{}': {e}",
            config.enforcement.mapping.rules_path
        )
    })?;

    // Build components
    let registry = pipeline::ActionClassRegistry::v0_1();
    let table = pipeline::MappingTable::from_config(
        &rules_file,
        &registry,
        config.enforcement.mapping.default_protected,
    )
    .map_err(|e| anyhow::anyhow!("failed to build mapping table: {e}"))?;

    let normalizer = pipeline::IntentNormalizer::new(table);

    // Capability validation.
    // Capability map and token verifier/revocation store are populated
    // from the Authority at pre-flight; for now use empty defaults so
    // the binary starts.  Authority integration (task 007+) will
    // populate these.
    let capability_validator = pipeline::CapabilityValidator::new(
        pipeline::CapabilityMap::new(vec![]),
        // TODO(authority): replace stubs with Authority-backed impls
        Box::new(StubTokenVerifier),
        Box::new(StubRevocationStore),
        std::time::Duration::from_secs(
            config
                .enforcement
                .capability_validation
                .clock_skew_tolerance_seconds,
        ),
    );

    // Constraint enforcement.
    // Policy evaluation will be populated from cedar bundle loading
    // (task 005+); stub accepts everything for now.
    let constraint_enforcer = pipeline::ConstraintEnforcer::new(
        // TODO(policy): replace stub with Cedar policy evaluator
        Box::new(StubPolicyEvaluation),
    );

    let pipeline =
        pipeline::EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);
    tracing::info!("enforcement pipeline initialized");

    Ok(Arc::new(pipeline))
}

/// Spawn the configured interceptor as a background tokio task.
///
/// Returns a [`tokio::task::JoinHandle`] that resolves when the
/// interceptor shuts down.
///
/// # Errors
///
/// Returns an error when the interceptor mode is `unix_socket` but
/// the required `socket_path` is missing (should be caught by
/// validation, but enforced here defensively).
fn spawn_interceptor(
    config: &config::SidecarConfig,
    pipeline: Arc<pipeline::EnforcementPipeline>,
    cancel: CancellationToken,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let ic = &config.interceptor;

    match ic.mode {
        InterceptorMode::HttpProxy => {
            let interceptor = interceptor::http::HttpInterceptor::new(ic.listen_addr);
            tracing::info!(listen_addr = %ic.listen_addr, "HTTP proxy interceptor configured");
            Ok(tokio::spawn(async move {
                if let Err(e) = interceptor.run(pipeline, cancel).await {
                    tracing::error!(error = %e, "HTTP proxy interceptor failed");
                }
            }))
        }
        InterceptorMode::Grpc => {
            let interceptor = interceptor::grpc::GrpcInterceptor::new(ic.listen_addr);
            tracing::info!(listen_addr = %ic.listen_addr, "gRPC interceptor configured");
            Ok(tokio::spawn(async move {
                if let Err(e) = interceptor.run(pipeline, cancel).await {
                    tracing::error!(error = %e, "gRPC interceptor failed");
                }
            }))
        }
        #[cfg(unix)]
        InterceptorMode::UnixSocket => {
            let socket_path = ic
                .socket_path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("unix_socket mode requires socket_path"))?;
            let interceptor =
                interceptor::unix_socket::UnixSocketInterceptor::new(socket_path.clone());
            tracing::info!(socket_path = %socket_path.display(), "Unix socket interceptor configured");
            Ok(tokio::spawn(async move {
                if let Err(e) = interceptor.run(pipeline, cancel).await {
                    tracing::error!(error = %e, "Unix socket interceptor failed");
                }
            }))
        }
    }
}

/// Spawn the [`AuditSink`](crate::audit::AuditSink) as a background tokio task, consuming from the provided `Receiver`.
/// Returns a [`tokio::task::JoinHandle`] that resolves when the sink shuts down.
///
/// # Errors
///
/// Returns an error when the sink fails to initialize (e.g. invalid config, failure to connect to external sink).
fn spawn_audit_sink(
    config: &AuditConfig,
    rx: tokio::sync::mpsc::Receiver<audit::ExecutionEvent>,
    exit: CancellationToken,
) -> anyhow::Result<tokio::task::JoinHandle<Result<(), audit::AuditSinkError>>> {
    match config.sink {
        config::AuditSink::File => {
            let path = config.file_path.clone().ok_or_else(|| {
                anyhow::anyhow!("file sink requires file_path in audit configuration")
            })?;
            Ok(tokio::spawn(async move {
                audit_sink::FileAuditSink::new(path).run(rx, exit).await
            }))
        }
        config::AuditSink::Grpc => {
            let endpoint = config.grpc_url.clone().ok_or_else(|| {
                anyhow::anyhow!("gRPC sink requires grpc_url in audit configuration")
            })?;
            Ok(tokio::spawn(async move {
                audit_sink::GrpcAuditSink::new(endpoint).run(rx, exit).await
            }))
        }
        config::AuditSink::Stdout => Ok(tokio::spawn(async move {
            audit_sink::StdoutAuditSink::new().run(rx, exit).await
        })),
        config::AuditSink::Wal => {
            let path = config.wal_path.clone().ok_or_else(|| {
                anyhow::anyhow!("WAL sink requires wal_path in audit configuration")
            })?;
            let grpc_url = config.grpc_url.clone().ok_or_else(|| {
                anyhow::anyhow!("WAL sink requires grpc_url in audit configuration")
            })?;
            let wal_max_bytes = config.wal_max_bytes;
            Ok(tokio::spawn(async move {
                audit_sink::WalAuditSink::new(grpc_url, path, wal_max_bytes)
                    .run(rx, exit)
                    .await
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Stub implementations (replaced by Authority / Cedar integration later)
// ---------------------------------------------------------------------------

/// Stub token verifier that always rejects. Replaced once Authority
/// integration is wired in.
struct StubTokenVerifier;

impl firma_core::TokenVerifier for StubTokenVerifier {
    fn verify(
        &self,
        _raw_token: &str,
    ) -> Result<firma_core::CapabilityClaims, firma_core::TokenError> {
        Err(firma_core::TokenError::SignatureInvalid {
            reason: "stub verifier: no Authority configured".to_string(),
        })
    }
}

/// Stub revocation store that reports nothing revoked. Replaced once
/// Authority integration is wired in.
struct StubRevocationStore;

impl firma_core::RevocationStore for StubRevocationStore {
    fn is_revoked(&self, _token_id: &str) -> Result<bool, firma_core::TokenError> {
        Ok(false)
    }

    fn add_revocation(&self, _token_id: &str) -> Result<(), firma_core::TokenError> {
        Ok(())
    }
}

/// Stub policy evaluator that accepts everything. Replaced once Cedar
/// bundle loading is wired in.
struct StubPolicyEvaluation;

impl pipeline::PolicyEvaluation for StubPolicyEvaluation {
    fn evaluate(
        &self,
        _principal: &str,
        _action: &str,
        _resource: &str,
        _context: &serde_json::Value,
    ) -> Result<bool, String> {
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn version(&self) -> Option<String> {
        None
    }
}
