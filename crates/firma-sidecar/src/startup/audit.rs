//! Audit subsystem startup.
//!
//! Covers three responsibilities:
//!
//! - [`load_audit_event_builder`] — reads the ECDSA signing key from
//!   file or environment and constructs an
//!   [`EventBuilder`](crate::audit::builder::EventBuilder).
//! - [`spawn_audit_sink`] — spawns the signing adapter plus the
//!   concrete sink (stdout/file/gRPC/WAL) as background tokio tasks.
//! - internal `run_signing_adapter` — sits between the pipeline and
//!   the concrete sink, signing [`AuditPayload`]s into
//!   [`ExecutionEvent`]s on their way out.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::audit;
use crate::audit::AuditSink as _;
use crate::audit::sink as audit_sink;
use crate::config;

/// Spawns the audit sink pipeline.
///
/// The pipeline is a signing adapter that receives [`AuditPayload`](audit::AuditPayload)s,
/// signs them into [`ExecutionEvent`](audit::ExecutionEvent)s, and forwards to the
/// concrete [`AuditSink`](audit::AuditSink).
///
/// Returns a [`tokio::task::JoinHandle`] that resolves when the sink
/// shuts down.
///
/// # Errors
///
/// Returns an error when the sink fails to initialize (invalid
/// config, inability to connect to an external sink).
pub fn spawn_audit_sink(
    config: &config::AuditConfig,
    payload_rx: mpsc::Receiver<audit::AuditPayload>,
    event_builder: audit::builder::EventBuilder,
    exit: CancellationToken,
) -> anyhow::Result<tokio::task::JoinHandle<Result<(), audit::AuditSinkError>>> {
    let (event_tx, event_rx) = mpsc::channel::<audit::ExecutionEvent>(100);

    let adapter_exit = exit.clone();
    tokio::spawn(async move {
        run_signing_adapter(payload_rx, event_tx, event_builder, adapter_exit).await;
    });

    match config.sink {
        config::AuditSink::File => {
            let path = config.file_path.clone().ok_or_else(|| {
                anyhow::anyhow!("file sink requires file_path in audit configuration")
            })?;
            Ok(tokio::spawn(async move {
                audit_sink::FileAuditSink::new(path)
                    .run(event_rx, exit)
                    .await
            }))
        }
        config::AuditSink::Grpc => {
            let endpoint = config.grpc_url.clone().ok_or_else(|| {
                anyhow::anyhow!("gRPC sink requires grpc_url in audit configuration")
            })?;
            Ok(tokio::spawn(async move {
                audit_sink::GrpcAuditSink::new(endpoint)
                    .run(event_rx, exit)
                    .await
            }))
        }
        config::AuditSink::Stdout => Ok(tokio::spawn(async move {
            audit_sink::StdoutAuditSink::new().run(event_rx, exit).await
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
                    .run(event_rx, exit)
                    .await
            }))
        }
    }
}

/// Loads the ECDSA signing key PEM from the audit configuration and
/// constructs an [`audit::builder::EventBuilder`].
///
/// The key is loaded from either `signing_key_path` (file) or
/// `signing_key_env` (environment variable). Returns an error when
/// neither is set.
///
/// # Errors
///
/// Returns an error if the file cannot be read or the PEM is invalid.
pub fn load_audit_event_builder(
    config: &config::AuditConfig,
) -> anyhow::Result<audit::builder::EventBuilder> {
    let pem = if let Some(ref path) = config.signing_key_path {
        std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("failed to read signing key from {}: {e}", path.display())
        })?
    } else if let Some(ref env_var) = config.signing_key_env {
        std::env::var(env_var).map_err(|e| {
            anyhow::anyhow!("failed to read signing key from env var {env_var}: {e}")
        })?
    } else {
        return Err(anyhow::anyhow!(
            "audit signing key not configured: set signing_key_path or signing_key_env"
        ));
    };

    audit::builder::EventBuilder::new(&pem)
        .map_err(|e| anyhow::anyhow!("failed to initialize audit event builder: {e}"))
}

/// Signing adapter that sits between the pipeline and the concrete
/// sink.
///
/// Receives [`AuditPayload`](audit::AuditPayload)s from the pipeline,
/// signs each into a full [`ExecutionEvent`](audit::ExecutionEvent),
/// and forwards to the concrete sink via `event_tx`.
async fn run_signing_adapter(
    mut payload_rx: mpsc::Receiver<audit::AuditPayload>,
    event_tx: mpsc::Sender<audit::ExecutionEvent>,
    builder: audit::builder::EventBuilder,
    exit: CancellationToken,
) {
    loop {
        tokio::select! {
            payload = payload_rx.recv() => {
                let Some(payload) = payload else { break; };
                let event = builder.build(payload);
                if event_tx.send(event).await.is_err() {
                    break;
                }
            }
            () = exit.cancelled() => {
                // Drain remaining payloads before exiting.
                while let Ok(payload) = payload_rx.try_recv() {
                    let event = builder.build(payload);
                    if event_tx.send(event).await.is_err() {
                        break;
                    }
                }
                break;
            }
        }
    }
}
