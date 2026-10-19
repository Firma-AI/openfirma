//! Audit subsystem startup.
//!
//! Covers three responsibilities:
//!
//! - [`load_audit_event_builder`] — reads the ECDSA signing key from
//!   file or environment and constructs an
//!   [`EventBuilder`](crate::audit::builder::EventBuilder).
//! - [`spawn_audit_sink`] — spawns the signing adapter plus the
//!   concrete sink (stdout/file/gRPC) as background tokio tasks.
//! - internal `run_signing_adapter` — sits between the pipeline and
//!   the concrete sink, signing [`AuditPayload`](crate::audit::AuditPayload)s into
//!   [`ExecutionEvent`](crate::audit::ExecutionEvent)s on their way out.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use firma_config_schema::sidecar::AuditSink;

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
/// config, inability to open the audit log, inability to connect to an
/// external sink).
pub fn spawn_audit_sink(
    config: &config::SidecarConfig,
    payload_rx: mpsc::Receiver<audit::AuditPayload>,
    event_builder: audit::builder::EventBuilder,
    exit: CancellationToken,
) -> anyhow::Result<tokio::task::JoinHandle<Result<(), audit::AuditSinkError>>> {
    let (event_tx, event_rx) = mpsc::channel::<audit::ExecutionEvent>(100);
    let audit_config = &config.audit;

    let adapter_exit = exit.clone();
    tokio::spawn(async move {
        run_signing_adapter(payload_rx, event_tx, event_builder, adapter_exit).await;
    });

    match audit_config.sink {
        AuditSink::File => {
            let path = audit_config.file_path.clone().ok_or_else(|| {
                anyhow::anyhow!("file sink requires file_path in audit configuration")
            })?;
            // Opened here, not in the task: a log that cannot be written is a
            // startup failure, not a detached task nobody joins.
            let sink = audit_sink::FileAuditSink::open(path)?;
            Ok(tokio::spawn(async move { sink.run(event_rx, exit).await }))
        }
        AuditSink::Grpc => {
            let endpoint = audit_config.grpc_url.clone().ok_or_else(|| {
                anyhow::anyhow!("gRPC sink requires grpc_url in audit configuration")
            })?;
            let buffer_path = audit_config.buffer_path.clone().ok_or_else(|| {
                anyhow::anyhow!("gRPC sink requires buffer_path in audit configuration")
            })?;
            let buffer_max_bytes = audit_config.buffer_max_bytes;
            let credentials = resolve_audit_credentials(config)?;
            let sink = audit_sink::GrpcAuditSink::new(endpoint, buffer_path, buffer_max_bytes)
                .with_replay_ack_timeout(audit_config.replay_ack_timeout)
                .with_credentials(credentials)?;
            Ok(tokio::spawn(async move { sink.run(event_rx, exit).await }))
        }
        AuditSink::Stdout => Ok(tokio::spawn(async move {
            audit_sink::StdoutAuditSink::new().run(event_rx, exit).await
        })),
        AuditSink::Wal => {
            let path = audit_config.wal_path.clone().ok_or_else(|| {
                anyhow::anyhow!("WAL sink requires wal_path in audit configuration")
            })?;
            let grpc_url = audit_config.grpc_url.clone().ok_or_else(|| {
                anyhow::anyhow!("WAL sink requires grpc_url in audit configuration")
            })?;
            let wal_max_bytes = audit_config.wal_max_bytes;
            let request_timeout = audit_config.wal_request_timeout;
            let credentials = resolve_audit_credentials(config)?;
            Ok(tokio::spawn(async move {
                audit_sink::WalAuditSink::new(
                    grpc_url,
                    path,
                    wal_max_bytes,
                    request_timeout,
                    credentials,
                )
                .run(event_rx, exit)
                .await
            }))
        }
    }
}

fn resolve_audit_credentials(
    config: &config::SidecarConfig,
) -> anyhow::Result<Option<crate::authority_credentials::ResolvedSidecarCredentials>> {
    config
        .authority
        .credentials
        .as_ref()
        .map(crate::authority_credentials::SidecarCredentialsConfig::resolve)
        .transpose()
        .map_err(|error| anyhow::anyhow!("failed to resolve authority credentials: {error}"))
}

/// Loads the ECDSA signing key PEM named by the resolved audit configuration
/// and constructs an [`audit::builder::EventBuilder`].
///
/// # Errors
///
/// Returns an error if the file cannot be read or the PEM is invalid.
pub fn load_audit_event_builder(
    config: &config::AuditConfig,
) -> anyhow::Result<audit::builder::EventBuilder> {
    let pem = match &config.signing_key {
        config::AuditSigningKey::Env(variable) => std::env::var(variable).map_err(|e| {
            anyhow::anyhow!("failed to read signing key from env var {variable}: {e}")
        })?,
        config::AuditSigningKey::Path(path) => read_signing_key(path, "")?,
        // Nobody chose this path, so a bare ENOENT reads as a bug. Name the
        // command that generates it instead.
        config::AuditSigningKey::StateDefault(path) => read_signing_key(
            path,
            " — run `firma config` to generate it, or set signing_key_path",
        )?,
    };

    audit::builder::EventBuilder::new(&pem)
        .map_err(|e| anyhow::anyhow!("failed to initialize audit event builder: {e}"))
}

/// Read a signing key PEM, appending `remedy` when the file is simply absent.
fn read_signing_key(path: &std::path::Path, remedy: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        let remedy = if e.kind() == std::io::ErrorKind::NotFound {
            remedy
        } else {
            ""
        };
        anyhow::anyhow!(
            "failed to read signing key from {}: {e}{remedy}",
            path.display()
        )
    })
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
