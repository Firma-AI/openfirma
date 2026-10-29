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

use anyhow::Context as _;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tonic::transport::ClientTlsConfig;

use crate::authority_tls::{AuthorityTls, TlsTrust, client_tls_config};
use crate::config::{AuditServiceUrl, AuditSinkConfig};

use crate::audit;
use crate::audit::AuditSink as _;
use crate::audit::sink as audit_sink;
use crate::config;

/// Spawns the audit sink pipeline. A network sink to the Authority's own
/// audit service uses `authority_tls`, the TLS material read from `config`.
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
/// config, inability to open the audit log, unusable TLS settings for an
/// external sink).
pub fn spawn_audit_sink(
    config: &config::SidecarConfig,
    authority_tls: &AuthorityTls,
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

    match &audit_config.sink {
        AuditSinkConfig::File { path } => {
            // Opened here, not in the task: a log that cannot be written is a
            // startup failure, not a detached task nobody joins.
            let sink = audit_sink::FileAuditSink::open(path.clone())?;
            Ok(tokio::spawn(async move { sink.run(event_rx, exit).await }))
        }
        AuditSinkConfig::Grpc {
            url,
            buffer_path,
            buffer_max_bytes,
            replay_ack_timeout,
        } => {
            let destination = audit_destination(config, url)?;
            let mut sink =
                audit_sink::GrpcAuditSink::new(url.clone(), buffer_path.clone(), *buffer_max_bytes)
                    .with_replay_ack_timeout(*replay_ack_timeout)
                    .with_credentials(audit_credentials(config, destination)?)?;
            if let Some(tls) = audit_tls(authority_tls, destination, url) {
                sink = sink.with_tls(tls).context(INVALID_AUDIT_TLS)?;
            }
            Ok(tokio::spawn(async move { sink.run(event_rx, exit).await }))
        }
        AuditSinkConfig::Stdout => Ok(tokio::spawn(async move {
            audit_sink::StdoutAuditSink::new().run(event_rx, exit).await
        })),
        AuditSinkConfig::Wal {
            url,
            path,
            max_bytes,
            request_timeout,
        } => {
            let destination = audit_destination(config, url)?;
            let mut sink = audit_sink::WalAuditSink::new(
                url.clone(),
                path.clone(),
                *max_bytes,
                *request_timeout,
                audit_credentials(config, destination)?,
            );
            if let Some(tls) = audit_tls(authority_tls, destination, url) {
                sink = sink.with_tls(tls).context(INVALID_AUDIT_TLS)?;
            }
            Ok(tokio::spawn(async move { sink.run(event_rx, exit).await }))
        }
    }
}

/// Context for TLS settings that cannot be applied to the audit endpoint, for
/// instance because no trusted roots load: startup stops rather than every
/// delivery failing while events pile up.
const INVALID_AUDIT_TLS: &str = "invalid audit TLS configuration";

/// Where an audit URL points, which decides what travels with the events.
///
/// The Authority's own audit service is trusted as the Authority is and gets
/// the Sidecar's credentials. Any other host gets the platform's roots and
/// nothing that identifies this Sidecar to the Authority: neither its CA pin,
/// its mTLS identity, nor the credentials that would let that host call the
/// Authority as this Sidecar.
#[derive(Clone, Copy)]
enum AuditDestination {
    /// The audit URL is the Authority's own origin.
    Authority,
    /// The audit URL names another host.
    Other,
}

/// Classifies `url` against the Authority's origin: scheme, host and port.
///
/// # Errors
///
/// Returns an error when the Authority URL is invalid.
fn audit_destination(
    config: &config::SidecarConfig,
    url: &AuditServiceUrl,
) -> anyhow::Result<AuditDestination> {
    if config.authority.target()?.has_origin_of(url.uri()) {
        return Ok(AuditDestination::Authority);
    }
    tracing::info!(
        audit_url = %url.uri(),
        "the audit service is not the Authority's origin: events are sent without the \
         Authority's credentials, CA or client identity"
    );
    Ok(AuditDestination::Other)
}

/// The Sidecar's credentials for the audit service: the configured ones at
/// the Authority's origin, none elsewhere.
fn audit_credentials(
    config: &config::SidecarConfig,
    destination: AuditDestination,
) -> anyhow::Result<Option<crate::authority_credentials::SidecarCredential>> {
    match destination {
        AuditDestination::Authority => resolve_audit_credentials(config),
        AuditDestination::Other => Ok(None),
    }
}

/// The TLS settings for an `https` audit URL; none for `http`.
fn audit_tls(
    authority_tls: &AuthorityTls,
    destination: AuditDestination,
    url: &AuditServiceUrl,
) -> Option<ClientTlsConfig> {
    if url.uri().scheme_str() != Some("https") {
        return None;
    }
    Some(match destination {
        AuditDestination::Authority => authority_tls.client_config(),
        AuditDestination::Other => client_tls_config(TlsTrust::PlatformStore, None),
    })
}

fn resolve_audit_credentials(
    config: &config::SidecarConfig,
) -> anyhow::Result<Option<crate::authority_credentials::SidecarCredential>> {
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
