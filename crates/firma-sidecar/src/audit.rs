//! Audit event emitter.
//!
//! Produces a signed [`ExecutionEvent`] for every enforcement decision
//! (ALLOW, DENY, ABORT). No call enters or exits the sidecar without a
//! corresponding audit record.
//!
//! The emitter is invoked by the pipeline after every `enforce()` call,
//! regardless of outcome. Each event carries an ECDSA signature over all
//! fields, making the audit log tamper-evident and independently
//! verifiable.
//!
//! # Output sinks
//!
//! Four output modes are supported, selectable via the `[audit]`
//! configuration section:
//!
//! | Sink     | Description                                                |
//! |----------|------------------------------------------------------------|
//! | `stdout` | Structured JSON lines (default for containers).            |
//! | `file`   | Append-only file at a configured path.                     |
//! | `grpc`   | Client-streaming RPC to a downstream audit service.        |
//! | `wal`    | Write-ahead log: buffers events locally when gRPC is       |
//! |          | unavailable and replays on reconnect. Bounded by size cap; |
//! |          | oldest events are evicted when the cap is exceeded.        |
//!
//! # Signing
//!
//! Every event is signed with an ECDSA private key loaded at startup
//! from a file path or environment variable (mutually exclusive). The
//! signature covers all event fields preceding it, enabling downstream
//! consumers to verify event integrity without trusting the transport.

pub mod builder;
pub mod sink;

use std::future::Future;

use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;

/// An audit sink that consumes signed [`ExecutionEvent`]s and writes
/// them to an external destination.
///
/// Each concrete sink (stdout, file, gRPC, WAL) is constructed with
/// only the configuration it needs. The [`run`](AuditSink::run) method
/// drives the sink to completion, draining events from the channel
/// until the cancellation token fires or an unrecoverable error occurs.
///
/// # Object safety
///
/// This trait uses RPITIT (`impl Future`) and is therefore **not**
/// object-safe. That is intentional: the concrete sink type is selected
/// once at startup based on the `[audit]` config section, so dynamic
/// dispatch is unnecessary.
pub trait AuditSink {
    /// Drives the sink, consuming events from `rx` until `exit` is
    /// cancelled or an unrecoverable error occurs.
    ///
    /// Implementations must:
    ///
    /// - Drain `rx` until it is closed **or** `exit` is triggered.
    /// - On graceful shutdown (`exit` cancelled), finish writing any
    ///   buffered events before returning `Ok(())`.
    /// - Return [`AuditSinkError`] only for unrecoverable failures
    ///   (e.g. filesystem full, TLS handshake failure). Transient
    ///   errors (e.g. a single gRPC send failure) should be retried
    ///   internally.
    fn run(
        self,
        rx: Receiver<ExecutionEvent>,
        exit: CancellationToken,
    ) -> impl Future<Output = Result<(), AuditSinkError>>;
}

/// An error that can occur on an [`AuditSink`].
#[expect(
    dead_code,
    reason = "used by concrete sink implementations in follow-up"
)]
#[derive(Debug, thiserror::Error)]
pub enum AuditSinkError {
    /// The audit sink failed to bind to the configured address or
    /// socket path.
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// An unrecoverable server error occurred while the audit sink was
    /// running.
    #[error("server error: {0}")]
    ServerError(String),
}

/// Domain-level audit event produced by the enforcement pipeline.
///
/// Converted into the proto wire type via `From<ExecutionEvent>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionEvent {
    /// Unique event identifier (UUID v7, time-ordered).
    pub event_id: String,
    /// Session that produced this event.
    pub session_id: String,
    /// Capability token ID evaluated during enforcement.
    pub token_id: String,
    /// Agent that initiated the action.
    pub agent_id: String,
    /// Canonical action class from the normalizer (e.g., `http_get`).
    pub action: String,
    /// Target resource identifier (e.g., URL, table name).
    pub resource: String,
    /// Enforcement outcome.
    pub decision: i32,
    /// Human-readable reason when decision is DENY or ABORT. Empty on
    /// ALLOW.
    pub deny_reason: String,
    /// Wall-clock time spent in the enforcement pipeline, in
    /// microseconds.
    pub enforcement_latency_us: i64,
    /// Integrity hash of the Cedar context used during evaluation.
    pub context_hash: String,
    /// Policy bundle version active at decision time.
    pub bundle_version: String,
    /// Event timestamp as nanoseconds since the Unix epoch.
    pub timestamp: Option<u128>,
    /// ECDSA signature (DER-encoded) over all preceding fields.
    pub signature: Vec<u8>,
}

impl From<ExecutionEvent> for firma_proto::firma::v1::ExecutionEvent {
    fn from(value: ExecutionEvent) -> Self {
        Self {
            event_id: value.event_id,
            session_id: value.session_id,
            token_id: value.token_id,
            agent_id: value.agent_id,
            action: value.action,
            resource: value.resource,
            decision: value.decision,
            deny_reason: value.deny_reason,
            enforcement_latency_us: value.enforcement_latency_us,
            context_hash: value.context_hash,
            bundle_version: value.bundle_version,
            timestamp: value.timestamp.map(|nanos| {
                #[allow(clippy::cast_possible_truncation)]
                let seconds = (nanos / 1_000_000_000) as i64;
                #[allow(clippy::cast_possible_truncation)]
                let sub_nanos = (nanos % 1_000_000_000) as i32;
                firma_proto::prost_types::Timestamp {
                    seconds,
                    nanos: sub_nanos,
                }
            }),
            signature: value.signature,
        }
    }
}
