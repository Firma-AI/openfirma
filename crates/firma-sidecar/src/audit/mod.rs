//! Audit event emitter.
//!
//! Produces a signed [`ExecutionEvent`] for every enforcement decision
//! (ALLOW, DENY, ABORT). No call enters or exits the sidecar without a
//! corresponding audit record.
//!
//! The emitter is invoked by the [`RequestHandler`](crate::handler::RequestHandler)
//! after every handled call, regardless of outcome. Each event carries an
//! ECDSA signature over all fields, making the audit log tamper-evident and
//! independently verifiable.
//!
//! # Output sinks
//!
//! Four output modes are supported, selectable via the `[sidecar.audit]`
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
pub(crate) mod sink;

use std::future::Future;

pub use firma_audit_schema::{Decision, ExecutionEvent};
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
/// once at startup based on the `[sidecar.audit]` config section, so dynamic
/// dispatch is unnecessary.
pub(crate) trait AuditSink {
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

/// Lightweight audit payload sent from the pipeline hot path through the channel.
///
/// Contains only the fields extracted from the enforcement decision — no signing,
/// no UUID generation. The [`EventBuilder`](builder::EventBuilder) on the sink side
/// converts this into a fully populated, signed [`ExecutionEvent`].
#[derive(Debug, Clone)]
pub struct AuditPayload {
    /// Session that produced this event.
    pub(crate) session_id: String,
    /// Capability token ID evaluated during enforcement.
    pub(crate) token_id: String,
    /// Agent that initiated the action.
    pub(crate) agent_id: String,
    /// Canonical action class from the normalizer (e.g., `llm.inference`).
    pub(crate) action: String,
    /// Target resource identifier (e.g., URL, table name).
    pub(crate) resource: String,
    /// Enforcement outcome.
    pub(crate) decision: Decision,
    /// Human-readable reason when decision is DENY or ABORT. Empty on
    /// ALLOW, except in monitor mode where an overridden DENY carries
    /// `"monitor_mode: <original_deny_reason>"`.
    pub(crate) deny_reason: String,
    /// Wall-clock time spent in the enforcement pipeline, in
    /// microseconds.
    pub(crate) enforcement_latency_us: i64,
    /// Integrity hash of the Cedar context used during evaluation.
    pub(crate) context_hash: String,
    /// Policy bundle version active at decision time.
    pub(crate) bundle_version: String,
    /// HTTP status code returned by the connector. Zero when the call
    /// never dispatched (pre-dispatch DENY or ABORT).
    pub(crate) dispatch_status: i32,
    /// Connector dispatch latency in microseconds. Zero when the call
    /// never dispatched.
    pub(crate) dispatch_latency_us: i64,
    /// Target response body size in bytes. Zero when the call never
    /// dispatched or the target returned no body.
    pub(crate) response_size: i64,
    /// Tamper-evident provenance chain anchor (AARM R2 G2) for admitted
    /// (Allow/Modify) actions; empty for pre-dispatch outcomes.
    pub(crate) provenance: String,
    /// Server-derived conversation thread identity (AARM R2 G2).
    pub(crate) thread_id: String,
    /// Server-derived parent action identity (AARM R2 G2).
    pub(crate) parent_action_id: String,
}

impl AuditPayload {
    /// Returns the target resource identifier recorded for the action.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Returns the enforcement outcome recorded for the action.
    #[must_use]
    pub fn decision(&self) -> &Decision {
        &self.decision
    }

    /// Returns the denial reason, empty on outcomes that carry none.
    #[must_use]
    pub fn deny_reason(&self) -> &str {
        &self.deny_reason
    }

    /// Returns the connector HTTP status, zero when the call never dispatched.
    #[must_use]
    pub fn dispatch_status(&self) -> i32 {
        self.dispatch_status
    }

    /// Returns the connector dispatch latency in microseconds, zero when the
    /// call never dispatched.
    #[must_use]
    pub fn dispatch_latency_us(&self) -> i64 {
        self.dispatch_latency_us
    }

    /// Returns the target response body size in bytes, zero when the call
    /// never dispatched or returned no body.
    #[must_use]
    pub fn response_size(&self) -> i64 {
        self.response_size
    }
}
