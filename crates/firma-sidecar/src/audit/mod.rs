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
pub(crate) mod sink;

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

/// Enforcement outcome as recorded in the audit log.
///
/// Serialized as its numeric proto wire value (`1` = `ALLOW`, `2` = `DENY`,
/// `3` = `ABORT`, `4` = `MODIFY`, `5` = `STEP_UP`, `6` = `DEFER`), matching the
/// `i32` `decision` field on [`AuditPayload`] and [`ExecutionEvent`] and the
/// `firma.v1.EnforcementDecision` proto enum (AARM R4). This typed view is
/// for consumers that read back the JSON audit records and want to match on
/// the outcome instead of bare ints. `PASSTHROUGH` is serialized as
/// `ALLOW` (`1`) with an empty `token_id`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
)]
#[repr(u8)]
pub enum Decision {
    /// Request passed enforcement and was dispatched.
    Allow = 1,
    /// Request was denied before dispatch.
    Deny = 2,
    /// Critical failure aborted the request.
    Abort = 3,
    /// AARM R4 `MODIFY`: a transformed version of the request was dispatched.
    Modify = 4,
    /// AARM R4 `STEP_UP`: the request was blocked pending human approval.
    StepUp = 5,
    /// AARM R4 `DEFER`: the request was blocked and deferred for retry.
    Defer = 6,
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

/// Domain-level audit event produced by the enforcement pipeline.
///
/// Converted into the proto wire type via `From<ExecutionEvent>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionEvent {
    /// Unique event identifier (UUID v7, time-ordered).
    event_id: String,
    /// Session that produced this event.
    session_id: String,
    /// Capability token ID evaluated during enforcement.
    token_id: String,
    /// Agent that initiated the action.
    agent_id: String,
    /// Canonical action class from the normalizer (e.g., `http_get`).
    action: String,
    /// Target resource identifier (e.g., URL, table name).
    resource: String,
    /// Enforcement outcome.
    decision: Decision,
    /// Human-readable reason when decision is DENY or ABORT. Empty on
    /// ALLOW, except in monitor mode where an overridden DENY carries
    /// `"monitor_mode: <original_deny_reason>"`.
    deny_reason: String,
    /// Wall-clock time spent in the enforcement pipeline, in
    /// microseconds.
    enforcement_latency_us: i64,
    /// Integrity hash of the Cedar context used during evaluation.
    context_hash: String,
    /// Policy bundle version active at decision time.
    bundle_version: String,
    /// Event timestamp as nanoseconds since the Unix epoch.
    timestamp: Option<u128>,
    /// HTTP status code returned by the connector. Zero when the call
    /// never dispatched (pre-dispatch DENY or ABORT).
    dispatch_status: i32,
    /// Connector dispatch latency in microseconds. Zero when the call
    /// never dispatched.
    dispatch_latency_us: i64,
    /// Target response body size in bytes. Zero when the call never
    /// dispatched or the target returned no body.
    response_size: i64,
    /// Per-run identity scoping the event to a single `firma run`
    /// invocation. Matches the marker directory name written by the
    /// run component orchestrator. Empty when the sidecar is not autostarted.
    sandbox_id: String,
    /// Tamper-evident provenance chain anchor (AARM R2 G2) for admitted
    /// (Allow/Modify) actions. Empty for pre-dispatch outcomes.
    provenance: String,
    /// Server-derived conversation thread identity (AARM R2 G2).
    thread_id: String,
    /// Server-derived parent action identity (AARM R2 G2).
    parent_action_id: String,
    /// ECDSA signature (DER-encoded) over all preceding fields.
    ///
    /// Serialized in JSON as a standard base64 string so it round-trips
    /// cleanly through structured log pipelines (e.g. Cloud Logging)
    /// without byte loss or reinterpretation. The proto wire type keeps
    /// the raw bytes unchanged.
    #[serde(with = "base64_signature")]
    signature: Vec<u8>,
}

/// Serde adapter that encodes the audit signature as a standard,
/// padded base64 string instead of a JSON array of bytes.
///
/// The in-memory representation stays `Vec<u8>`; only the JSON form
/// changes. This keeps the signature a compact opaque value that
/// survives any JSON log pipeline intact.
mod base64_signature {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize as _, Deserializer, Serializer};

    /// Encodes the signature bytes as a base64 string.
    pub(super) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    /// Decodes a base64 string back into the raw signature bytes.
    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

impl From<ExecutionEvent> for firma_protobuf::v1::ExecutionEvent {
    fn from(value: ExecutionEvent) -> Self {
        Self {
            event_id: value.event_id,
            session_id: value.session_id,
            token_id: value.token_id,
            agent_id: value.agent_id,
            action: value.action,
            resource: value.resource,
            decision: value.decision as i32,
            deny_reason: value.deny_reason,
            enforcement_latency_us: value.enforcement_latency_us,
            context_hash: value.context_hash,
            bundle_version: value.bundle_version,
            timestamp: value.timestamp.map(|nanos| {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "timestamp seconds fit i64 for supported event times"
                )]
                let seconds = (nanos / 1_000_000_000) as i64;
                let sub_nanos = (nanos % 1_000_000_000) as i32;
                prost_types::Timestamp {
                    seconds,
                    nanos: sub_nanos,
                }
            }),
            signature: value.signature,
            dispatch_status: value.dispatch_status,
            dispatch_latency_us: value.dispatch_latency_us,
            response_size: value.response_size,
            sandbox_id: value.sandbox_id,
            provenance: value.provenance,
            thread_id: value.thread_id,
            parent_action_id: value.parent_action_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an [`ExecutionEvent`] with deterministic fields and the
    /// given signature bytes for serialization assertions.
    fn sample_event(signature: Vec<u8>) -> ExecutionEvent {
        ExecutionEvent {
            event_id: "evt_1".to_string(),
            session_id: "sess_1".to_string(),
            token_id: "tok_1".to_string(),
            agent_id: "agent_1".to_string(),
            action: "http_get".to_string(),
            resource: "api.example.com".to_string(),
            decision: Decision::Allow,
            deny_reason: String::new(),
            enforcement_latency_us: 42,
            context_hash: "ctx_1".to_string(),
            bundle_version: "v1".to_string(),
            timestamp: Some(1_700_000_000_000_000_000),
            dispatch_status: 200,
            dispatch_latency_us: 7,
            response_size: 1024,
            sandbox_id: "sbx_01j0000000e008000000000001".to_string(),
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
            signature,
        }
    }

    #[test]
    fn signature_serializes_as_base64_string() {
        // DER prefix bytes [0x30, 0x45, 0x02, 0x21] encode to "MEUCIQ==".
        let event = sample_event(vec![0x30, 0x45, 0x02, 0x21]);

        let value = serde_json::to_value(&event).expect("event serializes");

        assert_eq!(
            value["signature"],
            serde_json::Value::String("MEUCIQ==".to_string()),
            "signature must serialize as a base64 string, not a byte array"
        );
    }

    #[test]
    fn event_json_round_trips_through_base64_signature() {
        let event = sample_event(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let json = serde_json::to_string(&event).expect("event serializes");
        let decoded: ExecutionEvent = serde_json::from_str(&json).expect("event deserializes");

        assert_eq!(decoded, event, "event must survive a JSON round-trip");
    }
}
