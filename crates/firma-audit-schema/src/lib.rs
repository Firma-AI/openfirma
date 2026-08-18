//! Serializable representation of the `OpenFirma` audit log.
//!
//! This crate contains only the types written to and read from audit logs. It
//! deliberately excludes event construction, signing, signature verification,
//! storage, and transport so producers and consumers share one representation
//! without depending on the Sidecar runtime.

/// Enforcement outcome recorded in an [`ExecutionEvent`].
///
/// The numeric representation matches the `firma.v1.EnforcementDecision`
/// protocol enum. Passthrough requests are represented as [`Self::Allow`] with
/// an empty [`ExecutionEvent::token_id`].
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
    /// A transformed version of the request was dispatched.
    Modify = 4,
    /// The request was blocked pending human approval.
    StepUp = 5,
    /// The request was blocked and deferred for retry.
    Defer = 6,
}

/// One signed execution event in the `OpenFirma` audit log.
///
/// Each JSON-lines audit record is the serialization of this structure. String
/// fields remain strings, including identifier-shaped fields, because empty
/// strings have defined wire meaning for passthrough and pre-dispatch events.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionEvent {
    /// Unique `aevt` `TypeID` backed by UUID v7 (time-ordered).
    pub event_id: String,
    /// Session that produced this event.
    pub session_id: String,
    /// Capability token ID evaluated during enforcement.
    pub token_id: String,
    /// Agent that initiated the action.
    pub agent_id: String,
    /// Canonical action class from the normalizer (for example, `http_get`).
    pub action: String,
    /// Target resource identifier (for example, a URL or table name).
    pub resource: String,
    /// Enforcement outcome.
    pub decision: Decision,
    /// Human-readable reason when the decision carries one.
    pub deny_reason: String,
    /// Wall-clock time spent in the enforcement pipeline, in microseconds.
    pub enforcement_latency_us: i64,
    /// Integrity hash of the Cedar context used during evaluation.
    pub context_hash: String,
    /// Policy bundle version active at decision time.
    pub bundle_version: String,
    /// Event timestamp as nanoseconds since the Unix epoch.
    pub timestamp: Option<u128>,
    /// HTTP status returned by the connector, or zero if no call dispatched.
    pub dispatch_status: i32,
    /// Connector dispatch latency in microseconds, or zero if not dispatched.
    pub dispatch_latency_us: i64,
    /// Target response body size in bytes, or zero if no body was received.
    pub response_size: i64,
    /// Per-run sandbox identity, or an empty string outside `firma run`.
    pub sandbox_id: String,
    /// Tamper-evident provenance chain anchor for admitted actions.
    pub provenance: String,
    /// Server-derived conversation thread identity.
    pub thread_id: String,
    /// Provenance anchor of the preceding admitted action in the thread.
    pub parent_action_id: String,
    /// DER-encoded ECDSA signature over all preceding fields.
    ///
    /// JSON encodes these bytes as a standard padded base64 string. Binary
    /// transports may retain the raw bytes.
    #[serde(with = "base64_signature")]
    pub signature: Vec<u8>,
}

/// Serde adapter for the signature's base64 JSON representation.
mod base64_signature {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
