//! Audit event builder.
//!
//! Constructs and signs [`ExecutionEvent`]s from [`AuditPayload`]s.
//! The builder holds the ECDSA signing key, loaded once at startup, and
//! provides a single [`EventBuilder::build`] method that maps an
//! [`AuditPayload`] into a fully populated, signed audit event.
//!
//! The builder lives on the **sink side** of the audit channel, keeping
//! ECDSA signing off the enforcement hot path.

use std::fmt;

use ecdsa::SignatureEncoding;
use ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{AuditPayload, ExecutionEvent};

/// Builds signed [`ExecutionEvent`]s from [`AuditPayload`]s.
///
/// Loaded once at startup with an ECDSA P-256 signing key. Each call
/// to [`build`](Self::build) produces a new event with a UUID v7
/// identifier, a nanosecond-precision timestamp, and an ECDSA signature
/// covering all preceding fields.
pub struct EventBuilder {
    signing_key: SigningKey,
    sandbox_id: String,
}

// custom Debug to avoid leaking key material.
impl fmt::Debug for EventBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBuilder")
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

/// Errors that can occur when constructing an [`EventBuilder`].
#[derive(Debug, thiserror::Error)]
pub enum EventBuilderError {
    /// The PEM-encoded signing key could not be parsed.
    #[error("invalid signing key: {0}")]
    InvalidKey(String),
}

impl EventBuilder {
    /// Creates a new builder from a PEM-encoded ECDSA P-256 private key.
    ///
    /// # Errors
    ///
    /// Returns [`EventBuilderError::InvalidKey`] if the PEM payload is
    /// not a valid P-256 secret key.
    pub fn new(pem: &str) -> Result<Self, EventBuilderError> {
        let signing_key = pem
            .parse::<SigningKey>()
            .map_err(|e| EventBuilderError::InvalidKey(e.to_string()))?;

        Ok(Self {
            signing_key,
            sandbox_id: String::new(),
        })
    }

    /// Sets the per-run sandbox identity stamped on every emitted
    /// event. Sourced from the `FIRMA_RUN_SANDBOX_ID` environment
    /// variable when the sidecar is autostarted by `firma run`; left
    /// empty otherwise.
    #[must_use]
    pub fn with_sandbox_id(mut self, sandbox_id: String) -> Self {
        self.sandbox_id = sandbox_id;
        self
    }

    /// Builds a signed [`ExecutionEvent`] from an [`AuditPayload`].
    ///
    /// Generates a UUID v7 event ID, captures the current wall-clock
    /// timestamp in nanoseconds, and signs all fields with ECDSA P-256.
    #[must_use]
    pub fn build(&self, payload: AuditPayload) -> ExecutionEvent {
        let event_id = Uuid::now_v7().to_string();
        let timestamp = timestamp_nanos();

        let mut event = ExecutionEvent {
            event_id,
            session_id: payload.session_id,
            token_id: payload.token_id,
            agent_id: payload.agent_id,
            action: payload.action,
            resource: payload.resource,
            decision: payload.decision,
            deny_reason: payload.deny_reason,
            enforcement_latency_us: payload.enforcement_latency_us,
            context_hash: payload.context_hash,
            bundle_version: payload.bundle_version,
            timestamp: Some(timestamp),
            dispatch_status: payload.dispatch_status,
            dispatch_latency_us: payload.dispatch_latency_us,
            response_size: payload.response_size,
            sandbox_id: self.sandbox_id.clone(),
            signature: Vec::new(),
        };

        event.signature = self.sign(&event);
        event
    }

    /// Computes the ECDSA P-256 signature over all event fields
    /// (excluding the signature field itself).
    ///
    /// The signing payload is the SHA-256 digest of the canonical
    /// field concatenation.
    fn sign(&self, event: &ExecutionEvent) -> Vec<u8> {
        let payload = signing_payload(event);
        let signature: DerSignature = self.signing_key.sign(&payload);
        signature.to_vec()
    }
}

/// Builds the canonical byte payload that is signed.
///
/// Concatenates all event fields (except `signature`) in declaration
/// order, separated by newlines. This deterministic representation
/// avoids depending on JSON serialization ordering.
fn signing_payload(event: &ExecutionEvent) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(event.event_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.session_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.token_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.agent_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.action.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.resource.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.decision.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(event.deny_reason.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.enforcement_latency_us.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(event.context_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.bundle_version.as_bytes());
    hasher.update(b"\n");
    let ts = event
        .timestamp
        .map_or_else(|| "0".to_string(), |n| n.to_string());
    hasher.update(ts.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.dispatch_status.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(event.dispatch_latency_us.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(event.response_size.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(event.sandbox_id.as_bytes());
    hasher.finalize().to_vec()
}

/// Returns the current wall-clock time as nanoseconds since the Unix
/// epoch.
fn timestamp_nanos() -> u128 {
    let now = chrono::Utc::now();
    #[expect(
        clippy::cast_sign_loss,
        reason = "timestamp_nanos_opt returns None for dates before epoch; \
                  current wall-clock is always positive"
    )]
    now.timestamp_nanos_opt().map_or(0, |ns| ns as u128)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::time::Duration;

    use chrono::Utc;
    use ecdsa::signature::Verifier;
    use firma_core::{
        ActionParams, CapabilityClaims, DenyReason, ExecutionEnvelope, ExecutionIntent,
        ExecutionMetadata, HttpMethod, HttpParams,
    };
    use p256::ecdsa::VerifyingKey;

    use crate::enforcement::decision::{
        CapabilityValidationStage, EnforcementDecision, EnforcementStage,
    };
    use crate::normalizer::NormalizedEnvelope;

    /// Deterministic P-256 test key in PKCS#8 PEM format.
    const TEST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----";

    /// Proto wire values for the `EnforcementDecision` enum.
    const DECISION_ALLOW: i32 = 1;
    const DECISION_DENY: i32 = 2;

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "3713c5fc-b569-650c-c780-c64051473370"
                .parse()
                .expect("literal token id"),
            agent_id: "agent_test".parse().expect("literal agent id"),
            session_id: "sess_001".parse().expect("literal session id"),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: "ctx_abc".to_string(),
            budget_ceiling: None,
        }
    }

    fn test_envelope() -> ExecutionEnvelope {
        ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "communication.external.send".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from(
                    "api.openai.com/v1/chat/completions",
                ),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::POST,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "POST /v1/chat/completions".to_string(),
            },
            "v4.public.test_token".to_string(),
            ExecutionMetadata {
                session_id: "sess_001".parse().expect("literal session id"),
                agent_id: "agent_test".parse().expect("literal agent id"),
                timestamp: Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            None,
        )
    }

    fn test_normalized_envelope() -> NormalizedEnvelope {
        NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "communication.external.send".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from(
                    "api.openai.com/v1/chat/completions",
                ),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::POST,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "POST /v1/chat/completions".to_string(),
            },
            timestamp: Utc::now(),
        }
    }

    /// Helper to build an `AuditPayload` from an `EnforcementDecision`,
    /// mirroring what the pipeline does on the hot path.
    fn payload_from_decision(
        decision: &EnforcementDecision,
        session_id: &str,
        latency: Duration,
    ) -> AuditPayload {
        let request = crate::normalizer::RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };
        crate::pipeline::audit_payload_from_decision(decision, &request, session_id, latency, None)
    }

    #[test]
    fn test_build_allow_event() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
            credentials: firma_core::InjectedCredentials::empty(),
        };

        let payload = payload_from_decision(&decision, "sess_001", Duration::from_micros(150));
        let event = builder.build(payload);

        assert_eq!(event.session_id, "sess_001");
        assert_eq!(event.token_id, "3713c5fc-b569-650c-c780-c64051473370");
        assert_eq!(event.agent_id, "agent_test");
        assert_eq!(event.action, "communication.external.send");
        assert_eq!(event.resource, "api.openai.com/v1/chat/completions");
        assert_eq!(event.decision, DECISION_ALLOW);
        assert!(event.deny_reason.is_empty());
        assert_eq!(event.enforcement_latency_us, 150);
        assert_eq!(event.context_hash, "ctx_abc");
        assert!(event.timestamp.is_some());
        assert!(!event.signature.is_empty());
    }

    #[test]
    fn test_build_deny_event() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Deny {
            reason: DenyReason::TokenExpired,
            stage: EnforcementStage::CapabilityValidation(
                CapabilityValidationStage::TokenValidation,
            ),
            detail: "token has expired".to_string(),
            envelope: Some(test_normalized_envelope()),
            identity: None,
        };

        let payload = payload_from_decision(&decision, "sess_deny", Duration::from_micros(42));
        let event = builder.build(payload);

        assert_eq!(event.session_id, "sess_deny");
        assert_eq!(event.decision, DECISION_DENY);
        assert!(event.deny_reason.contains("token expired"));
        assert_eq!(event.action, "communication.external.send");
        assert!(!event.signature.is_empty());
    }

    #[test]
    fn test_build_passthrough_event() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Passthrough {
            detail: "non-protected host".to_string(),
        };

        let payload = payload_from_decision(&decision, "sess_pt", Duration::from_micros(5));
        let event = builder.build(payload);

        assert_eq!(event.decision, DECISION_ALLOW);
        assert!(event.token_id.is_empty());
        assert!(event.agent_id.is_empty());
    }

    #[test]
    fn test_signature_is_verifiable() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
            credentials: firma_core::InjectedCredentials::empty(),
        };

        let payload = payload_from_decision(&decision, "sess_001", Duration::from_micros(100));
        let event = builder.build(payload);

        // Derive the verifying (public) key from the signing key.
        let signing_key: SigningKey = TEST_KEY_PEM
            .parse()
            .unwrap_or_else(|e: ecdsa::Error| panic!("{e}"));
        let verifying_key = VerifyingKey::from(&signing_key);

        let payload = signing_payload(&event);
        let sig = DerSignature::from_bytes(&event.signature).unwrap_or_else(|e| panic!("{e}"));

        assert!(
            verifying_key.verify(&payload, &sig).is_ok(),
            "signature must verify against the corresponding public key"
        );
    }

    #[test]
    fn test_tampered_event_fails_verification() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
            credentials: firma_core::InjectedCredentials::empty(),
        };

        let payload = payload_from_decision(&decision, "sess_001", Duration::from_micros(100));
        let mut event = builder.build(payload);

        // Tamper with the event after signing.
        event.agent_id = "evil_agent".to_string();

        let signing_key: SigningKey = TEST_KEY_PEM
            .parse()
            .unwrap_or_else(|e: ecdsa::Error| panic!("{e}"));
        let verifying_key = VerifyingKey::from(&signing_key);

        let payload = signing_payload(&event);
        let sig = DerSignature::from_bytes(&event.signature).unwrap_or_else(|e| panic!("{e}"));

        assert!(
            verifying_key.verify(&payload, &sig).is_err(),
            "tampered event must fail signature verification"
        );
    }

    #[test]
    fn test_tampered_sandbox_id_fails_verification() {
        let builder = EventBuilder::new(TEST_KEY_PEM)
            .unwrap_or_else(|e| panic!("{e}"))
            .with_sandbox_id("sbx_legit".to_string());

        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
            credentials: firma_core::InjectedCredentials::empty(),
        };

        let payload = payload_from_decision(&decision, "sess_001", Duration::from_micros(100));
        let mut event = builder.build(payload);

        event.sandbox_id = "sbx_evil".to_string();

        let signing_key: SigningKey = TEST_KEY_PEM
            .parse()
            .unwrap_or_else(|e: ecdsa::Error| panic!("{e}"));
        let verifying_key = VerifyingKey::from(&signing_key);

        let payload = signing_payload(&event);
        let sig = DerSignature::from_bytes(&event.signature).unwrap_or_else(|e| panic!("{e}"));

        assert!(
            verifying_key.verify(&payload, &sig).is_err(),
            "sandbox_id must be covered by the signature"
        );
    }

    #[test]
    fn test_debug_redacts_key() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));
        let rendered = format!("{builder:?}");

        assert!(rendered.contains("EventBuilder"));
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains("MIGHAgEA"),
            "signing key material must not appear in Debug output"
        );
    }

    #[test]
    fn test_invalid_pem_returns_error() {
        let result = EventBuilder::new("not a pem key");
        assert!(result.is_err());
    }

    #[test]
    fn test_event_ids_are_unique() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let payload1 = AuditPayload {
            session_id: "s".parse().expect("literal session id"),
            token_id: String::new(),
            agent_id: "_test_".parse().expect("literal agent id"),
            action: String::new(),
            resource: String::new(),
            decision: 1,
            deny_reason: String::new(),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: String::new(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
        };
        let payload2 = payload1.clone();

        let e1 = builder.build(payload1);
        let e2 = builder.build(payload2);

        assert_ne!(
            e1.event_id, e2.event_id,
            "each event must get a unique UUID v7"
        );
    }

    #[test]
    fn test_builder_stamps_configured_sandbox_id() {
        let builder = EventBuilder::new(TEST_KEY_PEM)
            .unwrap_or_else(|e| panic!("{e}"))
            .with_sandbox_id("sbx_abc123".to_string());

        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
            credentials: firma_core::InjectedCredentials::empty(),
        };
        let payload = payload_from_decision(&decision, "sess_001", Duration::from_micros(10));
        let event = builder.build(payload);

        assert_eq!(event.sandbox_id, "sbx_abc123");
    }

    #[test]
    fn test_builder_default_sandbox_id_is_empty() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));
        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
            credentials: firma_core::InjectedCredentials::empty(),
        };
        let payload = payload_from_decision(&decision, "sess_001", Duration::from_micros(10));
        let event = builder.build(payload);

        assert!(event.sandbox_id.is_empty());
    }

    #[test]
    fn test_build_deny_without_envelope() {
        let builder = EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Deny {
            reason: DenyReason::UnclassifiedIntent,
            stage: EnforcementStage::Normalization,
            detail: "no matching rule".to_string(),
            envelope: None,
            identity: None,
        };

        let payload = payload_from_decision(&decision, "sess_no_env", Duration::from_micros(10));
        let event = builder.build(payload);

        assert_eq!(event.decision, DECISION_DENY);
        assert!(event.deny_reason.contains("unclassified intent"));
        assert_eq!(event.action, "raw.http.POST");
        assert_eq!(event.resource, "api.openai.com/v1/chat/completions");
        assert!(!event.signature.is_empty());
    }
}
