//! Audit event builder.
//!
//! Constructs and signs [`ExecutionEvent`]s from enforcement decisions.
//! The builder holds the ECDSA signing key, loaded once at startup, and
//! provides a single [`EventBuilder::build`] method that maps an
//! [`EnforcementDecision`] into a fully populated, signed audit event.

use std::fmt;
use std::time::Duration;

use ecdsa::signature::Signer;
use ecdsa::SignatureEncoding;
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::ExecutionEvent;
use crate::enforcement::decision::EnforcementDecision;

/// Proto wire values for the `EnforcementDecision` enum.
#[allow(dead_code, reason = "used once pipeline wires send_audit_event")]
const DECISION_ALLOW: i32 = 1;
#[allow(dead_code, reason = "used once pipeline wires send_audit_event")]
const DECISION_DENY: i32 = 2;

/// Builds signed [`ExecutionEvent`]s from enforcement decisions.
///
/// Loaded once at startup with an ECDSA P-256 signing key. Each call
/// to [`build`](Self::build) produces a new event with a UUID v7
/// identifier, a nanosecond-precision timestamp, and an ECDSA signature
/// covering all preceding fields.
#[allow(dead_code, reason = "used once pipeline wires send_audit_event")]
pub struct EventBuilder {
    signing_key: SigningKey,
}

// M-PUBLIC-DEBUG: custom Debug to avoid leaking key material.
impl fmt::Debug for EventBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBuilder")
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

/// Errors that can occur when constructing an [`EventBuilder`].
#[allow(dead_code, reason = "used once pipeline wires send_audit_event")]
#[derive(Debug, thiserror::Error)]
pub enum EventBuilderError {
    /// The PEM-encoded signing key could not be parsed.
    #[error("invalid signing key: {0}")]
    InvalidKey(String),
}

#[allow(dead_code, reason = "used once pipeline wires send_audit_event")]
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

        Ok(Self { signing_key })
    }

    /// Builds a signed [`ExecutionEvent`] from an enforcement decision.
    ///
    /// Fields are extracted from the decision variant:
    /// - **Allow**: token ID, agent ID, action, and resource come from
    ///   the claims and envelope.
    /// - **Deny**: token ID, agent ID, action, and resource come from
    ///   the envelope when available; deny reason is serialized.
    /// - **Passthrough**: produces an event with empty token/agent
    ///   fields and decision set to ALLOW (non-protected traffic).
    #[must_use]
    pub fn build(
        &self,
        decision: &EnforcementDecision,
        session_id: &str,
        enforcement_latency: Duration,
    ) -> ExecutionEvent {
        let event_id = Uuid::now_v7().to_string();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "duration micros fits i64 for any realistic enforcement latency"
        )]
        let enforcement_latency_us = enforcement_latency.as_micros() as i64;
        let timestamp = timestamp_nanos();

        let (token_id, agent_id, action, resource, decision_code, deny_reason, context_hash, bundle_version) =
            match decision {
                EnforcementDecision::Allow { claims, envelope } => (
                    claims.token_id.clone(),
                    claims.agent_id.clone(),
                    envelope.intent().action_class.clone(),
                    envelope.intent().resource.clone(),
                    DECISION_ALLOW,
                    String::new(),
                    claims.context_hash.clone(),
                    String::new(),
                ),
                EnforcementDecision::Deny {
                    reason,
                    detail,
                    envelope,
                    ..
                } => {
                    let (action, resource) = envelope
                        .as_ref()
                        .map(|e| {
                            (
                                e.intent.action_class.clone(),
                                e.intent.resource.clone(),
                            )
                        })
                        .unwrap_or_default();

                    (
                        String::new(),
                        String::new(),
                        action,
                        resource,
                        DECISION_DENY,
                        format!("{reason}: {detail}"),
                        String::new(),
                        String::new(),
                    )
                }
                EnforcementDecision::Passthrough { .. } => (
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    DECISION_ALLOW,
                    String::new(),
                    String::new(),
                    String::new(),
                ),
            };

        let mut event = ExecutionEvent {
            event_id,
            session_id: session_id.to_string(),
            token_id,
            agent_id,
            action,
            resource,
            decision: decision_code,
            deny_reason,
            enforcement_latency_us,
            context_hash,
            bundle_version,
            timestamp: Some(timestamp),
            signature: Vec::new(),
        };

        event.signature = self.sign(&event);
        event
    }

    /// Computes the ECDSA P-256 signature over all event fields
    /// (excluding the signature field itself).
    ///
    /// The signing payload is the SHA-256 digest of the canonical
    /// JSON serialization of the signable fields.
    fn sign(&self, event: &ExecutionEvent) -> Vec<u8> {
        let payload = signing_payload(event);
        let signature: DerSignature = self.signing_key.sign(&payload);
        signature.to_vec()
    }
}

#[allow(dead_code, reason = "used once pipeline wires send_audit_event")]
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
    let ts = event.timestamp.map_or_else(|| "0".to_string(), |n| n.to_string());
    hasher.update(ts.as_bytes());
    hasher.finalize().to_vec()
}

#[allow(dead_code, reason = "used once pipeline wires send_audit_event")]
/// Returns the current wall-clock time as nanoseconds since the Unix
/// epoch.
fn timestamp_nanos() -> u128 {
    let now = chrono::Utc::now();
    #[expect(
        clippy::cast_sign_loss,
        reason = "timestamp_nanos_opt returns None for dates before epoch; \
                  current wall-clock is always positive"
    )]
    now.timestamp_nanos_opt()
        .map_or(0, |ns| ns as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::time::Duration;

    use chrono::Utc;
    use ecdsa::signature::Verifier;
    use firma_core::{
        ActionParams, CapabilityClaims, DenyReason, ExecutionEnvelope,
        ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams,
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

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent_test".to_string(),
            session_id: "sess_001".to_string(),
            action_set: vec!["llm.inference".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: "ctx_abc".to_string(),
        }
    }

    fn test_envelope() -> ExecutionEnvelope {
        ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "llm.inference".to_string(),
                resource: "api.openai.com/v1/chat/completions".to_string(),
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
                session_id: "sess_001".to_string(),
                agent_id: "agent_test".to_string(),
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
                action_class: "llm.inference".to_string(),
                resource: "api.openai.com/v1/chat/completions".to_string(),
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

    #[test]
    fn test_build_allow_event() {
        let builder =
            EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
        };

        let event =
            builder.build(&decision, "sess_001", Duration::from_micros(150));

        assert_eq!(event.session_id, "sess_001");
        assert_eq!(event.token_id, "tok_001");
        assert_eq!(event.agent_id, "agent_test");
        assert_eq!(event.action, "llm.inference");
        assert_eq!(
            event.resource,
            "api.openai.com/v1/chat/completions"
        );
        assert_eq!(event.decision, DECISION_ALLOW);
        assert!(event.deny_reason.is_empty());
        assert_eq!(event.enforcement_latency_us, 150);
        assert_eq!(event.context_hash, "ctx_abc");
        assert!(event.timestamp.is_some());
        assert!(!event.signature.is_empty());
    }

    #[test]
    fn test_build_deny_event() {
        let builder =
            EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Deny {
            reason: DenyReason::TokenExpired,
            stage: EnforcementStage::CapabilityValidation(
                CapabilityValidationStage::TokenValidation,
            ),
            detail: "token has expired".to_string(),
            envelope: Some(test_normalized_envelope()),
        };

        let event =
            builder.build(&decision, "sess_deny", Duration::from_micros(42));

        assert_eq!(event.session_id, "sess_deny");
        assert_eq!(event.decision, DECISION_DENY);
        assert!(event.deny_reason.contains("token expired"));
        assert_eq!(event.action, "llm.inference");
        assert!(!event.signature.is_empty());
    }

    #[test]
    fn test_build_passthrough_event() {
        let builder =
            EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Passthrough {
            detail: "non-protected host".to_string(),
        };

        let event = builder.build(
            &decision,
            "sess_pt",
            Duration::from_micros(5),
        );

        assert_eq!(event.decision, DECISION_ALLOW);
        assert!(event.token_id.is_empty());
        assert!(event.agent_id.is_empty());
    }

    #[test]
    fn test_signature_is_verifiable() {
        let builder =
            EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
        };

        let event =
            builder.build(&decision, "sess_001", Duration::from_micros(100));

        // Derive the verifying (public) key from the signing key.
        let signing_key: SigningKey = TEST_KEY_PEM
            .parse()
            .unwrap_or_else(|e: ecdsa::Error| panic!("{e}"));
        let verifying_key = VerifyingKey::from(&signing_key);

        let payload = signing_payload(&event);
        let sig = DerSignature::from_bytes(&event.signature)
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(
            verifying_key.verify(&payload, &sig).is_ok(),
            "signature must verify against the corresponding public key"
        );
    }

    #[test]
    fn test_tampered_event_fails_verification() {
        let builder =
            EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Allow {
            claims: test_claims(),
            envelope: Box::new(test_envelope()),
        };

        let mut event =
            builder.build(&decision, "sess_001", Duration::from_micros(100));

        // Tamper with the event after signing.
        event.agent_id = "evil_agent".to_string();

        let signing_key: SigningKey = TEST_KEY_PEM
            .parse()
            .unwrap_or_else(|e: ecdsa::Error| panic!("{e}"));
        let verifying_key = VerifyingKey::from(&signing_key);

        let payload = signing_payload(&event);
        let sig = DerSignature::from_bytes(&event.signature)
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(
            verifying_key.verify(&payload, &sig).is_err(),
            "tampered event must fail signature verification"
        );
    }

    #[test]
    fn test_debug_redacts_key() {
        let builder =
            EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));
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
        let builder =
            EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Passthrough {
            detail: "test".to_string(),
        };

        let e1 = builder.build(&decision, "s", Duration::ZERO);
        let e2 = builder.build(&decision, "s", Duration::ZERO);

        assert_ne!(
            e1.event_id, e2.event_id,
            "each event must get a unique UUID v7"
        );
    }

    #[test]
    fn test_build_deny_without_envelope() {
        let builder =
            EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"));

        let decision = EnforcementDecision::Deny {
            reason: DenyReason::UnclassifiedIntent,
            stage: EnforcementStage::Normalization,
            detail: "no matching rule".to_string(),
            envelope: None,
        };

        let event =
            builder.build(&decision, "sess_no_env", Duration::from_micros(10));

        assert_eq!(event.decision, DECISION_DENY);
        assert!(event.deny_reason.contains("unclassified intent"));
        assert!(
            event.action.is_empty(),
            "action should be empty when no envelope is available"
        );
        assert!(
            event.resource.is_empty(),
            "resource should be empty when no envelope is available"
        );
        assert!(!event.signature.is_empty());
    }
}
