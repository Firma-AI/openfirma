//! Stage 1 — Capability Validation.
//!
//! First enforcement phase. Selects the best-matching capability token and
//! validates it:
//!
//! 1. **Capability token selection** — selects the best-matching pre-provisioned
//!    token from the [`CapabilityMap`] by
//!    action class and resource scope (ADR-002). The agent knows nothing about
//!    Firma; the sidecar selects the correct token internally.
//! 2. **Token validation** — parse PASETO v4, verify Ed25519 signature, check
//!    expiry (with configurable clock skew tolerance), and check revocation via
//!    bloom filter + LRU cache.
//!
//! All operations are fully local — the Authority is never contacted on the
//! hot path. Target latency: < 1 ms p95.
//!
//! # Security properties
//!
//! Stage 1 prevents forged, tampered, expired, or revoked capabilities from
//! entering the execution path:
//! - **Token forgery** — cryptographic signature verification rejects tokens
//!   not signed by a trusted Authority.
//! - **Token tampering** — any modification to scope, budget, expiry, agent ID,
//!   or resource scope invalidates the signature.
//! - **Expired credential reuse** — expiry check rejects tokens whose TTL has
//!   elapsed.
//! - **Revoked token reuse** — bloom filter + LRU cache check rejects tokens
//!   that have been explicitly invalidated.

use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(test)]
use firma_core::TokenId;
use firma_core::{AgentId, CapabilityClaims, RevocationStore, TokenError, TokenVerifier};

use crate::config::TenancyMode;
use crate::normalizer::NormalizedEnvelope;

use super::capability_map::CapabilityMap;
use super::decision::{CapabilityValidationStage, EnforcementDecision, EnforcementStage};
use super::error::EnforcementError;

/// A capability token that has been selected from the map and
/// cryptographically validated (signature, expiry, revocation).
#[derive(Debug, Clone)]
pub struct ValidatedCapability {
    /// The raw PASETO v4 token string.
    pub raw_token: String,
    /// Verified claims extracted from the token.
    pub claims: CapabilityClaims,
}

/// Stage 1: Capability Validation.
///
/// Selects the best-matching capability token and validates it:
/// parse PASETO v4, verify Ed25519 signature, check expiry, and check
/// revocation via bloom filter + LRU cache.
/// Fully local — the Authority is never contacted.
///
/// Target: < 1ms p95.
pub struct CapabilityValidator {
    clock_skew_tolerance: Duration,
    capability_map: CapabilityMap,
    revocation: Arc<dyn RevocationStore + Send + Sync>,
    verifier: Box<dyn TokenVerifier + Send + Sync>,
    tenancy_mode: TenancyMode,
    first_agent_id: Mutex<Option<AgentId>>,
}

impl CapabilityValidator {
    /// Creates a new [`CapabilityValidator`] with the given [`CapabilityMap`],
    /// and implementations of [`TokenVerifier`] and [`RevocationStore`].
    #[must_use]
    pub fn new(
        capability_map: CapabilityMap,
        verifier: Box<dyn TokenVerifier + Send + Sync>,
        revocation: Arc<dyn RevocationStore + Send + Sync>,
        clock_skew_tolerance: Duration,
        tenancy_mode: TenancyMode,
    ) -> Self {
        Self {
            clock_skew_tolerance,
            capability_map,
            revocation,
            verifier,
            tenancy_mode,
            first_agent_id: Mutex::new(None),
        }
    }

    /// Run Stage 1: select token → validate.
    ///
    /// Receives an already-normalized [`NormalizedEnvelope`] (produced by
    /// [`crate::normalizer::IntentNormalizer`]) and the session ID.
    /// Selects the best-matching capability token from the map and validates it.
    ///
    /// Returns a [`ValidatedCapability`] (raw token + verified claims) on
    /// success, or a DENY decision.
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if no token matches or token
    /// validation fails.
    ///
    /// # Panics
    ///
    /// Panics if the mutex guarding the first observed `agent_id` is poisoned.
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    #[allow(clippy::unwrap_used, reason = "mutex poison is fatal")]
    pub fn enforce(
        &self,
        envelope: &NormalizedEnvelope,
        session_id: &str,
    ) -> Result<ValidatedCapability, EnforcementDecision> {
        // Step 1: Select capability token from map (ADR-002)
        let resource_display = envelope.intent.resource_display();
        let entry = self.capability_map.select(
            session_id,
            &envelope.intent.action_class,
            &resource_display,
        )?;

        // Step 2: Validate selected token
        let claims = self.validate(&entry.raw_token)?;

        // Step 3: Enforce single-agent tenancy (V1 ADR §2)
        if self.tenancy_mode == TenancyMode::SingleAgent {
            let mut first_agent = self.first_agent_id.lock().unwrap();
            match &*first_agent {
                None => *first_agent = Some(claims.agent_id.clone()),
                Some(observed) if observed != &claims.agent_id => {
                    return Err(EnforcementDecision::Deny {
                        reason: firma_core::DenyReason::TenantMismatch,
                        stage: EnforcementStage::CapabilityValidation(
                            CapabilityValidationStage::TokenValidation,
                        ),
                        detail: format!(
                            "agent_id '{}' does not match first observed agent_id '{}'",
                            claims.agent_id, observed
                        ),
                        envelope: None,
                        identity: None,
                    });
                }
                _ => {}
            }
        }

        Ok(ValidatedCapability {
            raw_token: entry.raw_token.clone(),
            claims,
        })
    }

    /// Validate a raw token string.
    ///
    /// Validation sequence (fail at first check):
    /// 1. Parse PASETO v4 token structure
    /// 2. Verify Ed25519 cryptographic signature
    /// 3. Extract claims
    /// 4. Check expiry (with configurable clock skew tolerance)
    /// 5. Check revocation via `RevocationStore`
    ///
    /// Returns verified `CapabilityClaims` on success, or DENY on failure.
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if the token is invalid, expired,
    /// or revoked.
    ///
    /// # Panics
    ///
    /// Panics if the clock skew tolerance exceeds the range representable by
    /// `chrono::Duration` (practically unreachable).
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    fn validate(&self, raw_token: &str) -> Result<CapabilityClaims, EnforcementDecision> {
        let stage =
            EnforcementStage::CapabilityValidation(CapabilityValidationStage::TokenValidation);

        // Steps 1-3: Parse + verify + extract claims
        let claims = self
            .verifier
            .verify(raw_token)
            .map_err(|e| EnforcementError::from(e).into_deny(stage))?;

        // Step 4: Check expiry with clock skew tolerance
        let now = chrono::Utc::now();
        let tolerance = chrono::Duration::from_std(self.clock_skew_tolerance)
            .unwrap_or(chrono::Duration::zero());
        if claims.expiry + tolerance <= now {
            return Err(EnforcementError::TokenValidation(TokenError::Expired {
                token_id: claims.token_id,
            })
            .into_deny(stage));
        }

        // Step 5: Check revocation
        let is_revoked = self
            .revocation
            .is_revoked(&claims.token_id)
            .map_err(|e| EnforcementError::from(e).into_deny(stage))?;

        if is_revoked {
            return Err(EnforcementError::TokenValidation(TokenError::Revoked {
                token_id: claims.token_id,
            })
            .into_deny(stage));
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::capability_map::CapabilityEntry;
    use chrono::Utc;
    use firma_core::CapabilityClaims;

    struct MockVerifier {
        claims: CapabilityClaims,
    }

    impl TokenVerifier for MockVerifier {
        fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
            Ok(self.claims.clone())
        }
    }

    struct FailingVerifier;
    impl TokenVerifier for FailingVerifier {
        fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
            Err(TokenError::SignatureInvalid {
                reason: "forged".to_string(),
            })
        }
    }

    struct MockRevocationStore {
        revoked: Vec<String>,
    }

    impl RevocationStore for MockRevocationStore {
        fn is_revoked(&self, token_id: &TokenId) -> Result<bool, TokenError> {
            Ok(self.revoked.contains(&token_id.to_string()))
        }
        fn add_revocation(&self, _token_id: &TokenId) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn valid_claims() -> CapabilityClaims {
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
            context_hash: String::new(),
            budget_ceiling: None,
        }
    }

    fn test_capability_map() -> CapabilityMap {
        CapabilityMap::new(vec![CapabilityEntry {
            raw_token: "v4.public.test_token".to_string(),
            claims: valid_claims(),
        }])
    }

    fn make_validator() -> CapabilityValidator {
        CapabilityValidator::new(
            test_capability_map(),
            Box::new(MockVerifier {
                claims: valid_claims(),
            }),
            Arc::new(MockRevocationStore { revoked: vec![] }),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        )
    }

    #[test]
    fn test_valid_token_passes() {
        let validator = make_validator();

        let result = validator.validate("v4.public.test_token");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_denied() {
        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(FailingVerifier),
            Arc::new(MockRevocationStore { revoked: vec![] }),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let result = validator.validate("v4.public.bad_token");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert_eq!(
            decision.deny_reason(),
            Some(firma_core::DenyReason::TokenInvalid)
        );
    }

    #[test]
    fn test_revoked_token_denied() {
        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(MockVerifier {
                claims: valid_claims(),
            }),
            Arc::new(MockRevocationStore {
                revoked: vec!["3713c5fc-b569-650c-c780-c64051473370".to_string()],
            }),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let result = validator.validate("v4.public.test_token");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert_eq!(
            decision.deny_reason(),
            Some(firma_core::DenyReason::TokenRevoked)
        );
    }

    #[test]
    fn test_expired_token_denied() {
        let mut claims = valid_claims();
        claims.expiry = Utc::now() - chrono::Duration::hours(1);

        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(MockVerifier { claims }),
            Arc::new(MockRevocationStore { revoked: vec![] }),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let result = validator.validate("v4.public.test_token");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert_eq!(
            decision.deny_reason(),
            Some(firma_core::DenyReason::TokenExpired)
        );
    }

    #[test]
    fn test_malformed_token_denied() {
        struct MalformedVerifier;
        impl TokenVerifier for MalformedVerifier {
            fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
                Err(TokenError::Malformed {
                    reason: "not PASETO v4 format".to_string(),
                })
            }
        }

        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(MalformedVerifier),
            Arc::new(MockRevocationStore { revoked: vec![] }),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let result = validator.validate("garbage-not-a-token");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().deny_reason(),
            Some(firma_core::DenyReason::TokenInvalid)
        );
    }

    #[test]
    fn test_clock_skew_tolerance_allows_slightly_expired() {
        let mut claims = valid_claims();
        claims.expiry = Utc::now() - chrono::Duration::seconds(2);

        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(MockVerifier { claims }),
            Arc::new(MockRevocationStore { revoked: vec![] }),
            Duration::from_secs(5),
            TenancyMode::SingleAgent,
        );

        let result = validator.validate("v4.public.test_token");
        assert!(
            result.is_ok(),
            "clock skew tolerance should allow slightly expired token"
        );
    }

    #[test]
    fn test_enforce_selects_and_validates_token() {
        let claims = valid_claims();
        let envelope = NormalizedEnvelope {
            intent: firma_core::ExecutionIntent {
                action_class: "communication.external.send".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("api.openai.com/v1/chat"),
                params: firma_core::ActionParams::Http(firma_core::HttpParams {
                    method: firma_core::HttpMethod::POST,
                    headers: std::collections::HashMap::new(),
                    body: None,
                    query: std::collections::HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "POST /v1/chat".to_string(),
            },
            timestamp: Utc::now(),
        };

        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(MockVerifier { claims }),
            Arc::new(MockRevocationStore { revoked: vec![] }),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let result = validator.enforce(&envelope, "sess_001");
        assert!(result.is_ok());
        let validated = result.unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(
            validated.claims.token_id.to_string(),
            "3713c5fc-b569-650c-c780-c64051473370"
        );
        assert_eq!(validated.raw_token, "v4.public.test_token");
    }

    #[test]
    fn test_enforce_no_matching_token_denies() {
        let claims = valid_claims();
        let envelope = NormalizedEnvelope {
            intent: firma_core::ExecutionIntent {
                action_class: "filesystem.delete".to_string(), // not in token's action_set
                resource: firma_core::ExecutionIntent::resource_map_from("any.resource"),
                params: firma_core::ActionParams::Http(firma_core::HttpParams {
                    method: firma_core::HttpMethod::DELETE,
                    headers: std::collections::HashMap::new(),
                    body: None,
                    query: std::collections::HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "DELETE /files".to_string(),
            },
            timestamp: Utc::now(),
        };

        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(MockVerifier { claims }),
            Arc::new(MockRevocationStore { revoked: vec![] }),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let result = validator.enforce(&envelope, "sess_001");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(
            decision.stage(),
            Some(
                super::super::decision::EnforcementStage::CapabilityValidation(
                    super::super::decision::CapabilityValidationStage::TokenSelection
                )
            )
        );
    }

    #[test]
    fn test_every_validation_error_is_deny() {
        let error_verifiers: Vec<Box<dyn TokenVerifier + Send + Sync>> =
            vec![Box::new(FailingVerifier)];

        for verifier in error_verifiers {
            let validator = CapabilityValidator::new(
                test_capability_map(),
                verifier,
                Arc::new(MockRevocationStore { revoked: vec![] }),
                Duration::from_secs(0),
                TenancyMode::SingleAgent,
            );
            let result = validator.validate("any");
            assert!(
                result.is_err(),
                "every TokenVerifier error must produce DENY"
            );
            assert!(result.unwrap_err().is_deny());
        }
    }
}
