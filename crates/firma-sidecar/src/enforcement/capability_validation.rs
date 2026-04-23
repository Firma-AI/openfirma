//! Stage 1 — Capability Validation.
//!
//! First enforcement phase. Selects the best-matching capability token and
//! validates it:
//!
//! 1. **Capability token selection** — selects the best-matching pre-provisioned
//!    token from the [`CapabilityMap`](super::capability_map::CapabilityMap) by
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

use firma_core::session::SessionId;
use firma_core::token::{CapabilityClaims, RevocationStore, TokenError, TokenVerifier};

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
/// Expiry checking (including clock skew leeway) is the responsibility of
/// the [`TokenVerifier`] implementation, not this stage.
///
/// Target: < 1ms p95.
pub struct CapabilityValidator {
    capability_map: CapabilityMap,
    revocation: Box<dyn RevocationStore + Send + Sync>,
    verifier: Box<dyn TokenVerifier + Send + Sync>,
}

impl CapabilityValidator {
    /// Creates a new [`CapabilityValidator`] with the given [`CapabilityMap`],
    /// and implementations of [`TokenVerifier`] and [`RevocationStore`].
    #[must_use]
    pub fn new(
        capability_map: CapabilityMap,
        verifier: Box<dyn TokenVerifier + Send + Sync>,
        revocation: Box<dyn RevocationStore + Send + Sync>,
    ) -> Self {
        Self {
            capability_map,
            revocation,
            verifier,
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
    #[allow(clippy::result_large_err)]
    pub fn enforce(
        &self,
        envelope: &NormalizedEnvelope,
        session_id: SessionId,
    ) -> Result<ValidatedCapability, EnforcementDecision> {
        // Step 1: Select capability token from map (ADR-002)
        let resource_display = envelope.intent.resource_display();
        let entry = self.capability_map.select(
            session_id,
            &envelope.intent.action_class,
            &resource_display,
        )?;

        // Step 2: Validate selected token
        let claims = self.validate(entry.raw_token())?;
        Ok(ValidatedCapability {
            raw_token: entry.raw_token().to_string(),
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
    #[allow(clippy::result_large_err)]
    fn validate(&self, raw_token: &str) -> Result<CapabilityClaims, EnforcementDecision> {
        let stage =
            EnforcementStage::CapabilityValidation(CapabilityValidationStage::TokenValidation);

        // Steps 1-3: Parse + verify signature + check expiry (with leeway) + extract claims.
        // Expiry validation including clock skew leeway is owned by the verifier.
        let claims = self
            .verifier
            .verify(raw_token)
            .map_err(|e| EnforcementError::from(e).into_deny(stage))?;

        // Step 4: Check revocation
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
    use firma_core::token::{CapabilityClaims, TokenId};

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
            token_id: TokenId::new(),
            agent_id: "agent_test".parse().unwrap(),
            session_id: "sess_001".parse().unwrap(),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    fn test_capability_map() -> CapabilityMap {
        CapabilityMap::new(vec![
            CapabilityEntry::from_raw_token(
                "v4.public.test_token",
                &MockVerifier {
                    claims: valid_claims(),
                },
            )
            .unwrap_or_else(|e| panic!("{e}")),
        ])
    }

    #[test]
    fn test_valid_token_passes() {
        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(MockVerifier {
                claims: valid_claims(),
            }),
            Box::new(MockRevocationStore { revoked: vec![] }),
        );

        let result = validator.validate("v4.public.test_token");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_denied() {
        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(FailingVerifier),
            Box::new(MockRevocationStore { revoked: vec![] }),
        );

        let result = validator.validate("v4.public.bad_token");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert_eq!(
            decision.deny_reason(),
            Some(firma_core::decision::DenyReason::TokenInvalid)
        );
    }

    #[test]
    fn test_revoked_token_denied() {
        let claims = valid_claims();
        let token_id = claims.token_id;

        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(MockVerifier {
                claims: claims.clone(),
            }),
            Box::new(MockRevocationStore {
                revoked: vec![token_id.to_string()],
            }),
        );

        let result = validator.validate("v4.public.test_token");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert_eq!(
            decision.deny_reason(),
            Some(firma_core::decision::DenyReason::TokenRevoked)
        );
    }

    /// Expiry is the verifier's responsibility. This test verifies that when
    /// the verifier returns `TokenError::Expired`, Stage 1 maps it to
    /// `DenyReason::TokenExpired` and short-circuits.
    #[test]
    fn test_expired_token_denied() {
        struct ExpiredVerifier;
        impl TokenVerifier for ExpiredVerifier {
            fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
                Err(TokenError::Expired {
                    token_id: TokenId::new(),
                })
            }
        }

        let validator = CapabilityValidator::new(
            test_capability_map(),
            Box::new(ExpiredVerifier),
            Box::new(MockRevocationStore { revoked: vec![] }),
        );

        let result = validator.validate("v4.public.test_token");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().deny_reason(),
            Some(firma_core::decision::DenyReason::TokenExpired)
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
            Box::new(MockRevocationStore { revoked: vec![] }),
        );

        let result = validator.validate("garbage-not-a-token");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().deny_reason(),
            Some(firma_core::decision::DenyReason::TokenInvalid)
        );
    }

    #[test]
    fn test_every_stage1_error_is_deny() {
        let error_verifiers: Vec<Box<dyn TokenVerifier + Send + Sync>> =
            vec![Box::new(FailingVerifier)];

        for verifier in error_verifiers {
            let validator = CapabilityValidator::new(
                test_capability_map(),
                verifier,
                Box::new(MockRevocationStore { revoked: vec![] }),
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
