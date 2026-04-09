pub mod paseto;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Errors from token signing, verification, and revocation operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// Token could not be parsed from the raw string.
    #[error("token parse failure: {reason}")]
    ParseFailure { reason: String },
    /// Token signature verification failed.
    #[error("token signature invalid: {reason}")]
    SignatureInvalid { reason: String },
    /// Token has expired.
    #[error("token expired: {token_id}")]
    Expired { token_id: String },
    /// Token has been revoked.
    #[error("token revoked: {token_id}")]
    Revoked { token_id: String },
    /// Token payload is malformed or missing required fields.
    #[error("token malformed: {reason}")]
    Malformed { reason: String },
}

/// Payload of a signed capability token.
///
/// Represents the authority's grant to an agent for a scoped set of actions
/// and resources within a session. Carried inside a PASETO v4 or JWT token.
///
/// Field names mirror the proto `CapabilityToken` message in `firma/v1/types.proto`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Globally unique identifier for this token. Used for revocation lookups.
    pub token_id: String,
    /// Identity of the agent this token was issued to.
    pub agent_id: String,
    /// Session within which this token is valid.
    pub session_id: String,
    /// Allowed action set (e.g., `["http:GET", "tool:execute"]`). May be empty.
    pub action_set: Vec<String>,
    /// Resource scope pattern this token covers (e.g., `"api.example.com/*"`).
    pub resource_scope: String,
    /// When the Authority issued this token.
    pub issued_at: DateTime<Utc>,
    /// When this token expires. Validation enforced by `TokenVerifier`, not at construction.
    pub expiry: DateTime<Utc>,
    /// Hex-encoded SHA-256 of the Cedar context snapshot at issuance time.
    pub context_hash: String,
}

/// Lifecycle state of a capability token.
///
/// Terminal states (`Expired`, `Revoked`, `Aborted`) cannot transition to any other state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenState {
    /// Token created by Authority, not yet delivered to agent.
    Issued,
    /// Token delivered to agent, available for use.
    Active,
    /// Token currently attached to an in-flight execution.
    InUse,
    /// Token TTL has elapsed. Terminal.
    Expired,
    /// Token explicitly revoked by Authority or policy. Terminal.
    Revoked,
    /// Token invalidated due to policy abort. Terminal.
    Aborted,
}

/// Serialize and cryptographically sign capability claims into a token string.
///
/// Format-agnostic — implementations choose the token format (PASETO v4, JWT, etc.).
/// All implementations must be object-safe for dynamic dispatch.
pub trait TokenSigner {
    /// Sign the given claims and return a serialized token string.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if signing fails (e.g., key unavailable, serialization error).
    fn sign(&self, claims: &CapabilityClaims) -> Result<String, TokenError>;
}

/// Parse, verify signature, validate expiry, and return capability claims.
///
/// Format-agnostic — implementations choose the token format (PASETO v4, JWT, etc.).
/// All implementations must be object-safe for dynamic dispatch.
pub trait TokenVerifier {
    /// Verify a raw token string and return the validated claims.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if the token is invalid, expired, revoked, or malformed.
    fn verify(&self, raw_token: &str) -> Result<CapabilityClaims, TokenError>;
}

/// Check and record token revocations.
pub trait RevocationStore {
    /// Check if a token has been revoked by its ID.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if the revocation store cannot be queried.
    fn is_revoked(&self, token_id: &str) -> Result<bool, TokenError>;
    /// Record a token revocation.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if the revocation cannot be recorded.
    fn add_revocation(&self, token_id: &str) -> Result<(), TokenError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent_abc".to_string(),
            session_id: "sess_xyz".to_string(),
            action_set: vec!["http:GET".to_string()],
            resource_scope: "https://api.example.com/*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now(),
            context_hash: "abcdef1234567890".to_string(),
        }
    }

    #[test]
    fn test_capability_claims_construction() {
        let claims = sample_claims();
        assert_eq!(claims.token_id, "tok_001");
        assert_eq!(claims.agent_id, "agent_abc");
        assert_eq!(claims.session_id, "sess_xyz");
        assert_eq!(claims.action_set.len(), 1);
        assert_eq!(claims.resource_scope, "https://api.example.com/*");
    }

    #[test]
    fn test_capability_claims_serde_round_trip() {
        let claims = sample_claims();
        let json = serde_json::to_string(&claims).unwrap_or_else(|e| panic!("{e}"));
        let parsed: CapabilityClaims =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(claims, parsed);
    }

    #[test]
    fn test_capability_claims_empty_action_set() {
        let claims = CapabilityClaims {
            action_set: vec![],
            ..sample_claims()
        };
        assert!(claims.action_set.is_empty());
    }

    #[test]
    fn test_capability_claims_debug_clone() {
        let claims = sample_claims();
        let cloned = claims.clone();
        assert_eq!(claims, cloned);
        let debug = format!("{claims:?}");
        assert!(debug.contains("tok_001"));
    }

    #[test]
    fn test_token_state_all_variants() {
        let states = [
            TokenState::Issued,
            TokenState::Active,
            TokenState::InUse,
            TokenState::Expired,
            TokenState::Revoked,
            TokenState::Aborted,
        ];
        assert_eq!(states.len(), 6);
    }

    #[test]
    fn test_token_state_copy_eq() {
        let state = TokenState::Active;
        let copied = state;
        assert_eq!(state, copied);
    }

    #[test]
    fn test_token_state_serde_round_trip() {
        let state = TokenState::Revoked;
        let json = serde_json::to_string(&state).unwrap_or_else(|e| panic!("{e}"));
        let parsed: TokenState = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(state, parsed);
    }

    // -- TokenSigner, TokenVerifier, RevocationStore object-safety tests --

    struct MockSigner;
    impl TokenSigner for MockSigner {
        fn sign(&self, _claims: &CapabilityClaims) -> Result<String, TokenError> {
            Ok("mock_token".to_string())
        }
    }

    struct MockVerifier;
    impl TokenVerifier for MockVerifier {
        fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
            Err(TokenError::ParseFailure {
                reason: "mock".to_string(),
            })
        }
    }

    struct MockRevocationStore;
    impl RevocationStore for MockRevocationStore {
        fn is_revoked(&self, _token_id: &str) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _token_id: &str) -> Result<(), TokenError> {
            Ok(())
        }
    }

    #[test]
    fn test_token_signer_object_safe() {
        let signer: Box<dyn TokenSigner> = Box::new(MockSigner);
        let claims = CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent".to_string(),
            session_id: "sess".to_string(),
            action_set: vec![],
            resource_scope: String::new(),
            issued_at: Utc::now(),
            expiry: Utc::now(),
            context_hash: "hash".to_string(),
        };
        let result = signer.sign(&claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_verifier_object_safe() {
        let verifier: Box<dyn TokenVerifier> = Box::new(MockVerifier);
        let result = verifier.verify("some_token");
        assert!(result.is_err());
    }

    #[test]
    fn test_revocation_store_object_safe() {
        let store: Box<dyn RevocationStore> = Box::new(MockRevocationStore);
        assert_eq!(store.is_revoked("tok_001").ok(), Some(false));
        assert!(store.add_revocation("tok_001").is_ok());
    }
}
