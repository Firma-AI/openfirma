use crate::decision::Decision;
use crate::envelope::ExecutionContext;
use crate::error::{EvaluationError, TokenError};
use crate::token::CapabilityClaims;

/// Policy bundle containing Cedar policies and entity schema.
///
/// Created by the Authority when loading policies from disk, and distributed
/// to Sidecars via `WatchPolicyBundle` streaming. The `version` field is a
/// hex-encoded SHA-256 hash of the concatenated policy + schema bytes,
/// enabling cheap equality checks for deduplication.
#[derive(Debug, Clone)]
pub struct PolicyBundle {
    /// Bundle version identifier (hex SHA-256 of policies + schema).
    pub version: String,
    /// Raw Cedar policy source (concatenated `.cedar` files).
    pub policies: Vec<u8>,
    /// Raw Cedar entity schema bytes.
    pub entity_schema: Vec<u8>,
    /// Time-to-live in seconds. Sidecars enter fail-closed when stale.
    pub ttl_seconds: i32,
}

impl PolicyBundle {
    /// Create a new `PolicyBundle`.
    #[must_use]
    pub fn new(version: String, policies: Vec<u8>, entity_schema: Vec<u8>, ttl_seconds: i32) -> Self {
        Self {
            version,
            policies,
            entity_schema,
            ttl_seconds,
        }
    }
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

/// Evaluate policy rules against an execution context.
///
/// No Cedar dependency — this is a contract that Cedar implementations
/// fulfill in later intents (005/006).
pub trait PolicyEvaluator {
    /// Evaluate the policy against the given context and return a decision.
    ///
    /// # Errors
    ///
    /// Returns `EvaluationError` if policy loading or evaluation fails.
    fn evaluate(&self, context: &ExecutionContext) -> Result<Decision, EvaluationError>;
}

/// Load and manage policy bundles.
///
/// Implementations handle storage, caching, and TTL management.
pub trait PolicyBundleStore {
    /// Load the current policy bundle from storage/cache.
    ///
    /// # Errors
    ///
    /// Returns `EvaluationError::PolicyLoadFailure` if the bundle cannot be loaded.
    fn load_bundle(&self) -> Result<PolicyBundle, EvaluationError>;
    /// Return the current bundle version ID, if known.
    fn get_version(&self) -> Option<String>;
    /// Whether the bundle TTL is still valid.
    fn is_fresh(&self) -> bool;
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
    use crate::decision::DenyReason;

    // -- Mock implementations for object-safety verification --

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

    struct MockEvaluator;
    impl PolicyEvaluator for MockEvaluator {
        fn evaluate(&self, _context: &ExecutionContext) -> Result<Decision, EvaluationError> {
            Ok(Decision::Allow)
        }
    }

    struct MockBundleStore;
    impl PolicyBundleStore for MockBundleStore {
        fn load_bundle(&self) -> Result<PolicyBundle, EvaluationError> {
            Ok(PolicyBundle::new(
                "v1".to_string(),
                vec![],
                vec![],
                30,
            ))
        }
        fn get_version(&self) -> Option<String> {
            Some("v1".to_string())
        }
        fn is_fresh(&self) -> bool {
            true
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

    // -- Object-safety tests: Box<dyn Trait> must compile --

    #[test]
    fn test_token_signer_object_safe() {
        let signer: Box<dyn TokenSigner> = Box::new(MockSigner);
        let claims = crate::token::CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent".to_string(),
            session_id: "sess".to_string(),
            actions: vec![],
            resources: vec![],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
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
    fn test_policy_evaluator_object_safe() {
        let evaluator: Box<dyn PolicyEvaluator> = Box::new(MockEvaluator);
        let ctx = ExecutionContext {
            agent_id: "agent".to_string(),
            action: "http:GET".to_string(),
            resource: "https://example.com".to_string(),
            session_id: "sess".to_string(),
            token_id: "tok".to_string(),
            token_actions: vec![],
            token_resources: vec![],
        };
        let result = evaluator.evaluate(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_policy_bundle_store_object_safe() {
        let store: Box<dyn PolicyBundleStore> = Box::new(MockBundleStore);
        assert!(store.load_bundle().is_ok());
        assert_eq!(store.get_version(), Some("v1".to_string()));
        assert!(store.is_fresh());
    }

    #[test]
    fn test_revocation_store_object_safe() {
        let store: Box<dyn RevocationStore> = Box::new(MockRevocationStore);
        assert_eq!(store.is_revoked("tok_001").ok(), Some(false));
        assert!(store.add_revocation("tok_001").is_ok());
    }

    #[test]
    fn test_mock_evaluator_deny() {
        struct DenyEvaluator;
        impl PolicyEvaluator for DenyEvaluator {
            fn evaluate(&self, _ctx: &ExecutionContext) -> Result<Decision, EvaluationError> {
                Ok(Decision::Deny {
                    reason: DenyReason::PolicyDenied,
                })
            }
        }
        let evaluator: Box<dyn PolicyEvaluator> = Box::new(DenyEvaluator);
        let ctx = ExecutionContext {
            agent_id: "a".to_string(),
            action: "x".to_string(),
            resource: "r".to_string(),
            session_id: "s".to_string(),
            token_id: "t".to_string(),
            token_actions: vec![],
            token_resources: vec![],
        };
        let result = evaluator.evaluate(&ctx);
        assert!(matches!(
            result,
            Ok(Decision::Deny {
                reason: DenyReason::PolicyDenied
            })
        ));
    }

    #[test]
    fn test_policy_bundle_debug() {
        let bundle = PolicyBundle::new("v1".to_string(), vec![], vec![], 30);
        let debug = format!("{bundle:?}");
        assert!(debug.contains("PolicyBundle"));
    }
}
