use crate::decision::Decision;
use crate::envelope::ExecutionContext;

/// Errors from policy evaluation operations.
#[derive(Debug, thiserror::Error)]
pub enum EvaluationError {
    /// Policy bundle could not be loaded.
    #[error("policy load failure: {reason}")]
    PolicyLoadFailure { reason: String },
    /// Execution context could not be built from the envelope.
    #[error("context build failure: {reason}")]
    ContextBuildFailure { reason: String },
    /// Internal evaluation error.
    #[error("evaluation internal error: {reason}")]
    InternalError { reason: String },
}

/// Opaque policy bundle type.
///
/// Internals will be defined when Cedar integration lands (intent 005).
/// Private field prevents external construction — bundles must come from
/// `PolicyBundleStore::load_bundle`.
#[derive(Debug, Clone)]
pub struct PolicyBundle {
    _private: (),
}

impl PolicyBundle {
    /// Create a new `PolicyBundle`. Only available within firma-core.
    #[cfg(test)]
    fn new() -> Self {
        Self { _private: () }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::DenyReason;

    struct MockEvaluator;
    impl PolicyEvaluator for MockEvaluator {
        fn evaluate(&self, _context: &ExecutionContext) -> Result<Decision, EvaluationError> {
            Ok(Decision::Allow)
        }
    }

    struct MockBundleStore;
    impl PolicyBundleStore for MockBundleStore {
        fn load_bundle(&self) -> Result<PolicyBundle, EvaluationError> {
            Ok(PolicyBundle::new())
        }
        fn get_version(&self) -> Option<String> {
            Some("v1".to_string())
        }
        fn is_fresh(&self) -> bool {
            true
        }
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
        let bundle = PolicyBundle::new();
        let debug = format!("{bundle:?}");
        assert!(debug.contains("PolicyBundle"));
    }
}
