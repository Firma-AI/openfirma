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
    #[allow(dead_code)]
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
