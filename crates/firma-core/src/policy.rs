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
    pub ttl_seconds: u32,
}

impl PolicyBundle {
    /// Create a new `PolicyBundle`.
    #[must_use]
    pub const fn new(
        version: String,
        policies: Vec<u8>,
        entity_schema: Vec<u8>,
        ttl_seconds: u32,
    ) -> Self {
        Self {
            version,
            policies,
            entity_schema,
            ttl_seconds,
        }
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
