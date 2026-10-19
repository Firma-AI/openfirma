//! Atomic publication of compiled enforcement state.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use firma_identifiers::AgentId;
use tokio::time::Instant;

use crate::enforcement::constraint_enforcement::{PolicyEvaluation, PolicyVerdict};
use crate::normalizer::IntentNormalizer;

/// A complete compiled enforcement generation.
///
/// The evaluator owns its compiled entity schema, and the normalizer owns the
/// mapping table and protection posture. Producers must compile both from the
/// same generation before publication. Freshness starts when published, not
/// when compilation completes.
pub struct RuntimeSnapshot {
    policy: Arc<dyn PolicyEvaluation + Send + Sync>,
    normalizer: Arc<IntentNormalizer>,
    ttl_seconds: u32,
    version: Option<String>,
}

impl RuntimeSnapshot {
    /// Assemble already compiled components for one generation.
    #[must_use]
    pub fn new(
        normalizer: IntentNormalizer,
        policy: Arc<dyn PolicyEvaluation + Send + Sync>,
        ttl_seconds: u32,
        version: Option<String>,
    ) -> Self {
        Self {
            policy,
            normalizer: Arc::new(normalizer),
            ttl_seconds,
            version,
        }
    }

    fn into_published(self) -> PublishedSnapshot {
        PublishedSnapshot {
            policy: self.policy,
            normalizer: self.normalizer,
            deadline: deadline(self.ttl_seconds),
            ttl_seconds: self.ttl_seconds,
            version: self.version,
        }
    }
}

/// Immutable reader pin for one complete generation.
pub(crate) struct PublishedSnapshot {
    policy: Arc<dyn PolicyEvaluation + Send + Sync>,
    normalizer: Arc<IntentNormalizer>,
    deadline: Instant,
    ttl_seconds: u32,
    version: Option<String>,
}

impl PublishedSnapshot {
    pub(crate) fn normalizer(&self) -> &IntentNormalizer {
        &self.normalizer
    }

    /// Instant after which this generation is stale.
    pub(crate) const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// TTL this generation was published with.
    pub(crate) const fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }
}

impl PolicyEvaluation for PublishedSnapshot {
    fn evaluate(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<bool, String> {
        self.policy.evaluate(principal, action, resource, context)
    }

    fn evaluate_verdict(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<PolicyVerdict, String> {
        self.policy
            .evaluate_verdict(principal, action, resource, context)
    }

    fn is_available(&self) -> bool {
        self.policy.is_available()
    }

    fn is_fresh(&self) -> bool {
        Instant::now() < self.deadline
    }

    fn version(&self) -> Option<String> {
        self.version.clone()
    }
}

/// Policy evaluator backed by an atomically swappable snapshot.
pub struct SwappablePolicyEvaluation {
    inner: ArcSwap<PublishedSnapshot>,
}

impl SwappablePolicyEvaluation {
    /// Publish an initial complete generation.
    #[must_use]
    pub fn from_snapshot(snapshot: RuntimeSnapshot) -> Self {
        Self {
            inner: ArcSwap::from_pointee(snapshot.into_published()),
        }
    }

    /// Replace all compiled components and freshness metadata in one store.
    /// Existing reader pins retain their original generation and deadline.
    pub fn swap_snapshot(&self, snapshot: RuntimeSnapshot) {
        self.inner.store(Arc::new(snapshot.into_published()));
    }

    pub(crate) fn load(&self) -> Arc<PublishedSnapshot> {
        self.inner.load_full()
    }
}

impl PolicyEvaluation for SwappablePolicyEvaluation {
    /// Evaluate against the currently published generation.
    ///
    /// Each method pins one generation for its own call. Multi-step
    /// evaluations (freshness check, then verdict, then version) must pin
    /// once via [`SwappablePolicyEvaluation::load`] and reuse that pin;
    /// the pipeline does this through its per-call snapshot. Calling these
    /// methods one by one across a concurrent publication can otherwise
    /// observe different generations per step.
    fn evaluate(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<bool, String> {
        self.inner
            .load()
            .evaluate(principal, action, resource, context)
    }

    /// Delegate to the inner evaluator so a `CedarPolicyEvaluator` snapshot's
    /// `@modify` / `@step_up` / `@defer` annotations surface through the swap
    /// boundary. Without this override the trait default would collapse to
    /// the bool `evaluate` view and drop remediation.
    fn evaluate_verdict(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<PolicyVerdict, String> {
        self.inner
            .load()
            .evaluate_verdict(principal, action, resource, context)
    }

    fn is_fresh(&self) -> bool {
        self.inner.load().is_fresh()
    }

    fn is_available(&self) -> bool {
        self.inner.load().is_available()
    }

    fn version(&self) -> Option<String> {
        self.inner.load().version()
    }
}

fn deadline(ttl_seconds: u32) -> Instant {
    Instant::now() + Duration::from_secs(u64::from(ttl_seconds))
}

/// Sentinel evaluator installed as the initial snapshot of
/// [`SwappablePolicyEvaluation`] before the first Authority bundle
/// arrives. Denies every call and reports itself as stale so Stage 2
/// falls through to `PolicyBundleStale` if the readiness gate is ever
/// bypassed.
#[derive(Debug, Default)]
pub(crate) struct DenyAllPolicyEvaluation;

impl PolicyEvaluation for DenyAllPolicyEvaluation {
    fn evaluate(
        &self,
        _principal: &AgentId,
        _action: &str,
        _resource: &str,
        _context: serde_json::Value,
    ) -> Result<bool, String> {
        Ok(false)
    }

    fn is_fresh(&self) -> bool {
        false
    }

    fn version(&self) -> Option<String> {
        None
    }
}
