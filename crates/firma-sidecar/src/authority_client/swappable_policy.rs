//! Hot-swappable policy evaluator.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::{ArcSwap, ArcSwapOption};
use firma_core::{AgentId, SecretDecision};

use crate::enforcement::constraint_enforcement::{PolicyEvaluation, PolicyVerdict};

/// Policy evaluator backed by an atomically swappable snapshot.
pub struct SwappablePolicyEvaluation {
    inner: ArcSwap<Box<dyn PolicyEvaluation + Send + Sync>>,
    deadline_unix_ms: AtomicI64,
    ttl_seconds: AtomicU32,
    version: ArcSwapOption<String>,
}

impl SwappablePolicyEvaluation {
    /// Create a new swappable evaluator with the supplied initial snapshot.
    #[must_use]
    pub fn new(initial: Box<dyn PolicyEvaluation + Send + Sync>) -> Self {
        Self {
            inner: ArcSwap::from_pointee(initial),
            deadline_unix_ms: AtomicI64::new(0),
            ttl_seconds: AtomicU32::new(0),
            version: ArcSwapOption::empty(),
        }
    }

    /// Swap in a new policy evaluator and refresh its TTL deadline.
    pub fn swap(
        &self,
        new_eval: Box<dyn PolicyEvaluation + Send + Sync>,
        ttl_seconds: u32,
        version: Option<String>,
    ) {
        self.inner.store(Arc::new(new_eval));
        self.ttl_seconds.store(ttl_seconds, Ordering::Relaxed);
        self.deadline_unix_ms.store(
            now_ms().saturating_add(i64::from(ttl_seconds) * 1000),
            Ordering::Relaxed,
        );
        self.version.store(version.map(Arc::new));
    }
}

impl PolicyEvaluation for SwappablePolicyEvaluation {
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

    /// Delegate secret-mediation decisions to the inner snapshot so the live
    /// Cedar evaluator's `secret.mediate` policies apply through the swap
    /// boundary.
    fn evaluate_secret_mediation(
        &self,
        principal: &AgentId,
        argv: &str,
        context: serde_json::Value,
    ) -> Result<SecretDecision, String> {
        self.inner
            .load()
            .evaluate_secret_mediation(principal, argv, context)
    }

    fn is_fresh(&self) -> bool {
        now_ms() < self.deadline_unix_ms.load(Ordering::Relaxed)
    }

    fn version(&self) -> Option<String> {
        self.version.load().as_ref().map(|v| v.as_ref().clone())
    }
}

fn now_ms() -> i64 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "current UNIX milliseconds fit i64"
    )]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as i64)
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

#[cfg(test)]
mod tests {
    use firma_core::SecretMediation;

    use super::*;

    /// Snapshot that returns a fixed [`SecretDecision::Mediate`], to prove the
    /// swap boundary forwards secret-mediation decisions.
    struct MediatePolicy(SecretMediation);

    impl PolicyEvaluation for MediatePolicy {
        fn evaluate(
            &self,
            _principal: &AgentId,
            _action: &str,
            _resource: &str,
            _context: serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }

        fn is_fresh(&self) -> bool {
            true
        }

        fn version(&self) -> Option<String> {
            None
        }

        fn evaluate_secret_mediation(
            &self,
            _principal: &AgentId,
            _argv: &str,
            _context: serde_json::Value,
        ) -> Result<SecretDecision, String> {
            Ok(SecretDecision::Mediate(self.0.clone()))
        }
    }

    fn agent() -> AgentId {
        "agent_test".parse().expect("agent id")
    }

    #[test]
    fn initial_deny_all_snapshot_passes_secret_mediation_through() {
        let swap = SwappablePolicyEvaluation::new(Box::new(DenyAllPolicyEvaluation));
        let decision = swap
            .evaluate_secret_mediation(&agent(), "bws secret get x", serde_json::json!({}))
            .expect("decision");
        assert_eq!(decision, SecretDecision::Passthrough);
    }

    #[test]
    fn swapped_snapshot_secret_mediation_is_forwarded() {
        let directive = SecretMediation::from_annotations(|key| match key {
            "mode" => Some("redact"),
            "transform" => Some("raw"),
            _ => None,
        })
        .expect("valid directive");
        let swap = SwappablePolicyEvaluation::new(Box::new(DenyAllPolicyEvaluation));
        swap.swap(
            Box::new(MediatePolicy(directive.clone())),
            30,
            Some("v1".to_string()),
        );
        let decision = swap
            .evaluate_secret_mediation(&agent(), "anything", serde_json::json!({}))
            .expect("decision");
        assert_eq!(decision, SecretDecision::Mediate(directive));
    }
}
