//! Hot-swappable policy evaluator.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::{ArcSwap, ArcSwapOption};
use firma_core::AgentId;

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

    fn evaluate_secret_redact(
        &self,
        principal: &AgentId,
        host: &str,
        path: &str,
        method: &str,
        context: serde_json::Value,
    ) -> Result<bool, String> {
        self.inner
            .load()
            .evaluate_secret_redact(principal, host, path, method, context)
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
    use super::*;

    struct PermitPolicy;

    impl PolicyEvaluation for PermitPolicy {
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
    }

    fn agent() -> AgentId {
        "agt_01j0000000e008000000000001"
            .parse()
            .expect("valid agent id")
    }

    #[test]
    fn initial_deny_all_snapshot_denies_and_reports_stale() {
        let swap = SwappablePolicyEvaluation::new(Box::new(DenyAllPolicyEvaluation));
        let decision = swap
            .evaluate(
                &agent(),
                "communication.external.send",
                "res",
                serde_json::json!({}),
            )
            .expect("decision");
        assert!(!decision);
        assert!(!swap.is_fresh());
    }

    #[test]
    fn swapped_snapshot_is_forwarded() {
        let swap = SwappablePolicyEvaluation::new(Box::new(DenyAllPolicyEvaluation));
        swap.swap(Box::new(PermitPolicy), 30, Some("v1".to_string()));
        let decision = swap
            .evaluate(
                &agent(),
                "communication.external.send",
                "res",
                serde_json::json!({}),
            )
            .expect("decision");
        assert!(decision);
        assert!(swap.is_fresh());
        assert_eq!(swap.version(), Some("v1".to_string()));
    }
}
