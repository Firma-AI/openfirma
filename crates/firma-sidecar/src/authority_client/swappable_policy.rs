//! Hot-swappable policy evaluator.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::{ArcSwap, ArcSwapOption};

use crate::enforcement::constraint_enforcement::PolicyEvaluation;

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
        principal: &str,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> Result<bool, String> {
        self.inner
            .load()
            .evaluate(principal, action, resource, context)
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
