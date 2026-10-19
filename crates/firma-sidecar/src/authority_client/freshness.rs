//! Readiness tracking for enforced snapshot expiry.
//!
//! Requests already fail closed once the enforced snapshot passes its TTL; this
//! watcher makes that state visible to readiness probes and logs, including
//! while the policy stream is disconnected or backing off.

use std::sync::Arc;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::enforcement::constraint_enforcement::PolicyEvaluation as _;

use super::readiness::ReadinessFlag;
use super::swappable_policy::SwappablePolicyEvaluation;

/// Clears `policy_bundle_fresh` when the enforced generation expires.
pub struct FreshnessWatcher {
    pub swappable: Arc<SwappablePolicyEvaluation>,
    pub readiness: Arc<ReadinessFlag>,
    /// Notified after every publication so the watcher re-arms its deadline.
    pub swapped: Arc<Notify>,
    pub cancel: CancellationToken,
}

impl FreshnessWatcher {
    /// Run until cancelled.
    pub async fn run(self) {
        loop {
            let snapshot = self.swappable.load();
            // The initial deny-all generation has no version and was never
            // fresh; only a published Authority generation can expire.
            if snapshot.version().is_some() && snapshot.is_fresh() {
                tokio::select! {
                    () = self.cancel.cancelled() => return,
                    () = self.swapped.notified() => continue,
                    () = tokio::time::sleep_until(snapshot.deadline()) => {}
                }
                self.refresh();
            } else {
                tokio::select! {
                    () = self.cancel.cancelled() => return,
                    () = self.swapped.notified() => {}
                }
            }
        }
    }

    fn refresh(&self) {
        let mut current = None;
        let changed = self.readiness.refresh_policy_bundle_freshness(|| {
            let snapshot = self.swappable.load();
            let fresh = snapshot.is_fresh();
            current = Some(snapshot);
            fresh
        });
        if changed == Some(false)
            && let Some(snapshot) = current
        {
            tracing::warn!(
                stream = "policy_bundle",
                version = snapshot.version().as_deref(),
                ttl_seconds = snapshot.ttl_seconds(),
                "enforcement snapshot expired"
            );
        }
    }
}
