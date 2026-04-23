//! Policy bundle watcher — persistent `WatchPolicyBundle` gRPC stream.
//!
//! [`PolicyWatcher`] connects to the Authority, receives [`PolicyBundleUpdate`]
//! messages, compiles them into [`CedarPolicyEvaluator`] instances, and
//! atomically swaps the active evaluator in the [`ConstraintEnforcer`] watch
//! channel.
//!
//! # Fail-closed guarantee
//!
//! The watch channel is seeded (via [`new_policy_watch_pair`]) with a
//! `NoBundleInstalled` sentinel whose `is_available()` returns `false` — all
//! Stage 2 evaluations fail closed until the first bundle arrives.  After the
//! installed bundle's `ttl_seconds` elapse without a fresh delivery,
//! `is_fresh()` returns `false` and Stage 2 denies with
//! [`firma_core::decision::DenyReason::PolicyBundleStale`].  No separate TTL
//! timer is needed; the evaluator's own staleness check handles it.
//!
//! # Reconnection
//!
//! On any stream or transport error, [`PolicyWatcher::run`] backs off
//! exponentially (doubling from `initial_backoff` up to `max_backoff`) and
//! reconnects.  The last valid bundle remains active during the outage; once
//! its TTL expires enforcement transitions to fail-closed automatically.

use std::sync::Arc;
use std::time::Duration;

use firma_core::policy::PolicyBundle as CoreBundle;
use firma_proto::firma::v1::WatchPolicyBundleRequest;
use firma_proto::firma::v1::authority_service_client::AuthorityServiceClient;
use tracing::{info, warn};

use crate::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use crate::enforcement::constraint_enforcement::{PolicyEvaluation, policy_channel};
pub use crate::enforcement::constraint_enforcement::{PolicyReceiver, PolicySender};

/// Configuration for [`PolicyWatcher`].
#[derive(Debug, Clone)]
pub struct PolicyWatcherConfig {
    /// gRPC endpoint of the Authority (e.g. `"http://127.0.0.1:50051"`).
    pub authority_endpoint: String,
    /// Initial reconnect delay; doubles on each consecutive failure.
    pub initial_backoff: Duration,
    /// Upper bound on reconnect delay.
    pub max_backoff: Duration,
}

impl Default for PolicyWatcherConfig {
    fn default() -> Self {
        Self {
            authority_endpoint: "http://127.0.0.1:50051".to_string(),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
        }
    }
}

/// Errors produced by the policy bundle stream.
#[derive(Debug, thiserror::Error)]
pub enum PolicyWatcherError {
    #[error("failed to connect to authority at {endpoint}: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: tonic::transport::Error,
    },
    #[error("WatchPolicyBundle RPC failed: {0}")]
    Rpc(#[source] tonic::Status),
    #[error("stream message error: {0}")]
    Stream(#[source] tonic::Status),
}

/// Background task that maintains a persistent `WatchPolicyBundle` stream.
///
/// On each received [`PolicyBundleUpdate`], compiles the bundle and atomically
/// swaps the active evaluator.  On parse failure, logs and retains the
/// previous evaluator.  On disconnect, exponentially backs off and reconnects.
///
/// Construct with [`PolicyWatcher::new`] (or [`new_policy_watch_pair`]) and
/// spawn [`PolicyWatcher::run`] in a [`tokio::spawn`].
pub struct PolicyWatcher {
    config: PolicyWatcherConfig,
    tx: PolicySender,
}

impl PolicyWatcher {
    /// Create a watcher backed by the given watch sender.
    ///
    /// Prefer [`new_policy_watch_pair`] which seeds the channel with the
    /// fail-closed sentinel in one step.
    #[must_use]
    pub fn new(config: PolicyWatcherConfig, tx: PolicySender) -> Self {
        Self { config, tx }
    }

    /// Run the watcher loop forever.
    ///
    /// Connects to the Authority, streams bundle updates, and swaps the active
    /// evaluator on each delivery.  On error, backs off and reconnects.
    /// Spawn via [`tokio::spawn`]; the task runs until the process exits.
    pub async fn run(self) {
        let mut backoff = self.config.initial_backoff;
        let mut current_version = String::new();

        loop {
            match self.connect_and_stream(&mut current_version).await {
                Ok(()) => {
                    info!("policy bundle stream ended cleanly; reconnecting");
                    backoff = self.config.initial_backoff;
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        delay_secs = backoff.as_secs(),
                        "policy bundle stream error; reconnecting after backoff",
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(self.config.max_backoff);
                }
            }
        }
    }

    /// Connect to the Authority, read the stream, and install each bundle.
    ///
    /// Returns `Ok(())` when the stream ends cleanly (server closed it).
    /// Returns `Err(_)` on transport or RPC failure.
    async fn connect_and_stream(
        &self,
        current_version: &mut String,
    ) -> Result<(), PolicyWatcherError> {
        let endpoint = self.config.authority_endpoint.clone();

        let mut client = AuthorityServiceClient::connect(endpoint.clone())
            .await
            .map_err(|source| PolicyWatcherError::Connect {
                endpoint: endpoint.clone(),
                source,
            })?;

        let request = WatchPolicyBundleRequest {
            current_version: current_version.clone(),
        };
        let mut stream = client
            .watch_policy_bundle(request)
            .await
            .map_err(PolicyWatcherError::Rpc)?
            .into_inner();

        info!(%endpoint, "policy bundle stream connected");

        while let Some(update) = stream.message().await.map_err(PolicyWatcherError::Stream)? {
            let Some(proto_bundle) = update.bundle else {
                warn!("received PolicyBundleUpdate with no bundle field; skipping");
                continue;
            };

            let core_bundle = CoreBundle::new(
                proto_bundle.version,
                proto_bundle.policies,
                proto_bundle.entity_schema,
                proto_bundle.ttl_seconds,
            );

            Self::install_bundle(&self.tx, &core_bundle, current_version);
        }

        Ok(())
    }

    /// Compile `bundle` and atomically swap the active evaluator.
    ///
    /// Returns `true` if installed successfully.  Returns `false` and retains
    /// the previous evaluator if `CedarPolicyEvaluator::from_bundle` fails.
    fn install_bundle(
        tx: &PolicySender,
        bundle: &CoreBundle,
        current_version: &mut String,
    ) -> bool {
        match CedarPolicyEvaluator::from_bundle(bundle) {
            Ok(evaluator) => {
                current_version.clone_from(&bundle.version);
                tx.send_replace(Arc::new(evaluator) as Arc<dyn PolicyEvaluation>);
                info!(version = %bundle.version, "policy bundle installed");
                true
            }
            Err(err) => {
                warn!(%err, "policy bundle parse failed; retaining previous bundle");
                false
            }
        }
    }
}

/// Create the watch channel seeded with the fail-closed sentinel and a
/// ready-to-run [`PolicyWatcher`].
///
/// Returns `(rx, watcher)`:
/// - Pass `rx` to [`crate::enforcement::constraint_enforcement::ConstraintEnforcer::new`].
/// - Spawn `watcher.run()` in a background task before processing any requests.
#[must_use]
pub fn new_policy_watch_pair(config: PolicyWatcherConfig) -> (PolicyReceiver, PolicyWatcher) {
    let (tx, rx) = policy_channel();
    (rx, PolicyWatcher::new(config, tx))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use firma_core::policy::PolicyBundle;

    // Minimal schema matching cedar_evaluator.rs test schema.
    const TEST_SCHEMA: &str = r#"
namespace Firma {
    type EnforcementContext = {
        session_id: String,
        timestamp_ms: Long,
        params: String,
        risk_score: Long
    };
    entity Agent;
    entity Resource;
    action "llm.inference" appliesTo {
        principal: [Agent],
        resource:  [Resource],
        context:   EnforcementContext
    };
}"#;

    fn permit_all_bundle(version: &str) -> PolicyBundle {
        PolicyBundle::new(
            version.to_string(),
            b"permit(principal, action, resource);".to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    fn invalid_bundle() -> PolicyBundle {
        // Malformed Cedar — parse will fail
        PolicyBundle::new(
            "bad-v1".to_string(),
            b"this is not valid cedar {{{".to_vec(),
            vec![],
            30,
        )
    }

    // ── Channel seeding ──────────────────────────────────────────────────────

    #[test]
    fn policy_channel_seeded_fail_closed() {
        let (tx, rx) = policy_channel();
        let policy = rx.borrow();
        assert!(
            !policy.is_available(),
            "channel must be fail-closed before first bundle"
        );
        assert!(!policy.is_fresh(), "sentinel must not report fresh");
        assert!(policy.version().is_none(), "sentinel version must be None");
        drop(tx);
    }

    #[test]
    fn new_policy_watch_pair_channel_seeded_fail_closed() {
        let (rx, _watcher) = new_policy_watch_pair(PolicyWatcherConfig::default());
        assert!(
            !rx.borrow().is_available(),
            "pair channel must start fail-closed"
        );
    }

    // ── install_bundle ───────────────────────────────────────────────────────

    #[test]
    fn install_bundle_swaps_evaluator() {
        let (tx, rx) = policy_channel();
        let mut version = String::new();

        let installed =
            PolicyWatcher::install_bundle(&tx, &permit_all_bundle("test-v1"), &mut version);

        assert!(installed);
        assert_eq!(version, "test-v1");
        let policy = rx.borrow();
        assert!(
            policy.is_available(),
            "installed evaluator must be available"
        );
        assert!(policy.is_fresh(), "fresh bundle must be fresh");
        assert_eq!(policy.version(), Some("test-v1".to_string()));
    }

    #[test]
    fn install_bundle_parse_failure_retains_previous() {
        let (tx, rx) = policy_channel();
        let mut version = String::new();

        // Install valid bundle first
        PolicyWatcher::install_bundle(&tx, &permit_all_bundle("test-v1"), &mut version);
        assert_eq!(version, "test-v1");

        // Attempt to install invalid bundle
        let installed = PolicyWatcher::install_bundle(&tx, &invalid_bundle(), &mut version);

        assert!(!installed, "invalid bundle must not be installed");
        assert_eq!(
            version, "test-v1",
            "version must not advance on parse failure"
        );
        assert_eq!(
            rx.borrow().version(),
            Some("test-v1".to_string()),
            "previous evaluator must be retained"
        );
    }

    #[test]
    fn install_bundle_updates_version_on_each_delivery() {
        let (tx, _rx) = policy_channel();
        let mut version = String::new();

        PolicyWatcher::install_bundle(&tx, &permit_all_bundle("v1"), &mut version);
        assert_eq!(version, "v1");

        PolicyWatcher::install_bundle(&tx, &permit_all_bundle("v2"), &mut version);
        assert_eq!(version, "v2");

        PolicyWatcher::install_bundle(&tx, &permit_all_bundle("v3"), &mut version);
        assert_eq!(version, "v3");
    }

    #[test]
    fn install_bundle_zero_ttl_immediately_stale() {
        let (tx, rx) = policy_channel();
        let mut version = String::new();

        let stale = PolicyBundle::new(
            "stale-v1".to_string(),
            b"permit(principal, action, resource);".to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            0, // zero TTL — immediately stale
        );
        PolicyWatcher::install_bundle(&tx, &stale, &mut version);

        assert!(
            rx.borrow().is_available(),
            "zero-TTL bundle is still available"
        );
        assert!(
            !rx.borrow().is_fresh(),
            "zero-TTL bundle must be immediately stale"
        );
    }
}
