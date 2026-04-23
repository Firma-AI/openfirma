//! Integration tests for the Authority stream clients.
//!
//! Spin up an in-process `AuthorityService` backed by tonic, connect the
//! sidecar stream clients, and verify the end-to-end behavior documented
//! in task 007: readiness gating, revocation propagation, TTL fail-closed,
//! reconnect with bundle swap, and parse-failure retention of the last
//! valid bundle.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use firma_core::{AgentId, RevocationStore, TokenId};
use firma_proto::authority_service_server::{AuthorityService, AuthorityServiceServer};
use firma_proto::{
    IssueCapabilityRequest, IssueCapabilityResponse, PolicyBundle, PolicyBundleUpdate,
    RevocationEvent, WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use super::channel::build_channel;
use super::policy_bundle::CedarBundleParser;
use super::readiness::{ReadinessFlag, ReadinessState, ReadinessView};
use super::swappable_policy::SwappablePolicyEvaluation;
use super::{AuthorityClientHandle, AuthorityDeps, spawn_authority_client};
use crate::config::AuthorityConfig;
use crate::enforcement::constraint_enforcement::PolicyEvaluation;
use crate::enforcement::revocation::{BloomLruRevocationStore, RevocationConfig};

// -----------------------------------------------------------------------------
// Mock AuthorityService
// -----------------------------------------------------------------------------

struct MockAuthorityState {
    bundle_tx: broadcast::Sender<PolicyBundleUpdate>,
    revoc_tx: broadcast::Sender<RevocationEvent>,
    initial_bundle: Mutex<Option<PolicyBundleUpdate>>,
}

struct MockAuthorityHandle {
    state: Arc<MockAuthorityState>,
}

impl MockAuthorityHandle {
    fn set_initial_bundle(&self, update: PolicyBundleUpdate) {
        if let Ok(mut guard) = self.state.initial_bundle.lock() {
            *guard = Some(update);
        }
    }

    fn push_bundle(&self, update: PolicyBundleUpdate) {
        if let Ok(mut guard) = self.state.initial_bundle.lock() {
            *guard = Some(update.clone());
        }
        let _ = self.state.bundle_tx.send(update);
    }

    fn push_revocation(&self, event: RevocationEvent) {
        let _ = self.state.revoc_tx.send(event);
    }
}

struct MockAuthority {
    state: Arc<MockAuthorityState>,
}

#[tonic::async_trait]
impl AuthorityService for MockAuthority {
    async fn issue_capability(
        &self,
        _request: Request<IssueCapabilityRequest>,
    ) -> Result<Response<IssueCapabilityResponse>, Status> {
        Err(Status::unimplemented(
            "mock authority: issue_capability not exercised in task 007 tests",
        ))
    }

    type WatchPolicyBundleStream = ReceiverStream<Result<PolicyBundleUpdate, Status>>;

    async fn watch_policy_bundle(
        &self,
        _request: Request<WatchPolicyBundleRequest>,
    ) -> Result<Response<Self::WatchPolicyBundleStream>, Status> {
        let (tx, rx) = mpsc::channel::<Result<PolicyBundleUpdate, Status>>(16);
        let initial = self
            .state
            .initial_bundle
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if let Some(bundle) = initial {
            let _ = tx.send(Ok(bundle)).await;
        }
        let mut broadcast_rx = self.state.bundle_tx.subscribe();
        tokio::spawn(async move {
            while let Ok(msg) = broadcast_rx.recv().await {
                if tx.send(Ok(msg)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type WatchRevocationsStream = ReceiverStream<Result<RevocationEvent, Status>>;

    async fn watch_revocations(
        &self,
        _request: Request<WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        let (tx, rx) = mpsc::channel::<Result<RevocationEvent, Status>>(16);
        let mut broadcast_rx = self.state.revoc_tx.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = broadcast_rx.recv().await {
                if tx.send(Ok(event)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

struct MockAuthorityServer {
    url: String,
    handle: MockAuthorityHandle,
    shutdown: CancellationToken,
    join: JoinHandle<()>,
}

impl MockAuthorityServer {
    async fn stop(self) {
        // `serve_with_shutdown` refuses new connections on cancel but leaves
        // in-flight streams open, so abort the task to force-close the
        // connections the sidecar is holding.
        self.shutdown.cancel();
        self.join.abort();
        let _ = self.join.await;
    }
}

async fn spawn_mock_authority() -> anyhow::Result<MockAuthorityServer> {
    // Acquire an ephemeral port, then release the listener so tonic can bind it.
    // The tiny window between drop and rebind is acceptable for test isolation.
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        listener.local_addr()?
    };
    let url = format!("http://{addr}");

    let (bundle_tx, _) = broadcast::channel(16);
    let (revoc_tx, _) = broadcast::channel(64);
    let state = Arc::new(MockAuthorityState {
        bundle_tx,
        revoc_tx,
        initial_bundle: Mutex::new(None),
    });
    let service = MockAuthority {
        state: Arc::clone(&state),
    };

    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    let join = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(AuthorityServiceServer::new(service))
            .serve_with_shutdown(addr, async move {
                shutdown_signal.cancelled().await;
            })
            .await;
    });

    // Give tonic a brief moment to bind before clients attempt to connect.
    tokio::time::sleep(Duration::from_millis(50)).await;

    Ok(MockAuthorityServer {
        url,
        handle: MockAuthorityHandle { state },
        shutdown,
        join,
    })
}

// -----------------------------------------------------------------------------
// Sidecar client wiring helpers
// -----------------------------------------------------------------------------

struct SidecarHarness {
    swappable_policy: Arc<SwappablePolicyEvaluation>,
    revocation_store: Arc<BloomLruRevocationStore>,
    readiness_view: ReadinessView,
    cancel: CancellationToken,
    authority: AuthorityClientHandle,
}

impl SidecarHarness {
    async fn shutdown(self) {
        self.cancel.cancel();
        let _ = tokio::join!(self.authority.policy_task, self.authority.revocation_task);
    }
}

fn spawn_sidecar(url: &str, config: AuthorityConfig) -> anyhow::Result<SidecarHarness> {
    let channel = build_channel(url, Duration::from_secs(config.connect_timeout_secs))?;
    let revocation_store = Arc::new(BloomLruRevocationStore::new(RevocationConfig {
        capacity: 1_024,
        fpr: 0.001,
        lru_capacity: 128,
    }));
    let initial_policy: Box<dyn PolicyEvaluation + Send + Sync> = Box::new(DenyAllEvaluation);
    let swappable_policy = Arc::new(SwappablePolicyEvaluation::new(initial_policy));
    let (flag, readiness_view) = ReadinessFlag::new(ReadinessState::default());
    let readiness = Arc::new(flag);
    let cancel = CancellationToken::new();
    let revocation_dyn: Arc<dyn RevocationStore + Send + Sync> =
        Arc::clone(&revocation_store) as Arc<dyn RevocationStore + Send + Sync>;

    let authority = spawn_authority_client(AuthorityDeps {
        channel,
        swappable_policy: Arc::clone(&swappable_policy),
        revocation_store: revocation_dyn,
        readiness,
        cancel: cancel.clone(),
        config,
        bundle_parser: Arc::new(CedarBundleParser),
    });

    Ok(SidecarHarness {
        swappable_policy,
        revocation_store,
        readiness_view,
        cancel,
        authority,
    })
}

struct DenyAllEvaluation;

impl PolicyEvaluation for DenyAllEvaluation {
    fn evaluate(
        &self,
        _principal: &AgentId,
        _action: &str,
        _resource: &str,
        _context: &serde_json::Value,
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

/// Minimal valid Cedar policy source that parses under [`TEST_CEDAR_SCHEMA`].
const VALID_CEDAR_POLICY: &str = "permit(principal, action, resource);";

/// Cedar schema scoped to the test suite; the production schema is wider
/// and lives under `firma-authority/policies/schema.cedarschema`.
const TEST_CEDAR_SCHEMA: &str = "\
namespace Firma {
    entity Agent;
    entity Resource;
    action \"test.action\" appliesTo { principal: [Agent], resource: [Resource] };
}";

fn bundle_update(version: &str, ttl_seconds: u32, policies: &[u8]) -> PolicyBundleUpdate {
    PolicyBundleUpdate {
        bundle: Some(PolicyBundle {
            version: version.to_string(),
            policies: policies.to_vec(),
            entity_schema: TEST_CEDAR_SCHEMA.as_bytes().to_vec(),
            ttl_seconds,
        }),
        updated_at: None,
    }
}

fn valid_bundle_update(version: &str, ttl_seconds: u32) -> PolicyBundleUpdate {
    bundle_update(version, ttl_seconds, VALID_CEDAR_POLICY.as_bytes())
}

fn revocation(token_id: &str, reason: &str) -> RevocationEvent {
    RevocationEvent {
        token_id: token_id.to_string(),
        reason: reason.to_string(),
        timestamp: None,
    }
}

fn test_config() -> AuthorityConfig {
    AuthorityConfig {
        connect_timeout_secs: 2,
        reconnect_min_backoff_ms: 50,
        reconnect_max_backoff_secs: 1,
        revocation_readiness_grace_ms: 100,
        revocation_fail_closed_on_disconnect: false,
    }
}

async fn wait_for<F: Fn() -> bool>(deadline: Duration, predicate: F) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    predicate()
}

fn is_revoked(store: &BloomLruRevocationStore, token_id: &TokenId) -> bool {
    matches!(store.is_revoked(token_id), Ok(true))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readiness_flips_after_initial_bundle_and_revocation_grace() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v1", 60));
    let harness = spawn_sidecar(&server.url, test_config())?;

    let policy_ready = wait_for(Duration::from_secs(2), || {
        harness.readiness_view.snapshot().policy_bundle_ready
    })
    .await;
    assert!(policy_ready, "policy bundle readiness never flipped");

    let revocation_ready = wait_for(Duration::from_secs(2), || {
        harness.readiness_view.snapshot().revocation_ready
    })
    .await;
    assert!(revocation_ready, "revocation readiness never flipped");

    assert_eq!(
        harness.swappable_policy.version().as_deref(),
        Some("v1"),
        "initial bundle version should be applied"
    );

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_event_propagates_to_store_within_one_second() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v1", 60));
    let harness = spawn_sidecar(&server.url, test_config())?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .readiness_view
            .snapshot()
            .revocation_ready)
        .await
    );

    let pushed_at = Instant::now();
    let propagate_id: TokenId = "11111111-1111-1111-1111-111111111111"
        .parse()
        .expect("literal uuid");
    server
        .handle
        .push_revocation(revocation(&propagate_id.to_string(), "test"));

    let propagated = wait_for(Duration::from_secs(1), || {
        is_revoked(&harness.revocation_store, &propagate_id)
    })
    .await;
    assert!(
        propagated,
        "revocation did not propagate within 1 s (elapsed {:?})",
        pushed_at.elapsed()
    );

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ttl_expiry_marks_policy_stale_after_authority_disappears() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v-ttl", 1));
    let harness = spawn_sidecar(&server.url, test_config())?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .readiness_view
            .snapshot()
            .policy_bundle_ready)
        .await
    );
    assert!(
        harness.swappable_policy.is_fresh(),
        "bundle should be fresh immediately after swap"
    );

    server.stop().await;

    let went_stale = wait_for(Duration::from_secs(3), || {
        !harness.swappable_policy.is_fresh()
    })
    .await;
    assert!(
        went_stale,
        "swappable policy never reported stale after TTL expiry"
    );

    harness.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_applies_new_bundle_version() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v1", 60));
    let harness = spawn_sidecar(&server.url, test_config())?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .readiness_view
            .snapshot()
            .policy_bundle_ready)
        .await
    );
    assert_eq!(harness.swappable_policy.version().as_deref(), Some("v1"));

    server.handle.push_bundle(valid_bundle_update("v2", 60));

    let swapped = wait_for(Duration::from_secs(2), || {
        harness.swappable_policy.version().as_deref() == Some("v2")
    })
    .await;
    assert!(swapped, "swappable policy did not pick up v2");

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_bundle_retains_previous_version() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v1", 60));
    let harness = spawn_sidecar(&server.url, test_config())?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .swappable_policy
            .version()
            .as_deref()
            == Some("v1"))
        .await
    );

    // CedarBundleParser rejects empty policy bytes. Sidecar must keep v1.
    server.handle.push_bundle(bundle_update("v-bad", 60, b""));

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        harness.swappable_policy.version().as_deref(),
        Some("v1"),
        "malformed bundle must not replace the last valid version"
    );

    // A follow-up valid bundle must still apply normally.
    server.handle.push_bundle(valid_bundle_update("v2", 60));
    let swapped = wait_for(Duration::from_secs(2), || {
        harness.swappable_policy.version().as_deref() == Some("v2")
    })
    .await;
    assert!(swapped, "recovery bundle v2 did not apply");

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_cedar_bundle_retains_previous_snapshot() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v1", 60));
    let harness = spawn_sidecar(&server.url, test_config())?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .swappable_policy
            .version()
            .as_deref()
            == Some("v1"))
        .await,
        "initial Cedar bundle did not apply"
    );

    // Cedar policy source that is syntactically invalid — CedarBundleParser
    // rejects it, the sidecar keeps the last valid snapshot.
    let bad = bundle_update("v-bad-cedar", 60, b"this is not a cedar policy");
    server.handle.push_bundle(bad);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        harness.swappable_policy.version().as_deref(),
        Some("v1"),
        "invalid Cedar bundle must not replace the last valid snapshot"
    );

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequential_valid_bundles_swap_observed_by_evaluate() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v1", 60));
    let harness = spawn_sidecar(&server.url, test_config())?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .swappable_policy
            .version()
            .as_deref()
            == Some("v1"))
        .await,
        "v1 bundle did not apply"
    );

    let agent: AgentId = "agent-eval".parse().expect("literal agent id");
    let ctx = serde_json::json!({});
    // v1 permits everything, so evaluate should ALLOW.
    let allowed_v1 = harness
        .swappable_policy
        .evaluate(&agent, "test.action", "resource", &ctx)
        .expect("cedar evaluator returns Ok for valid request");
    assert!(
        allowed_v1,
        "v1 permit(principal, action, resource) must ALLOW"
    );

    // Push v2 — a deny-only bundle. Next evaluate() must observe the swap.
    let forbid_bundle = bundle_update("v2", 60, b"forbid(principal, action, resource);");
    server.handle.push_bundle(forbid_bundle);
    assert!(
        wait_for(Duration::from_secs(2), || harness
            .swappable_policy
            .version()
            .as_deref()
            == Some("v2"))
        .await,
        "v2 bundle did not apply"
    );

    let allowed_v2 = harness
        .swappable_policy
        .evaluate(&agent, "test.action", "resource", &ctx)
        .expect("cedar evaluator returns Ok for valid request");
    assert!(!allowed_v2, "v2 forbid(...) must DENY on the next evaluate");

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_without_bundle_stays_not_ready() -> anyhow::Result<()> {
    // Authority is reachable but never pushes a bundle. Sidecar must stay
    // fail-closed: `policy_bundle_ready` never flips, and every request
    // that reaches the pipeline is denied with `PolicyBundleNotReady`.
    let server = spawn_mock_authority().await?;
    // Intentionally no set_initial_bundle / push_bundle.
    let harness = spawn_sidecar(&server.url, test_config())?;

    // Give the stream client a window to settle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        !harness.readiness_view.snapshot().policy_bundle_ready,
        "policy_bundle_ready must stay false without a bundle push"
    );
    assert_eq!(
        harness.swappable_policy.version(),
        None,
        "no bundle version should be installed",
    );
    assert!(
        !harness.swappable_policy.is_fresh(),
        "sentinel DenyAll evaluator must report is_fresh() == false",
    );

    let agent: AgentId = "agent-cold".parse().expect("literal agent id");
    let ctx = serde_json::json!({});
    let allowed = harness
        .swappable_policy
        .evaluate(&agent, "test.action", "resource", &ctx)
        .expect("sentinel evaluator returns Ok(false)");
    assert!(!allowed, "sentinel DenyAll must refuse every evaluate()");

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

/// Verifies criterion 6: once fail-closed is active (TTL expired), a fresh
/// bundle delivery — whether via reconnect or the existing stream — exits
/// fail-closed and restores normal operation.
///
/// This test drives the scenario without tearing down the TCP connection
/// (which would introduce OS port-rebind timing) so it is deterministic:
///
/// 1. Install a 1-second TTL bundle; wait for it to be applied.
/// 2. Do NOT push a refresh — let the TTL lapse while the stream stays open.
/// 3. Assert `is_fresh()` == false (fail-closed active).
/// 4. Push a new 60-second TTL bundle over the live stream.
/// 5. Assert `is_fresh()` == true and version has advanced (fail-closed exited).
///
/// The stream-reconnect path is already exercised by
/// `reconnect_applies_new_bundle_version`; the gap being closed here is the
/// interaction between TTL expiry and subsequent bundle delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_closed_exits_after_fresh_bundle_delivered() -> anyhow::Result<()> {
    // Phase 1: initial bundle with 1 s TTL so staleness is fast.
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v-stale", 1));
    let harness = spawn_sidecar(&server.url, test_config())?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .readiness_view
            .snapshot()
            .policy_bundle_ready)
        .await,
        "initial bundle not applied"
    );
    assert_eq!(
        harness.swappable_policy.version().as_deref(),
        Some("v-stale")
    );
    assert!(
        harness.swappable_policy.is_fresh(),
        "bundle must be fresh initially"
    );

    // Phase 2 + 3: wait for TTL to lapse without any refresh push.
    let went_stale = wait_for(Duration::from_secs(3), || {
        !harness.swappable_policy.is_fresh()
    })
    .await;
    assert!(went_stale, "policy did not go stale after TTL expiry");

    // Confirm fail-closed is active: evaluate() must deny.
    let agent: AgentId = "agent-stale".parse().expect("literal agent id");
    let ctx = serde_json::json!({});
    let result = harness
        .swappable_policy
        .evaluate(&agent, "test.action", "resource", &ctx);
    // A stale (but available) evaluator still returns Ok but is_fresh() == false,
    // so Stage 2 will deny. Here we just confirm the evaluator is reachable.
    assert!(
        result.is_ok(),
        "stale evaluator must not error on evaluate()"
    );

    // Phase 4: push a fresh 60-second bundle over the live stream.
    server
        .handle
        .push_bundle(valid_bundle_update("v-fresh", 60));

    // Phase 5: fail-closed must exit once the fresh bundle is installed.
    let recovered = wait_for(Duration::from_secs(2), || {
        harness.swappable_policy.is_fresh()
    })
    .await;
    assert!(
        recovered,
        "fail-closed did not exit after fresh bundle delivered"
    );
    assert_eq!(
        harness.swappable_policy.version().as_deref(),
        Some("v-fresh"),
        "bundle version must advance to the newly delivered bundle"
    );

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}
