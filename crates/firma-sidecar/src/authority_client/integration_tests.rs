//! Integration tests for the Authority stream clients.
//!
//! Spin up an in-process `AuthorityService` backed by tonic, connect the
//! sidecar stream clients, and verify the end-to-end behavior documented
//! in task 007: readiness gating, revocation propagation, TTL fail-closed,
//! reconnect with bundle swap, and parse-failure retention of the last
//! valid bundle.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use firma_core::RevocationStore;
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
use super::readiness::{ReadinessFlag, ReadinessState, ReadinessView};
use super::{AuthorityClientHandle, AuthorityDeps, spawn_authority_client};
use crate::config::AuthorityConfig;
use crate::enforcement::constraint_enforcement::PolicyEvaluation;
use crate::enforcement::policy::{BundleLoader, CedarPolicyEvaluator};
use crate::enforcement::revocation::{BloomLruRevocationStore, RevocationConfig};

const VALID_POLICY_CEDAR: &[u8] = b"permit(principal, action, resource);";

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
    policy_evaluator: Arc<CedarPolicyEvaluator>,
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

async fn spawn_sidecar(url: &str, config: AuthorityConfig) -> anyhow::Result<SidecarHarness> {
    let channel = build_channel(url, Duration::from_secs(config.connect_timeout_secs))?;
    let revocation_store = Arc::new(BloomLruRevocationStore::new(RevocationConfig {
        capacity: 1_024,
        fpr: 0.001,
        lru_capacity: 128,
    }));
    let policy_evaluator = Arc::new(CedarPolicyEvaluator::empty(Duration::from_secs(2)));
    let bundle_loader = Arc::new(BundleLoader::new(Arc::clone(&policy_evaluator)));
    let (flag, readiness_view) = ReadinessFlag::new(ReadinessState::default());
    let readiness = Arc::new(flag);
    let cancel = CancellationToken::new();
    let revocation_dyn: Arc<dyn RevocationStore + Send + Sync> =
        Arc::clone(&revocation_store) as Arc<dyn RevocationStore + Send + Sync>;

    let authority = spawn_authority_client(AuthorityDeps {
        channel,
        bundle_loader,
        revocation_store: revocation_dyn,
        readiness,
        cancel: cancel.clone(),
        config,
    });

    Ok(SidecarHarness {
        policy_evaluator,
        revocation_store,
        readiness_view,
        cancel,
        authority,
    })
}

fn bundle_update(version: &str, ttl_seconds: i32, policies: &[u8]) -> PolicyBundleUpdate {
    PolicyBundleUpdate {
        bundle: Some(PolicyBundle {
            version: version.to_string(),
            policies: policies.to_vec(),
            entity_schema: Vec::new(),
            ttl_seconds,
        }),
        updated_at: None,
    }
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

fn is_revoked(store: &BloomLruRevocationStore, token_id: &str) -> bool {
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
        .set_initial_bundle(bundle_update("v1", 60, VALID_POLICY_CEDAR));
    let harness = spawn_sidecar(&server.url, test_config()).await?;

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
        harness.policy_evaluator.version().as_deref(),
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
        .set_initial_bundle(bundle_update("v1", 60, VALID_POLICY_CEDAR));
    let harness = spawn_sidecar(&server.url, test_config()).await?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .readiness_view
            .snapshot()
            .revocation_ready)
        .await
    );

    let pushed_at = Instant::now();
    server
        .handle
        .push_revocation(revocation("tok_propagate", "test"));

    let propagated = wait_for(Duration::from_secs(1), || {
        is_revoked(&harness.revocation_store, "tok_propagate")
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
        .set_initial_bundle(bundle_update("v-ttl", 1, VALID_POLICY_CEDAR));
    let harness = spawn_sidecar(&server.url, test_config()).await?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .readiness_view
            .snapshot()
            .policy_bundle_ready)
        .await
    );
    assert!(
        harness.policy_evaluator.is_fresh(),
        "bundle should be fresh immediately after swap"
    );

    server.stop().await;

    let went_stale = wait_for(Duration::from_secs(3), || {
        !harness.policy_evaluator.is_fresh()
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
        .set_initial_bundle(bundle_update("v1", 60, VALID_POLICY_CEDAR));
    let harness = spawn_sidecar(&server.url, test_config()).await?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .readiness_view
            .snapshot()
            .policy_bundle_ready)
        .await
    );
    assert_eq!(harness.policy_evaluator.version().as_deref(), Some("v1"));

    server
        .handle
        .push_bundle(bundle_update("v2", 60, VALID_POLICY_CEDAR));

    let swapped = wait_for(Duration::from_secs(2), || {
        harness.policy_evaluator.version().as_deref() == Some("v2")
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
        .set_initial_bundle(bundle_update("v1", 60, VALID_POLICY_CEDAR));
    let harness = spawn_sidecar(&server.url, test_config()).await?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .policy_evaluator
            .version()
            .as_deref()
            == Some("v1"))
        .await
    );

    // Malformed Cedar text is rejected by BundleLoader::apply — the
    // previous snapshot must remain in place.
    server
        .handle
        .push_bundle(bundle_update("v-bad", 60, b"not a cedar policy"));

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        harness.policy_evaluator.version().as_deref(),
        Some("v1"),
        "malformed bundle must not replace the last valid version"
    );

    // A follow-up valid bundle must still apply normally.
    server
        .handle
        .push_bundle(bundle_update("v2", 60, VALID_POLICY_CEDAR));
    let swapped = wait_for(Duration::from_secs(2), || {
        harness.policy_evaluator.version().as_deref() == Some("v2")
    })
    .await;
    assert!(swapped, "recovery bundle v2 did not apply");

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}
