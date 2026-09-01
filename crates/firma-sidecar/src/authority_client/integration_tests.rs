//! Integration tests for the Authority stream clients.
//!
//! Spin up an in-process `AuthorityService` backed by tonic, connect the
//! sidecar stream clients, and verify the end-to-end behavior documented
//! in task 007: readiness gating, revocation propagation, TTL fail-closed,
//! reconnect with bundle swap, and parse-failure retention of the last
//! valid bundle.

#![cfg(test)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use firma_core::RevocationStore;
use firma_identifiers::{AgentId, TokenId};
use firma_protobuf::v1::authority_service_server::{AuthorityService, AuthorityServiceServer};
use firma_protobuf::v1::{
    GetApprovalOutcomeRequest, GetApprovalOutcomeResponse, IssueCapabilityRequest,
    IssueCapabilityResponse, PolicyBundle, PolicyBundleUpdate, RevocationEvent, SidecarCredentials,
    WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use super::channel::build_channel;
use super::policy_bundle::CedarBundleParser;
use super::readiness::{ReadinessFlag, ReadinessState, ReadinessView};
use super::swappable_policy::SwappablePolicyEvaluation;
use super::{AuthorityClientHandle, AuthorityDeps, spawn_authority_client};
use crate::authority_credentials::{
    RedactedPreSharedKey, ResolvedSidecarCredentials, SidecarCredentialSource,
};
use crate::config::{AuthorityConfig, AuthorityEndpoint};
use crate::enforcement::constraint_enforcement::PolicyEvaluation;
use crate::enforcement::revocation::{BloomLruRevocationStore, RevocationConfig};

// -----------------------------------------------------------------------------
// Mock AuthorityService
// -----------------------------------------------------------------------------

struct MockAuthorityState {
    bundle_tx: broadcast::Sender<PolicyBundleUpdate>,
    revoc_tx: broadcast::Sender<RevocationEvent>,
    revoc_disconnect_tx: broadcast::Sender<()>,
    initial_bundle: Mutex<Option<PolicyBundleUpdate>>,
    policy_credentials: Mutex<Option<SidecarCredentials>>,
    revocation_credentials: Mutex<Option<SidecarCredentials>>,
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

    fn disconnect_revocation_streams(&self) {
        let _ = self.state.revoc_disconnect_tx.send(());
    }

    fn policy_credentials(&self) -> Option<SidecarCredentials> {
        self.state
            .policy_credentials
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn revocation_credentials(&self) -> Option<SidecarCredentials> {
        self.state
            .revocation_credentials
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
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

    async fn get_approval_outcome(
        &self,
        _request: Request<GetApprovalOutcomeRequest>,
    ) -> Result<Response<GetApprovalOutcomeResponse>, Status> {
        Err(Status::unimplemented(
            "mock authority: get_approval_outcome not exercised in task 007 tests",
        ))
    }

    type WatchPolicyBundleStream = ReceiverStream<Result<PolicyBundleUpdate, Status>>;

    async fn watch_policy_bundle(
        &self,
        request: Request<WatchPolicyBundleRequest>,
    ) -> Result<Response<Self::WatchPolicyBundleStream>, Status> {
        if let Ok(mut guard) = self.state.policy_credentials.lock() {
            *guard = request.into_inner().credentials;
        }
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
        request: Request<WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        if let Ok(mut guard) = self.state.revocation_credentials.lock() {
            *guard = request.into_inner().credentials;
        }
        let (tx, rx) = mpsc::channel::<Result<RevocationEvent, Status>>(16);
        let mut broadcast_rx = self.state.revoc_tx.subscribe();
        let mut disconnect_rx = self.state.revoc_disconnect_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = broadcast_rx.recv() => {
                        let Ok(event) = event else {
                            break;
                        };
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    _ = disconnect_rx.recv() => break,
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

struct MockAuthorityServer {
    url: String,
    addr: std::net::SocketAddr,
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
    let (revoc_disconnect_tx, _) = broadcast::channel(16);
    let state = Arc::new(MockAuthorityState {
        bundle_tx,
        revoc_tx,
        revoc_disconnect_tx,
        initial_bundle: Mutex::new(None),
        policy_credentials: Mutex::new(None),
        revocation_credentials: Mutex::new(None),
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

    wait_for_tcp_listen(addr, Duration::from_secs(2)).await?;

    Ok(MockAuthorityServer {
        url,
        addr,
        handle: MockAuthorityHandle { state },
        shutdown,
        join,
    })
}

/// Spawn a TLS-enabled mock authority. The server uses `cert_pem`/`key_pem`
/// as its identity; clients must present a CA that signed the server cert.
/// The returned URL uses `https://localhost:<port>`.
async fn spawn_mock_authority_tls(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<MockAuthorityServer> {
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        listener.local_addr()?
    };
    let port = addr.port();
    let url = format!("https://localhost:{port}");

    let (bundle_tx, _) = broadcast::channel(16);
    let (revoc_tx, _) = broadcast::channel(64);
    let (revoc_disconnect_tx, _) = broadcast::channel(16);
    let state = Arc::new(MockAuthorityState {
        bundle_tx,
        revoc_tx,
        revoc_disconnect_tx,
        initial_bundle: Mutex::new(None),
        policy_credentials: Mutex::new(None),
        revocation_credentials: Mutex::new(None),
    });
    let service = MockAuthority {
        state: Arc::clone(&state),
    };

    let identity = Identity::from_pem(cert_pem, key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    let join = tokio::spawn(async move {
        let _ = Server::builder()
            .tls_config(tls)
            .expect("valid TLS config in test")
            .add_service(AuthorityServiceServer::new(service))
            .serve_with_shutdown(addr, async move {
                shutdown_signal.cancelled().await;
            })
            .await;
    });

    wait_for_tcp_listen(addr, Duration::from_secs(2)).await?;

    Ok(MockAuthorityServer {
        url,
        addr,
        handle: MockAuthorityHandle { state },
        shutdown,
        join,
    })
}

// -----------------------------------------------------------------------------
// TLS certificate helpers
// -----------------------------------------------------------------------------

struct TlsCerts {
    ca_cert: Vec<u8>,
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
}

fn generate_test_tls_certs() -> anyhow::Result<TlsCerts> {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    // Self-signed CA
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Test CA");
    ca_params.distinguished_name = dn;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Server cert with DNS SAN "localhost", signed by the test CA
    let server_key = KeyPair::generate()?;
    let server_params = CertificateParams::new(vec!["localhost".to_string()])?;
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    Ok(TlsCerts {
        ca_cert: ca_cert.pem().into_bytes(),
        server_cert: server_cert.pem().into_bytes(),
        server_key: server_key.serialize_pem().into_bytes(),
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

fn spawn_sidecar(
    url: &str,
    config: AuthorityConfig,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> anyhow::Result<SidecarHarness> {
    spawn_sidecar_with_credentials(
        url,
        config,
        ca_cert_pem,
        client_cert_pem,
        client_key_pem,
        None,
    )
}

fn spawn_sidecar_with_credentials(
    url: &str,
    config: AuthorityConfig,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
    credentials: Option<ResolvedSidecarCredentials>,
) -> anyhow::Result<SidecarHarness> {
    let endpoint = AuthorityEndpoint::new(url, config.connect_addr)?;
    let channel = build_channel(
        &endpoint,
        config.connect_timeout,
        ca_cert_pem,
        client_cert_pem,
        client_key_pem,
    )?;
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
        credentials,
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

/// Minimal valid Cedar policy source that parses under [`TEST_CEDAR_SCHEMA`].
const VALID_CEDAR_POLICY: &str = "permit(principal, action, resource);";

/// Cedar schema scoped to the test suite; the production schema is wider
/// and is available as [`firma_core::cedar::FIRMA_SCHEMA`].
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
        agent_id: None,
        url: None,
        connect_addr: None,
        connect_timeout: Duration::from_secs(2),
        reconnect_min_backoff: Duration::from_millis(50),
        reconnect_max_backoff: Duration::from_secs(1),
        revocation_readiness_grace: Duration::from_millis(100),
        revocation_fail_closed_on_disconnect: false,
        public_key_path: None,
        ca_cert_path: None,
        allow_insecure_remote_authority: false,
        tls_client_cert_path: None,
        tls_client_key_path: None,
        credentials: None,
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

async fn wait_for_tcp_listen(addr: std::net::SocketAddr, deadline: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    while start.elapsed() < deadline {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    anyhow::bail!("authority test server did not start listening on {addr} within {deadline:?}")
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
    let harness = spawn_sidecar(&server.url, test_config(), None, None, None)?;

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
async fn stream_requests_include_configured_credentials() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v1", 60));
    let credentials = ResolvedSidecarCredentials {
        workspace_id: "ws-acme".to_string(),
        sidecar_id: "sc-eu-1".to_string(),
        pre_shared_key: RedactedPreSharedKey::new("psk-secret".to_string()),
        source: SidecarCredentialSource::Env("FIRMA_SIDECAR_PSK".to_string()),
    };
    let harness = spawn_sidecar_with_credentials(
        &server.url,
        test_config(),
        None,
        None,
        None,
        Some(credentials),
    )?;

    let policy_seen = wait_for(Duration::from_secs(2), || {
        server.handle.policy_credentials().is_some()
    })
    .await;
    let revocation_seen = wait_for(Duration::from_secs(2), || {
        server.handle.revocation_credentials().is_some()
    })
    .await;

    assert!(policy_seen, "policy stream credentials were not observed");
    assert!(
        revocation_seen,
        "revocation stream credentials were not observed"
    );
    assert_eq!(
        server
            .handle
            .policy_credentials()
            .map(|credentials| credentials.pre_shared_key),
        Some("psk-secret".to_string())
    );
    assert_eq!(
        server
            .handle
            .revocation_credentials()
            .map(|credentials| credentials.workspace_id),
        Some("ws-acme".to_string())
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
    let harness = spawn_sidecar(&server.url, test_config(), None, None, None)?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .readiness_view
            .snapshot()
            .revocation_ready)
        .await
    );

    let pushed_at = Instant::now();
    let propagate_id: TokenId = "ctok_01j0000000e008000000000001"
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
async fn revocation_disconnect_loses_readiness_when_fail_closed() -> anyhow::Result<()> {
    let server = spawn_mock_authority().await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v1", 60));
    let mut config = test_config();
    config.revocation_fail_closed_on_disconnect = true;
    config.revocation_readiness_grace = Duration::from_millis(10);
    config.reconnect_min_backoff = Duration::from_millis(500);
    let harness = spawn_sidecar(&server.url, config, None, None, None)?;

    let became_ready = wait_for(Duration::from_secs(2), || {
        harness.readiness_view.snapshot().revocation_ready
    })
    .await;
    assert!(became_ready, "revocation readiness never flipped true");

    server.handle.disconnect_revocation_streams();

    let lost_readiness = wait_for(Duration::from_secs(2), || {
        !harness.readiness_view.snapshot().revocation_ready
    })
    .await;
    assert!(
        lost_readiness,
        "revocation readiness stayed true after stream disconnect"
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
    let harness = spawn_sidecar(&server.url, test_config(), None, None, None)?;

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
    let harness = spawn_sidecar(&server.url, test_config(), None, None, None)?;

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
    let harness = spawn_sidecar(&server.url, test_config(), None, None, None)?;

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
    let harness = spawn_sidecar(&server.url, test_config(), None, None, None)?;

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
    let harness = spawn_sidecar(&server.url, test_config(), None, None, None)?;

    assert!(
        wait_for(Duration::from_secs(2), || harness
            .swappable_policy
            .version()
            .as_deref()
            == Some("v1"))
        .await,
        "v1 bundle did not apply"
    );

    let agent: AgentId = "agt_01j0000000e008000000000001"
        .parse()
        .expect("literal agent id");
    let ctx = serde_json::json!({});
    // v1 permits everything, so evaluate should ALLOW.
    let allowed_v1 = harness
        .swappable_policy
        .evaluate(&agent, "test.action", "resource", ctx.clone())
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
        .evaluate(&agent, "test.action", "resource", ctx)
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
    let harness = spawn_sidecar(&server.url, test_config(), None, None, None)?;

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

    let agent: AgentId = "agt_01j0000000e008000000000001"
        .parse()
        .expect("literal agent id");
    let ctx = serde_json::json!({});
    let allowed = harness
        .swappable_policy
        .evaluate(&agent, "test.action", "resource", ctx)
        .expect("sentinel evaluator returns Ok(false)");
    assert!(!allowed, "sentinel DenyAll must refuse every evaluate()");

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

// -----------------------------------------------------------------------------
// TLS tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_succeeds_and_policy_streams_over_tls() -> anyhow::Result<()> {
    let certs = generate_test_tls_certs()?;
    let server = spawn_mock_authority_tls(&certs.server_cert, &certs.server_key).await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v-tls", 60));

    let harness = spawn_sidecar(&server.url, test_config(), Some(&certs.ca_cert), None, None)?;

    let policy_ready = wait_for(Duration::from_secs(5), || {
        harness.readiness_view.snapshot().policy_bundle_ready
    })
    .await;
    assert!(
        policy_ready,
        "policy bundle readiness never flipped over TLS"
    );

    assert_eq!(
        harness.swappable_policy.version().as_deref(),
        Some("v-tls"),
        "TLS-delivered bundle version should be applied"
    );

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_connect_addr_routes_physically_without_changing_server_identity() -> anyhow::Result<()>
{
    let certs = generate_test_tls_certs()?;
    let server = spawn_mock_authority_tls(&certs.server_cert, &certs.server_key).await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v-connect-addr", 60));
    let mut config = test_config();
    config.connect_addr = Some(server.addr);

    let harness = spawn_sidecar(
        "https://localhost:1",
        config,
        Some(&certs.ca_cert),
        None,
        None,
    )?;

    assert!(
        wait_for(Duration::from_secs(5), || {
            harness.readiness_view.snapshot().policy_bundle_ready
        })
        .await,
        "logical URL with an unreachable port did not connect through connect_addr"
    );
    assert_eq!(
        harness.swappable_policy.version().as_deref(),
        Some("v-connect-addr")
    );

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_connect_addr_does_not_bypass_logical_hostname_verification() -> anyhow::Result<()> {
    let certs = generate_test_tls_certs()?;
    let server = spawn_mock_authority_tls(&certs.server_cert, &certs.server_key).await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v-wrong-host", 60));
    let mut config = test_config();
    config.connect_addr = Some(server.addr);

    let harness = spawn_sidecar(
        "https://wrong.example:1",
        config,
        Some(&certs.ca_cert),
        None,
        None,
    )?;

    assert!(
        !wait_for(Duration::from_millis(600), || {
            harness.readiness_view.snapshot().policy_bundle_ready
        })
        .await,
        "wrong logical hostname bypassed TLS certificate verification"
    );
    assert_eq!(harness.swappable_policy.version(), None);

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_fails_with_wrong_ca_cert_stays_not_ready() -> anyhow::Result<()> {
    // Server uses a cert signed by CA-1.
    // Client trusts CA-2 only — the handshake must be rejected and
    // policy_bundle_ready must remain false (fail-closed).
    let server_certs = generate_test_tls_certs()?;
    let wrong_ca_certs = generate_test_tls_certs()?; // independent CA

    let server =
        spawn_mock_authority_tls(&server_certs.server_cert, &server_certs.server_key).await?;
    server
        .handle
        .set_initial_bundle(valid_bundle_update("v-should-not-arrive", 60));

    // Connect with the wrong CA — TLS verification will fail.
    let harness = spawn_sidecar(
        &server.url,
        test_config(),
        Some(&wrong_ca_certs.ca_cert),
        None,
        None,
    )?;

    let stayed_not_ready = wait_for(Duration::from_millis(600), || {
        harness.readiness_view.snapshot().policy_bundle_ready
    })
    .await;

    assert!(
        !stayed_not_ready,
        "policy_bundle_ready must stay false when TLS cert is untrusted"
    );
    assert_eq!(
        harness.swappable_policy.version(),
        None,
        "no bundle should be installed when TLS handshake fails"
    );
    assert!(
        !harness.swappable_policy.is_fresh(),
        "when TLS handshake fails, policy state must stay stale and fail-closed"
    );
    let agent: AgentId = "agt_01j0000000e008000000000001"
        .parse()
        .expect("literal agent id");
    let ctx = serde_json::json!({});
    let allowed = harness
        .swappable_policy
        .evaluate(&agent, "test.action", "resource", ctx)
        .expect("sentinel evaluator returns Ok(false)");
    assert!(
        !allowed,
        "TLS handshake failure must result in deny semantics (no policy bundle installed)"
    );

    harness.shutdown().await;
    server.stop().await;
    Ok(())
}
