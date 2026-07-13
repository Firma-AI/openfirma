//! Success-path coverage for capability minting and background refresh against
//! an in-process mock Authority gRPC server.
//!
//! The failure paths are covered in `capability_issue`/`capability_refresh`;
//! these drive the granted-response path that needs a live Authority:
//! `mint()` -> verify -> write seed, and the refresher's re-mint loop actually
//! rewriting the seed before expiry.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use chrono::Utc;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use firma_core::token::paseto::PasetoV4Signer;
use firma_core::{CapabilityClaims, TokenId, TokenSigner};
use firma_protobuf::v1::authority_service_server::{AuthorityService, AuthorityServiceServer};
use firma_protobuf::v1::{
    CapabilityToken, IssueCapabilityRequest, IssueCapabilityResponse, PolicyBundleUpdate,
    RevocationEvent, WatchPolicyBundleRequest, WatchRevocationsRequest,
};

use firma_run::capability::issue::{IssueParams, mint_and_write};
use firma_run::capability::refresh::CapabilityRefresher;
use firma_run::config::{CapabilityLeaseConfig, CapabilitySource};

/// Mock Authority that signs whatever it is asked to issue with a test key.
struct MockAuthority {
    signer: PasetoV4Signer,
}

#[tonic::async_trait]
impl AuthorityService for MockAuthority {
    async fn issue_capability(
        &self,
        request: Request<IssueCapabilityRequest>,
    ) -> Result<Response<IssueCapabilityResponse>, Status> {
        let req = request.into_inner();
        let now = Utc::now();
        let claims = CapabilityClaims {
            token_id: TokenId::new(),
            agent_id: req
                .agent_id
                .parse()
                .map_err(|e| Status::invalid_argument(format!("agent_id: {e}")))?,
            session_id: req
                .session_id
                .parse()
                .map_err(|e| Status::invalid_argument(format!("session_id: {e}")))?,
            action_set: req.requested_actions,
            resource_scope: req.resource_scope,
            issued_at: now,
            expiry: now + chrono::Duration::seconds(i64::from(req.requested_ttl_seconds.max(1))),
            context_hash: String::new(),
            budget_ceiling: None,
        };
        let raw_token = self
            .signer
            .sign(&claims)
            .map_err(|e| Status::internal(format!("sign: {e}")))?;
        Ok(Response::new(IssueCapabilityResponse {
            granted: true,
            token: Some(CapabilityToken {
                signature: raw_token.into_bytes(),
                ..Default::default()
            }),
            deny_reason: String::new(),
            deny_message: String::new(),
        }))
    }

    type WatchPolicyBundleStream =
        Pin<Box<dyn Stream<Item = Result<PolicyBundleUpdate, Status>> + Send>>;
    async fn watch_policy_bundle(
        &self,
        _request: Request<WatchPolicyBundleRequest>,
    ) -> Result<Response<Self::WatchPolicyBundleStream>, Status> {
        Err(Status::unimplemented("mock authority: no policy stream"))
    }

    type WatchRevocationsStream =
        Pin<Box<dyn Stream<Item = Result<RevocationEvent, Status>> + Send>>;
    async fn watch_revocations(
        &self,
        _request: Request<WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        Err(Status::unimplemented(
            "mock authority: no revocation stream",
        ))
    }
}

/// Handle to a running mock Authority. Dropping it shuts the server down.
struct MockServer {
    url: String,
    pub_key_path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Start a mock Authority on a loopback port and write its public key to disk.
fn start_mock_authority() -> MockServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let kp = AsymmetricKeyPair::<V4>::generate().expect("keypair");
    let pub_key_path = dir.path().join("authority.pub");
    std::fs::write(&pub_key_path, kp.public.as_bytes()).expect("write pubkey");
    let secret = kp.secret.as_bytes().to_vec();

    // Reserve a loopback port, then hand its address to the server.
    let addr: SocketAddr = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async move {
            let signer = PasetoV4Signer::try_new(&secret).expect("signer");
            let svc = AuthorityServiceServer::new(MockAuthority { signer });
            tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_shutdown(addr, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve");
        });
    });

    // Wait for the listener to accept connections.
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "mock authority never came up");
        std::thread::sleep(Duration::from_millis(20));
    }

    MockServer {
        url: format!("http://{addr}"),
        pub_key_path,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
        _dir: dir,
    }
}

fn params(server: &MockServer) -> IssueParams {
    IssueParams {
        authority_url: server.url.clone(),
        authority_pub_key_path: server.pub_key_path.clone(),
        authority_ca_cert_path: None,
        credentials: None,
        agent_id: "agent_mint".to_string(),
        session_id: "sess_mint".to_string(),
        requested_actions: vec!["communication.external.send".to_string()],
        resource_scope: "*".to_string(),
        ttl_seconds: 900,
    }
}

fn lease() -> CapabilityLeaseConfig {
    CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        refresh_ratio: 0.60,
        grace_seconds: 30,
    }
}

#[test]
fn mint_writes_verified_seed_from_authority() {
    let server = start_mock_authority();
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let written = mint_and_write(&params(&server), &seed_path).expect("mint succeeds");
    assert_eq!(written, seed_path);

    let body = std::fs::read_to_string(&seed_path).expect("read seed");
    let seed: firma_core::CapabilitySeed = toml::from_str(&body).expect("parse seed");
    assert_eq!(seed.agent_id, "agent_mint");
    assert_eq!(seed.session_id, "sess_mint");
    assert!(!seed.raw_token.is_empty(), "seed carries the signed token");
}

#[test]
fn refresher_rewrites_seed_before_expiry() {
    let server = start_mock_authority();
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");
    // Placeholder the refresher will overwrite once it re-mints.
    std::fs::write(&seed_path, "placeholder\n").expect("write placeholder");

    // A near-term expiry forces the first renewal at the minimum interval.
    let initial_expiry = Utc::now() + chrono::Duration::seconds(2);
    let refresher =
        CapabilityRefresher::spawn(params(&server), &seed_path, initial_expiry, &lease())
            .expect("spawn refresher");

    let token_id = wait_for_reminted_token(&seed_path);
    assert!(!token_id.is_empty(), "refresher wrote a verified seed");

    drop(refresher);
}

/// Poll `seed_path` until it holds a parseable, re-minted seed; return its
/// `token_id`.
fn wait_for_reminted_token(seed_path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Ok(body) = std::fs::read_to_string(seed_path)
            && let Ok(seed) = toml::from_str::<firma_core::CapabilitySeed>(&body)
        {
            return seed.token_id;
        }
        assert!(
            Instant::now() < deadline,
            "refresher never rewrote the seed with a valid token"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
