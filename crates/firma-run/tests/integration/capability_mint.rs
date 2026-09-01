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

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use firma_core::token::paseto::{PasetoV4Signer, PasetoV4Verifier};
use firma_core::{CapabilityClaims, CapabilitySeed, TokenSigner, TokenVerifier};
use firma_identifiers::TokenId;
use firma_protobuf::v1::authority_service_server::{AuthorityService, AuthorityServiceServer};
use firma_protobuf::v1::get_approval_outcome_response::Outcome;
use firma_protobuf::v1::{
    CapabilityToken, DeniedApproval, ExpiredApproval, GetApprovalOutcomeRequest,
    GetApprovalOutcomeResponse, GrantedApproval, IssueCapabilityRequest, IssueCapabilityResponse,
    IssueDecision, PendingApproval, PolicyBundleUpdate, RevocationEvent, WatchPolicyBundleRequest,
    WatchRevocationsRequest,
};
use firma_sidecar::config::CapabilitySeedConfig;
use firma_sidecar::startup::{build_token_verifier, load_capability_map};

use firma_run::capability::approval_wait::ApprovalWaitPolicy;
use firma_run::capability::issue::{IssueParams, mint_and_write};
use firma_run::capability::refresh::CapabilityRefresher;
use firma_run::config::CapabilityLeaseConfig;

use super::helper::RealAuthority;

/// One scripted `GetApprovalOutcome` answer, consumed in order.
#[derive(Clone, Copy)]
enum ApprovalOutcomeStep {
    /// Still pending; advises polling again after this many seconds.
    Pending { retry_after_secs: i64 },
    /// Granted: the mock signs a real token for the enrolled test agent.
    Granted,
    /// Denied by the (scripted) operator.
    Denied,
    /// Expired before a decision.
    Expired,
    /// The call fails with this status code.
    Fail(tonic::Code),
}

/// Mock Authority that signs whatever it is asked to issue with a test key.
struct MockAuthority {
    signer: PasetoV4Signer,
    token_kind: MockTokenKind,
    denial: Option<(&'static str, &'static str)>,
    seen_agent_ids: Arc<Mutex<Vec<String>>>,
    /// Scripted answers for `GetApprovalOutcome`; an exhausted script
    /// answers `UNIMPLEMENTED`, the same as an Authority without HITL.
    approval_script: Arc<Mutex<VecDeque<ApprovalOutcomeStep>>>,
    /// How many `GetApprovalOutcome` calls arrived, for ordering asserts.
    outcome_calls: Arc<Mutex<u32>>,
    /// Answer `IssueCapability` pending with an already-past expiry.
    pending_expiry_past: bool,
}

#[derive(Clone, Copy)]
enum MockTokenKind {
    Valid,
    Malformed,
    NonUtf8,
    Expired,
    PendingApproval,
}

#[tonic::async_trait]
impl AuthorityService for MockAuthority {
    async fn get_approval_outcome(
        &self,
        _request: Request<GetApprovalOutcomeRequest>,
    ) -> Result<Response<GetApprovalOutcomeResponse>, Status> {
        *self.outcome_calls.lock().expect("calls lock") += 1;
        let step = self
            .approval_script
            .lock()
            .expect("script lock")
            .pop_front();
        let Some(step) = step else {
            return Err(Status::unimplemented(
                "MockAuthority script exhausted: no HITL retrieval",
            ));
        };
        let now = Utc::now();
        let outcome = match step {
            ApprovalOutcomeStep::Pending { retry_after_secs } => {
                Outcome::Pending(PendingApproval {
                    expires_at: Some(prost_types::Timestamp {
                        seconds: (now + chrono::Duration::seconds(600)).timestamp(),
                        nanos: 0,
                    }),
                    retry_after: Some(prost_types::Duration {
                        seconds: retry_after_secs,
                        nanos: 0,
                    }),
                })
            }
            ApprovalOutcomeStep::Granted => {
                let claims = CapabilityClaims {
                    token_id: TokenId::generate(),
                    agent_id: *super::helper::agent_id(),
                    session_id: "sess_mint".parse().expect("session id"),
                    action_set: vec!["communication.external.send".to_string()],
                    resource_scope: "*".to_string(),
                    issued_at: now,
                    expiry: now + chrono::Duration::seconds(900),
                    context_hash: String::new(),
                };
                let signature = self
                    .signer
                    .sign(&claims)
                    .map(String::into_bytes)
                    .map_err(|e| Status::internal(format!("sign: {e}")))?;
                Outcome::Granted(Box::new(GrantedApproval {
                    token: Some(CapabilityToken {
                        signature,
                        ..Default::default()
                    }),
                }))
            }
            ApprovalOutcomeStep::Denied => Outcome::Denied(DeniedApproval {}),
            ApprovalOutcomeStep::Expired => Outcome::Expired(ExpiredApproval {}),
            ApprovalOutcomeStep::Fail(code) => {
                return Err(Status::new(code, "scripted failure"));
            }
        };
        Ok(Response::new(GetApprovalOutcomeResponse {
            outcome: Some(outcome),
        }))
    }

    async fn issue_capability(
        &self,
        request: Request<IssueCapabilityRequest>,
    ) -> Result<Response<IssueCapabilityResponse>, Status> {
        let req = request.into_inner();
        self.seen_agent_ids
            .lock()
            .expect("capture lock")
            .push(req.agent_id.clone());
        if let Some((reason, message)) = self.denial {
            return Ok(Response::new(IssueCapabilityResponse {
                granted: false,
                token: None,
                deny_reason: reason.to_string(),
                deny_message: message.to_string(),
                decision: IssueDecision::Deny.into(),
                approval_id: None,
                approval_url: None,
                approval_expiry: None,
            }));
        }
        if matches!(self.token_kind, MockTokenKind::PendingApproval) {
            let expiry = if self.pending_expiry_past {
                Utc::now() - chrono::Duration::seconds(60)
            } else {
                Utc::now() + chrono::Duration::seconds(600)
            };
            return Ok(Response::new(IssueCapabilityResponse {
                granted: false,
                token: None,
                deny_reason: String::new(),
                deny_message: String::new(),
                decision: IssueDecision::PendingApproval.into(),
                approval_id: Some("approval-123".to_string()),
                approval_url: Some("https://authority.example/approvals/123".to_string()),
                approval_expiry: Some(prost_types::Timestamp {
                    seconds: expiry.timestamp(),
                    nanos: 0,
                }),
            }));
        }
        let now = Utc::now();
        let expiry = match self.token_kind {
            MockTokenKind::Valid
            | MockTokenKind::Malformed
            | MockTokenKind::NonUtf8
            | MockTokenKind::PendingApproval => {
                now + chrono::Duration::seconds(i64::from(req.requested_ttl_seconds.max(1)))
            }
            MockTokenKind::Expired => now - chrono::Duration::seconds(60),
        };
        let claims = CapabilityClaims {
            token_id: TokenId::generate(),
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
            expiry,
            context_hash: String::new(),
        };
        let signature = match self.token_kind {
            MockTokenKind::Malformed => b"not-a-paseto-token".to_vec(),
            MockTokenKind::NonUtf8 => vec![0xff, 0xfe],
            MockTokenKind::Valid | MockTokenKind::Expired | MockTokenKind::PendingApproval => self
                .signer
                .sign(&claims)
                .map(String::into_bytes)
                .map_err(|e| Status::internal(format!("sign: {e}")))?,
        };
        Ok(Response::new(IssueCapabilityResponse {
            granted: true,
            token: Some(CapabilityToken {
                signature,
                ..Default::default()
            }),
            deny_reason: String::new(),
            deny_message: String::new(),
            decision: IssueDecision::Allow.into(),
            approval_id: None,
            approval_url: None,
            approval_expiry: None,
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
    seen_agent_ids: Arc<Mutex<Vec<String>>>,
    outcome_calls: Arc<Mutex<u32>>,
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
    start_mock_authority_with(MockTokenKind::Valid)
}

fn start_mock_authority_with(token_kind: MockTokenKind) -> MockServer {
    start_authority(token_kind, None)
}

fn start_denying_authority(reason: &'static str, message: &'static str) -> MockServer {
    start_authority(MockTokenKind::Valid, Some((reason, message)))
}

fn start_authority(
    token_kind: MockTokenKind,
    denial: Option<(&'static str, &'static str)>,
) -> MockServer {
    start_authority_scripted(token_kind, denial, VecDeque::new(), false)
}

/// Starts the mock with a scripted `GetApprovalOutcome` answer sequence.
fn start_authority_scripted(
    token_kind: MockTokenKind,
    denial: Option<(&'static str, &'static str)>,
    script: VecDeque<ApprovalOutcomeStep>,
    pending_expiry_past: bool,
) -> MockServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let kp = AsymmetricKeyPair::<V4>::generate().expect("keypair");
    let pub_key_path = dir.path().join("authority.pub");
    std::fs::write(&pub_key_path, kp.public.as_bytes()).expect("write pubkey");
    let secret = kp.secret.as_bytes().to_vec();
    let seen_agent_ids = Arc::new(Mutex::new(Vec::new()));
    let server_seen_agent_ids = Arc::clone(&seen_agent_ids);
    let approval_script = Arc::new(Mutex::new(script));
    let server_script = Arc::clone(&approval_script);
    let outcome_calls = Arc::new(Mutex::new(0_u32));
    let server_outcome_calls = Arc::clone(&outcome_calls);

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
            let svc = AuthorityServiceServer::new(MockAuthority {
                signer,
                denial,
                token_kind,
                seen_agent_ids: server_seen_agent_ids,
                approval_script: server_script,
                outcome_calls: server_outcome_calls,
                pending_expiry_past,
            });
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
        seen_agent_ids,
        outcome_calls,
        _dir: dir,
    }
}

fn params(server: &MockServer) -> IssueParams {
    IssueParams {
        authority_url: server.url.clone(),
        authority_pub_key_path: server.pub_key_path.clone(),
        authority_ca_cert_path: None,
        credentials: None,
        agent_id: *super::helper::agent_id(),
        session_id: "sess_mint".to_string(),
        requested_actions: vec!["communication.external.send".to_string()],
        resource_scope: "*".to_string(),
        ttl_seconds: 900,
        issuance_attempt_id: uuid::Uuid::new_v4(),
        approval_wait: ApprovalWaitPolicy::default(),
    }
}

fn lease() -> CapabilityLeaseConfig {
    super::helper::default_lease()
}

#[tokio::test]
async fn real_authority_token_mints_compatible_seed() {
    let authority = RealAuthority::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");
    let params = IssueParams {
        authority_url: authority.url.clone(),
        authority_pub_key_path: authority.pub_key_path.clone(),
        authority_ca_cert_path: None,
        credentials: None,
        agent_id: *super::helper::agent_id(),
        session_id: "live-session".to_string(),
        requested_actions: vec!["communication.external.send".to_string()],
        resource_scope: "*".to_string(),
        ttl_seconds: 900,
        issuance_attempt_id: uuid::Uuid::new_v4(),
        approval_wait: ApprovalWaitPolicy::default(),
    };
    let mint_path = seed_path.clone();

    let written = tokio::task::spawn_blocking(move || mint_and_write(&params, &mint_path))
        .await
        .expect("join capability mint")
        .expect("mint against real Authority");

    assert_eq!(written, seed_path);
    let body = std::fs::read_to_string(&seed_path).expect("read minted seed");
    let seed: CapabilitySeed = toml::from_str(&body).expect("parse minted seed");
    assert_eq!(seed.agent_id, super::helper::agent_id().to_string());
    assert_eq!(seed.session_id, "live-session");
    assert_eq!(
        seed.action_set,
        vec!["communication.external.send".to_string()]
    );
    assert!(!seed.raw_token.is_empty(), "seed carries the signed token");

    let verifier = build_token_verifier(Some(&authority.pub_key_path))
        .expect("build verifier from real Authority key");
    let capability_map = load_capability_map(
        &CapabilitySeedConfig {
            paths: vec![seed_path],
            hot_reload: true,
        },
        verifier.as_ref(),
        &dir.path().join("runtime-capabilities"),
    )
    .expect("Sidecar loads seed minted through firma-run");
    let entry = capability_map
        .select(
            "live-session",
            "communication.external.send",
            "example.test/request",
        )
        .expect("minted capability admits matching request at Stage 1");
    let claims = verifier
        .verify(&entry.raw_token)
        .expect("Sidecar verifies token from real Authority");
    assert_eq!(claims.session_id.to_string(), "live-session");

    authority.stop().await;
}

#[test]
fn firmateam_compatible_token_verifies_with_matching_raw_key() {
    let server = start_mock_authority();
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let written = mint_and_write(&params(&server), &seed_path).expect("mint succeeds");
    assert_eq!(written, seed_path);

    let body = std::fs::read_to_string(&seed_path).expect("read seed");
    let seed: CapabilitySeed = toml::from_str(&body).expect("parse seed");
    let public_key = std::fs::read(&server.pub_key_path).expect("read public key");
    let verifier = PasetoV4Verifier::try_new(&public_key).expect("verifier");
    let claims = verifier
        .verify(&seed.raw_token)
        .expect("verify written token");
    let expected_seed = CapabilitySeed::from_claims(&claims, seed.raw_token.clone());

    assert_eq!(seed, expected_seed);
    assert_eq!(seed.agent_id, super::helper::agent_id().to_string());
    assert_eq!(seed.session_id, "sess_mint");
    assert!(!seed.raw_token.is_empty(), "seed carries the signed token");
    assert_eq!(
        *server.seen_agent_ids.lock().expect("capture lock"),
        vec![super::helper::agent_id().to_string()]
    );
}

#[test]
fn mint_rejects_malformed_token() {
    let server = start_mock_authority_with(MockTokenKind::Malformed);
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path).expect_err("malformed token must fail");

    assert!(err.to_string().contains("not a valid PASETO"), "got: {err}");
    assert!(!seed_path.exists(), "no seed should be written on failure");
}

#[test]
fn mint_rejects_non_utf8_token() {
    let server = start_mock_authority_with(MockTokenKind::NonUtf8);
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path).expect_err("non-UTF-8 token must fail");

    assert!(err.to_string().contains("not valid UTF-8"), "got: {err}");
    assert!(!seed_path.exists(), "no seed should be written on failure");
}

#[test]
fn mint_rejects_expired_token() {
    let server = start_mock_authority_with(MockTokenKind::Expired);
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path).expect_err("expired token must fail");

    assert!(err.to_string().contains("token expired"), "got: {err}");
    assert!(!seed_path.exists(), "no seed should be written on failure");
}

#[test]
fn pending_approval_waits_and_retrieves_the_granted_seed() {
    // Pending once (1s advisory), then granted: the run must wait, retrieve
    // the token, verify it, and write a loadable seed.
    let server = start_authority_scripted(
        MockTokenKind::PendingApproval,
        None,
        VecDeque::from([
            ApprovalOutcomeStep::Pending {
                retry_after_secs: 1,
            },
            ApprovalOutcomeStep::Granted,
        ]),
        false,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    mint_and_write(&params(&server), &seed_path).expect("granted after one pending poll");

    assert!(seed_path.exists(), "seed must be written after the grant");
    let verifier =
        build_token_verifier(Some(&server.pub_key_path)).expect("verifier from authority key");
    let capability_map = load_capability_map(
        &CapabilitySeedConfig {
            paths: vec![seed_path],
            hot_reload: false,
        },
        verifier.as_ref(),
        &dir.path().join("runtime-capabilities"),
    )
    .expect("retrieved seed loads and verifies against the authority key");
    capability_map
        .select("sess_mint", "communication.external.send", "any/request")
        .expect("retrieved capability admits a matching request");
    assert_eq!(
        *server.outcome_calls.lock().expect("calls"),
        2,
        "one pending poll plus the granted one"
    );
}

#[test]
fn denied_approval_fails_closed_without_a_seed() {
    let server = start_authority_scripted(
        MockTokenKind::PendingApproval,
        None,
        VecDeque::from([ApprovalOutcomeStep::Denied]),
        false,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path).expect_err("denied must fail closed");

    assert!(
        matches!(
            &err,
            firma_run::error::RunError::CapabilityApprovalDenied { approval_id }
                if approval_id == "approval-123"
        ),
        "got: {err}"
    );
    assert!(!seed_path.exists(), "no seed on a denied approval");
}

#[test]
fn past_approval_expiry_fails_closed_before_any_poll() {
    // The IssueCapability answer already carries a dead deadline: the wait
    // must stop locally without a single outcome poll.
    let server =
        start_authority_scripted(MockTokenKind::PendingApproval, None, VecDeque::new(), true);
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path).expect_err("expired must fail closed");

    assert!(
        matches!(
            &err,
            firma_run::error::RunError::CapabilityApprovalExpired { approval_id }
                if approval_id == "approval-123"
        ),
        "got: {err}"
    );
    assert_eq!(
        *server.outcome_calls.lock().expect("calls"),
        0,
        "a dead deadline must not be polled at all"
    );
    assert!(!seed_path.exists(), "no seed on an expired approval");
}

#[test]
fn local_max_wait_reports_pending_not_expired() {
    // approval_max_wait shortens the deadline while the server-side expiry
    // is still far: the run must report the approval as still pending (the
    // user can go decide via the URL), never as expired.
    let server = start_authority_scripted(
        MockTokenKind::PendingApproval,
        None,
        VecDeque::from([ApprovalOutcomeStep::Pending {
            retry_after_secs: 1,
        }]),
        false,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");
    let mut issue_params = params(&server);
    issue_params.approval_wait.max_wait = Some(Duration::from_secs(1));

    let err = mint_and_write(&issue_params, &seed_path).expect_err("max_wait must stop the wait");

    assert!(
        matches!(
            &err,
            firma_run::error::RunError::CapabilityPendingApproval { approval_id, approval_url, .. }
                if approval_id == "approval-123"
                    && approval_url == "https://authority.example/approvals/123"
        ),
        "a locally capped wait must stay 'pending' with the URL, got: {err}"
    );
    assert!(!seed_path.exists(), "no seed while the approval is pending");
}

#[test]
fn server_reported_expiry_fails_closed() {
    // The server itself resolves the approval as expired (its worker or a
    // lazy expiry won the race): same terminal error as the local deadline,
    // no seed.
    let server = start_authority_scripted(
        MockTokenKind::PendingApproval,
        None,
        VecDeque::from([ApprovalOutcomeStep::Expired]),
        false,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path).expect_err("expired must fail closed");

    assert!(
        matches!(
            &err,
            firma_run::error::RunError::CapabilityApprovalExpired { approval_id }
                if approval_id == "approval-123"
        ),
        "got: {err}"
    );
    assert!(!seed_path.exists(), "no seed on a server-expired approval");
}

#[test]
fn foreign_approval_not_found_fails_closed() {
    let server = start_authority_scripted(
        MockTokenKind::PendingApproval,
        None,
        VecDeque::from([ApprovalOutcomeStep::Fail(tonic::Code::NotFound)]),
        false,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path).expect_err("not found must fail closed");

    assert!(
        err.to_string().contains("was not found for this identity"),
        "got: {err}"
    );
    assert!(!seed_path.exists(), "no seed on a foreign approval");
}

#[test]
fn authority_without_retrieval_reports_the_upgrade_path() {
    // Empty script: the mock answers UNIMPLEMENTED, like an Authority
    // predating protobuf 0.3 during a rollout.
    let server =
        start_authority_scripted(MockTokenKind::PendingApproval, None, VecDeque::new(), false);
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path).expect_err("unimplemented must stop");

    assert!(
        err.to_string()
            .contains("does not support approval retrieval yet"),
        "got: {err}"
    );
    assert!(!seed_path.exists());
}

#[test]
fn granted_wait_never_logs_the_bearer_token() {
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    // Capture every tracing line emitted while a pending approval resolves
    // into a grant, then prove the released bearer never appears in them.
    #[derive(Clone)]
    struct Capture(StdArc<StdMutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let server = start_authority_scripted(
        MockTokenKind::PendingApproval,
        None,
        VecDeque::from([ApprovalOutcomeStep::Granted]),
        false,
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let sink = StdArc::new(StdMutex::new(Vec::new()));
    let writer_sink = StdArc::clone(&sink);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || Capture(StdArc::clone(&writer_sink)))
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        mint_and_write(&params(&server), &seed_path).expect("granted");
    });

    let seed_text = fs_err::read_to_string(&seed_path).expect("seed file");
    let seed: CapabilitySeed = toml::from_str(&seed_text).expect("seed parses");
    let logs = String::from_utf8(sink.lock().expect("capture lock").clone()).expect("utf8 logs");
    assert!(!logs.is_empty(), "the wait must emit tracing");
    assert!(
        !logs.contains(&seed.raw_token),
        "the raw bearer token must never appear in tracing output"
    );
}

#[test]
fn mint_rejects_token_signed_by_different_key() {
    let server = start_mock_authority();
    let dir = tempfile::tempdir().expect("tempdir");
    let other_keypair = AsymmetricKeyPair::<V4>::generate().expect("other keypair");
    let other_key_path = dir.path().join("other-authority.pub");
    std::fs::write(&other_key_path, other_keypair.public.as_bytes()).expect("write other pubkey");
    let seed_path = dir.path().join("seed.toml");
    let mut issue_params = params(&server);
    issue_params.authority_pub_key_path = other_key_path;

    let err = mint_and_write(&issue_params, &seed_path).expect_err("wrong signature must fail");

    assert!(err.to_string().contains("signature invalid"), "got: {err}");
    assert!(!seed_path.exists(), "no seed should be written on failure");
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
    assert!(
        token_id.to_string().starts_with("ctok_"),
        "refresher wrote a verified seed"
    );
    assert!(
        server
            .seen_agent_ids
            .lock()
            .expect("capture lock")
            .iter()
            .all(|agent_id| agent_id == &super::helper::agent_id().to_string()),
        "initial and refreshed capabilities must retain the registered UUID"
    );

    drop(refresher);
}

#[test]
fn agent_not_registered_denial_maps_to_typed_error() {
    let server = start_denying_authority("AGENT_NOT_REGISTERED", "register this agent");
    let dir = tempfile::tempdir().expect("tempdir");
    let error = mint_and_write(&params(&server), &dir.path().join("seed.toml"))
        .expect_err("denial expected");

    assert!(matches!(
        error,
        firma_run::error::RunError::AgentNotRegistered { message, .. }
            if message == "register this agent"
    ));
}

#[test]
fn agent_profile_mismatch_denial_maps_to_typed_error() {
    let server = start_denying_authority("AGENT_PROFILE_MISMATCH", "profile is not bound");
    let dir = tempfile::tempdir().expect("tempdir");
    let error = mint_and_write(&params(&server), &dir.path().join("seed.toml"))
        .expect_err("denial expected");

    assert!(matches!(
        error,
        firma_run::error::RunError::AgentProfileMismatch { message, .. }
            if message == "profile is not bound"
    ));
}

#[test]
fn unknown_denial_reason_retains_generic_fallback() {
    let server = start_denying_authority("SOMETHING_NEW", "future denial");
    let dir = tempfile::tempdir().expect("tempdir");
    let error = mint_and_write(&params(&server), &dir.path().join("seed.toml"))
        .expect_err("denial expected");

    assert!(matches!(
        error,
        firma_run::error::RunError::CapabilityDenied { reason, message, .. }
            if reason == "SOMETHING_NEW" && message == "future denial"
    ));
}

/// Poll `seed_path` until it holds a parseable, re-minted seed; return its
/// `token_id`.
fn wait_for_reminted_token(seed_path: &Path) -> TokenId {
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
