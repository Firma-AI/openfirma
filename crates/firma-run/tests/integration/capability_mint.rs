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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use tokio_stream::Stream;
use tonic::transport::{Identity, ServerTlsConfig};
use tonic::{Request, Response, Status};

use firma_core::token::paseto::{PasetoV4Signer, PasetoV4Verifier};
use firma_core::{ActionClass, CapabilityClaims, CapabilitySeed, TokenSigner, TokenVerifier};
use firma_identifiers::TokenId;
use firma_protobuf::v1::authority_service_server::{AuthorityService, AuthorityServiceServer};
use firma_protobuf::v1::{
    CapabilityToken, GetApprovalOutcomeRequest, GetApprovalOutcomeResponse, IssueCapabilityRequest,
    IssueCapabilityResponse, IssueDecision, PolicyBundleUpdate, RevocationSet,
    WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use firma_sidecar::config::{AuthorityTrust, CapabilitySeedConfig};
use firma_sidecar::startup::{build_token_verifier, load_capability_map};

#[cfg(unix)]
use firma_run::backend::{BackendKind, EnforcementProof, NetworkConfinement, SandboxHandle};
use firma_run::capability::issue::{IssueParams, mint_and_write};
use firma_run::capability::read_capability_token;
use firma_run::capability::refresh::CapabilityRefresher;
use firma_run::config::{CapabilityLeaseConfig, CapabilitySource};
#[cfg(unix)]
use firma_run::config::{NetworkPolicy, SidecarEndpoint};
#[cfg(unix)]
use firma_run::identity::RunIdentity;
#[cfg(unix)]
use firma_run::routing::{AutostartFlags, ResolvedAuthority, prepare_network_runtime};

use firma_test_helpers::bounded::{self, step};

use super::helper::{IssuancePolicy, RealAuthority};

/// Covers the Authority's request deadline plus connection setup.
const MINT_LIMIT: Duration = Duration::from_secs(30);

/// Mock Authority that signs whatever it is asked to issue with a test key.
struct MockAuthority {
    signer: PasetoV4Signer,
    token_kind: MockTokenKind,
    denial: Option<(&'static str, &'static str)>,
    seen_agent_ids: Arc<Mutex<Vec<String>>>,
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
            return Ok(Response::new(IssueCapabilityResponse {
                granted: false,
                token: None,
                deny_reason: String::new(),
                deny_message: String::new(),
                decision: IssueDecision::PendingApproval.into(),
                approval_id: Some("approval-123".to_string()),
                approval_url: Some("https://authority.example/approvals/123".to_string()),
                approval_expiry: Some(prost_types::Timestamp::default()),
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

    async fn get_approval_outcome(
        &self,
        _request: Request<GetApprovalOutcomeRequest>,
    ) -> Result<Response<GetApprovalOutcomeResponse>, Status> {
        Err(Status::unimplemented(
            "mock authority: no approval outcome polling",
        ))
    }

    type WatchPolicyBundleStream =
        Pin<Box<dyn Stream<Item = Result<PolicyBundleUpdate, Status>> + Send>>;
    async fn watch_policy_bundle(
        &self,
        _request: Request<WatchPolicyBundleRequest>,
    ) -> Result<Response<Self::WatchPolicyBundleStream>, Status> {
        Err(Status::unimplemented("mock authority: no policy stream"))
    }

    type WatchRevocationsStream = Pin<Box<dyn Stream<Item = Result<RevocationSet, Status>> + Send>>;
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
    start_authority(token_kind, None, None)
}

fn start_denying_authority(reason: &'static str, message: &'static str) -> MockServer {
    start_authority(MockTokenKind::Valid, Some((reason, message)), None)
}

fn certificate_authority(name: &str) -> (String, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().expect("CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let pem = params.self_signed(&key).expect("CA certificate").pem();
    (pem, Issuer::new(params, key))
}

/// A CA's PEM and the TLS identity of a `127.0.0.1` server it issued.
fn test_pki(ca_name: &str) -> (String, ServerTlsConfig) {
    // The mock server builds its rustls config on its own thread, before the
    // mint picks the process-wide provider; pick the same one here.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_pem, issuer) = certificate_authority(ca_name);
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .expect("server params")
        .signed_by(&server_key, &issuer)
        .expect("server certificate");
    let identity = Identity::from_pem(server_cert.pem(), server_key.serialize_pem());
    (ca_pem, ServerTlsConfig::new().identity(identity))
}

/// Start a mock Authority, over TLS when `tls` names a server identity.
fn start_authority(
    token_kind: MockTokenKind,
    denial: Option<(&'static str, &'static str)>,
    tls: Option<ServerTlsConfig>,
) -> MockServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let kp = AsymmetricKeyPair::<V4>::generate().expect("keypair");
    let pub_key_path = dir.path().join("authority.pub");
    std::fs::write(&pub_key_path, kp.public.as_bytes()).expect("write pubkey");
    let secret = kp.secret.as_bytes().to_vec();
    let seen_agent_ids = Arc::new(Mutex::new(Vec::new()));
    let server_seen_agent_ids = Arc::clone(&seen_agent_ids);

    // Reserve a loopback port, then hand its address to the server.
    let addr: SocketAddr = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("local addr");

    let scheme = if tls.is_some() { "https" } else { "http" };
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
            });
            let mut server = tonic::transport::Server::builder();
            if let Some(tls) = tls {
                server = server.tls_config(tls).expect("server TLS config");
            }
            server
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
        url: format!("{scheme}://{addr}"),
        pub_key_path,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
        seen_agent_ids,
        _dir: dir,
    }
}

fn params(server: &MockServer) -> IssueParams {
    IssueParams {
        authority_url: server.url.clone(),
        authority_pub_key_path: server.pub_key_path.clone(),
        trust: firma_sidecar::config::AuthorityTrust::PlatformStore,
        connect_addr: None,
        credentials: None,
        agent_id: *super::helper::agent_id(),
        session_id: "sess_mint".to_string(),
        resource_scope: "*".to_string(),
        ttl_seconds: 900,
    }
}

fn lease() -> CapabilityLeaseConfig {
    CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        public_key_path: None,
        refresh_ratio: 0.60,
        grace: Duration::from_secs(30),
    }
}

/// The run asks for every action class, so the single class in the seed can only
/// have come from the issuance policy narrowing the request.
#[test]
fn real_authority_token_mints_compatible_seed() -> anyhow::Result<()> {
    bounded::run(async {
        let authority =
            RealAuthority::start_with(IssuancePolicy::PermitOnly("communication.external.send"))
                .await?;
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime_layout = firma_runtime_state::RuntimeLayout::from_root(dir.path());
        let capabilities_dir = runtime_layout.capabilities_dir();
        std::fs::create_dir(&capabilities_dir).expect("create capabilities directory");
        let seed_path = capabilities_dir.join("seed.toml");
        let params = IssueParams {
            authority_url: authority.url.clone(),
            authority_pub_key_path: authority.pub_key_path.clone(),
            trust: firma_sidecar::config::AuthorityTrust::PlatformStore,
            connect_addr: None,
            credentials: None,
            agent_id: *super::helper::agent_id(),
            session_id: "live-session".to_string(),
            resource_scope: "*".to_string(),
            ttl_seconds: 900,
        };
        let mint_path = seed_path.clone();

        let mint = tokio::task::spawn_blocking(move || mint_and_write(&params, &mint_path));
        let written = step("mint a capability", MINT_LIMIT, mint)
            .await??
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
        let run_token = read_capability_token(&CapabilitySource::File {
            path: seed_path.clone(),
        })
        .expect("Run parses Authority-issued seed")
        .expect("file source carries a token");
        assert_eq!(run_token, seed.raw_token);

        let verifier = build_token_verifier(Some(&authority.pub_key_path))
            .expect("build verifier from real Authority key");
        let capability_map = load_capability_map(
            &CapabilitySeedConfig {
                paths: vec![seed_path],
                hot_reload: true,
            },
            verifier.as_ref(),
            &capabilities_dir,
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

        authority.stop().await
    })
}

/// A mint requests every action class, so a policy set that authorizes none of
/// them is how issuance comes back empty. It must fail closed.
#[test]
fn real_authority_rejects_unauthorized_actions_without_writing_seed() -> anyhow::Result<()> {
    bounded::run(async {
        let authority = RealAuthority::start_with(IssuancePolicy::ForbidAll).await?;
        let dir = tempfile::tempdir().expect("tempdir");
        let seed_path = dir.path().join("unauthorized-actions.toml");
        let params = IssueParams {
            authority_url: authority.url.clone(),
            authority_pub_key_path: authority.pub_key_path.clone(),
            trust: firma_sidecar::config::AuthorityTrust::PlatformStore,
            connect_addr: None,
            credentials: None,
            agent_id: *super::helper::agent_id(),
            session_id: "unauthorized-actions".to_string(),
            resource_scope: "*".to_string(),
            ttl_seconds: 900,
        };
        let mint_path = seed_path.clone();

        let mint = tokio::task::spawn_blocking(move || mint_and_write(&params, &mint_path));
        let error = step("mint a capability", MINT_LIMIT, mint)
            .await??
            .expect_err("a policy set granting nothing must fail closed");

        assert!(matches!(
            error,
            firma_run::error::RunError::CapabilityDenied { reason, .. }
                if reason == "NO_AUTHORIZED_ACTIONS"
        ));
        assert!(!seed_path.exists(), "denied issuance must not write a seed");

        authority.stop().await
    })
}

#[cfg(unix)]
#[test]
fn unauthorized_actions_abort_routing_before_sidecar_or_refresh_setup() -> anyhow::Result<()> {
    bounded::run(async {
        let authority = RealAuthority::start_with(IssuancePolicy::ForbidAll).await?;
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(dir.path().join("runtime"));
        let identity = RunIdentity::new(*super::helper::agent_id(), "generic");
        let seed_path = runtime_layout.capability_seed(&identity.sandbox_id);
        let marker_dir = runtime_layout
            .run_entry_layout(&identity.sandbox_id)
            .into_root();
        let sandbox_runtime = dir.path().join("sandbox");
        std::fs::create_dir_all(&sandbox_runtime).expect("sandbox runtime");
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: sandbox_runtime,
            identity: identity.clone(),
            mounts: Vec::new(),
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let proof = EnforcementProof {
            backend: BackendKind::Vz,
            structural: false,
            fail_closed: true,
            detail: "unauthorized capability action test".to_string(),
            network_confinement: NetworkConfinement::ProxyOnly,
        };
        let flags = AutostartFlags {
            sidecar_autostart: true,
            startup_timeout: Duration::from_secs(1),
            ..AutostartFlags::default()
        };
        let resolved_authority = ResolvedAuthority {
            url: authority.url.clone(),
            ca_cert_path: None,
            trust: firma_sidecar::config::AuthorityTrust::PlatformStore,
            connect_addr: None,
            pub_key_path: Some(authority.pub_key_path.clone()),
            credentials: None,
            credentials_config: None,
            owned: None,
            capability_public_key: None,
        };
        let capability = CapabilityLeaseConfig {
            source: CapabilitySource::Disabled,
            public_key_path: Some(authority.pub_key_path.clone()),
            refresh_ratio: 0.60,
            grace: Duration::from_secs(30),
        };

        let preparation = tokio::task::spawn_blocking(move || {
            prepare_network_runtime(
                &runtime_layout,
                &handle,
                &proof,
                &SidecarEndpoint::Tcp {
                    addr: "127.0.0.1:1".parse().expect("sidecar address"),
                },
                &identity,
                &flags,
                resolved_authority,
                &capability,
            )
        });
        let result = step("prepare the network runtime", MINT_LIMIT, preparation).await??;
        let Err(error) = result else {
            panic!("a policy set granting nothing must abort routing preparation");
        };

        assert!(
            error.to_string().contains("NO_AUTHORIZED_ACTIONS"),
            "unexpected error: {error}"
        );
        assert!(!seed_path.exists(), "denied issuance must not leave a seed");
        assert!(
            !marker_dir.join("sidecar.toml").exists(),
            "Sidecar preparation must not begin after denied issuance"
        );

        authority.stop().await
    })
}

/// The grant is the policy set's call, which only holds if the request itself
/// is never narrowed: a mint must name every action class, whatever the local
/// config says. The mock echoes the request into the claims, so the seed's
/// `action_set` is the request.
#[test]
fn mint_requests_every_action_class() {
    let server = start_mock_authority();
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    mint_and_write(&params(&server), &seed_path).expect("mint succeeds");

    let body = std::fs::read_to_string(&seed_path).expect("read seed");
    let seed: CapabilitySeed = toml::from_str(&body).expect("parse seed");
    let every_class: Vec<String> = ActionClass::ALL
        .iter()
        .map(|class| class.as_str().to_string())
        .collect();

    assert_eq!(seed.action_set, every_class);
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
fn mint_reports_pending_approval() {
    let server = start_mock_authority_with(MockTokenKind::PendingApproval);
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params(&server), &seed_path)
        .expect_err("pending approval must stop capability issuance");
    let message = err.to_string();

    assert!(
        message.contains("approval-123")
            && message.contains("https://authority.example/approvals/123"),
        "got: {err}"
    );
    assert!(!seed_path.exists(), "no seed should be written on failure");
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

/// The mint verifies an `https` Authority against the configured CA list,
/// whichever entry issued its certificate, here the second, and writes the
/// seed.
#[test]
fn mint_over_tls_trusts_any_listed_ca() {
    let (unrelated_ca, _) = certificate_authority("Unrelated CA");
    let (authority_ca, tls) = test_pki("Authority CA");
    let server = start_authority(MockTokenKind::Valid, None, Some(tls));
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_list = [
        ("unrelated-ca.pem", unrelated_ca),
        ("authority-ca.pem", authority_ca),
    ]
    .map(|(name, pem)| {
        let path = dir.path().join(name);
        std::fs::write(&path, pem).expect("write CA");
        path
    });
    let seed_path = dir.path().join("seed.toml");

    mint_and_write(
        &IssueParams {
            trust: AuthorityTrust::CustomCas(ca_list.to_vec()),
            ..params(&server)
        },
        &seed_path,
    )
    .expect("the second listed CA must verify the Authority");

    assert!(seed_path.exists(), "the seed must be written");
}
