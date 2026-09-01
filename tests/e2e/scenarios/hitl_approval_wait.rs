//! HITL startup flow through the real CLI: a run whose issuance is gated on
//! a human approval announces the request on stderr, waits, retrieves the
//! granted token, and starts the session (FIR-504).
//!
//! The Authority is a test double: this scenario proves the client half of
//! the wire contract (announce → poll → verify → run), not a real Firma
//! Team control plane. The Sidecar, sandbox, and wrapped command are real.
//! One deliberate blind spot: the granted token is signed with the same
//! firma-core signer the client verifies with, so a serialization bug
//! shared by both sides would pass here — token verification has its own
//! coverage in the capability suites.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use firma_core::token::paseto::PasetoV4Signer;
use firma_core::{CapabilityClaims, TokenSigner};
use firma_identifiers::TokenId;
use firma_protobuf::v1::authority_service_server::{AuthorityService, AuthorityServiceServer};
use firma_protobuf::v1::get_approval_outcome_response::Outcome;
use firma_protobuf::v1::{
    CapabilityToken, GetApprovalOutcomeRequest, GetApprovalOutcomeResponse, GrantedApproval,
    IssueCapabilityRequest, IssueCapabilityResponse, IssueDecision, PendingApproval, PolicyBundle,
    PolicyBundleUpdate, RevocationEvent, WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use toml_edit::{DocumentMut, Item, Table, value};
use tonic::{Request, Response, Status};

use crate::harness::TestWorld;
use crate::poll::wait_for;

const APPROVAL_ID: &str = "approval-e2e-hitl-1";
const APPROVAL_URL: &str = "https://authority.example/approvals/e2e-hitl-1";

/// Minimal Cedar policy and schema pair the Sidecar accepts as a bundle.
const CEDAR_POLICY: &str = "permit(principal, action, resource);";
const CEDAR_SCHEMA: &str = "\
namespace Firma {
    entity Agent;
    entity Resource;
    action \"test.action\" appliesTo { principal: [Agent], resource: [Resource] };
}";

/// The identity a run presented on `IssueCapability`, echoed into the
/// granted token so the released capability matches the run that asked.
#[derive(Clone)]
struct CapturedIdentity {
    agent_id: String,
    session_id: String,
}

/// Wire timestamp for a UTC instant, seconds precision.
fn ts(at: chrono::DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: at.timestamp(),
        nanos: 0,
    }
}

/// Parks `tx` on a never-completing task so the stream stays open for the
/// lifetime of the run.
fn park_sender<T: Send + 'static>(tx: tokio::sync::mpsc::Sender<T>) {
    tokio::spawn(async move {
        let _tx = tx;
        std::future::pending::<()>().await;
    });
}

/// A remote Authority double for the HITL startup flow: issuance always
/// answers `PENDING_APPROVAL`, the outcome is pending once and then
/// granted, and the policy plane serves one valid bundle so the Sidecar
/// becomes ready.
struct HitlAuthority {
    signer: PasetoV4Signer,
    issue_identity: Arc<Mutex<Option<CapturedIdentity>>>,
    outcome_calls: Arc<AtomicU32>,
}

#[tonic::async_trait]
impl AuthorityService for HitlAuthority {
    async fn issue_capability(
        &self,
        request: Request<IssueCapabilityRequest>,
    ) -> Result<Response<IssueCapabilityResponse>, Status> {
        let req = request.into_inner();
        *self.issue_identity.lock().expect("identity lock") = Some(CapturedIdentity {
            agent_id: req.agent_id,
            session_id: req.session_id,
        });
        let expiry = Utc::now() + chrono::Duration::seconds(120);
        Ok(Response::new(IssueCapabilityResponse {
            granted: false,
            token: None,
            deny_reason: String::new(),
            deny_message: String::new(),
            decision: IssueDecision::PendingApproval.into(),
            approval_id: Some(APPROVAL_ID.to_string()),
            approval_url: Some(APPROVAL_URL.to_string()),
            approval_expiry: Some(ts(expiry)),
        }))
    }

    async fn get_approval_outcome(
        &self,
        _request: Request<GetApprovalOutcomeRequest>,
    ) -> Result<Response<GetApprovalOutcomeResponse>, Status> {
        let call = self.outcome_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let outcome = if call == 1 {
            Outcome::Pending(PendingApproval {
                expires_at: Some(ts(Utc::now() + chrono::Duration::seconds(120))),
                retry_after: Some(prost_types::Duration {
                    seconds: 1,
                    nanos: 0,
                }),
            })
        } else {
            let identity = self
                .issue_identity
                .lock()
                .expect("identity lock")
                .clone()
                .ok_or_else(|| Status::failed_precondition("no issuance seen yet"))?;
            let now = Utc::now();
            let claims = CapabilityClaims {
                token_id: TokenId::generate(),
                agent_id: identity
                    .agent_id
                    .parse()
                    .map_err(|e| Status::internal(format!("agent_id: {e}")))?,
                session_id: identity
                    .session_id
                    .parse()
                    .map_err(|e| Status::internal(format!("session_id: {e}")))?,
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
        };
        Ok(Response::new(GetApprovalOutcomeResponse {
            outcome: Some(outcome),
        }))
    }

    type WatchPolicyBundleStream = ReceiverStream<Result<PolicyBundleUpdate, Status>>;

    async fn watch_policy_bundle(
        &self,
        _request: Request<WatchPolicyBundleRequest>,
    ) -> Result<Response<Self::WatchPolicyBundleStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let bundle = PolicyBundleUpdate {
            bundle: Some(PolicyBundle {
                version: "v1".to_string(),
                policies: CEDAR_POLICY.as_bytes().to_vec(),
                entity_schema: CEDAR_SCHEMA.as_bytes().to_vec(),
                ttl_seconds: 300,
            }),
            updated_at: None,
        };
        tx.send(Ok(bundle))
            .await
            .expect("policy bundle receiver dropped before the bundle was served");
        park_sender(tx);
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type WatchRevocationsStream = ReceiverStream<Result<RevocationEvent, Status>>;

    async fn watch_revocations(
        &self,
        _request: Request<WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<RevocationEvent, Status>>(1);
        park_sender(tx);
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// The running double: URL, key on disk, counters, and shutdown on drop.
struct HitlAuthorityServer {
    url: String,
    pub_key_path: PathBuf,
    outcome_calls: Arc<AtomicU32>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Drop for HitlAuthorityServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn start_hitl_authority() -> HitlAuthorityServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let keypair = AsymmetricKeyPair::<V4>::generate().expect("keypair");
    let pub_key_path = dir.path().join("authority.pub");
    std::fs::write(&pub_key_path, keypair.public.as_bytes()).expect("write pubkey");
    let secret = keypair.secret.as_bytes().to_vec();
    let outcome_calls = Arc::new(AtomicU32::new(0));
    let server_outcome_calls = Arc::clone(&outcome_calls);

    // The listener is bound once and handed to tonic as-is: no
    // release-and-rebind window another process could race for.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind port");
    let addr = listener.local_addr().expect("local addr");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        runtime.block_on(async move {
            let signer = PasetoV4Signer::try_new(&secret).expect("signer");
            let service = AuthorityServiceServer::new(HitlAuthority {
                signer,
                issue_identity: Arc::new(Mutex::new(None)),
                outcome_calls: server_outcome_calls,
            });
            let incoming = TcpListenerStream::new(
                tokio::net::TcpListener::from_std(listener).expect("adopt listener"),
            );
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve");
        });
    });

    wait_for(
        "mock authority to accept connections",
        Duration::from_secs(5),
        || TcpStream::connect(addr).ok(),
    );

    HitlAuthorityServer {
        url: format!("http://{addr}"),
        pub_key_path,
        outcome_calls,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
        _dir: dir,
    }
}

/// Points the generic profile's capability lease at the double's key and
/// tightens the poll interval so the scenario stays fast.
fn configure_hitl_capability(world: &TestWorld, pub_key_path: &Path) {
    let config_path = world.config_path();
    let body = std::fs::read_to_string(&config_path).expect("read generated config");
    let mut config = body.parse::<DocumentMut>().expect("parse generated config");

    let generic = config["run"]["profiles"]["generic"]
        .as_table_mut()
        .expect("generated config has the generic run profile");
    generic
        .entry("capability")
        .or_insert(Item::Table(Table::new()));
    let capability = generic["capability"]
        .as_table_mut()
        .expect("generic profile capability is a table");
    capability["public_key_path"] = value(pub_key_path.display().to_string());
    capability["approval_poll_interval"] = value("1s");

    std::fs::write(config_path, config.to_string()).expect("write HITL test config");
}

#[test]
fn pending_approval_announces_waits_and_starts_the_session() {
    let world = TestWorld::new();
    let authority = start_hitl_authority();
    configure_hitl_capability(&world, &authority.pub_key_path);

    let marker = world.workspace_path().join("session-started");
    let script = format!("echo started > '{}'", marker.display());

    let output = world.run_firma(
        "generic",
        Some(&world.config_path()),
        &world.workspace_path(),
        &[
            "--authority",
            &authority.url,
            "--sidecar",
            "local",
            // The claim under test is the HITL wait, not structural
            // confinement; the flag lets the scenario also run on
            // proxy-only hosts (WSL2) besides bwrap-capable CI.
            "--allow-non-structural",
        ],
        "/bin/sh",
        ["-c", &script],
    );

    assert!(
        output.success(),
        "the run must start once the approval is granted:\n{output}"
    );
    assert!(
        output
            .stderr
            .contains(&format!("approval required: request {APPROVAL_ID}")),
        "the operator-visible announcement must reach stderr:\n{output}"
    );
    assert!(
        output
            .stderr
            .contains(&format!("approve at: {APPROVAL_URL}")),
        "the announcement must carry the approval URL:\n{output}"
    );
    assert!(
        marker.exists(),
        "the wrapped command must have run after the grant:\n{output}"
    );
    assert!(
        authority.outcome_calls.load(Ordering::SeqCst) >= 2,
        "the run must have polled through at least one pending answer"
    );
}
