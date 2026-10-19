use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use firma_core::token::paseto::PasetoV4Signer;
use firma_core::{CapabilityClaims, CapabilitySeed, TokenSigner};
use firma_http::{Authority, HeaderMap, Method};
use firma_protobuf::v1::{
    self,
    authority_service_server::{AuthorityService, AuthorityServiceServer},
};
use firma_runtime_state::RuntimeLayout;
use firma_sidecar::authority_client::AuthorityClientHandle;
use firma_sidecar::config::SidecarConfig;
use firma_sidecar::pipeline::RawRequest;
use firma_sidecar::startup::{PipelineRuntime, build_pipeline_runtime, spawn_authority_client};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

pub(super) const ACTION_A: &str = "communication.internal.send";
pub(super) const ACTION_B: &str = "communication.external.send";
pub(super) const SESSION: &str = "snapshot-session";

pub(super) struct Subscription {
    pub request: v1::WatchPolicyBundleRequest,
    pub updates: mpsc::Sender<Result<v1::PolicyBundleUpdate, Status>>,
}

struct Service(mpsc::Sender<Subscription>);

#[tonic::async_trait]
impl AuthorityService for Service {
    async fn issue_capability(
        &self,
        _: Request<v1::IssueCapabilityRequest>,
    ) -> Result<Response<v1::IssueCapabilityResponse>, Status> {
        Err(Status::unimplemented("tokens are signed by the fixture"))
    }

    async fn get_approval_outcome(
        &self,
        _: Request<v1::GetApprovalOutcomeRequest>,
    ) -> Result<Response<v1::GetApprovalOutcomeResponse>, Status> {
        Err(Status::unimplemented("no approval flow"))
    }

    type WatchPolicyBundleStream = ReceiverStream<Result<v1::PolicyBundleUpdate, Status>>;

    async fn watch_policy_bundle(
        &self,
        request: Request<v1::WatchPolicyBundleRequest>,
    ) -> Result<Response<Self::WatchPolicyBundleStream>, Status> {
        let (updates, receiver) = mpsc::channel(4);
        self.0
            .send(Subscription {
                request: request.into_inner(),
                updates,
            })
            .await
            .map_err(|_| Status::cancelled("fixture closed"))?;
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    type WatchRevocationsStream = tokio_stream::Pending<Result<v1::RevocationEvent, Status>>;

    async fn watch_revocations(
        &self,
        _: Request<v1::WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        Ok(Response::new(tokio_stream::pending()))
    }
}

pub(super) struct Harness {
    pub runtime: PipelineRuntime,
    pub config: SidecarConfig,
    pub root: tempfile::TempDir,
    requests: mpsc::Receiver<Subscription>,
    cancel: CancellationToken,
    client: AuthorityClientHandle,
    server: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl Harness {
    pub fn new(credentialed: bool) -> anyhow::Result<Self> {
        let root = tempfile::tempdir()?;
        let layout = RuntimeLayout::from_root(root.path().join("state"));
        std::fs::create_dir_all(layout.capabilities_dir())?;
        let keys = AsymmetricKeyPair::<V4>::generate()?;
        let signer = PasetoV4Signer::try_new(keys.secret.as_bytes())?;
        let now = Utc::now();
        let claims = CapabilityClaims {
            token_id: "ctok_01j0000000e008000000000001".parse()?,
            agent_id: "agt_01j0000000e008000000000001".parse()?,
            session_id: SESSION.parse()?,
            action_set: vec![
                ACTION_A.into(),
                ACTION_B.into(),
                "communication.external.read".into(),
            ],
            resource_scope: "*".into(),
            issued_at: now,
            expiry: now + chrono::Duration::hours(1),
            context_hash: String::new(),
        };
        let seed_path = layout.capabilities_dir().join("seed.toml");
        let seed = CapabilitySeed::from_claims(&claims, signer.sign(&claims)?);
        std::fs::write(&seed_path, toml::to_string(&seed)?)?;
        std::fs::write(root.path().join("authority.pub"), keys.public.as_bytes())?;
        std::fs::write(root.path().join("sidecar.psk"), "test-secret")?;
        std::fs::write(
            root.path().join("audit.pem"),
            rcgen::KeyPair::generate()?.serialize_pem(),
        )?;

        let incoming = tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse()?)?;
        let endpoint = incoming.local_addr()?;
        let (sent, requests) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AuthorityServiceServer::new(Service(sent)))
                .serve_with_incoming_shutdown(incoming, server_cancel.cancelled())
                .await
        });
        let credentials = if credentialed {
            "[authority.credentials]\nworkspace_id = 'workspace-test'\nsidecar_id = 'sidecar-test'\npre_shared_key_path = 'sidecar.psk'\n"
        } else {
            ""
        };
        let path = root.path().join("firma.toml");
        std::fs::write(
            &path,
            format!(
                r#"
[authority]
url = "http://{endpoint}"
public_key_path = "authority.pub"
reconnect_min_backoff = "1ms"
reconnect_max_backoff = "2ms"
{credentials}
[capability_seed]
paths = ['{}']
[audit]
sink = "file"
file_path = "audit.jsonl"
signing_key_path = "audit.pem"
"#,
                seed_path.display()
            ),
        )?;
        let mut config =
            SidecarConfig::load_from_path(&path, &layout).map_err(anyhow::Error::msg)?;
        config.rebase_defaults(root.path());
        let runtime = build_pipeline_runtime(&layout, &config)?;
        let client = spawn_authority_client(&config, &runtime, cancel.clone())?;
        Ok(Self {
            runtime,
            config,
            root,
            requests,
            cancel,
            client,
            server,
        })
    }

    pub async fn subscription(&mut self) -> anyhow::Result<Subscription> {
        tokio::time::timeout(Duration::from_secs(10), self.requests.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream subscription closed"))
    }

    pub async fn publish(
        &self,
        subscription: &Subscription,
        bundle: v1::PolicyBundle,
    ) -> anyhow::Result<()> {
        let mut readiness = self.runtime.readiness.subscribe();
        readiness.borrow_and_update();
        let version = bundle.version.clone();
        send(subscription, bundle).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                readiness.changed().await?;
                // Expiry of the previous generation also changes readiness,
                // so wait for this exact version to be enforced and fresh.
                let state = *readiness.borrow();
                if state.policy_bundle_ready
                    && state.policy_bundle_fresh
                    && self.runtime.enforced_bundle().0.as_deref() == Some(version.as_str())
                {
                    break;
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        tokio::time::timeout(
            Duration::from_secs(10),
            self.runtime.readiness.wait_until_fully_ready(),
        )
        .await?;
        Ok(())
    }

    pub async fn audit(
        &self,
        payloads: Vec<firma_sidecar::audit::AuditPayload>,
    ) -> anyhow::Result<Vec<firma_audit_schema::ExecutionEvent>> {
        use firma_sidecar::startup::{load_audit_event_builder, spawn_audit_sink};
        let (sender, receiver) = mpsc::channel(16);
        let builder = load_audit_event_builder(&self.config.audit)?;
        let exit = CancellationToken::new();
        let sink = spawn_audit_sink(&self.config, receiver, builder, exit.clone())?;
        for payload in payloads {
            sender.send(payload).await?;
        }
        drop(sender);
        exit.cancel();
        tokio::time::timeout(Duration::from_secs(10), sink).await???;
        std::fs::read_to_string(self.audit_path())?
            .lines()
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }

    fn audit_path(&self) -> PathBuf {
        self.root.path().join("audit.jsonl")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.client.policy_task.abort();
        self.client.revocation_task.abort();
        self.server.abort();
    }
}

pub(super) async fn send(
    subscription: &Subscription,
    bundle: v1::PolicyBundle,
) -> anyhow::Result<()> {
    subscription
        .updates
        .send(Ok(v1::PolicyBundleUpdate {
            bundle: Some(bundle),
            updated_at: None,
            policy_set: None,
        }))
        .await?;
    Ok(())
}

pub(super) fn rule(action: &str) -> v1::ActionMappingRule {
    v1::ActionMappingRule {
        host: "api.test".into(),
        method: Some("GET".into()),
        path: Some("/request".into()),
        action_class: action.into(),
    }
}

pub(super) fn bundle(version: &str, action: &str, permit: &str) -> v1::PolicyBundle {
    v1::PolicyBundle {
        version: version.into(),
        policies: format!("permit(principal, action == Firma::Action::\"{permit}\", resource);")
            .into_bytes(),
        entity_schema: include_bytes!("../../../../firma-core/firma.cedarschema").to_vec(),
        ttl_seconds: 300,
        mappings: Some(v1::ActionMappingSnapshot {
            format_version: 1,
            default_protected: true,
            rules: vec![rule(action)],
        }),
    }
}

pub(super) fn request() -> RawRequest {
    RawRequest {
        method: Method::GET,
        host: Authority::from_static("api.test"),
        path: "/request".into(),
        headers: HeaderMap::new(),
        body: None,
        is_https: true,
    }
}
