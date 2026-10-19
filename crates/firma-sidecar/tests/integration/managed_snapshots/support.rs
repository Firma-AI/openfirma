use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use firma_core::token::paseto::PasetoV4Signer;
use firma_core::{CapabilityClaims, CapabilitySeed, TokenSigner};
use firma_http::{Authority, HeaderMap, Method};
use firma_protobuf::v1::authority_service_server::{AuthorityService, AuthorityServiceServer};
use firma_protobuf::v1::{
    ActionMappingRule, ActionMappingSnapshot, GetApprovalOutcomeRequest,
    GetApprovalOutcomeResponse, IssueCapabilityRequest, IssueCapabilityResponse, PolicyBundle,
    PolicyBundleUpdate, RevocationEvent, WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use firma_sidecar::audit::{AuditPayload, ExecutionEvent};
use firma_sidecar::config::SidecarConfig;
use firma_sidecar::pipeline::{EnforcementDecision, RawRequest};
use firma_sidecar::startup::{
    PipelineRuntime, build_pipeline_runtime, load_audit_event_builder, spawn_audit_sink,
    spawn_authority_client_publishing,
};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

pub(super) type Updates = mpsc::Sender<Result<PolicyBundleUpdate, Status>>;
pub(super) type Connection = (WatchPolicyBundleRequest, Updates);

struct FixtureAuthority {
    connections: mpsc::Sender<Connection>,
}

#[tonic::async_trait]
impl AuthorityService for FixtureAuthority {
    async fn issue_capability(
        &self,
        _: Request<IssueCapabilityRequest>,
    ) -> Result<Response<IssueCapabilityResponse>, Status> {
        Err(Status::unimplemented(
            "fixture uses signed local capability seeds",
        ))
    }

    async fn get_approval_outcome(
        &self,
        _: Request<GetApprovalOutcomeRequest>,
    ) -> Result<Response<GetApprovalOutcomeResponse>, Status> {
        Err(Status::unimplemented("fixture does not request approvals"))
    }

    type WatchPolicyBundleStream = ReceiverStream<Result<PolicyBundleUpdate, Status>>;

    async fn watch_policy_bundle(
        &self,
        request: Request<WatchPolicyBundleRequest>,
    ) -> Result<Response<Self::WatchPolicyBundleStream>, Status> {
        let (tx, rx) = mpsc::channel(16);
        self.connections
            .send((request.into_inner(), tx))
            .await
            .map_err(|_| Status::unavailable("fixture stopped"))?;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type WatchRevocationsStream = ReceiverStream<Result<RevocationEvent, Status>>;

    async fn watch_revocations(
        &self,
        _: Request<WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move { tx.closed().await });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

pub(super) struct Fixture {
    pub runtime: PipelineRuntime,
    pub connections: mpsc::Receiver<Connection>,
    pub audit_tx: mpsc::Sender<AuditPayload>,
    directory: tempfile::TempDir,
    emitted: usize,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_configured(|_| {}).await
    }

    pub async fn start_configured(
        configure: impl FnOnce(&mut firma_config_schema::sidecar::SidecarConfig),
    ) -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let layout = firma_runtime_state::RuntimeLayout::from_root(root);
        std::fs::create_dir_all(layout.capabilities_dir())?;
        let keys = AsymmetricKeyPair::<V4>::generate()?;
        let signer = PasetoV4Signer::try_new(keys.secret.as_bytes())?;
        let public_key = root.join("public.key");
        std::fs::write(&public_key, keys.public.as_bytes())?;
        let claims = CapabilityClaims {
            token_id: "ctok_01j0000000e008000000000001".parse()?,
            agent_id: "agt_01j0000000e008000000000001".parse()?,
            session_id: "managed-test".parse()?,
            action_set: vec![
                "code.read".into(),
                "code.write".into(),
                "communication.external.read".into(),
            ],
            resource_scope: "*".into(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        };
        let seed_path = layout.capabilities_dir().join("seed.toml");
        let seed = CapabilitySeed::from_claims(&claims, signer.sign(&claims)?);
        std::fs::write(&seed_path, toml::to_string(&seed)?)?;
        let signing_key_path = root.join("audit.key");
        let key = p256::SecretKey::from_slice(&[1; 32])?;
        std::fs::write(
            &signing_key_path,
            key.to_pkcs8_pem(LineEnding::LF)?.as_bytes(),
        )?;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (connections_tx, connections) = mpsc::channel(16);
        let server = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(AuthorityServiceServer::new(FixtureAuthority {
                    connections: connections_tx,
                }))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
        let mut schema: firma_config_schema::sidecar::SidecarConfig = toml::from_str("")?;
        schema.authority.url = Some(url);
        schema.authority.public_key_path = Some(public_key);
        schema.authority.reconnect_min_backoff = Duration::from_millis(10).try_into()?;
        schema.authority.reconnect_max_backoff = Duration::from_millis(20).try_into()?;
        schema.authority.revocation_readiness_grace = Duration::ZERO;
        schema.capability_seed.paths = vec![seed_path];
        schema.audit.redact_query_params = vec![
            "private_query".to_string(),
            "auth[token]".to_string(),
            "private(query)".to_string(),
            "private?query".to_string(),
        ];
        schema.audit.sink = firma_config_schema::sidecar::AuditSink::File;
        schema.audit.file_path = Some(root.join("audit.jsonl"));
        schema.audit.signing_key_path = Some(signing_key_path);
        configure(&mut schema);
        let config = SidecarConfig::resolve(schema, &layout)?;
        let runtime = build_pipeline_runtime(&layout, &config)?;
        let cancel = CancellationToken::new();
        let handle = spawn_authority_client_publishing(
            &config,
            &runtime,
            cancel.clone(),
            Some(root.join("enforcement.toml")),
        )?;
        let (audit_tx, audit_rx) = mpsc::channel(64);
        let sink = spawn_audit_sink(
            &config,
            audit_rx,
            load_audit_event_builder(&config.audit)?,
            cancel.clone(),
        )?;
        let sink = tokio::spawn(async move {
            let _ = sink.await;
        });
        Ok(Self {
            runtime,
            connections,
            audit_tx,
            directory,
            emitted: 0,
            cancel,
            tasks: vec![server, handle.policy_task, handle.revocation_task, sink],
        })
    }

    pub async fn connection(&mut self) -> anyhow::Result<Connection> {
        tokio::time::timeout(Duration::from_secs(5), self.connections.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing stream connection"))
    }

    pub async fn observe(
        &mut self,
        request: &RawRequest,
    ) -> anyhow::Result<(EnforcementDecision, ExecutionEvent)> {
        let (decision, audit) = self.runtime.pipeline.enforce(request, "managed-test").await;
        Ok((decision, self.audit(audit).await?))
    }

    pub async fn audit(
        &mut self,
        payload: firma_sidecar::audit::AuditPayload,
    ) -> anyhow::Result<ExecutionEvent> {
        self.audit_tx.send(payload).await?;
        self.event().await
    }

    pub async fn event(&mut self) -> anyhow::Result<ExecutionEvent> {
        self.emitted += 1;
        let path = self.directory.path().join("audit.jsonl");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
                if content.ends_with('\n') && content.lines().count() == self.emitted {
                    let line = content
                        .lines()
                        .last()
                        .ok_or_else(|| anyhow::anyhow!("missing event"))?;
                    return serde_json::from_str(line).map_err(anyhow::Error::from);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?
    }

    /// Waits until the published enforcement state names `version`.
    pub async fn published(
        &self,
        version: &str,
    ) -> anyhow::Result<firma_runtime_state::enforcement_state::EnforcementState> {
        let path = self.directory.path().join("enforcement.toml");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(state) = firma_runtime_state::enforcement_state::read(&path)
                    && state.version == version
                {
                    return state;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(anyhow::Error::from)
    }

    pub async fn applied(&mut self, version: &str) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (_, event) = self.observe(&request()).await?;
                if event.bundle_version == version {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        Ok(())
    }
}

pub(super) fn request() -> RawRequest {
    RawRequest {
        method: Method::GET,
        host: Authority::from_static("example.test"),
        path: "/resource?private_query=secret&visible=value".into(),
        headers: HeaderMap::new(),
        body: None,
        is_https: true,
    }
}

pub(super) fn rule(action: &str) -> ActionMappingRule {
    ActionMappingRule {
        method: None,
        host: "example.test".into(),
        path: None,
        action_class: action.into(),
    }
}

pub(super) fn bundle(version: &str, rules: Vec<ActionMappingRule>) -> PolicyBundle {
    PolicyBundle {
        version: version.into(),
        policies: b"permit(principal, action, resource);".to_vec(),
        entity_schema: firma_core::FIRMA_SCHEMA.as_bytes().to_vec(),
        ttl_seconds: 60,
        mappings: Some(ActionMappingSnapshot {
            format_version: 1,
            rules,
            default_protected: true,
        }),
    }
}

pub(super) async fn push(tx: &Updates, bundle: PolicyBundle) -> anyhow::Result<()> {
    tx.send(Ok(PolicyBundleUpdate {
        bundle: Some(bundle),
        updated_at: None,
        policy_set: None,
    }))
    .await?;
    Ok(())
}

/// Captured formatted log output for assertions on emitted events.
#[derive(Clone, Default)]
pub(super) struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("log lock poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Logs {
    pub(super) fn count(&self, text: &str) -> anyhow::Result<usize> {
        let bytes = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("log lock poisoned"))?;
        Ok(String::from_utf8_lossy(&bytes).matches(text).count())
    }

    pub(super) async fn wait(&self, text: &str, count: usize) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.count(text)? < count {
                tokio::task::yield_now().await;
            }
            anyhow::Ok(())
        })
        .await??;
        Ok(())
    }
}
