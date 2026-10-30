#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use firma_audit_schema::{Decision, ExecutionEvent, RunEvidence};
use firma_protobuf::v1::{
    self, StreamEventsResponse,
    audit_service_server::{AuditService, AuditServiceServer},
};
use firma_sidecar::audit::{AuditPayload, AuditSinkError};
use firma_sidecar::authority_client::RunRejection;
use firma_sidecar::authority_client::readiness::{ReadinessFlag, ReadinessState};
use firma_sidecar::authority_tls::AuthorityTls;
use firma_sidecar::config::SidecarConfig;
use firma_sidecar::startup::{load_audit_event_builder, spawn_audit_sink};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use super::legacy_routes::Routes;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type SinkTask = tokio::task::JoinHandle<Result<(), AuditSinkError>>;

pub struct Pending {
    pub event: v1::ExecutionEvent,
    pub key: String,
    reply: oneshot::Sender<Result<Response<StreamEventsResponse>, Status>>,
}

impl Pending {
    pub fn respond(self, result: Result<StreamEventsResponse, Status>) {
        self.reply
            .send(result.map(Response::new))
            .expect("collector response receiver");
    }

    pub fn persist(self) {
        let receipt = StreamEventsResponse {
            last_event_id: self.event.event_id.clone(),
            events_received: 1,
            durably_persisted: true,
        };
        self.respond(Ok(receipt));
    }
}

struct Service {
    sent: mpsc::Sender<Pending>,
    legacy_calls: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl AuditService for Service {
    async fn submit_event(
        &self,
        request: Request<v1::ExecutionEvent>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        let key = request
            .metadata()
            .get("firma-sidecar-psk")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let (reply, receiver) = oneshot::channel();
        self.sent
            .send(Pending {
                event: request.into_inner(),
                key,
                reply,
            })
            .await
            .map_err(|_| Status::unavailable("test collector stopped"))?;
        receiver
            .await
            .map_err(|_| Status::unavailable("test response lost"))?
    }

    async fn stream_events(
        &self,
        _: Request<tonic::Streaming<v1::ExecutionEvent>>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(StreamEventsResponse::default()))
    }
}

pub struct Collector {
    pub url: String,
    received: mpsc::Receiver<Pending>,
    task: tokio::task::JoinHandle<()>,
    pub legacy_calls: Arc<AtomicUsize>,
    unsupported: mpsc::UnboundedReceiver<()>,
}

impl Collector {
    pub fn start() -> TestResult<Self> {
        Self::start_with_routes(false)
    }

    pub fn start_legacy() -> TestResult<Self> {
        Self::start_with_routes(true)
    }

    fn start_with_routes(legacy_only: bool) -> TestResult<Self> {
        let incoming = tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse()?)?;
        let url = format!("http://{}", incoming.local_addr()?);
        let (sent, received) = mpsc::channel(16);
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let service = Service {
            sent,
            legacy_calls: Arc::clone(&legacy_calls),
        };
        let (unsupported_tx, unsupported) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(Routes {
                    inner: AuditServiceServer::new(service),
                    legacy_only,
                    unsupported: unsupported_tx,
                })
                .serve_with_incoming(incoming)
                .await
                .expect("test collector");
        });
        Ok(Self {
            url,
            received,
            task,
            legacy_calls,
            unsupported,
        })
    }

    pub async fn next(&mut self) -> TestResult<Pending> {
        Ok(
            tokio::time::timeout(Duration::from_secs(8), self.received.recv())
                .await?
                .ok_or("collector closed")?,
        )
    }

    pub async fn unsupported_request(&mut self) -> TestResult {
        tokio::time::timeout(Duration::from_secs(5), self.unsupported.recv())
            .await?
            .ok_or("collector closed")?;
        Ok(())
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct Fixture {
    pub root: tempfile::TempDir,
    pub wal: PathBuf,
    pub key: PathBuf,
    pub config: SidecarConfig,
}

/// The variable a runtime-authenticated fixture's Sidecar reads its
/// credential from; set once per test process, read by this crate alone.
pub const RUNTIME_CREDENTIAL_ENV: &str = "FIRMA_TEST_AUDIT_RUNTIME_CREDENTIAL";

impl Fixture {
    pub async fn new(endpoint: &str) -> TestResult<Self> {
        Self::with_options(endpoint, "", None).await
    }

    /// Like [`Self::new`], with `audit_settings` appended to `[audit]`.
    pub async fn with_audit(endpoint: &str, audit_settings: &str) -> TestResult<Self> {
        Self::with_options(endpoint, audit_settings, None).await
    }

    /// A Sidecar authenticating as `run_id` with a runtime credential.
    pub async fn for_run(endpoint: &str, run_id: &str) -> TestResult<Self> {
        Self::with_options(endpoint, "", Some(run_id)).await
    }

    async fn with_options(
        endpoint: &str,
        audit_settings: &str,
        run_id: Option<&str>,
    ) -> TestResult<Self> {
        let root = tempfile::tempdir()?;
        let wal = root.path().join("audit.jsonl");
        let key = root.path().join("psk");
        std::fs::write(&key, "original-key")?;
        let signing = root.path().join("audit.pem");
        std::fs::write(&signing, rcgen::KeyPair::generate()?.serialize_pem())?;
        let credentials = run_id.map_or_else(
            || format!("pre_shared_key_path = '{}'", key.display()),
            |run_id| {
                // Each nextest test is its own process; the name is this
                // crate's alone, so no other reader races the write.
                #[expect(unsafe_code, reason = "test-private variable in a single-test process")]
                // SAFETY: nothing else in this process reads or writes the
                // environment concurrently with this single-threaded setup.
                unsafe {
                    std::env::set_var(RUNTIME_CREDENTIAL_ENV, "runtime-credential-value");
                }
                format!(
                    "run_id = \"{run_id}\"\nruntime_credential_env = \"{RUNTIME_CREDENTIAL_ENV}\""
                )
            },
        );
        std::fs::write(
            root.path().join("sidecar.toml"),
            format!(
                r#"
[audit]
sink = "wal"
grpc_url = '{endpoint}'
wal_path = '{}'
wal_max_size = "1 MiB"
signing_key_path = '{}'
{audit_settings}
[authority]
url = '{endpoint}'
[authority.credentials]
workspace_id = "workspace-a"
sidecar_id = "sidecar-a"
{credentials}
"#,
                wal.display(),
                signing.display(),
            ),
        )?;
        let config = Self::load_config(root.path())?;
        let wal = match run_id {
            Some(id) => wal.with_file_name(format!("audit.jsonl.{id}")),
            None => wal,
        };
        let fixture = Self {
            root,
            wal,
            key,
            config,
        };
        let (tx, task, _) = fixture.start()?;
        drop(tx);
        finish(task).await?;
        Ok(fixture)
    }

    /// The Sidecar's configuration file, for a test to edit.
    pub fn config_path(&self) -> PathBuf {
        self.root.path().join("sidecar.toml")
    }

    /// The journal's scope file.
    pub fn scope_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.scope", self.wal.display()))
    }

    /// Reloads the configuration after a test edited the file.
    pub fn reload_config(&mut self) -> TestResult {
        self.config = Self::load_config(self.root.path())?;
        Ok(())
    }

    fn load_config(root: &std::path::Path) -> TestResult<SidecarConfig> {
        Ok(SidecarConfig::load_from_path(
            &root.join("sidecar.toml"),
            &firma_runtime_state::RuntimeLayout::from_root(root),
        )?)
    }

    pub fn start(&self) -> TestResult<(mpsc::Sender<AuditPayload>, SinkTask, CancellationToken)> {
        let (tx, task, cancel, _readiness) = self.start_with_readiness()?;
        Ok((tx, task, cancel))
    }

    /// Like [`Self::start`], also returning the readiness a run rejection
    /// marks.
    pub fn start_with_readiness(
        &self,
    ) -> TestResult<(
        mpsc::Sender<AuditPayload>,
        SinkTask,
        CancellationToken,
        Arc<ReadinessFlag>,
    )> {
        let builder = load_audit_event_builder(&self.config.audit)?;
        let (tx, rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        let readiness = Arc::new(ReadinessFlag::new(ReadinessState::default()).0);
        let task = spawn_audit_sink(
            &self.config,
            &AuthorityTls::read(&self.config.authority)?,
            rx,
            builder,
            cancel.clone(),
            RunRejection::new(Arc::clone(&readiness), cancel.clone()),
        )?;
        Ok((tx, task, cancel, readiness))
    }

    pub fn seed(&self, events: &[ExecutionEvent]) -> TestResult<Vec<u8>> {
        let mut bytes = Vec::new();
        for event in events {
            serde_json::to_writer(&mut bytes, event)?;
            bytes.push(b'\n');
        }
        std::fs::write(&self.wal, &bytes)?;
        Ok(bytes)
    }

    pub fn archive(&self) -> PathBuf {
        self.root.path().join("audit.jsonl.rejected.jsonl")
    }

    pub async fn payload(&self) -> TestResult<AuditPayload> {
        Ok(super::super::pipeline_fixture::audit_payload().await?)
    }
}

pub async fn finish(task: SinkTask) -> TestResult {
    tokio::time::timeout(Duration::from_secs(6), task).await???;
    Ok(())
}

pub fn event(id: &str, evidence: Option<&[u8]>) -> ExecutionEvent {
    ExecutionEvent {
        event_id: id.to_owned(),
        session_id: format!("session-{id}"),
        token_id: String::new(),
        agent_id: "agent-shared".to_owned(),
        action: "communication.internal.send".to_owned(),
        resource: "https://example.test/message".to_owned(),
        decision: Decision::Allow,
        deny_reason: String::new(),
        enforcement_latency_us: 42,
        context_hash: "hash".to_owned(),
        bundle_version: "1".to_owned(),
        timestamp: Some(1_700_000_000_000_000_000),
        dispatch_status: 200,
        dispatch_latency_us: 7,
        response_size: 3,
        sandbox_id: format!("sandbox-{id}"),
        provenance: String::new(),
        thread_id: String::new(),
        parent_action_id: String::new(),
        signature: vec![1, 2, 3],
        run_evidence: evidence.map(|bytes| RunEvidence(bytes.to_vec())),
    }
}
