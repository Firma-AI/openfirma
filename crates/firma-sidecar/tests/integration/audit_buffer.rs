//! Regression coverage for acknowledged audit-buffer replay through startup.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use firma_config_schema::sidecar::audit::{AuditConfig as SchemaAuditConfig, AuditSink};
use firma_config_utils::NonZeroDuration;
use firma_protobuf::v1::audit_service_server::{AuditService, AuditServiceServer};
use firma_protobuf::v1::{ExecutionEvent as ProtoEvent, StreamEventsResponse};
use firma_runtime_state::RuntimeLayout;
use firma_sidecar::audit::{AuditPayload, AuditSinkError, Decision, ExecutionEvent};
use firma_sidecar::authority_tls::AuthorityTls;
use firma_sidecar::config::SidecarConfig;
use firma_sidecar::startup::{load_audit_event_builder, spawn_audit_sink};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

struct PartialAudit {
    calls: Arc<AtomicUsize>,
    stall: bool,
}

#[tonic::async_trait]
impl AuditService for PartialAudit {
    async fn submit_event(
        &self,
        _request: Request<ProtoEvent>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        Err(Status::unimplemented("legacy collector"))
    }

    async fn stream_events(
        &self,
        request: Request<Streaming<ProtoEvent>>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        let mut stream = request.into_inner();
        let Some(first) = stream.message().await? else {
            return Ok(Response::new(StreamEventsResponse {
                last_event_id: String::new(),
                events_received: 0,
                durably_persisted: false,
            }));
        };
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.stall {
            std::future::pending::<()>().await;
        }
        // A successful RPC may acknowledge fewer records than the batch.
        // The second record has not been consumed or persisted.
        Ok(Response::new(StreamEventsResponse {
            last_event_id: first.event_id,
            events_received: 1,
            durably_persisted: false,
        }))
    }
}

fn event(id: &str) -> ExecutionEvent {
    ExecutionEvent {
        event_id: id.to_owned(),
        session_id: "sess-1".parse().expect("session id"),
        token_id: "ctok_01j0000000e008000000000001".parse().expect("token id"),
        agent_id: "agt_01j0000000e008000000000001".parse().expect("agent id"),
        action: "http_get".to_owned(),
        resource: "https://example.com".to_owned(),
        decision: Decision::Allow,
        deny_reason: String::new(),
        enforcement_latency_us: 1,
        context_hash: String::new(),
        bundle_version: String::new(),
        timestamp: None,
        dispatch_status: 0,
        dispatch_latency_us: 0,
        response_size: 0,
        sandbox_id: String::new(),
        provenance: String::new(),
        thread_id: String::new(),
        parent_action_id: String::new(),
        signature: Vec::new(),
        run_evidence: None,
    }
}

fn buffered_ids(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .expect("read buffer")
        .lines()
        .map(|line| {
            serde_json::from_str::<ExecutionEvent>(line)
                .expect("buffer event")
                .event_id
        })
        .collect()
}

fn spawn_buffer_sink(
    dir: &Path,
    buffer_path: &Path,
    address: SocketAddr,
    exit: CancellationToken,
) -> JoinHandle<Result<(), AuditSinkError>> {
    spawn_configured_buffer_sink(dir, buffer_path, address, exit, None)
}

fn spawn_configured_buffer_sink(
    dir: &Path,
    buffer_path: &Path,
    address: SocketAddr,
    exit: CancellationToken,
    credentials: Option<firma_config_schema::sidecar::authority::SidecarCredentials>,
) -> JoinHandle<Result<(), AuditSinkError>> {
    let audit = SchemaAuditConfig::default();
    let (_payload_tx, sink) =
        start_buffer_sink(dir, buffer_path, address, exit, audit, credentials);
    sink
}

/// Starts the `grpc` sink from `audit` and returns its payload sender. The
/// sink, URL, buffer, and signing key fields of `audit` are filled in here.
fn start_buffer_sink(
    dir: &Path,
    buffer_path: &Path,
    address: SocketAddr,
    exit: CancellationToken,
    audit: SchemaAuditConfig,
    credentials: Option<firma_config_schema::sidecar::authority::SidecarCredentials>,
) -> (
    mpsc::Sender<AuditPayload>,
    JoinHandle<Result<(), AuditSinkError>>,
) {
    let signing_key = p256::SecretKey::generate();
    let key_path = dir.join("signing.pem");
    std::fs::write(
        &key_path,
        signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("PEM key")
            .as_bytes(),
    )
    .expect("write signing key");
    // `AuditConfig` is only built by resolving a whole Sidecar config against
    // a state directory, so the sink under test is wired exactly as startup
    // wires it.
    // Built by parsing a config section rather than by naming the schema's
    // fields: the sink under test is reached the way an operator's file reaches
    // it, and the serializer handles path quoting on every platform.
    let audit = SchemaAuditConfig {
        sink: AuditSink::Grpc,
        grpc_url: Some(format!("http://{address}")),
        buffer_path: Some(buffer_path.to_owned()),
        signing_key_path: Some(key_path),
        ..audit
    };
    // The audit service is the Authority's own, so the credentials go with
    // the events.
    let authority = firma_config_schema::sidecar::authority::AuthorityConfig {
        url: Some(format!("http://{address}")),
        credentials,
        ..Default::default()
    };
    let section = toml::to_string(&toml::Table::from_iter([
        (
            "audit".to_owned(),
            toml::Value::try_from(&audit).expect("audit section serializes"),
        ),
        (
            "authority".to_owned(),
            toml::Value::try_from(&authority).expect("authority section serializes"),
        ),
    ]))
    .expect("sidecar config serializes");
    let schema: firma_config_schema::sidecar::SidecarConfig =
        toml::from_str(&section).expect("audit section parses as a sidecar config");
    let config = SidecarConfig::resolve(schema, &RuntimeLayout::from_root(dir))
        .expect("valid sidecar config");
    let builder = load_audit_event_builder(&config.audit).expect("event builder");
    let (payload_tx, payload_rx) = mpsc::channel(1);
    let sink = spawn_audit_sink(
        &config,
        &AuthorityTls::read(&config.authority).expect("authority TLS"),
        payload_rx,
        builder,
        exit.clone(),
        crate::test_rejection(exit),
    )
    .expect("spawn sink");
    (payload_tx, sink)
}

struct MetadataAudit {
    requests: mpsc::UnboundedSender<tonic::metadata::MetadataMap>,
}

#[tonic::async_trait]
impl AuditService for MetadataAudit {
    async fn submit_event(
        &self,
        _request: Request<ProtoEvent>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        Err(Status::unimplemented("legacy collector"))
    }

    async fn stream_events(
        &self,
        request: Request<Streaming<ProtoEvent>>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        self.requests
            .send(request.metadata().clone())
            .expect("test receiver");
        let mut stream = request.into_inner();
        let mut receipt = StreamEventsResponse::default();
        while let Some(event) = stream.message().await? {
            receipt.last_event_id = event.event_id;
            receipt.events_received += 1;
        }
        Ok(Response::new(receipt))
    }
}

#[tokio::test]
async fn configured_credentials_authenticate_replay_and_live_streams() {
    let dir = tempfile::tempdir().expect("temporary audit directory");
    let buffer = dir.path().join("buffer.jsonl");
    std::fs::write(
        &buffer,
        format!("{}\n", serde_json::to_string(&event("replay")).unwrap()),
    )
    .unwrap();
    let psk = dir.path().join("sidecar.psk");
    std::fs::write(&psk, "audit-test-psk\n").unwrap();
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = incoming.local_addr().unwrap();
    let (requests, mut observed) = mpsc::unbounded_channel();
    let stop = CancellationToken::new();
    let server = tokio::spawn(
        Server::builder()
            .add_service(AuditServiceServer::new(MetadataAudit { requests }))
            .serve_with_incoming_shutdown(incoming, stop.clone().cancelled_owned()),
    );
    let exit = CancellationToken::new();
    let sink = spawn_configured_buffer_sink(
        dir.path(),
        &buffer,
        address,
        exit.clone(),
        Some(
            firma_config_schema::sidecar::authority::SidecarCredentials {
                workspace_id: "workspace-a".into(),
                sidecar_id: "sidecar-a".into(),
                pre_shared_key_env: None,
                pre_shared_key_path: Some(psk),
                run_id: None,
                runtime_credential_env: None,
            },
        ),
    );
    for phase in ["replay", "live"] {
        let metadata = tokio::time::timeout(Duration::from_secs(10), observed.recv())
            .await
            .expect(phase)
            .expect("stream opened");
        assert_eq!(
            metadata.get("firma-workspace-id").unwrap(),
            "workspace-a",
            "{phase}"
        );
        assert_eq!(
            metadata.get("firma-sidecar-id").unwrap(),
            "sidecar-a",
            "{phase}"
        );
        assert_eq!(
            metadata.get("firma-sidecar-psk").unwrap(),
            "audit-test-psk",
            "{phase}"
        );
    }
    assert_eq!(std::fs::read_to_string(&buffer).unwrap(), "");
    exit.cancel();
    tokio::time::timeout(Duration::from_secs(10), sink)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn buffered_evidence_is_retained_without_opening_a_legacy_stream() {
    for evidence in [Vec::new(), b"unsupported evidence".to_vec()] {
        let dir = tempfile::tempdir().unwrap();
        let buffer = dir.path().join("buffer.jsonl");
        let mut retained = event("evidence");
        retained.run_evidence = Some(firma_audit_schema::RunEvidence(evidence));
        let bytes = format!("{}\n", serde_json::to_string(&retained).unwrap());
        std::fs::write(&buffer, &bytes).unwrap();
        let incoming =
            tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = incoming.local_addr().unwrap();
        let (requests, mut observed) = mpsc::unbounded_channel();
        let stop = CancellationToken::new();
        let server = tokio::spawn(
            Server::builder()
                .add_service(AuditServiceServer::new(MetadataAudit { requests }))
                .serve_with_incoming_shutdown(incoming, stop.clone().cancelled_owned()),
        );
        let sink = spawn_buffer_sink(dir.path(), &buffer, address, CancellationToken::new());
        let error = tokio::time::timeout(Duration::from_secs(10), sink)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, AuditSinkError::ServerError(_)));
        insta::allow_duplicates! {
            insta::assert_snapshot!(error, @"server error: run evidence requires the wal audit sink; buffered grpc uses the legacy RPC");
        }
        assert_eq!(std::fs::read_to_string(&buffer).unwrap(), bytes);
        assert_eq!(
            observed.try_recv().unwrap_err(),
            mpsc::error::TryRecvError::Empty
        );
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn partial_acknowledgment_does_not_delete_unpersisted_buffered_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("audit.jsonl");
    let contents = format!(
        "{}\n{}\n",
        serde_json::to_string(&event("first")).expect("serialize first"),
        serde_json::to_string(&event("second")).expect("serialize second")
    );
    std::fs::write(&buffer_path, contents).expect("seed buffer");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(AuditServiceServer::new(PartialAudit {
                calls: server_calls,
                stall: false,
            }))
            .serve(address)
            .await
            .expect("serve audit");
    });

    let exit = CancellationToken::new();
    let sink = spawn_buffer_sink(dir.path(), &buffer_path, address, exit.clone());

    tokio::time::timeout(Duration::from_secs(5), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("collector received the first event");
    exit.cancel();
    tokio::time::timeout(Duration::from_secs(5), sink)
        .await
        .expect("sink shutdown")
        .expect("sink task")
        .expect("sink result");
    server.abort();

    assert_eq!(
        buffered_ids(&buffer_path),
        ["first", "second"],
        "a partial acknowledgment must not erase events the collector did not persist"
    );
}

#[tokio::test]
async fn stalled_replay_does_not_prevent_sink_shutdown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("audit.jsonl");
    std::fs::write(
        &buffer_path,
        format!(
            "{}\n",
            serde_json::to_string(&event("pending")).expect("serialize")
        ),
    )
    .expect("seed buffer");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(AuditServiceServer::new(PartialAudit {
                calls: server_calls,
                stall: true,
            }))
            .serve(address)
            .await
            .expect("serve audit");
    });
    let exit = CancellationToken::new();
    let mut sink = spawn_buffer_sink(dir.path(), &buffer_path, address, exit.clone());

    tokio::time::timeout(Duration::from_secs(5), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("collector received replay event");
    exit.cancel();
    let stopped = tokio::time::timeout(Duration::from_millis(500), &mut sink).await;
    sink.abort();
    server.abort();

    assert!(stopped.is_ok(), "cancellation must stop a stalled replay");
    assert_eq!(buffered_ids(&buffer_path), ["pending"]);
}

/// A collector that accepts a replay and never acknowledges it must not hold
/// the sink forever: `audit.replay_ack_timeout` bounds the wait, so live
/// traffic that queued behind the replay still reaches the buffer.
#[tokio::test]
async fn unacknowledged_replay_still_buffers_live_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("audit.jsonl");
    std::fs::write(
        &buffer_path,
        format!(
            "{}\n",
            serde_json::to_string(&event("pending")).expect("serialize")
        ),
    )
    .expect("seed buffer");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(AuditServiceServer::new(PartialAudit {
                calls: server_calls,
                stall: true,
            }))
            .serve(address)
            .await
            .expect("serve audit");
    });
    // Waiting out the bound is what proves it exists; a short one keeps that cheap.
    let audit = SchemaAuditConfig {
        replay_ack_timeout: NonZeroDuration::new(Duration::from_secs(2)).expect("non-zero"),
        ..SchemaAuditConfig::default()
    };
    let exit = CancellationToken::new();
    let (payload_tx, sink) =
        start_buffer_sink(dir.path(), &buffer_path, address, exit.clone(), audit, None);

    tokio::time::timeout(Duration::from_secs(5), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("collector received replay event");
    // The sink is one task, so it consumes this only once the acknowledgment
    // wait resolves.
    let payload = super::pipeline_fixture::audit_payload()
        .await
        .expect("audit payload");
    payload_tx.send(payload).await.expect("enqueue payload");

    // Above the configured bound and below the 30 s default, so a sink that
    // ignored the configuration fails here rather than merely running slowly.
    let buffered = tokio::time::timeout(Duration::from_secs(15), async {
        while buffered_ids(&buffer_path).len() < 2 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    exit.cancel();
    drop(payload_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), sink).await;
    server.abort();

    assert!(
        buffered.is_ok(),
        "a replay the collector never acknowledges must not stop live events \
         from reaching the buffer"
    );
    assert_eq!(buffered_ids(&buffer_path)[0], "pending");
}

#[tokio::test]
async fn unparseable_only_buffer_is_discarded_once_connected() {
    // Lines no sink version can parse can never be replayed or acknowledged;
    // keeping them means re-reading and re-warning on every reconnect while
    // the garbage occupies the bounded buffer forever. No live traffic flows
    // in this test, so nothing can truncate the file as a replay side effect:
    // only the sink discarding the garbage itself makes this pass.
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("audit.jsonl");
    std::fs::write(&buffer_path, "not-json\n{still: not json}\n").expect("seed garbage");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(AuditServiceServer::new(PartialAudit {
                calls: Arc::new(AtomicUsize::new(0)),
                stall: false,
            }))
            .serve(address)
            .await
            .expect("serve audit");
    });

    let exit = CancellationToken::new();
    let sink = spawn_buffer_sink(dir.path(), &buffer_path, address, exit.clone());

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let discarded = std::fs::read_to_string(&buffer_path)
                .is_ok_and(|contents| contents.lines().next().is_none());
            if discarded {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("unparseable buffer content must be discarded once connected");
    exit.cancel();
    tokio::time::timeout(Duration::from_secs(5), sink)
        .await
        .expect("sink shutdown")
        .expect("sink task")
        .expect("sink result");
    server.abort();
}

/// Legacy buffers carry no execution provenance, so runtime authentication
/// must be refused before a pre-existing buffer can be opened or replayed.
#[test]
fn runtime_credentials_reject_legacy_grpc_buffering_before_startup() {
    use firma_sidecar::config::{AuditConfigError, SidecarConfigError};

    let dir = tempfile::tempdir().expect("tempdir");
    let buffer = dir.path().join("buffer.jsonl");
    let original = b"{\"event_id\":\"old-execution\"}\n{\"torn";
    std::fs::write(&buffer, original).expect("old buffer");
    let mut schema = firma_config_schema::sidecar::SidecarConfig::default();
    schema.authority.url = Some("http://127.0.0.1:50051".into());
    schema.authority.credentials = Some(
        firma_config_schema::sidecar::authority::SidecarCredentials {
            workspace_id: "workspace-a".into(),
            sidecar_id: "sidecar-b".into(),
            pre_shared_key_env: None,
            pre_shared_key_path: None,
            run_id: Some("run_01j0000000e008000000000002".into()),
            runtime_credential_env: Some("CARGO_PKG_NAME".into()),
        },
    );
    schema.audit = SchemaAuditConfig {
        sink: firma_config_schema::sidecar::audit::AuditSink::Grpc,
        grpc_url: Some("http://127.0.0.1:50051".into()),
        buffer_path: Some(buffer.clone()),
        ..SchemaAuditConfig::default()
    };
    let error = firma_sidecar::config::SidecarConfig::resolve(
        schema,
        &firma_runtime_state::RuntimeLayout::from_root(dir.path()),
    )
    .expect_err("runtime grpc is unsupported");
    assert!(matches!(
        error,
        SidecarConfigError::Audit(AuditConfigError::RuntimeGrpcUnsupported)
    ));
    assert_eq!(
        error.to_string(),
        "audit: runtime credentials do not support audit.sink = grpc; use wal instead"
    );
    assert_eq!(std::fs::read(buffer).expect("retained buffer"), original);
}
