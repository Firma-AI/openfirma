//! What an `https` audit sink sends to whom: at the Authority's own origin the
//! Authority's CA verifies the service, and the Sidecar's mTLS identity and
//! credentials go with the events; any other host is verified against the
//! platform's roots and gets neither.
//!
//! The audit service terminates TLS itself and asks for a client certificate,
//! so what the sink trusted and presented is observed at the handshake rather
//! than inferred from silence. The platform's roots come from `SSL_CERT_FILE`,
//! so the test of another host they trust runs in a child of this test binary
//! whose `SSL_CERT_FILE` names a test CA.

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "test code")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use firma_config_schema::sidecar::audit::{AuditConfig as SchemaAuditConfig, AuditSink};
use firma_protobuf::v1::audit_service_server::{AuditService, AuditServiceServer};
use firma_protobuf::v1::{ExecutionEvent as ProtoEvent, StreamEventsResponse};
use firma_runtime_state::RuntimeLayout;
use firma_sidecar::audit::{AuditPayload, AuditSinkError, Decision, ExecutionEvent};
use firma_sidecar::authority_tls::AuthorityTls;
use firma_sidecar::config::SidecarConfig;
use firma_sidecar::startup::{load_audit_event_builder, spawn_audit_sink};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use rcgen::{CertificateParams, Issuer, KeyPair, SanType};
use rustls::pki_types::pem::PemObject as _;

use super::authority_trust::certificate_authority;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{AlertDescription, Error as TlsError, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::task::JoinHandle;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status, Streaming};

const EVENT_ID: &str = "buffered-before-start";
/// Set in the child process to the directory holding the platform CA.
const CHILD_DIR: &str = "FIRMA_TEST_AUDIT_TRUST_DIR";
/// The test the child runs, by its path in this binary.
const CHILD_TEST: &str =
    "audit_tls::the_platform_roots_verify_another_origin_which_gets_nothing_of_the_authority";

#[tokio::test]
async fn the_authority_ca_verifies_an_audit_url_at_the_authority_origin() {
    let mut fixture = Fixture::start(ServerTrust::AuthorityCa).await;
    let (sink, exit) = fixture.spawn_sink(AuditSink::Grpc, Origin::Authority);

    assert_eq!(
        fixture.handshake().await,
        Handshake::Completed {
            client_certificate: true
        }
    );
    assert_eq!(
        fixture.received().await,
        (EVENT_ID.to_owned(), Credentials::Present)
    );
    fixture.stop(sink, exit).await;
}

/// The sink of a managed run, which `firma run --agent` points at the
/// Authority's own origin.
#[tokio::test]
async fn the_authority_ca_verifies_the_wal_sink_at_the_authority_origin() {
    let mut fixture = Fixture::start(ServerTrust::AuthorityCa).await;
    let (sink, exit) = fixture.spawn_sink(AuditSink::Wal, Origin::Authority);
    let payload = crate::pipeline_fixture::audit_payload()
        .await
        .expect("audit payload");
    fixture
        .payload_tx
        .send(payload)
        .await
        .expect("the sink accepts a payload");

    assert_eq!(
        fixture.handshake().await,
        Handshake::Completed {
            client_certificate: true
        }
    );
    let (event_id, credentials) = fixture.received().await;
    assert_ne!(event_id, "");
    assert_eq!(credentials, Credentials::Present);
    fixture.stop(sink, exit).await;
}

#[tokio::test]
async fn the_platform_roots_verify_an_audit_url_at_another_origin() {
    let mut fixture = Fixture::start(ServerTrust::AuthorityCa).await;
    let (sink, exit) = fixture.spawn_sink(AuditSink::Grpc, Origin::Other);

    assert_eq!(
        fixture.handshake().await,
        Handshake::Refused(TlsError::AlertReceived(AlertDescription::UnknownCA)),
        "the Authority's CA is not applied, and the platform's roots never issued this certificate"
    );
    assert_eq!(fixture.events.try_recv(), Err(TryRecvError::Empty));
    fixture.stop(sink, exit).await;
    assert_eq!(
        buffered_ids(&fixture.buffer),
        [EVENT_ID],
        "an event the sink could not deliver stays buffered"
    );
}

/// Another origin the platform's roots do trust completes the handshake, and
/// receives the events without the Sidecar's client certificate or its
/// credentials. The platform's roots are a test CA named by `SSL_CERT_FILE`
/// in a child of this binary.
#[tokio::test]
async fn the_platform_roots_verify_another_origin_which_gets_nothing_of_the_authority() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        run_in_a_child_whose_platform_roots_trust_the_server();
        return;
    };
    let platform = Path::new(&dir).join("platform-ca.pem");
    let mut fixture = Fixture::start(ServerTrust::PlatformRoots(platform)).await;
    let (sink, exit) = fixture.spawn_sink(AuditSink::Grpc, Origin::Other);

    assert_eq!(
        fixture.handshake().await,
        Handshake::Completed {
            client_certificate: false
        },
        "the platform's roots verify the service, and the Authority's identity is not presented"
    );
    assert_eq!(
        fixture.received().await,
        (EVENT_ID.to_owned(), Credentials::Absent)
    );
    fixture.stop(sink, exit).await;
}

/// Write a platform CA and its key where the child can find them, name it as
/// the platform's roots through `SSL_CERT_FILE`, and run the test there.
fn run_in_a_child_whose_platform_roots_trust_the_server() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let (ca_pem, issuer) = certificate_authority("Platform CA");
    std::fs::write(dir.path().join("platform-ca.pem"), ca_pem).expect("write platform CA");
    std::fs::write(
        dir.path().join("platform-ca-key.pem"),
        issuer.key().serialize_pem(),
    )
    .expect("write platform CA key");

    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", CHILD_TEST])
        .env(CHILD_DIR, dir.path())
        .env("SSL_CERT_FILE", dir.path().join("platform-ca.pem"))
        .env_remove("SSL_CERT_DIR")
        .output()
        .expect("run the test in a child process");

    assert!(
        output.status.success(),
        "the child test failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "the child must have run the test:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Where the Authority is, relative to the audit service.
#[derive(Clone, Copy)]
enum Origin {
    /// The audit service is the Authority's own origin.
    Authority,
    /// The Authority is on another loopback port, which nothing listens at.
    Other,
}

/// Who issued the audit service's certificate.
enum ServerTrust {
    /// The CA the Authority configuration names.
    AuthorityCa,
    /// A CA at this path, which the platform's roots consist of in the child
    /// process; the Authority configuration names an unrelated CA.
    PlatformRoots(PathBuf),
}

/// The outcome of one TLS handshake with the audit service.
#[derive(Debug, PartialEq)]
enum Handshake {
    /// Completed, with or without a client certificate from the sink.
    Completed { client_certificate: bool },
    /// The client ended the handshake with this error.
    Refused(TlsError),
}

/// Whether a request to the audit service carried the Sidecar's credentials.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Credentials {
    Present,
    Absent,
}

/// An audit service behind TLS on a loopback port, with a certificate for
/// `127.0.0.1` issued by a test CA that the Authority configuration names as
/// its own.
struct Fixture {
    dir: tempfile::TempDir,
    buffer: std::path::PathBuf,
    address: SocketAddr,
    /// Bound so the other origin's port is nobody else's.
    other_origin: TcpListener,
    handshakes: mpsc::UnboundedReceiver<Handshake>,
    events: mpsc::UnboundedReceiver<(String, Credentials)>,
    server: Server,
    /// The sink's payload channel, kept open until the test ends.
    payload_tx: mpsc::Sender<AuditPayload>,
}

impl Fixture {
    async fn start(trust: ServerTrust) -> Self {
        let dir = tempfile::tempdir().expect("temporary directory");
        let (authority_ca_pem, authority_issuer) = certificate_authority("Authority test CA");
        std::fs::write(dir.path().join("authority-ca.pem"), authority_ca_pem).expect("write CA");
        let server_issuer = match trust {
            ServerTrust::AuthorityCa => authority_issuer,
            ServerTrust::PlatformRoots(ca) => {
                let key = std::fs::read_to_string(ca.with_file_name("platform-ca-key.pem"))
                    .expect("read platform CA key");
                let ca = std::fs::read_to_string(ca).expect("read platform CA");
                let key = KeyPair::from_pem(&key).expect("platform CA key");
                Issuer::from_ca_cert_pem(&ca, key).expect("platform CA")
            }
        };
        let server_key = KeyPair::generate().expect("server key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let server_cert = params
            .signed_by(&server_key, &server_issuer)
            .expect("server certificate");
        // The Sidecar's mTLS identity, which the audit service accepts but does
        // not require.
        let (client_ca_pem, client_issuer) = certificate_authority("Client test CA");
        let client_key = KeyPair::generate().expect("client key");
        let client_cert = CertificateParams::new(vec!["sidecar.test".to_owned()])
            .expect("client params")
            .signed_by(&client_key, &client_issuer)
            .expect("client certificate");
        std::fs::write(dir.path().join("client.pem"), client_cert.pem()).expect("write cert");
        std::fs::write(
            dir.path().join("client-key.pem"),
            client_key.serialize_pem(),
        )
        .expect("write key");
        std::fs::write(dir.path().join("psk"), "pre-shared-key").expect("write PSK");
        let buffer = dir.path().join("buffer.jsonl");
        std::fs::write(
            &buffer,
            format!("{}\n", serde_json::to_string(&event(EVENT_ID)).unwrap()),
        )
        .expect("write buffer");

        let (address, handshakes, events, server) = serve_tls(
            server_cert.pem().as_bytes(),
            server_key.serialize_pem().as_bytes(),
            client_ca_pem.as_bytes(),
        )
        .await;
        let other_origin = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let (payload_tx, _) = mpsc::channel(1);
        Self {
            dir,
            buffer,
            address,
            other_origin,
            handshakes,
            events,
            server,
            payload_tx,
        }
    }

    /// Starts `sink` at the audit service, with the Authority at `origin`
    /// verified by the test CA, through the same config resolution and
    /// startup as production.
    fn spawn_sink(
        &mut self,
        sink: AuditSink,
        origin: Origin,
    ) -> (JoinHandle<Result<(), AuditSinkError>>, CancellationToken) {
        let signing_key = p256::SecretKey::generate();
        let key_path = self.dir.path().join("signing.pem");
        std::fs::write(
            &key_path,
            signing_key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("PEM key")
                .as_bytes(),
        )
        .expect("write signing key");
        let authority_address = match origin {
            Origin::Authority => self.address,
            Origin::Other => self.other_origin.local_addr().expect("local address"),
        };
        let audit = SchemaAuditConfig {
            sink,
            grpc_url: Some(format!("https://{}", self.address)),
            buffer_path: Some(self.buffer.clone()),
            wal_path: Some(self.dir.path().join("audit.wal")),
            signing_key_path: Some(key_path),
            ..SchemaAuditConfig::default()
        };
        let authority = firma_config_schema::sidecar::authority::AuthorityConfig {
            url: Some(format!("https://{authority_address}")),
            ca_cert_paths: vec![self.dir.path().join("authority-ca.pem")],
            tls_client_cert_path: Some(self.dir.path().join("client.pem")),
            tls_client_key_path: Some(self.dir.path().join("client-key.pem")),
            credentials: Some(
                firma_config_schema::sidecar::authority::SidecarCredentials {
                    workspace_id: "workspace-a".to_owned(),
                    sidecar_id: "sidecar-a".to_owned(),
                    pre_shared_key_path: Some(self.dir.path().join("psk")),
                    pre_shared_key_env: None,
                    run_id: None,
                    runtime_credential_env: None,
                },
            ),
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
            toml::from_str(&section).expect("sections parse as a sidecar config");
        let config = SidecarConfig::resolve(schema, &RuntimeLayout::from_root(self.dir.path()))
            .expect("valid sidecar config");
        let builder = load_audit_event_builder(&config.audit).expect("event builder");
        let (payload_tx, payload_rx) = mpsc::channel(1);
        self.payload_tx = payload_tx;
        let exit = CancellationToken::new();
        let sink = spawn_audit_sink(
            &config,
            &AuthorityTls::read(&config.authority).expect("authority TLS"),
            payload_rx,
            builder,
            exit.clone(),
        )
        .expect("spawn sink");
        (sink, exit)
    }

    async fn handshake(&mut self) -> Handshake {
        tokio::time::timeout(Duration::from_secs(10), self.handshakes.recv())
            .await
            .expect("a handshake within the timeout")
            .expect("the server is running")
    }

    async fn received(&mut self) -> (String, Credentials) {
        tokio::time::timeout(Duration::from_secs(10), self.events.recv())
            .await
            .expect("an event within the timeout")
            .expect("the server is running")
    }

    async fn stop(&self, sink: JoinHandle<Result<(), AuditSinkError>>, exit: CancellationToken) {
        exit.cancel();
        tokio::time::timeout(Duration::from_secs(10), sink)
            .await
            .expect("the sink exits")
            .expect("the sink task completes")
            .expect("the sink exits cleanly");
        self.server.accept.abort();
        self.server.serve.abort();
    }
}

/// The tasks of the audit test server.
struct Server {
    accept: JoinHandle<()>,
    serve: JoinHandle<()>,
}

/// Serves the audit service over TLS on a loopback port, asking for a client
/// certificate issued by `client_ca_pem` without requiring one. Reports each
/// handshake's outcome and, for each event the service receives, its id and
/// whether the request carried the Sidecar's credentials.
async fn serve_tls(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: &[u8],
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<Handshake>,
    mpsc::UnboundedReceiver<(String, Credentials)>,
    Server,
) {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("server certificate");
    let key = PrivateKeyDer::from_pem_slice(key_pem).expect("server key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_roots = RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(client_ca_pem) {
        client_roots
            .add(ca.expect("client CA"))
            .expect("client root");
    }
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider.clone())
            .allow_unauthenticated()
            .build()
            .expect("client verifier");
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .expect("server TLS config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let (handshakes_tx, handshakes) = mpsc::unbounded_channel();
    let (connections_tx, connections) = mpsc::channel::<Result<Accepted, std::io::Error>>(4);
    let accept = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    let _ = handshakes_tx.send(Handshake::Completed {
                        client_certificate: tls.get_ref().1.peer_certificates().is_some(),
                    });
                    if connections_tx.send(Ok(Accepted(tls))).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let tls = error
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<TlsError>())
                        .cloned()
                        .unwrap_or_else(|| TlsError::General(error.to_string()));
                    let _ = handshakes_tx.send(Handshake::Refused(tls));
                }
            }
        }
    });
    let (events_tx, events) = mpsc::unbounded_channel();
    let serve = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AuditServiceServer::new(RecordingAudit {
                events: events_tx,
            }))
            .serve_with_incoming(tokio_stream::wrappers::ReceiverStream::new(connections))
            .await
            .expect("audit test server");
    });
    (address, handshakes, events, Server { accept, serve })
}

/// A TLS connection the acceptor completed, served by tonic.
struct Accepted(TlsStream<TcpStream>);

impl Connected for Accepted {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for Accepted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Accepted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Acknowledges every event as persisted and reports its id and whether the
/// request carried the Sidecar's credentials, whether the event is submitted
/// on its own (the `wal` sink) or streamed (the `grpc` sink).
struct RecordingAudit {
    events: mpsc::UnboundedSender<(String, Credentials)>,
}

/// The pre-shared key travels in this header; a runtime credential would be
/// the request's bearer instead.
fn credentials_of<T>(request: &Request<T>) -> Credentials {
    if request.metadata().contains_key("firma-sidecar-psk") {
        Credentials::Present
    } else {
        Credentials::Absent
    }
}

#[tonic::async_trait]
impl AuditService for RecordingAudit {
    async fn submit_event(
        &self,
        request: Request<ProtoEvent>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        let credentials = credentials_of(&request);
        let event = request.into_inner();
        let _ = self.events.send((event.event_id.clone(), credentials));
        Ok(Response::new(StreamEventsResponse {
            last_event_id: event.event_id,
            events_received: 1,
            durably_persisted: true,
        }))
    }

    async fn stream_events(
        &self,
        request: Request<Streaming<ProtoEvent>>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        let credentials = credentials_of(&request);
        let mut stream = request.into_inner();
        let mut receipt = StreamEventsResponse::default();
        while let Some(event) = stream.message().await? {
            let _ = self.events.send((event.event_id.clone(), credentials));
            receipt.last_event_id = event.event_id;
            receipt.events_received += 1;
        }
        Ok(Response::new(receipt))
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
