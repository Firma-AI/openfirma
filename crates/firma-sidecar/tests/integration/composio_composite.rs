use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use firma_core::{
    AbortReason, ActionParams, CapabilityClaims, Connector, ConnectorError, ConnectorResponse,
    DenyReason, ExecutionEnvelope, InjectedCredentials, ModificationSpec, RevocationStore,
    StepUpSpec, TokenError, TokenVerifier, TransportView,
};
use firma_http::{Authority, HeaderMap, HeaderName, Method};
use firma_identifiers::{AgentId, TokenId};
use firma_sidecar::composio::{ComposioAction, ComposioCatalogs, DecodeResult, decode};
use firma_sidecar::config::{
    HttpsMitmConfig, MappingRuleConfig, MappingRulesFile, SidecarMode, TenancyMode,
};
use firma_sidecar::connector::ConnectorRegistry;
use firma_sidecar::credential::{CredentialInjectionError, CredentialInjector};
use firma_sidecar::handler::{HandledResponse, RequestHandler, UpgradeAuthorization};
#[cfg(unix)]
use firma_sidecar::interceptor::Interceptor;
use firma_sidecar::interceptor::http::HttpInterceptor;
#[cfg(unix)]
use firma_sidecar::interceptor::unix_socket::UnixSocketInterceptor;
use firma_sidecar::pipeline::{
    ActionClassRegistry, CapabilityMap, CapabilityValidator, CompositeDisposition,
    ConstraintEnforcer, EnforcementDecision, EnforcementPipeline, IntentNormalizer, MappingTable,
    PipelineArgs, PolicyEvaluation, PolicyVerdict, RawRequest,
};
use http::HeaderName as HttpHeaderName;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

const SOURCE: &str = r#"{
  "toolkit": "gmail",
  "version": "20251111_00",
  "tools": [
    {
      "toolkit": "gmail",
      "version": "20251111_00",
      "slug": "GMAIL_FETCH_EMAILS",
      "name": "Fetch emails",
      "description": "Fetch emails"
    },
    {
      "toolkit": "gmail",
      "version": "20251111_00",
      "slug": "GMAIL_SEND_EMAIL",
      "name": "Send email",
      "description": "Send email"
    }
  ]
}"#;

const MAPPING: &str = r#"{
  "toolkit": "gmail",
  "version": "20251111_00",
  "mappings": {
    "GMAIL_FETCH_EMAILS": "communication.external.read",
    "GMAIL_SEND_EMAIL": "communication.external.send"
  }
}"#;

#[derive(Clone, Copy)]
enum PolicyMode {
    Allow,
    DenySend,
    ModifyRead,
    StepUpRead,
    DeferRead,
}

struct TestPolicy(PolicyMode);

impl PolicyEvaluation for TestPolicy {
    fn evaluate(
        &self,
        _agent_id: &AgentId,
        _action: &str,
        _resource: &str,
        _context: serde_json::Value,
    ) -> Result<bool, String> {
        Ok(true)
    }

    fn evaluate_verdict(
        &self,
        _agent_id: &AgentId,
        action: &str,
        _resource: &str,
        _context: serde_json::Value,
    ) -> Result<PolicyVerdict, String> {
        let verdict = match (self.0, action) {
            (PolicyMode::DenySend, "communication.external.send") => PolicyVerdict::Deny,
            (PolicyMode::ModifyRead, "communication.external.read") => PolicyVerdict::Modify {
                modifications: ModificationSpec::RedactHeader(HttpHeaderName::from_static(
                    "x-secret",
                )),
            },
            (PolicyMode::StepUpRead, "communication.external.read") => PolicyVerdict::StepUp {
                challenge: StepUpSpec::new("approve Gmail read").map_err(|err| err.to_string())?,
            },
            (PolicyMode::DeferRead, "communication.external.read") => PolicyVerdict::Defer {
                backoff: Duration::from_millis(250),
            },
            _ => PolicyVerdict::Allow,
        };
        Ok(verdict)
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn version(&self) -> Option<String> {
        Some("composite-test-policy".to_string())
    }
}

struct MockVerifier {
    claims: CapabilityClaims,
}

impl TokenVerifier for MockVerifier {
    fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
        Ok(self.claims.clone())
    }
}

struct NoRevocations;

impl RevocationStore for NoRevocations {
    fn is_revoked(&self, _token_id: &TokenId) -> Result<bool, TokenError> {
        Ok(false)
    }

    fn add_revocation(&self, _token_id: &TokenId) -> Result<(), TokenError> {
        Ok(())
    }
}

struct TestCredentials {
    mode: CredentialMode,
}

#[derive(Clone, Copy)]
enum CredentialMode {
    Shared,
    Disagree,
    Fail,
}

struct CountingConnector {
    dispatches: AtomicUsize,
    firma_header_seen: AtomicBool,
}

struct HeaderCapturingConnector {
    cookie_seen: AtomicBool,
    firma_header_seen: AtomicBool,
}

struct MockTlsConnector {
    address: SocketAddr,
    certificate: CertificateDer<'static>,
}

#[async_trait]
impl Connector for CountingConnector {
    async fn dispatch(&self, view: &TransportView) -> Result<ConnectorResponse, ConnectorError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        let ActionParams::Http(http) = &view.envelope().intent().params else {
            return Err(ConnectorError::InvalidRequest(
                "expected HTTP params".to_string(),
            ));
        };
        self.firma_header_seen.store(
            http.headers
                .keys()
                .any(|name| name.as_str().starts_with("x-firma-")),
            Ordering::SeqCst,
        );
        Ok(ConnectorResponse {
            status: 201,
            headers: HeaderMap::new(),
            body: b"ok".to_vec(),
            dispatch_latency: Duration::from_millis(2),
            response_size: 2,
        })
    }
}

#[async_trait]
impl Connector for HeaderCapturingConnector {
    async fn dispatch(&self, view: &TransportView) -> Result<ConnectorResponse, ConnectorError> {
        let ActionParams::Http(http) = &view.envelope().intent().params else {
            return Err(ConnectorError::InvalidRequest(
                "expected HTTP params".to_string(),
            ));
        };
        self.cookie_seen.store(
            http.headers
                .get("cookie")
                .is_some_and(|value| value == "session=agent-secret"),
            Ordering::SeqCst,
        );
        self.firma_header_seen.store(
            http.headers
                .keys()
                .any(|name| name.as_str().starts_with("x-firma-")),
            Ordering::SeqCst,
        );
        Ok(ConnectorResponse {
            status: 201,
            headers: HeaderMap::new(),
            body: b"ok".to_vec(),
            dispatch_latency: Duration::from_millis(2),
            response_size: 2,
        })
    }
}

#[async_trait]
impl Connector for MockTlsConnector {
    async fn dispatch(&self, _view: &TransportView) -> Result<ConnectorResponse, ConnectorError> {
        let started = std::time::Instant::now();
        let stream = TcpStream::connect(self.address)
            .await
            .map_err(|error| ConnectorError::Network(error.to_string()))?;
        let mut roots = RootCertStore::empty();
        roots
            .add(self.certificate.clone())
            .map_err(|error| ConnectorError::Network(error.to_string()))?;
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from("mock.composio.test".to_string())
            .map_err(|error| ConnectorError::Network(error.to_string()))?;
        let mut stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| ConnectorError::Network(error.to_string()))?;
        stream
            .write_all(b"POST /execute HTTP/1.1\r\nHost: mock.composio.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|error| ConnectorError::Network(error.to_string()))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|error| ConnectorError::Network(error.to_string()))?;
        if !response.starts_with(b"HTTP/1.1 200") {
            return Err(ConnectorError::Network(
                "mock TLS upstream returned an invalid response".to_string(),
            ));
        }
        Ok(ConnectorResponse {
            status: 200,
            headers: HeaderMap::new(),
            body: b"ok".to_vec(),
            dispatch_latency: started.elapsed(),
            response_size: 2,
        })
    }
}

#[async_trait]
impl CredentialInjector for TestCredentials {
    async fn inject(
        &self,
        envelope: &ExecutionEnvelope,
        connector_id: &str,
        _target: &str,
    ) -> Result<InjectedCredentials, CredentialInjectionError> {
        let value = match self.mode {
            CredentialMode::Shared => "shared".to_string(),
            CredentialMode::Disagree => envelope.intent().action_class.clone(),
            CredentialMode::Fail => {
                return Err(CredentialInjectionError::FetchFailed {
                    connector_id: connector_id.to_string(),
                    reason: "vault unavailable".to_string(),
                });
            }
        };
        Ok(InjectedCredentials::new(HashMap::from([(
            HeaderName::from_static("authorization"),
            value,
        )])))
    }
}

fn claims() -> anyhow::Result<CapabilityClaims> {
    Ok(CapabilityClaims {
        token_id: "ctok_01j0000000e008000000000001".parse()?,
        agent_id: "agt_01j0000000e008000000000001".parse()?,
        session_id: "sess_composite".parse()?,
        action_set: vec![
            "communication.external.read".to_string(),
            "communication.external.send".to_string(),
        ],
        resource_scope: "composio://gmail/*".to_string(),
        issued_at: Utc::now(),
        expiry: Utc::now() + chrono::Duration::hours(1),
        context_hash: "context".to_string(),
    })
}

fn pipeline(
    mode: PolicyMode,
    credential_mode: CredentialMode,
    sidecar_mode: SidecarMode,
) -> anyhow::Result<EnforcementPipeline> {
    let claims = claims()?;
    let capability_map = CapabilityMap::new(vec![
        firma_sidecar::enforcement::capability_map::CapabilityEntry {
            raw_token: "v4.public.test".to_string(),
            claims: claims.clone(),
        },
    ]);
    let mapping = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::GET),
                host: "example.test".to_string(),
                path: Some("/unused".to_string()),
                action_class: "communication.external.read".to_string(),
            }],
        },
        &ActionClassRegistry::v0_1(),
        false,
    )?;
    Ok(EnforcementPipeline::new(PipelineArgs {
        normalizer: IntentNormalizer::new(mapping),
        capability_validator: CapabilityValidator::new(
            capability_map,
            Arc::new(MockVerifier { claims }),
            Arc::new(NoRevocations),
            Duration::ZERO,
            TenancyMode::SingleAgent,
        ),
        constraint_enforcer: ConstraintEnforcer::new(Arc::new(TestPolicy(mode))),
        credential_injector: Box::new(TestCredentials {
            mode: credential_mode,
        }),
        session_state_store: Arc::new(firma_sidecar::enforcement::LruSessionStateStore::new(16)),
    })
    .with_mode(sidecar_mode))
}

fn request_and_actions() -> anyhow::Result<(RawRequest, Vec<ComposioAction>)> {
    let request = RawRequest {
        method: Method::POST,
        host: Authority::from_static("app.composio.dev"),
        path: "/tool_router/v3/trs_batch/mcp".to_string(),
        headers: HeaderMap::new(),
        body: Some(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "COMPOSIO_MULTI_EXECUTE_TOOL",
                    "arguments": {
                        "tools": [
                            {"tool_slug": "GMAIL_FETCH_EMAILS", "arguments": {"secret": "one"}},
                            {"tool_slug": "GMAIL_SEND_EMAIL", "arguments": {"secret": "two"}}
                        ]
                    }
                }
            })
            .to_string()
            .into_bytes(),
        ),
        is_https: true,
    };
    let catalogs = ComposioCatalogs::from_json_pairs([(SOURCE, MAPPING)])?;
    let DecodeResult::Actions(actions) = decode(&request, &catalogs) else {
        anyhow::bail!("expected decoded actions");
    };
    Ok((request, actions))
}

fn catalogs() -> anyhow::Result<Arc<ComposioCatalogs>> {
    Ok(Arc::new(ComposioCatalogs::from_json_pairs([(
        SOURCE, MAPPING,
    )])?))
}

fn direct_request(tool_slug: &str) -> RawRequest {
    RawRequest {
        method: Method::POST,
        host: Authority::from_static("backend.composio.dev"),
        path: format!("/api/v3.1/tools/execute/{tool_slug}"),
        headers: HeaderMap::new(),
        body: Some(
            serde_json::json!({
                "version": "20251111_00",
                "user_id": "pai-assistant:demo",
                "connected_account_id": "demo-account",
                "arguments": {},
            })
            .to_string()
            .into_bytes(),
        ),
        is_https: true,
    }
}

async fn start_mock_tls_upstream() -> anyhow::Result<(
    SocketAddr,
    CertificateDer<'static>,
    Arc<AtomicUsize>,
    CancellationToken,
)> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["mock.composio.test".to_string()])?;
    let certificate = CertificateDer::from(cert.der().to_vec());
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let dispatches = Arc::new(AtomicUsize::new(0));
    let server_dispatches = Arc::clone(&dispatches);
    let cancellation = CancellationToken::new();
    let server_cancellation = cancellation.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let server_dispatches = Arc::clone(&server_dispatches);
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut request = vec![0_u8; 4096];
                        let Ok(size) = stream.read(&mut request).await else {
                            return;
                        };
                        if size == 0 {
                            return;
                        }
                        server_dispatches.fetch_add(1, Ordering::SeqCst);
                        let response =
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                        let _ = stream.write_all(response).await;
                        let _ = stream.shutdown().await;
                    });
                }
                () = server_cancellation.cancelled() => break,
            }
        }
    });

    Ok((address, certificate, dispatches, cancellation))
}

#[tokio::test]
async fn allowed_children_share_one_atomic_dispatch() -> anyhow::Result<()> {
    let (request, actions) = request_and_actions()?;
    let result = pipeline(
        PolicyMode::Allow,
        CredentialMode::Shared,
        SidecarMode::Enforce,
    )?
    .enforce_composite(&request, "sess_composite", &actions)
    .await;

    assert!(matches!(
        result.disposition,
        CompositeDisposition::Dispatch {
            monitor_override: false,
            transport: Some(_)
        }
    ));
    assert_eq!(result.children.len(), 2);
    assert!(
        result
            .children
            .iter()
            .all(|child| matches!(child.decision, EnforcementDecision::Allow { .. }))
    );
    assert_eq!(
        result.children[0].audit_payload.resource(),
        "composio://gmail/GMAIL_FETCH_EMAILS"
    );
    assert_eq!(
        result.children[1].audit_payload.resource(),
        "composio://gmail/GMAIL_SEND_EMAIL"
    );
    Ok(())
}

/// An empty action slice must not reach dispatch: without this guard the
/// disposition would be `Dispatch { transport: None }`, which the handler
/// forwards unenforced.
#[tokio::test]
async fn empty_action_slice_fails_closed() -> anyhow::Result<()> {
    let (request, _) = request_and_actions()?;
    let result = pipeline(
        PolicyMode::Allow,
        CredentialMode::Shared,
        SidecarMode::Enforce,
    )?
    .enforce_composite(&request, "sess_composite", &[])
    .await;

    assert!(matches!(
        result.disposition,
        CompositeDisposition::Block { blocker_index: 0 }
    ));
    assert_eq!(result.children.len(), 1);
    assert!(matches!(
        result.children[0].decision,
        EnforcementDecision::Deny {
            reason: DenyReason::FailClosed,
            ..
        }
    ));
    Ok(())
}

#[tokio::test]
async fn deny_preserves_blocker_and_aborts_allowed_sibling() -> anyhow::Result<()> {
    let (request, actions) = request_and_actions()?;
    let result = pipeline(
        PolicyMode::DenySend,
        CredentialMode::Shared,
        SidecarMode::Enforce,
    )?
    .enforce_composite(&request, "sess_composite", &actions)
    .await;

    assert!(matches!(
        result.disposition,
        CompositeDisposition::Block { blocker_index: 1 }
    ));
    assert!(matches!(
        result.children[0].decision,
        EnforcementDecision::Abort {
            reason: AbortReason::BatchAtomicity,
            ..
        }
    ));
    assert!(matches!(
        result.children[1].decision,
        EnforcementDecision::Deny { .. }
    ));
    assert!(
        result.children[0]
            .audit_payload
            .deny_reason()
            .starts_with("BATCH_ATOMICITY:")
    );
    Ok(())
}

#[tokio::test]
async fn every_remediation_blocks_composio_dispatch() -> anyhow::Result<()> {
    for mode in [
        PolicyMode::ModifyRead,
        PolicyMode::StepUpRead,
        PolicyMode::DeferRead,
    ] {
        let (request, actions) = request_and_actions()?;
        let result = pipeline(mode, CredentialMode::Shared, SidecarMode::Enforce)?
            .enforce_composite(&request, "sess_composite", &actions[..1])
            .await;
        assert!(matches!(
            result.disposition,
            CompositeDisposition::Block { blocker_index: 0 }
        ));
    }
    Ok(())
}

#[tokio::test]
async fn monitor_retains_would_block_reason_and_dispatches_once() -> anyhow::Result<()> {
    let (request, actions) = request_and_actions()?;
    let result = pipeline(
        PolicyMode::DenySend,
        CredentialMode::Shared,
        SidecarMode::Monitor,
    )?
    .enforce_composite(&request, "sess_composite", &actions)
    .await;

    assert!(matches!(
        result.disposition,
        CompositeDisposition::Dispatch {
            monitor_override: true,
            transport: Some(_)
        }
    ));
    assert_eq!(
        *result.children[1].audit_payload.decision(),
        firma_sidecar::audit::Decision::Allow
    );
    assert!(
        result.children[1]
            .audit_payload
            .deny_reason()
            .starts_with("monitor_mode:")
    );
    Ok(())
}

#[tokio::test]
async fn monitor_keeps_credential_injection_abort_blocking() -> anyhow::Result<()> {
    let (request, actions) = request_and_actions()?;
    let result = pipeline(
        PolicyMode::Allow,
        CredentialMode::Fail,
        SidecarMode::Monitor,
    )?
    .enforce_composite(&request, "sess_composite", &actions)
    .await;

    assert!(matches!(
        result.disposition,
        CompositeDisposition::Block { blocker_index: 0 }
    ));
    assert!(result.children.iter().all(|child| {
        matches!(
            child.decision,
            EnforcementDecision::Abort {
                reason: AbortReason::CredentialInjectionFailed,
                ..
            }
        ) && *child.audit_payload.decision() == firma_sidecar::audit::Decision::Abort
            && !child
                .audit_payload
                .deny_reason()
                .starts_with("monitor_mode:")
    }));
    Ok(())
}

#[tokio::test]
async fn credential_disagreement_aborts_the_whole_batch() -> anyhow::Result<()> {
    let (request, actions) = request_and_actions()?;
    let result = pipeline(
        PolicyMode::Allow,
        CredentialMode::Disagree,
        SidecarMode::Enforce,
    )?
    .enforce_composite(&request, "sess_composite", &actions)
    .await;

    assert!(matches!(
        result.disposition,
        CompositeDisposition::Block { blocker_index: 0 }
    ));
    assert!(result.children.iter().all(|child| matches!(
        child.decision,
        EnforcementDecision::Abort {
            reason: AbortReason::BatchAtomicity,
            ..
        }
    )));
    Ok(())
}

#[tokio::test]
async fn protected_composio_hosts_reject_protocol_upgrades() -> anyhow::Result<()> {
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector));
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::Allow,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        registry,
        audit_tx,
    );

    for host in [
        Authority::from_static("app.composio.dev:443"),
        Authority::from_static("backend.composio.dev."),
        Authority::from_static("backend.composio.dev:8443"),
    ] {
        let authorization = handler
            .authorize_upgrade(
                RawRequest {
                    method: Method::POST,
                    host,
                    path: "/upgrade".to_string(),
                    headers: HeaderMap::new(),
                    body: Some(b"{}".to_vec()),
                    is_https: true,
                },
                "sess_composite",
            )
            .await;
        let UpgradeAuthorization::Deny { reason, detail } = authorization else {
            anyhow::bail!("expected Composio protocol upgrade denial");
        };
        assert_eq!(reason, firma_core::DenyReason::FailClosed);
        assert_eq!(detail, "Composio protocol upgrades are unsupported");

        let audit = audit_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("missing Composio upgrade audit"))?;
        assert_eq!(*audit.decision(), firma_sidecar::audit::Decision::Deny);
        assert_eq!(audit.dispatch_status(), 0);
    }
    Ok(())
}

/// Monitor mode must not change agent-visible behavior: a request the
/// decoder would deny (unknown tool) is forwarded once and the audit
/// record keeps the would-deny reason.
#[tokio::test]
async fn monitor_forwards_protocol_denial_with_would_deny_audit() -> anyhow::Result<()> {
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::Allow,
            CredentialMode::Shared,
            SidecarMode::Monitor,
        )?),
        registry,
        audit_tx,
    )
    .with_composio_catalogs(catalogs()?);

    let response = handler
        .handle(
            direct_request("GMAIL_TOOL_NOT_IN_CATALOG"),
            "sess_composite",
        )
        .await;

    assert!(matches!(response, HandledResponse::Passthrough(_)));
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 1);
    let audit = audit_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("missing protocol denial audit"))?;
    assert_eq!(*audit.decision(), firma_sidecar::audit::Decision::Allow);
    assert!(audit.deny_reason().starts_with("monitor_mode:"));
    assert!(audit.deny_reason().contains("unknown_tool"));
    Ok(())
}

/// Monitor mode observes protocol upgrades on protected Composio hosts
/// instead of hard-blocking them; the returned audit payload keeps the
/// would-deny reason.
#[tokio::test]
async fn monitor_observes_composio_protocol_upgrade() -> anyhow::Result<()> {
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector));
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::Allow,
            CredentialMode::Shared,
            SidecarMode::Monitor,
        )?),
        registry,
        audit_tx,
    );

    let authorization = handler
        .authorize_upgrade(
            RawRequest {
                method: Method::POST,
                host: Authority::from_static("backend.composio.dev"),
                path: "/upgrade".to_string(),
                headers: HeaderMap::new(),
                body: Some(b"{}".to_vec()),
                is_https: true,
            },
            "sess_composite",
        )
        .await;

    let UpgradeAuthorization::Allow { audit_payload, .. } = authorization else {
        anyhow::bail!("expected observed Composio upgrade in monitor mode");
    };
    assert_eq!(
        *audit_payload.decision(),
        firma_sidecar::audit::Decision::Allow
    );
    assert!(audit_payload.deny_reason().starts_with("monitor_mode:"));
    Ok(())
}

#[tokio::test]
async fn handler_dispatches_original_batch_once_and_audits_every_child() -> anyhow::Result<()> {
    let (mut request, _) = request_and_actions()?;
    request.headers.insert(
        http::HeaderName::from_static("x-firma-internal"),
        http::HeaderValue::from_static("must-not-leave"),
    );
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::Allow,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        registry,
        audit_tx,
    )
    .with_composio_catalogs(catalogs()?);

    let response = handler.handle(request, "sess_composite").await;

    assert!(matches!(response, HandledResponse::Ok(_)));
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 1);
    assert!(!connector.firma_header_seen.load(Ordering::SeqCst));
    let first = audit_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("missing first child audit"))?;
    let second = audit_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("missing second child audit"))?;
    assert_eq!(first.dispatch_status(), 201);
    assert_eq!(second.dispatch_status(), 201);
    assert_eq!(first.dispatch_latency_us(), second.dispatch_latency_us());
    assert_eq!(first.response_size(), second.response_size());
    Ok(())
}

#[tokio::test]
async fn handler_atomic_denial_dispatches_zero_times() -> anyhow::Result<()> {
    let (request, _) = request_and_actions()?;
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::DenySend,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        registry,
        audit_tx,
    )
    .with_composio_catalogs(catalogs()?);

    let response = handler.handle(request, "sess_composite").await;

    assert!(matches!(response, HandledResponse::Deny { .. }));
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 0);
    let first = audit_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("missing first child audit"))?;
    let second = audit_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("missing second child audit"))?;
    assert_eq!(*first.decision(), firma_sidecar::audit::Decision::Abort);
    assert_eq!(*second.decision(), firma_sidecar::audit::Decision::Deny);
    Ok(())
}

#[tokio::test]
async fn handler_monitor_override_still_dispatches_only_once() -> anyhow::Result<()> {
    let (request, _) = request_and_actions()?;
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::DenySend,
            CredentialMode::Shared,
            SidecarMode::Monitor,
        )?),
        registry,
        audit_tx,
    )
    .with_composio_catalogs(catalogs()?);

    let response = handler.handle(request, "sess_composite").await;

    assert!(matches!(response, HandledResponse::Passthrough(_)));
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 1);
    for _ in 0..2 {
        let audit = audit_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("missing child audit"))?;
        assert_eq!(*audit.decision(), firma_sidecar::audit::Decision::Allow);
    }
    Ok(())
}

async fn read_headers(stream: &mut TcpStream) -> anyhow::Result<String> {
    read_response_headers(stream).await
}

async fn read_response_headers(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> anyhow::Result<String> {
    let mut collected = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
        anyhow::ensure!(read > 0, "connection closed before response headers");
        collected.extend_from_slice(&buf[..read]);
        if collected.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&collected).to_string());
        }
    }
}

#[tokio::test]
async fn proxy_preserves_agent_cookie_after_allow() -> anyhow::Result<()> {
    let connector = Arc::new(HeaderCapturingConnector {
        cookie_seen: AtomicBool::new(false),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = Arc::new(
        RequestHandler::new(
            Arc::new(pipeline(
                PolicyMode::Allow,
                CredentialMode::Shared,
                SidecarMode::Enforce,
            )?),
            registry,
            audit_tx,
        )
        .with_composio_catalogs(catalogs()?),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            HttpInterceptor::new(proxy_addr)
                .run_with_listener(listener, handler, cancel)
                .await
        }
    });
    let (request, _) = request_and_actions()?;
    let body = request
        .body
        .ok_or_else(|| anyhow::anyhow!("Composio fixture must have a body"))?;
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let head = format!(
        "POST /tool_router/v3/trs_batch/mcp HTTP/1.1\r\n\
         Host: app.composio.dev\r\n\
         Cookie: session=agent-secret\r\n\
         X-Firma-Session-Id: sess_composite\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;

    let response = read_headers(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "expected dispatched response, got: {response:?}"
    );
    assert!(
        connector.cookie_seen.load(Ordering::SeqCst),
        "the allowed upstream dispatch must preserve the agent's Cookie header"
    );
    assert!(
        !connector.firma_header_seen.load(Ordering::SeqCst),
        "internal Firma headers must still be removed before dispatch"
    );

    cancel.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn proxy_returns_structured_denial_for_malformed_host() -> anyhow::Result<()> {
    proxy_returns_structured_denial_for_request(
        b"GET / HTTP/1.1\r\nHost: bad host\r\nConnection: close\r\n\r\n",
    )
    .await
}

#[tokio::test]
async fn proxy_returns_structured_denial_for_malformed_connect_host() -> anyhow::Result<()> {
    proxy_returns_structured_denial_for_request(
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: bad host\r\nConnection: close\r\n\r\n",
    )
    .await
}

#[tokio::test]
async fn proxy_returns_structured_denial_for_non_text_session_id() -> anyhow::Result<()> {
    proxy_returns_structured_denial_for_request(
        b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Firma-Session-Id: \xff\r\nConnection: close\r\n\r\n",
    )
    .await
}

#[tokio::test]
async fn proxy_returns_structured_denial_for_non_text_connect_session_id() -> anyhow::Result<()> {
    proxy_returns_structured_denial_for_request(
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nX-Firma-Session-Id: \xff\r\nConnection: close\r\n\r\n",
    )
    .await
}

async fn proxy_returns_structured_denial_for_request(request: &[u8]) -> anyhow::Result<()> {
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = Arc::new(RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::Allow,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        registry,
        audit_tx,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            HttpInterceptor::new(proxy_addr)
                .run_with_listener(listener, handler, cancel)
                .await
        }
    });
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(request).await?;

    let response = read_headers(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "malformed requests must receive a fail-closed 403, got: {response:?}"
    );
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 0);

    cancel.cancel();
    server.await??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_returns_structured_denial_for_non_text_session_id() -> anyhow::Result<()> {
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4);
    let handler = Arc::new(RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::Allow,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        registry,
        audit_tx,
    ));
    let socket_dir = tempfile::tempdir()?;
    let socket_path = socket_dir.path().join("sidecar.sock");
    let cancel = CancellationToken::new();
    let interceptor = UnixSocketInterceptor::from(socket_path.as_path());
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move { interceptor.run(handler, cancel).await }
    });
    let mut stream = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match UnixStream::connect(&socket_path).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await?;
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Firma-Session-Id: \xff\r\nConnection: close\r\n\r\n",
        )
        .await?;

    let response = read_response_headers(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "malformed requests must receive a fail-closed 403, got: {response:?}"
    );
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 0);

    cancel.cancel();
    server.await??;
    Ok(())
}

async fn connect_to_mitm_proxy(
    websocket: bool,
) -> anyhow::Result<(
    tokio_rustls::client::TlsStream<TcpStream>,
    CancellationToken,
    tokio::task::JoinHandle<()>,
    Arc<CountingConnector>,
    tempfile::TempDir,
)> {
    let ca_dir = tempfile::tempdir()?;
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(8);
    let handler = Arc::new(RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::Allow,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        registry,
        audit_tx,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let interceptor = HttpInterceptor::new(proxy_addr).with_https_mitm(
        HttpsMitmConfig::default()
            .with_enabled(true)
            .with_intercept_hosts(vec!["example.test".to_string()])
            .with_strict_hosts(vec!["example.test".to_string()])
            .with_bypass_hosts(Vec::new()),
        ca_dir.path().to_path_buf(),
    );
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            let _ = interceptor
                .run_with_listener(listener, handler, cancel)
                .await;
        }
    });
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream
        .write_all(
            b"CONNECT example.test:443 HTTP/1.1\r\n\
              Host: example.test:443\r\n\
              X-Firma-Session-Id: sess_composite\r\n\r\n",
        )
        .await?;
    let connect_response = read_headers(&mut stream).await?;
    anyhow::ensure!(
        connect_response.starts_with("HTTP/1.1 200"),
        "expected CONNECT 200, got: {connect_response:?}"
    );
    let tls = firma_ca_client(ca_dir.path()).await?;
    let mut tls_stream = tls
        .connect(ServerName::try_from("example.test".to_string())?, stream)
        .await?;
    let upgrade_headers = if websocket {
        "Connection: Upgrade\r\nUpgrade: websocket\r\n"
    } else {
        "Connection: close\r\n"
    };
    let mut request =
        b"GET /unused HTTP/1.1\r\nHost: example.test\r\nX-Firma-Session-Id: ".to_vec();
    request.push(0xff);
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(upgrade_headers.as_bytes());
    request.extend_from_slice(b"\r\n");
    tls_stream.write_all(&request).await?;
    Ok((tls_stream, cancel, server, connector, ca_dir))
}

#[tokio::test]
async fn mitm_http_returns_structured_denial_for_non_text_session_id() -> anyhow::Result<()> {
    let (mut stream, cancel, server, connector, _ca_dir) = connect_to_mitm_proxy(false).await?;

    let response = read_response_headers(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "malformed requests must receive a fail-closed 403, got: {response:?}"
    );
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 0);
    cancel.cancel();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn mitm_websocket_returns_structured_denial_for_non_text_session_id() -> anyhow::Result<()> {
    let (mut stream, cancel, server, connector, _ca_dir) = connect_to_mitm_proxy(true).await?;

    let response = read_response_headers(&mut stream).await?;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "malformed requests must receive a fail-closed 403, got: {response:?}"
    );
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 0);
    cancel.cancel();
    let _ = server.await;
    Ok(())
}

/// Build a TLS connector that trusts the interceptor's generated Firma CA,
/// waiting briefly for first-run CA generation to complete.
async fn firma_ca_client(ca_dir: &std::path::Path) -> anyhow::Result<TlsConnector> {
    let ca_path = ca_dir.join("firma-ca.crt");
    for _ in 0..40 {
        if ca_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut roots = RootCertStore::empty();
    let pem = std::fs::read(&ca_path)?;
    for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(certificate?)?;
    }
    Ok(TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )))
}

/// Drive a Composio denial through the real proxy stack — CONNECT, strict
/// HTTPS MITM with the generated Firma CA, protocol decode, and the audited
/// denial — covering the interception layers the in-process handler tests
/// bypass.
#[tokio::test]
async fn composio_denial_travels_through_the_mitm_proxy_stack() -> anyhow::Result<()> {
    let ca_dir = tempfile::tempdir()?;
    let connector = Arc::new(CountingConnector {
        dispatches: AtomicUsize::new(0),
        firma_header_seen: AtomicBool::new(false),
    });
    let registry = Arc::new(ConnectorRegistry::new(connector.clone()));
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(8);
    let handler = Arc::new(
        RequestHandler::new(
            Arc::new(pipeline(
                PolicyMode::Allow,
                CredentialMode::Shared,
                SidecarMode::Enforce,
            )?),
            registry,
            audit_tx,
        )
        .with_composio_catalogs(catalogs()?),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let interceptor = HttpInterceptor::new(proxy_addr).with_https_mitm(
        HttpsMitmConfig::default()
            .with_enabled(true)
            .with_intercept_hosts(vec!["backend.composio.dev".to_string()])
            .with_strict_hosts(vec!["backend.composio.dev".to_string()])
            .with_bypass_hosts(Vec::new()),
        ca_dir.path().to_path_buf(),
    );
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            let _ = interceptor
                .run_with_listener(listener, handler, cancel)
                .await;
        }
    });

    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream
        .write_all(
            b"CONNECT backend.composio.dev:443 HTTP/1.1\r\n\
              Host: backend.composio.dev:443\r\n\
              x-firma-session-id: sess_composite\r\n\r\n",
        )
        .await?;
    let connect_response = read_headers(&mut stream).await?;
    anyhow::ensure!(
        connect_response.starts_with("HTTP/1.1 200"),
        "expected CONNECT 200, got: {connect_response:?}"
    );

    let tls = firma_ca_client(ca_dir.path()).await?;
    let mut tls_stream = tls
        .connect(
            ServerName::try_from("backend.composio.dev".to_string())?,
            stream,
        )
        .await?;

    let body = serde_json::json!({"version": "20251111_00"}).to_string();
    let request = format!(
        "POST /api/v3/tools/execute/GMAIL_TOOL_NOT_IN_CATALOG HTTP/1.1\r\n\
         Host: backend.composio.dev\r\n\
         x-firma-session-id: sess_composite\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len(),
    );
    tls_stream.write_all(request.as_bytes()).await?;
    let mut buf = [0_u8; 2048];
    let read = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf)).await??;
    let response = String::from_utf8_lossy(&buf[..read]).to_string();
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    assert_eq!(
        status, 403,
        "expected decode denial over the MITM path, got: {response}"
    );
    assert_eq!(connector.dispatches.load(Ordering::SeqCst), 0);

    let mut saw_denial = false;
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(1), audit_rx.recv()).await
    {
        if *event.decision() == firma_sidecar::audit::Decision::Deny
            && event.deny_reason().contains("unknown_tool")
        {
            saw_denial = true;
            break;
        }
    }
    assert!(saw_denial, "expected an audited unknown_tool denial");

    cancel.cancel();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn composio_mock_tls_demo_covers_enforcement_outcomes() -> anyhow::Result<()> {
    let (address, certificate, dispatches, cancellation) = start_mock_tls_upstream().await?;
    let connector = Arc::new(MockTlsConnector {
        address,
        certificate,
    });
    let registry = Arc::new(ConnectorRegistry::new(connector));

    let (allow_audit_tx, _allow_audit_rx) = tokio::sync::mpsc::channel(2);
    let allow_handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::Allow,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        Arc::clone(&registry),
        allow_audit_tx,
    )
    .with_composio_catalogs(catalogs()?);
    let allowed = allow_handler
        .handle(direct_request("GMAIL_FETCH_EMAILS"), "sess_composite")
        .await;
    assert!(matches!(allowed, HandledResponse::Ok(_)));
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);

    let (deny_audit_tx, _deny_audit_rx) = tokio::sync::mpsc::channel(2);
    let deny_handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::DenySend,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        Arc::clone(&registry),
        deny_audit_tx,
    )
    .with_composio_catalogs(catalogs()?);
    let denied = deny_handler
        .handle(direct_request("GMAIL_SEND_EMAIL"), "sess_composite")
        .await;
    assert!(matches!(denied, HandledResponse::Deny { .. }));
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);

    let (batch_request, _) = request_and_actions()?;
    let (batch_audit_tx, _batch_audit_rx) = tokio::sync::mpsc::channel(4);
    let batch_handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::DenySend,
            CredentialMode::Shared,
            SidecarMode::Enforce,
        )?),
        Arc::clone(&registry),
        batch_audit_tx,
    )
    .with_composio_catalogs(catalogs()?);
    let batch_denied = batch_handler.handle(batch_request, "sess_composite").await;
    assert!(matches!(batch_denied, HandledResponse::Deny { .. }));
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);

    let (monitor_request, _) = request_and_actions()?;
    let (monitor_audit_tx, mut monitor_audit_rx) = tokio::sync::mpsc::channel(4);
    let monitor_handler = RequestHandler::new(
        Arc::new(pipeline(
            PolicyMode::DenySend,
            CredentialMode::Shared,
            SidecarMode::Monitor,
        )?),
        registry,
        monitor_audit_tx,
    )
    .with_composio_catalogs(catalogs()?);
    let monitored = monitor_handler
        .handle(monitor_request, "sess_composite")
        .await;
    assert!(matches!(monitored, HandledResponse::Passthrough(_)));
    assert_eq!(dispatches.load(Ordering::SeqCst), 2);
    let monitor_audits = [
        monitor_audit_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("missing first monitor audit"))?,
        monitor_audit_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("missing second monitor audit"))?,
    ];
    assert!(monitor_audits.iter().all(|audit| {
        *audit.decision() == firma_sidecar::audit::Decision::Allow
            && (audit.deny_reason().is_empty() || audit.deny_reason().starts_with("monitor_mode:"))
    }));

    cancellation.cancel();
    println!(
        "Composio mock TLS demo: allow=forwarded deny=blocked batch=atomic monitor=forwarded upstream_dispatches=2"
    );
    Ok(())
}
