use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use firma_core::{
    AbortReason, ActionParams, Connector, ConnectorError, ConnectorResponse, SecretMatcher,
    TransportView,
};
use firma_http::{Authority, HeaderMap, Method};
use firma_secret_provider::{
    SecretPlaceholder,
    gateway::{
        client::GatewayClient, client::config::GatewayClientConfig, endpoint::GatewayEndpoint,
    },
    non_empty::NonEmptyString,
    spec::http::{HttpIntegrationSpec, HttpMatcherRule, PathAndMatcher, PathOnly},
};
use firma_sidecar::config::SidecarConfig;
use firma_sidecar::connector::ConnectorRegistry;
use firma_sidecar::handler::{HandledResponse, RequestHandler};
use firma_sidecar::interceptor::http::HttpInterceptor;
use firma_sidecar::normalizer::RawRequest;
use firma_sidecar::startup::build_pipeline_runtime;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

const PATH: &str = "/v1/chat/completions";
const SECRET: &str = "s3cr3t-db-pass";
const GZIP_SECRET_RESPONSE: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xab, 0x56, 0x0a, 0x4e, 0x4d, 0x2e,
    0x4a, 0x2d, 0x09, 0x2e, 0x29, 0xca, 0xcc, 0x4b, 0x57, 0xb2, 0x52, 0x2a, 0x36, 0x4e, 0x2e, 0x32,
    0x2e, 0xd1, 0x4d, 0x49, 0xd2, 0x2d, 0x48, 0x2c, 0x2e, 0x56, 0xd2, 0x51, 0xf2, 0x4b, 0xcc, 0x4d,
    0x05, 0x8a, 0xa7, 0x24, 0x81, 0xf9, 0xb5, 0x00, 0x0e, 0xc1, 0x15, 0x87, 0x31, 0x00, 0x00, 0x00,
];

type CapturedRequests = Arc<Mutex<Vec<Vec<u8>>>>;

struct FixedConnector {
    response: ConnectorResponse,
    requests: CapturedRequests,
}

#[async_trait]
impl Connector for FixedConnector {
    async fn dispatch(&self, view: &TransportView) -> Result<ConnectorResponse, ConnectorError> {
        let ActionParams::Http(http) = &view.envelope().intent().params else {
            return Err(ConnectorError::InvalidRequest(
                "expected HTTP request".to_string(),
            ));
        };
        let body = http.body.clone().unwrap_or_default();
        self.requests
            .lock()
            .map_err(|error| ConnectorError::Network(error.to_string()))?
            .push(body);
        Ok(self.response.clone())
    }
}

struct ProxyResponse {
    status: u16,
    body: Vec<u8>,
}

impl ProxyResponse {
    fn assert_abort(&self, reason: AbortReason) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.status == 504,
            "expected fail-closed HTTP 504, got {} with body {:?}",
            self.status,
            String::from_utf8_lossy(&self.body)
        );
        let body: serde_json::Value = serde_json::from_slice(&self.body)?;
        anyhow::ensure!(body["aborted"] == true, "response was not an abort: {body}");
        anyhow::ensure!(
            body["reason"] == reason.code(),
            "expected abort reason {}, got {body}",
            reason.code()
        );
        Ok(())
    }
}

fn passthrough_pipeline() -> anyhow::Result<Arc<firma_sidecar::pipeline::EnforcementPipeline>> {
    let directory = tempfile::tempdir()?;
    let rules_path = directory.path().join("mapping-rules.toml");
    std::fs::write(
        &rules_path,
        r#"
[[rules]]
method = "GET"
host = "unused.example.test"
path = "/unused"
action_class = "communication.external.read"
"#,
    )?;
    let config_path = directory.path().join("firma.toml");
    std::fs::write(
        &config_path,
        format!(
            r"
[mapping]
rules_path = '{}'
default_protected = false
",
            rules_path.display()
        ),
    )?;
    let config = SidecarConfig::load_from_path(&config_path).map_err(anyhow::Error::msg)?;
    Ok(build_pipeline_runtime(&config)?.pipeline)
}

fn fixed_handler(
    body: Vec<u8>,
    headers: HeaderMap,
) -> anyhow::Result<(RequestHandler, CapturedRequests)> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connector = FixedConnector {
        response: ConnectorResponse {
            status: 200,
            headers,
            response_size: body.len(),
            body,
            dispatch_latency: Duration::ZERO,
        },
        requests: Arc::clone(&requests),
    };
    let registry = Arc::new(ConnectorRegistry::new(Arc::new(connector)));
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(8);
    Ok((
        RequestHandler::new(passthrough_pipeline()?, registry, audit_tx),
        requests,
    ))
}

fn sensitive_provider(host: &str) -> HttpIntegrationSpec {
    HttpIntegrationSpec {
        provider_id: "test-vault".to_string(),
        host: host.to_string(),
        matchers: vec![HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: Some(PATH.to_string()),
            matcher: SecretMatcher::Json {
                record_path: "$".to_string(),
                value_path: "$.SecretString".to_string(),
                name: firma_core::SecretNameSource::Path {
                    path: "$.Name".to_string(),
                },
                item_selector: None,
                domain_selector: None,
            },
        })],
    }
}

fn blocked_provider(host: &str) -> anyhow::Result<HttpIntegrationSpec> {
    Ok(HttpIntegrationSpec {
        provider_id: "test-vault".to_string(),
        host: host.to_string(),
        matchers: vec![HttpMatcherRule::BlockedCommand(PathOnly {
            path: NonEmptyString::new(PATH.to_string())?,
        })],
    })
}

fn raw_request(host: Authority, body: Vec<u8>) -> RawRequest {
    RawRequest {
        method: Method::POST,
        host,
        path: PATH.to_string(),
        headers: HeaderMap::from([(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )]),
        body: Some(body),
        is_https: false,
    }
}

async fn proxy_request(
    handler: RequestHandler,
    host: &str,
    body: &[u8],
) -> anyhow::Result<ProxyResponse> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let interceptor = HttpInterceptor::new(proxy_addr);
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            interceptor
                .run_with_listener(listener, Arc::new(handler), cancel)
                .await
        }
    });

    let mut stream = TcpStream::connect(proxy_addr).await?;
    let request = format!(
        "POST http://{host}{PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         x-firma-session-id: sess_secret_regression\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len(),
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await??;
    cancel.cancel();
    server.await??;

    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("proxy response contained no header terminator"))?;
    let headers = std::str::from_utf8(&response[..header_end])?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| anyhow::anyhow!("proxy response contained no status"))?
        .parse()?;
    Ok(ProxyResponse {
        status,
        body: response[header_end + 4..].to_vec(),
    })
}

async fn fake_resolve_gateway(secret: &str) -> anyhow::Result<GatewayClient> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = vec![0_u8; 8192];
            if stream.read(&mut request).await.is_ok() {
                let response = format!(r#"[{{"type":"ok","secret_b64":"{encoded}"}}]"#) + "\n";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        }
    });
    Ok(GatewayClient::new(
        GatewayEndpoint::parse(&format!("tcp:{address}"))?,
        GatewayClientConfig::default(),
    ))
}

async fn gateway_contact_probe() -> anyhow::Result<(
    GatewayClient,
    tokio::sync::oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (contacted_tx, contacted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        if listener.accept().await.is_ok() {
            let _ = contacted_tx.send(());
        }
    });
    let client = GatewayClient::new(
        GatewayEndpoint::parse(&format!("tcp:{address}"))?,
        GatewayClientConfig::default(),
    );
    Ok((client, contacted_rx, server))
}

#[tokio::test]
async fn provider_host_matching_uses_canonical_http_host() -> anyhow::Result<()> {
    let canonical_host = "vault.example.test";
    let request_host = "VAULT.EXAMPLE.TEST";
    let (handler, requests) = fixed_handler(b"should not dispatch".to_vec(), HeaderMap::new())?;
    let handler = handler.with_http_secret_providers(vec![blocked_provider(canonical_host)?]);

    let response = proxy_request(handler, request_host, b"{}").await?;

    response.assert_abort(AbortReason::CredentialInjectionBlocked)?;
    assert!(
        requests
            .lock()
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn sensitive_provider_without_gateway_fails_closed() -> anyhow::Result<()> {
    let host = "vault.example.test";
    let response_body = serde_json::json!({"SecretString": SECRET, "Name": "dbpass"})
        .to_string()
        .into_bytes();
    let (handler, requests) = fixed_handler(
        response_body,
        HeaderMap::from([(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )]),
    )?;
    let handler = handler.with_http_secret_providers(vec![sensitive_provider(host)]);

    let response = handler
        .handle(
            raw_request(Authority::from_static(host), b"{}".to_vec()),
            "sess_secret_regression",
        )
        .await;

    let HandledResponse::Aborted { reason, detail } = response else {
        anyhow::bail!("sensitive provider without a gateway must abort, got {response:?}");
    };
    assert_eq!(reason, AbortReason::CredentialInjectionFailed);
    assert_eq!(
        detail,
        "HTTP secret provider \"test-vault\" matched but no secret gateway is configured"
    );
    assert_eq!(
        requests
            .lock()
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .len(),
        1,
        "the provider response must reach mediation before the missing gateway aborts it"
    );
    Ok(())
}

#[tokio::test]
async fn compressed_sensitive_response_is_not_forwarded_verbatim() -> anyhow::Result<()> {
    let host = "vault.example.test";
    let (handler, _requests) = fixed_handler(
        GZIP_SECRET_RESPONSE.to_vec(),
        HeaderMap::from([
            (
                http::HeaderName::from_static("content-type"),
                http::HeaderValue::from_static("application/json"),
            ),
            (
                http::HeaderName::from_static("content-encoding"),
                http::HeaderValue::from_static("gzip"),
            ),
        ]),
    )?;
    let (gateway, contacted, gateway_server) = gateway_contact_probe().await?;
    let handler = handler
        .with_gateway_client(gateway)
        .with_http_secret_providers(vec![sensitive_provider(host)]);

    let response = proxy_request(handler, host, b"{}").await?;
    let gateway_contact = tokio::time::timeout(Duration::from_millis(100), contacted).await;
    gateway_server.abort();

    assert!(
        gateway_contact.is_err(),
        "compressed content must be rejected before extraction or gateway access"
    );
    response.assert_abort(AbortReason::CredentialInjectionFailed)?;
    assert_ne!(
        response.body, GZIP_SECRET_RESPONSE,
        "the secret-bearing gzip payload must never be forwarded verbatim"
    );
    Ok(())
}

#[tokio::test]
async fn embedded_secret_echo_is_masked_inside_json_string() -> anyhow::Result<()> {
    let host = "api.example.test";
    let placeholder = SecretPlaceholder::new();
    let response_body = serde_json::json!({
        "error": format!("credential {SECRET} is invalid")
    })
    .to_string()
    .into_bytes();
    let (handler, requests) = fixed_handler(
        response_body,
        HeaderMap::from([(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )]),
    )?;
    let handler = handler.with_gateway_client(fake_resolve_gateway(SECRET).await?);
    let request_body = serde_json::json!({"credential": placeholder.to_string()})
        .to_string()
        .into_bytes();

    let response = proxy_request(handler, host, &request_body).await?;

    assert_eq!(response.status, 200);
    assert!(
        !response
            .body
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );
    assert!(
        response
            .body
            .windows(placeholder.to_string().len())
            .any(|window| window == placeholder.to_string().as_bytes())
    );
    let dispatched = requests
        .lock()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    assert_eq!(dispatched.len(), 1);
    assert!(
        dispatched[0]
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );
    drop(dispatched);
    Ok(())
}
