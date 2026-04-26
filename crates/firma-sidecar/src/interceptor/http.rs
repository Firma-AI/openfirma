//! HTTP proxy interceptor.
//!
//! Implements the [`Interceptor`](super::Interceptor) trait using a TCP
//! HTTP/1.1 proxy endpoint. The agent sets
//! `HTTP_PROXY=http://localhost:<port>` and all outbound HTTP traffic flows
//! through this interceptor before reaching external systems.
//!
//! The interceptor parses each inbound request into a
//! [`RawRequest`](crate::normalizer::RawRequest), passes it to the shared
//! [`RequestHandler`](crate::handler::RequestHandler), and writes the handled
//! response downstream.
//!
//! HTTPS `CONNECT` is supported as transparent TCP tunneling (no MITM): the
//! sidecar authorizes `host:port` at handshake time, emits audit events, then
//! relays bytes bidirectionally between client and upstream target.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::handler::{ConnectDecision, DispatchedResponse, HandledResponse, RequestHandler};
use crate::interceptor::{Interceptor, InterceptorError};
use crate::pipeline::RawRequest;

/// HTTP forward proxy interceptor.
///
/// Listens on a configurable TCP port (default 8080) and captures every
/// outbound HTTP request made by the agent. Each request is converted into a
/// [`RawRequest`](crate::normalizer::RawRequest) and handled through the
/// [`RequestHandler`](crate::handler::RequestHandler) provided in
/// [`Interceptor::run`](super::Interceptor::run).
///
/// Malformed requests that cannot be parsed into a valid `RawRequest` are
/// rejected with a structured DENY carrying reason `MALFORMED_REQUEST`
/// (fail-closed).
pub struct HttpInterceptor {
    address: SocketAddr,
    handler: Option<Arc<RequestHandler>>,
}

impl HttpInterceptor {
    /// Create a new [`HttpInterceptor`] that listens on the specified address.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            handler: None,
        }
    }
}

impl From<SocketAddr> for HttpInterceptor {
    fn from(address: SocketAddr) -> Self {
        Self::new(address)
    }
}

impl Interceptor for HttpInterceptor {
    async fn run(
        mut self,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> Result<(), InterceptorError> {
        self.handler = Some(handler);
        let listener = TcpListener::bind(self.address)
            .await
            .map_err(|e| InterceptorError::BindFailed(e.to_string()))?;

        let handler =
            Arc::clone(self.handler.as_ref().ok_or_else(|| {
                InterceptorError::ServerError("request handler not set".to_string())
            })?);

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((stream, _)) = accepted {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(stream, handler).await {
                                tracing::warn!("http proxy connection error: {e}");
                            }
                        });
                    }
                }
                () = cancel.cancelled() => break,
            }
        }

        Ok(())
    }
}

async fn serve_connection(
    socket: TcpStream,
    handler: Arc<RequestHandler>,
) -> Result<(), InterceptorError> {
    let io = TokioIo::new(socket);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler);
                async move { handle_request(req, &handler).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| InterceptorError::ServerError(format!("HTTP connection error: {e}")))
}

async fn handle_request(
    mut req: Request<Incoming>,
    handler: &RequestHandler,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        return handle_connect_request(&mut req, handler).await;
    }

    let raw = match build_raw_request(req).await {
        Ok(raw) => raw,
        Err(detail) => return Ok(deny_response(StatusCode::FORBIDDEN, &detail)),
    };
    let session_id = raw
        .headers
        .get("x-firma-session-id")
        .cloned()
        .unwrap_or_default();

    let response = match handler.handle(raw, &session_id).await {
        HandledResponse::Ok(response) | HandledResponse::Passthrough(response) => {
            dispatched_response(response)
        }
        HandledResponse::Deny {
            reason,
            detail,
            context: _,
        } => deny_json_response(
            StatusCode::FORBIDDEN,
            crate::handler::deny_body_json(reason, &detail),
        ),
        HandledResponse::Aborted { reason, detail } => deny_json_response(
            StatusCode::GATEWAY_TIMEOUT,
            crate::handler::abort_body_json(reason, &detail),
        ),
    };

    Ok(response)
}

async fn handle_connect_request(
    req: &mut Request<Incoming>,
    handler: &RequestHandler,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let raw = match build_raw_request_head(req, true) {
        Ok(raw) => raw,
        Err(detail) => return Ok(deny_response(StatusCode::FORBIDDEN, &detail)),
    };
    let session_id = raw
        .headers
        .get("x-firma-session-id")
        .cloned()
        .unwrap_or_default();

    match handler.handle_connect(raw, &session_id).await {
        ConnectDecision::Deny { reason, detail } => Ok(deny_json_response(
            StatusCode::FORBIDDEN,
            crate::handler::deny_body_json(reason, &detail),
        )),
        ConnectDecision::Allow => {
            let target = connect_target(&host_with_default_port(req, true));
            let on_upgrade = hyper::upgrade::on(req);
            tokio::spawn(async move {
                if let Err(e) = relay_connect_tunnel(on_upgrade, &target).await {
                    tracing::warn!("CONNECT tunnel failed: {e}");
                }
            });
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from_static(b"internal error")))
                }))
        }
    }
}

async fn relay_connect_tunnel(
    on_upgrade: hyper::upgrade::OnUpgrade,
    target: &str,
) -> Result<(), String> {
    let upgraded = on_upgrade
        .await
        .map_err(|e| format!("upgrade failed: {e}"))?;
    let mut downstream = TokioIo::new(upgraded);
    let mut upstream = TcpStream::connect(target)
        .await
        .map_err(|e| format!("upstream connect failed for {target}: {e}"))?;
    let _ = copy_bidirectional(&mut downstream, &mut upstream)
        .await
        .map_err(|e| format!("tunnel relay failed: {e}"))?;
    Ok(())
}

async fn build_raw_request(req: Request<Incoming>) -> Result<RawRequest, String> {
    let mut raw = build_raw_request_head(&req, false)?;
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("MALFORMED_REQUEST: failed to read body: {e}"))?
        .to_bytes();
    raw.body = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.to_vec())
    };
    Ok(raw)
}

fn build_raw_request_head(req: &Request<Incoming>, is_connect: bool) -> Result<RawRequest, String> {
    let method = req.method().to_string();
    let host = host_with_default_port(req, is_connect);
    if host.is_empty() {
        return Err("MALFORMED_REQUEST: missing host".to_string());
    }
    let path = if is_connect {
        "/".to_string()
    } else {
        extract_path(req.uri().to_string().as_bytes())
    };
    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let is_https = is_connect
        || req
            .uri()
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"));

    Ok(RawRequest {
        method,
        host,
        headers,
        path,
        body: None,
        is_https,
    })
}

fn host_with_default_port(req: &Request<Incoming>, is_connect: bool) -> String {
    req.headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
        .or_else(|| req.uri().authority().map(ToString::to_string))
        .or_else(|| {
            req.uri().host().map(|h| {
                let port = req
                    .uri()
                    .port_u16()
                    .unwrap_or(if is_connect { 443 } else { 80 });
                format!("{h}:{port}")
            })
        })
        .unwrap_or_default()
}

fn connect_target(host: &str) -> String {
    if let Ok(authority) = host.parse::<hyper::http::uri::Authority>() {
        let host = authority.host();
        let port = authority.port_u16().unwrap_or(443);
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    } else {
        host.to_string()
    }
}

fn dispatched_response(response: DispatchedResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(response.body)))
        .unwrap_or_else(|_| {
            deny_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
        })
}

fn deny_response(status: StatusCode, detail: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::copy_from_slice(detail.as_bytes())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

fn deny_json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

/// Extracts the path component from a raw request-target.
///
/// For absolute-form proxy requests (`http://host/path`), strips the scheme
/// and authority to return just the path (e.g. `/path`). For origin-form
/// requests (`/path`), returns the value unchanged.
fn extract_path(raw_path: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw_path);
    if let Some(rest) = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
    {
        // Find the first '/' after the authority.
        rest.find('/')
            .map_or_else(|| "/".to_string(), |i| rest[i..].to_string())
    } else {
        s.into_owned()
    }
}

/// Resolves the upstream [`HttpPeer`] from a [`RawRequest`].
///
/// Parses `host` into address and port, defaulting to 443 for HTTPS
/// and 80 for HTTP.
// Note: CONNECT routing is handled explicitly in `handle_connect_request`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::credential::NullCredentialInjector;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, EnforcementPipeline,
        IntentNormalizer, MappingTable, PipelineArgs,
    };

    // ── helpers ────────────────────────────────────────────────────────

    /// Returns an available localhost address by binding to port 0.
    fn free_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()
            .and_then(|l| l.local_addr().ok());
        // SAFETY: this is test-only code; binding port 0 always succeeds
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        listener.unwrap()
    }

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
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

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "3713c5fc-b569-650c-c780-c64051473370"
                .parse()
                .expect("literal token id"),
            agent_id: "agent_test".parse().expect("literal agent id"),
            session_id: "_test_".parse().expect("literal session id"),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
            budget_ceiling: None,
        }
    }

    /// Builds a pipeline that ALLOWs POST requests to `host` at `path`.
    ///
    /// Uses a wildcard host pattern (`*`) combined with the concrete path
    /// so the rule matches regardless of port number in the host header.
    fn test_pipeline_allow(path: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "*".to_string(),
                path: Some(path.to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_pipeline_allow_connect() -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("CONNECT".to_string()),
                host: "*".to_string(),
                path: Some("/".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    /// Builds a pipeline that DENYs classified requests to `host` (empty
    /// capability map). Uses `default_protected: false` so unmapped hosts
    /// pass through.
    fn test_pipeline_deny_for_host(host: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: host.to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, false).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_pipeline_deny_connect_for_host(host: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("CONNECT".to_string()),
                host: host.to_string(),
                path: Some("/".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, false).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_handler(pipeline: Arc<EnforcementPipeline>) -> Arc<RequestHandler> {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        Arc::new(RequestHandler::new(
            pipeline,
            crate::handler::tests::test_connector_registry(),
            tx,
        ))
    }

    /// Starts a minimal HTTP server that always returns `200 OK`.
    /// Returns the address it is listening on.
    async fn mock_upstream() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let listener = listener.unwrap();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((mut stream, _)) = accepted {
                            // Read the request (consume everything available).
                            let mut buf = vec![0u8; 4096];
                            let _ = stream.read(&mut buf).await;

                            // Respond with a minimal 200 OK.
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                    }
                    () = cancel_clone.cancelled() => break,
                }
            }
        });

        (addr, cancel)
    }

    /// Starts a raw TCP target for CONNECT tunnel testing.
    ///
    /// After receiving bytes through the tunnel it replies with `pong`.
    async fn mock_connect_target() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let listener = listener.unwrap();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((mut stream, _)) = accepted {
                            let mut buf = [0u8; 4];
                            if stream.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                                let _ = stream.write_all(b"pong").await;
                            }
                            let _ = stream.shutdown().await;
                        }
                    }
                    () = cancel_clone.cancelled() => break,
                }
            }
        });

        (addr, cancel)
    }

    /// Sends a raw HTTP/1.1 request through the proxy and returns the response
    /// status code.
    async fn proxy_request(proxy_addr: SocketAddr, request: &str) -> u16 {
        let mut stream = TcpStream::connect(proxy_addr).await.ok();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let stream = stream.as_mut().unwrap();

        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        stream.write_all(request.as_bytes()).await.unwrap();

        // Read the response (with a timeout so the test does not hang).
        let mut buf = vec![0u8; 4096];
        let read_result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

        let n = match read_result {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        // Parse the status code from the first line: "HTTP/1.1 <code> ..."
        response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0)
    }

    async fn read_connect_response(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        for _ in 0..32 {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    /// Starts the HTTP proxy interceptor and waits for it to be ready.
    /// Returns a handle to the server task.
    async fn start_proxy(
        addr: SocketAddr,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<Result<(), super::super::InterceptorError>> {
        let interceptor = HttpInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        // Wait for the proxy to be ready by polling the port.
        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                return handle;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("proxy did not become ready within 2.5 seconds");
    }

    // ── extract_path unit tests ─────────────────────────────────────────

    #[test]
    fn test_extract_path_absolute_http() {
        let path = extract_path(b"http://api.openai.com/v1/chat/completions");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_extract_path_absolute_https() {
        let path = extract_path(b"https://api.openai.com/v1/chat/completions");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_extract_path_absolute_with_port() {
        let path = extract_path(b"http://127.0.0.1:9090/v1/chat/completions");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_extract_path_absolute_host_only() {
        let path = extract_path(b"http://api.openai.com");
        assert_eq!(path, "/");
    }

    #[test]
    fn test_extract_path_origin_form() {
        let path = extract_path(b"/v1/chat/completions");
        assert_eq!(path, "/v1/chat/completions");
    }

    // ── pipeline sanity checks ─────────────────────────────────────────

    #[tokio::test]
    async fn test_pipeline_allow_matches_with_port_in_host() {
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let raw = RawRequest {
            method: "POST".to_string(),
            host: "127.0.0.1:9999".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(b"{}".to_vec()),
            is_https: false,
        };
        let (decision, _payload) = pipeline.enforce(&raw, "").await;
        assert!(decision.is_allow(), "expected allow, got: {decision:?}");
    }

    // ── integration tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_proxy_allows_valid_request_and_forwards_to_upstream() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Length: 2\r\n\
             \r\n\
             {{}}"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(status, 200, "expected 200 OK for allowed request");

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_denies_when_no_capability() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        // Wildcard host, empty cap map → DENY at token selection
        let handler = test_handler(test_pipeline_deny_for_host("*"));
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Length: 2\r\n\
             \r\n\
             {{}}"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(status, 403, "expected 403 for denied request");

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_passthrough_for_unmapped_host() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        // Pipeline maps only api.openai.com, default_protected=false →
        // unmapped hosts pass through.
        let handler = test_handler(test_pipeline_deny_for_host("api.openai.com"));
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "GET http://{host}/anything HTTP/1.1\r\n\
             Host: {host}\r\n\
             \r\n"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(
            status, 200,
            "expected 200 for passthrough (unmapped) request"
        );

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_allows_and_tunnels_bytes() {
        let (target_addr, target_cancel) = mock_connect_target().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", target_addr.port());
        let handler = test_handler(test_pipeline_allow_connect());
        let cancel = CancellationToken::new();
        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .unwrap_or_else(|e| panic!("failed to connect to proxy: {e}"));
        let connect_req = format!(
            "CONNECT {host} HTTP/1.1\r\n\
             Host: {host}\r\n\
             \r\n"
        );
        stream
            .write_all(connect_req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("failed to write CONNECT request: {e}"));

        let response = read_connect_response(&mut stream).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected CONNECT 200, got: {response:?}"
        );

        stream
            .write_all(b"ping")
            .await
            .unwrap_or_else(|e| panic!("failed to write tunnel payload: {e}"));
        let mut reply = [0u8; 4];
        stream
            .read_exact(&mut reply)
            .await
            .unwrap_or_else(|e| panic!("failed to read tunnel reply: {e}"));
        assert_eq!(&reply, b"pong");

        cancel.cancel();
        target_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_denies_without_capability() {
        let (target_addr, target_cancel) = mock_connect_target().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", target_addr.port());
        let handler = test_handler(test_pipeline_deny_connect_for_host("*"));
        let cancel = CancellationToken::new();
        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "CONNECT {host} HTTP/1.1\r\n\
             Host: {host}\r\n\
             \r\n"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(status, 403, "expected 403 for denied CONNECT");

        cancel.cancel();
        target_cancel.cancel();
        let _ = server_handle.await;
    }
}
