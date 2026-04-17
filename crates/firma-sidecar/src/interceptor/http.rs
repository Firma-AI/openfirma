//! HTTP proxy interceptor.
//!
//! Implements the [`Interceptor`](super::Interceptor) trait using a
//! Pingora-based forward proxy. The agent sets
//! `HTTP_PROXY=http://localhost:<port>` and all outbound HTTP traffic flows
//! through this interceptor before reaching external systems.
//!
//! The Pingora `ProxyHttp` lifecycle hooks parse each inbound request into a
//! [`RawRequest`](crate::normalizer::RawRequest), pass it to the shared
//! [`RequestHandler`](crate::handler::RequestHandler), and write the handled
//! response downstream. HTTPS CONNECT tunneling with dynamic certificate
//! generation is planned but not yet implemented.

use std::net::SocketAddr;
use std::sync::Arc;

use pingora_core::server::configuration::ServerConf;
use pingora_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use tokio_util::sync::CancellationToken;

use crate::handler::{DispatchedResponse, HandledResponse, RequestHandler};
use crate::interceptor::Interceptor;
use crate::pipeline::RawRequest;

/// Pingora-based HTTP forward proxy interceptor.
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

#[async_trait::async_trait]
impl ProxyHttp for HttpInterceptor {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        let raw_request = build_raw_request(session).await?;

        let handler = self
            .handler
            .as_ref()
            .ok_or_else(|| pingora_core::Error::new(pingora_core::ErrorType::InternalError))?;

        let session_id = raw_request
            .headers
            .get("x-firma-session-id")
            .cloned()
            .unwrap_or_default();
        let outcome = handler.handle(raw_request, &session_id).await;

        write_handled_response(session, outcome).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        Ok(Box::new(resolve_upstream(&raw_request_from_header(
            session,
        )?)))
    }
}

async fn build_raw_request(session: &mut Session) -> pingora_core::Result<RawRequest> {
    let body = if session.is_body_empty() {
        None
    } else {
        let mut body = vec![];
        loop {
            match session.read_request_body().await {
                Ok(Some(chunk)) => body.extend(chunk.to_vec()),
                Ok(None) => break,
                Err(_error) => {
                    return Err(pingora_core::Error::new(
                        pingora_core::ErrorType::InternalError,
                    ));
                }
            }
        }

        Some(body)
    };

    let mut raw = raw_request_from_header(session)?;
    raw.body = body;
    Ok(raw)
}

fn raw_request_from_header(session: &Session) -> pingora_core::Result<RawRequest> {
    let header = session.req_header();
    let host = header
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
        .or_else(|| header.uri.authority().map(ToString::to_string))
        .unwrap_or_default();

    // Fail-closed: reject requests without a resolvable host.
    if host.is_empty() {
        return Err(pingora_core::Error::because(
            pingora_core::ErrorType::HTTPStatus(400),
            "MALFORMED_REQUEST: missing host",
            pingora_core::Error::new(pingora_core::ErrorType::InternalError),
        ));
    }

    Ok(RawRequest {
        method: header.method.to_string(),
        host,
        headers: header
            .headers
            .iter()
            .filter_map(|(key, value)| Some((key.to_string(), value.to_str().ok()?.to_string())))
            .collect(),
        path: extract_path(header.raw_path()),
        body: None,
        is_https: header.method == "CONNECT",
    })
}

impl Interceptor for HttpInterceptor {
    async fn run(
        mut self,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> Result<(), super::InterceptorError> {
        let address = self.address;
        self.handler = Some(handler);

        let conf = Arc::new(ServerConf::default());
        let mut svc = http_proxy_service(&conf, self);
        svc.add_tcp(&address.to_string());

        let mut server = Server::new_with_opt_and_conf(None, ServerConf::default());
        server.add_service(svc);
        server.bootstrap();

        // Run Pingora in a blocking thread so we don't block the async
        // runtime. The `CancellationTokenShutdown` bridges our token into
        // Pingora's shutdown mechanism.
        tokio::task::spawn_blocking(move || {
            server.run(RunArgs {
                shutdown_signal: Box::new(CancellationTokenShutdown(cancel)),
            });
        })
        .await
        .map_err(|e| super::InterceptorError::ServerError(e.to_string()))
    }
}

async fn write_handled_response(
    session: &mut Session,
    outcome: HandledResponse,
) -> pingora_core::Result<()> {
    match outcome {
        HandledResponse::Ok(response) | HandledResponse::Passthrough(response) => {
            write_dispatched_response(session, response).await
        }
        HandledResponse::Deny { reason, detail } => {
            session
                .respond_error_with_body(
                    403,
                    hyper::body::Bytes::from(crate::handler::deny_body_json(reason, &detail)),
                )
                .await
        }
    }
}

async fn write_dispatched_response(
    session: &mut Session,
    response: DispatchedResponse,
) -> pingora_core::Result<()> {
    let mut header = ResponseHeader::build(response.status, Some(response.headers.len()))?;
    for (name, value) in response.headers {
        let _inserted = header.append_header(name, value)?;
    }
    let is_empty = response.body.is_empty();
    session
        .write_response_header(Box::new(header), is_empty)
        .await?;
    if !is_empty {
        session
            .write_response_body(Some(hyper::body::Bytes::from(response.body)), true)
            .await?;
    }
    Ok(())
}

/// Bridges a [`CancellationToken`] into Pingora's [`ShutdownSignalWatch`].
struct CancellationTokenShutdown(CancellationToken);

#[async_trait::async_trait]
impl ShutdownSignalWatch for CancellationTokenShutdown {
    async fn recv(&self) -> ShutdownSignal {
        self.0.cancelled().await;
        ShutdownSignal::FastShutdown
    }
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
fn resolve_upstream(request: &RawRequest) -> HttpPeer {
    let default_port: u16 = if request.is_https { 443 } else { 80 };
    let (host, port) = if let Some((h, p)) = request.host.rsplit_once(':') {
        (h, p.parse::<u16>().unwrap_or(default_port))
    } else {
        (request.host.as_str(), default_port)
    };

    HttpPeer::new((host, port), request.is_https, String::new())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, EnforcementPipeline,
        IntentNormalizer, MappingTable, NullCredentialInjector, PipelineArgs,
    };

    // ── helpers ────────────────────────────────────────────────────────

    fn raw_request(host: &str, is_https: bool) -> RawRequest {
        RawRequest {
            method: "GET".to_string(),
            host: host.to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https,
        }
    }

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
            _: &str,
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
        fn is_revoked(&self, _token_id: &str) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _token_id: &str) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent_test".to_string(),
            session_id: String::new(),
            action_set: vec!["llm.inference".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
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
                action_class: "llm.inference".to_string(),
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
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
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
                action_class: "llm.inference".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, false).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
        }))
    }

    fn test_handler(pipeline: Arc<EnforcementPipeline>) -> Arc<RequestHandler> {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        Arc::new(RequestHandler::new(pipeline, tx))
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

    // ── resolve_upstream unit tests ───────────────────────────────────

    #[test]
    fn test_resolve_upstream_https_default_port() {
        let peer = resolve_upstream(&raw_request("127.0.0.1", true));
        let debug = format!("{peer:?}");
        assert!(
            debug.contains("127.0.0.1:443"),
            "expected :443, got: {debug}"
        );
        assert!(
            debug.contains("HTTPS"),
            "expected HTTPS scheme, got: {debug}"
        );
    }

    #[test]
    fn test_resolve_upstream_http_default_port() {
        let peer = resolve_upstream(&raw_request("127.0.0.1", false));
        let debug = format!("{peer:?}");
        assert!(debug.contains("127.0.0.1:80"), "expected :80, got: {debug}");
    }

    #[test]
    fn test_resolve_upstream_explicit_port() {
        let peer = resolve_upstream(&raw_request("127.0.0.1:9090", false));
        let debug = format!("{peer:?}");
        assert!(
            debug.contains("127.0.0.1:9090"),
            "expected :9090, got: {debug}"
        );
    }

    #[test]
    fn test_resolve_upstream_invalid_port_uses_default() {
        let peer = resolve_upstream(&raw_request("127.0.0.1:notaport", true));
        let debug = format!("{peer:?}");
        assert!(
            debug.contains("127.0.0.1:443"),
            "expected :443 fallback, got: {debug}"
        );
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
}
