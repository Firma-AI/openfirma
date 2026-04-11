//! HTTP proxy interceptor.
//!
//! Implements the [`Interceptor`](super::Interceptor) trait using a
//! Pingora-based forward proxy. The agent sets
//! `HTTP_PROXY=http://localhost:<port>` and all outbound HTTP traffic flows
//! through this interceptor before reaching external systems.
//!
//! The Pingora `ProxyHttp` lifecycle hooks parse each inbound request into a
//! [`RawRequest`](crate::normalizer::RawRequest), run it through the
//! [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline), and act on
//! the decision at the transport level. HTTPS CONNECT tunneling with dynamic
//! certificate generation is planned but not yet implemented.

use std::net::SocketAddr;
use std::sync::Arc;

use pingora_core::server::configuration::ServerConf;
use pingora_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use tokio_util::sync::CancellationToken;

use crate::interceptor::Interceptor;
use crate::pipeline::{EnforcementPipeline, RawRequest};

/// Pingora-based HTTP forward proxy interceptor.
///
/// Listens on a configurable TCP port (default 8080) and captures every
/// outbound HTTP request made by the agent. Each request is converted into a
/// [`RawRequest`](crate::normalizer::RawRequest) and enforced through the
/// [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline) provided in
/// [`Interceptor::run`](super::Interceptor::run).
///
/// Malformed requests that cannot be parsed into a valid `RawRequest` are
/// rejected with a structured DENY carrying reason `MALFORMED_REQUEST`
/// (fail-closed).
pub struct HttpInterceptor {
    address: SocketAddr,
    pipeline: Option<Arc<EnforcementPipeline>>,
}

impl HttpInterceptor {
    /// Create a new [`HttpInterceptor`] that listens on the specified address.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            pipeline: None,
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

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        // 1. Build RawRequest from session.req_header()
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

        let raw_request = RawRequest {
            method: header.method.to_string(),
            host,
            headers: header
                .headers
                .iter()
                .filter_map(|(key, value)| {
                    Some((key.to_string(), value.to_str().ok()?.to_string()))
                })
                .collect(),
            path: extract_path(header.raw_path()),
            body,
            is_https: header.method == "CONNECT",
        };

        // 2. Enforce through the pipeline
        let pipeline = self
            .pipeline
            .as_ref()
            .ok_or_else(|| pingora_core::Error::new(pingora_core::ErrorType::InternalError))?;

        let session_id = header
            .headers
            .get("x-firma-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let decision = pipeline.enforce(&raw_request, session_id);

        // 3. Act on the enforcement decision
        match decision {
            crate::pipeline::EnforcementDecision::Allow { .. }
            | crate::pipeline::EnforcementDecision::Passthrough { .. } => {
                Ok(Box::new(resolve_upstream(&raw_request)))
            }
            crate::pipeline::EnforcementDecision::Deny { reason, detail, .. } => {
                Err(pingora_core::Error::because(
                    pingora_core::ErrorType::HTTPStatus(403),
                    format!("{reason}: {detail}"),
                    pingora_core::Error::new(pingora_core::ErrorType::InternalError),
                ))
            }
        }
    }
}

impl Interceptor for HttpInterceptor {
    async fn run(
        mut self,
        pipeline: Arc<EnforcementPipeline>,
        cancel: CancellationToken,
    ) -> Result<(), super::InterceptorError> {
        let address = self.address;
        self.pipeline = Some(pipeline);

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
    use crate::pipeline::{
        ActionClassRegistry, CapabilityEntry, CapabilityMap, CapabilityValidator,
        ConstraintEnforcer, IntentNormalizer, MappingRuleConfig, MappingRulesFile, MappingTable,
        PolicyEvaluation,
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
        #[allow(clippy::unwrap_used)]
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
        let stage1 = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let stage2 = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(normalizer, stage1, stage2))
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
        let stage1 = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let stage2 = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(normalizer, stage1, stage2))
    }

    /// Starts a minimal HTTP server that always returns `200 OK`.
    /// Returns the address it is listening on.
    async fn mock_upstream() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        #[allow(clippy::unwrap_used)]
        let listener = listener.unwrap();
        #[allow(clippy::unwrap_used)]
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
        #[allow(clippy::unwrap_used)]
        let stream = stream.as_mut().unwrap();

        #[allow(clippy::unwrap_used)]
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
        pipeline: Arc<EnforcementPipeline>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<Result<(), super::super::InterceptorError>> {
        let interceptor = HttpInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(pipeline, cancel_clone).await });

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

    #[test]
    fn test_pipeline_allow_matches_with_port_in_host() {
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let raw = RawRequest {
            method: "POST".to_string(),
            host: "127.0.0.1:9999".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(b"{}".to_vec()),
            is_https: false,
        };
        let decision = pipeline.enforce(&raw, "");
        assert!(decision.is_allow(), "expected allow, got: {decision:?}");
    }

    // ── integration tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_proxy_allows_valid_request_and_forwards_to_upstream() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, pipeline, cancel.clone()).await;

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
        let pipeline = test_pipeline_deny_for_host("*");
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, pipeline, cancel.clone()).await;

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
        let pipeline = test_pipeline_deny_for_host("api.openai.com");
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, pipeline, cancel.clone()).await;

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
