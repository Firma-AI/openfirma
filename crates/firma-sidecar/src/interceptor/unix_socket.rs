//! Unix domain socket interceptor.
//!
//! Implements the [`Interceptor`] trait over a Unix
//! domain socket (UDS). The interceptor owns the full socket lifecycle: it
//! removes any stale socket file, binds a
//! [`tokio::net::UnixListener`], accepts connections, and unlinks the socket
//! on shutdown.
//!
//! Requests arrive as plain HTTP over the UDS and are parsed with hyper into
//! [`RawRequest`] values — the same parsing
//! logic used by the HTTP proxy mode. This mode avoids TCP port binding,
//! making it well suited for containerized environments.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use firma_http::{HeaderName, Method};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use crate::handler::{DispatchedResponse, HandledResponse, RequestHandler};
use crate::interceptor::{Interceptor, InterceptorError};
use crate::pipeline::RawRequest;

/// Unix domain socket interceptor.
///
/// Accepts a [`PathBuf`] pointing to the socket file and
/// manages the full bind / listen / accept / cleanup cycle. Incoming HTTP
/// requests are parsed into
/// [`RawRequest`] values and handled through
/// the [`RequestHandler`] provided
/// in [`Interceptor::run`].
///
/// Malformed requests that cannot be parsed into a valid `RawRequest` are
/// rejected with a structured DENY carrying reason `MALFORMED_REQUEST`
/// (fail-closed).
pub struct UnixSocketInterceptor {
    /// Path to the Unix domain socket file.
    path: PathBuf,
    /// Reference to the request handler, set when the interceptor is
    /// running.
    handler: Option<Arc<RequestHandler>>,
}

impl UnixSocketInterceptor {
    /// Create a new [`UnixSocketInterceptor`] with the given socket path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            handler: None,
        }
    }
}

impl From<PathBuf> for UnixSocketInterceptor {
    fn from(path: PathBuf) -> Self {
        Self::new(path)
    }
}

impl From<&Path> for UnixSocketInterceptor {
    fn from(path: &Path) -> Self {
        Self::new(path.to_path_buf())
    }
}

impl Interceptor for UnixSocketInterceptor {
    async fn run(
        mut self,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> Result<(), InterceptorError> {
        self.handler = Some(handler);
        // Remove stale socket if present
        let _ = std::fs::remove_file(&self.path);
        let listener = UnixListener::bind(&self.path)
            .map_err(|_| InterceptorError::BindFailed("Channel closed".to_string()))?;

        let handler = self
            .handler
            .as_ref()
            .ok_or_else(|| InterceptorError::ServerError("request handler not set".to_string()))?;

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((stream, _socket_addr)) = accepted {
                        let handler = Arc::clone(handler);
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(stream, handler).await {
                                tracing::warn!("connection error: {e}");
                            }
                        });
                    }
                }
                () = cancel.cancelled() => break,
            }
        }
        // Cleanup
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }
}

/// Serve a single HTTP/1.1 connection: parse requests, enforce through the
/// pipeline, and respond with the decision.
async fn serve_connection(
    socket: UnixStream,
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
        .await
        .map_err(|e| InterceptorError::ServerError(format!("HTTP connection error: {e}")))
}

/// Convert an incoming hyper request into a [`RawRequest`], run it through
/// the request handler, and return the appropriate HTTP response.
///
/// Malformed requests (missing host, unreadable body) are rejected with
/// `403 MALFORMED_REQUEST` (fail-closed).
async fn handle_request(
    req: Request<Incoming>,
    handler: &RequestHandler,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let raw = match build_raw_request(req).await {
        Ok(r) => r,
        Err(detail) => return Ok(deny_response(StatusCode::FORBIDDEN, &detail)),
    };

    let session_id = raw
        .headers
        .get(&HeaderName::from_static("x-firma-session-id"))
        .cloned()
        .unwrap_or_default();

    let outcome = handler.handle(raw, &session_id).await;

    let response = match outcome {
        HandledResponse::Ok(response) | HandledResponse::Passthrough(response) => {
            dispatched_response(response)
        }
        HandledResponse::Deny {
            reason,
            detail,
            context: _,
        } => deny_json_response(
            // V1: UDS serves HTTP requests; Tool and Api both return
            // 403 + deny_body_json. Fail-closed until a tool-call
            // transport is wired.
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

/// Build a [`RawRequest`] from a hyper [`Request`].
///
/// # Errors
///
/// Returns a detail string suitable for a `MALFORMED_REQUEST` denial when the
/// host cannot be resolved or the body cannot be read.
async fn build_raw_request(req: Request<Incoming>) -> Result<RawRequest, String> {
    let method = Method(req.method().clone());
    let path = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_string(), std::string::ToString::to_string);

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
        .or_else(|| req.uri().authority().map(ToString::to_string))
        .unwrap_or_default();

    if host.is_empty() {
        return Err("MALFORMED_REQUEST: missing host".to_string());
    }

    let headers = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((HeaderName::from(k), v.to_str().ok()?.to_string())))
        .collect();

    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("MALFORMED_REQUEST: failed to read body: {e}"))?
        .to_bytes();

    let body = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.to_vec())
    };

    Ok(RawRequest {
        method,
        host,
        path,
        headers,
        body,
        is_https: false,
    })
}

/// Build a structured denial HTTP response with a plain-text body.
///
/// Used for transport-level malformed-request errors that do not carry a
/// [`DenyReason`](firma_core::DenyReason).
fn deny_response(status: StatusCode, detail: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::copy_from_slice(detail.as_bytes())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

/// Build a structured denial HTTP response with a JSON body.
///
/// Used for enforcement denials routed through
/// [`HandledResponse::Deny`](crate::handler::HandledResponse::Deny).
fn deny_json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::net::UnixStream;

    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile, TenancyMode};
    use crate::credential::NullCredentialInjector;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, EnforcementPipeline,
        IntentNormalizer, MappingTable, PipelineArgs,
    };

    // ── helpers ────────────────────────────────────────────────────────

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
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

    /// Builds a pipeline that ALLOWs POST requests to any host at the given
    /// path. Uses a wildcard host pattern (`*`).
    fn test_pipeline_allow(path: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
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
            TenancyMode::SingleAgent,
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

    /// Builds a pipeline that DENYs classified requests (empty capability map).
    /// Uses `default_protected: true` so every host is protected.
    fn test_pipeline_deny_all() -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
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

    struct FailingCredentialInjector;

    #[async_trait::async_trait]
    impl crate::credential::CredentialInjector for FailingCredentialInjector {
        async fn inject(
            &self,
            _envelope: &ExecutionEnvelope,
            connector_id: &str,
            _target: &str,
        ) -> Result<InjectedCredentials, crate::credential::CredentialInjectionError> {
            Err(crate::credential::CredentialInjectionError::FetchFailed {
                connector_id: connector_id.to_string(),
                reason: "vault unavailable".to_string(),
            })
        }
    }

    /// Builds an ALLOW pipeline whose credential injection always fails,
    /// so `enforce()` returns ABORT after the call is authorized.
    fn test_pipeline_abort(path: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
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
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(FailingCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    /// Builds a pipeline where only `api.openai.com` is mapped and
    /// `default_protected` is false, so unmapped hosts pass through.
    fn test_pipeline_passthrough() -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, false).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
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

    async fn mock_upstream() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        let listener = listener.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((mut stream, _)) = accepted {
                            let mut buf = vec![0u8; 4096];
                            let _ = stream.read(&mut buf).await;
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
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

    /// Returns a unique temporary socket path for a test.
    fn temp_socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("firma_test_{name}_{}.sock", std::process::id()))
    }

    /// Starts the Unix socket interceptor and waits for it to be ready.
    async fn start_interceptor(
        path: &Path,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<Result<(), InterceptorError>> {
        let interceptor = UnixSocketInterceptor::new(path.to_path_buf());
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        // Wait for the socket file to appear.
        for _ in 0..50 {
            if path.exists() {
                return handle;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("unix socket interceptor did not become ready within 2.5 seconds");
    }

    /// Sends a raw HTTP/1.1 request over the Unix socket and returns the
    /// response status code and body.
    async fn uds_request(path: &Path, request: &str) -> (u16, String) {
        let mut stream = UnixStream::connect(path)
            .await
            .map_err(|e| format!("connect failed: {e}"));
        let stream = stream.as_mut().unwrap();

        stream.write_all(request.as_bytes()).await.unwrap();

        // Read the full response. The server writes the response after
        // processing the request; read until the server closes the
        // connection or the timeout fires.
        let mut buf = Vec::with_capacity(8192);
        let read_result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut tmp = [0u8; 4096];
            loop {
                match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
                // If we have a full HTTP response (headers + body), stop
                // waiting for more data.
                let so_far = String::from_utf8_lossy(&buf);
                if so_far.contains("\r\n\r\n") {
                    // Check if we received the full body by looking for
                    // Content-Length.
                    if response_body_complete(&so_far) {
                        break;
                    }
                }
            }
        })
        .await;

        if read_result.is_err() {
            return (0, String::new());
        }

        let response = String::from_utf8_lossy(&buf);

        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);

        // Extract body: everything after the blank line separating headers
        // from body.
        let body = response
            .find("\r\n\r\n")
            .map(|i| response[i + 4..].to_string())
            .unwrap_or_default();

        (status, body)
    }

    /// Returns `true` when the response has a complete body based on
    /// `Content-Length` (or has no `Content-Length` at all).
    fn response_body_complete(response: &str) -> bool {
        let Some(header_end) = response.find("\r\n\r\n") else {
            return false;
        };
        let headers = &response[..header_end];
        let body = &response[header_end + 4..];

        // Look for content-length header (case-insensitive).
        for line in headers.lines() {
            if let Some(val) = line
                .strip_prefix("content-length: ")
                .or_else(|| line.strip_prefix("Content-Length: "))
                && let Ok(expected) = val.trim().parse::<usize>()
            {
                return body.len() >= expected;
            }
        }
        // No content-length — assume body is complete (transfer-encoding
        // chunked is not used in our test responses).
        true
    }

    // ── integration tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_uds_allows_valid_request() {
        let sock = temp_socket_path("allow");
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\n\
                        Host: 127.0.0.1:{}\r\n\
                        X-Firma-Session-Id: _test_\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {{}}",
            upstream_addr.port()
        );

        let (status, body) = uds_request(&sock, &request).await;
        assert_eq!(status, 200, "expected 200 OK for allowed request");
        assert_eq!(body, "OK");

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_denies_when_no_capability() {
        let sock = temp_socket_path("deny_cap");
        let handler = test_handler(test_pipeline_deny_all());
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        let request = "POST /v1/chat/completions HTTP/1.1\r\n\
                        Host: api.openai.com\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {}";

        let (status, body) = uds_request(&sock, request).await;
        assert_eq!(status, 403, "expected 403 for denied request");
        assert!(!body.is_empty(), "deny body should contain reason");

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_aborts_returns_gateway_timeout() {
        let sock = temp_socket_path("abort");
        let handler = test_handler(test_pipeline_abort("/v1/chat/completions"));
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        let request = "POST /v1/chat/completions HTTP/1.1\r\n\
                        Host: api.openai.com\r\n\
                        X-Firma-Session-Id: _test_\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {}";

        let (status, body) = uds_request(&sock, request).await;
        assert_eq!(status, 504, "post-ALLOW abort should return 504");
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("abort body should be valid JSON");
        assert_eq!(parsed["aborted"], serde_json::Value::Bool(true));
        assert_eq!(parsed["reason"], "CREDENTIAL_INJECTION_FAILED");

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_denies_unclassified_intent() {
        let sock = temp_socket_path("deny_unclass");
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        // DELETE to a mapped host but unmapped method+path → unclassified → DENY
        let request = "DELETE /v1/files/abc HTTP/1.1\r\n\
                        Host: api.openai.com\r\n\
                        \r\n";

        let (status, _body) = uds_request(&sock, request).await;
        assert_eq!(status, 403, "unclassified intent should be denied");

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_passthrough_for_unmapped_host() {
        let sock = temp_socket_path("passthrough");
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let handler = test_handler(test_pipeline_passthrough());
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        let request = format!(
            "GET /anything HTTP/1.1\r\n\
                        Host: 127.0.0.1:{}\r\n\
                        \r\n",
            upstream_addr.port()
        );

        let (status, body) = uds_request(&sock, &request).await;
        assert_eq!(
            status, 200,
            "non-protected host should passthrough (200), got {status}"
        );
        assert_eq!(body, "OK");

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_denies_missing_host() {
        let sock = temp_socket_path("no_host");
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        // HTTP/1.1 request with no Host header → MALFORMED_REQUEST
        let request = "POST /v1/chat/completions HTTP/1.1\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {}";

        let (status, body) = uds_request(&sock, request).await;
        assert_eq!(status, 403, "missing host should be denied");
        assert!(
            body.contains("MALFORMED_REQUEST"),
            "body should mention MALFORMED_REQUEST, got: {body}"
        );

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_allows_request_with_body() {
        let sock = temp_socket_path("body");
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        let json_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\n\
             Host: 127.0.0.1:{}\r\n\
             X-Firma-Session-Id: _test_\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {json_body}",
            upstream_addr.port(),
            json_body.len()
        );

        let (status, body) = uds_request(&sock, &request).await;
        assert_eq!(status, 200, "request with body should be allowed");
        assert_eq!(body, "OK");

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_handles_multiple_sequential_connections() {
        let sock = temp_socket_path("multi");
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\n\
                        Host: 127.0.0.1:{}\r\n\
                        X-Firma-Session-Id: _test_\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {{}}",
            upstream_addr.port()
        );

        // Send three sequential requests on separate connections.
        for i in 0..3 {
            let (status, body) = uds_request(&sock, &request).await;
            assert_eq!(status, 200, "connection {i}: expected 200 OK, got {status}");
            assert_eq!(body, "OK", "connection {i}: unexpected body");
        }

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_cleans_up_socket_on_shutdown() {
        let sock = temp_socket_path("cleanup");
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, handler, cancel.clone()).await;

        assert!(sock.exists(), "socket file should exist while running");

        cancel.cancel();
        handle.await.unwrap().unwrap();

        assert!(
            !sock.exists(),
            "socket file should be removed after shutdown"
        );
    }

    #[tokio::test]
    async fn test_uds_removes_stale_socket_on_start() {
        let sock = temp_socket_path("stale");
        // Create a stale file at the socket path.
        std::fs::write(&sock, b"stale").unwrap_or_default();
        assert!(sock.exists(), "stale file should exist before start");

        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();

        // Cannot use start_interceptor here because the stale regular file
        // satisfies `path.exists()` immediately. Instead, manually start
        // and wait for a successful connection.
        let interceptor = UnixSocketInterceptor::new(sock.clone());
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        // Wait until we can actually connect to the socket.
        for _ in 0..50 {
            if UnixStream::connect(&sock).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // The interceptor should have removed the stale file and bound
        // successfully.
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\n\
                        Host: 127.0.0.1:{}\r\n\
                        X-Firma-Session-Id: _test_\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {{}}",
            upstream_addr.port()
        );

        let (status, _) = uds_request(&sock, &request).await;
        assert_eq!(
            status, 200,
            "interceptor should work after removing stale socket"
        );

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = handle.await;
    }
}
