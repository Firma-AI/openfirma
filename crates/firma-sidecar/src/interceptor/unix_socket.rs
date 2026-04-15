//! Unix domain socket interceptor.
//!
//! Implements the [`Interceptor`](super::Interceptor) trait over a Unix
//! domain socket (UDS). The interceptor owns the full socket lifecycle: it
//! removes any stale socket file, binds a
//! [`tokio::net::UnixListener`], accepts connections, and unlinks the socket
//! on shutdown.
//!
//! Requests arrive as plain HTTP over the UDS and are parsed with hyper into
//! [`RawRequest`](crate::normalizer::RawRequest) values — the same parsing
//! logic used by the HTTP proxy mode. This mode avoids TCP port binding,
//! making it well suited for containerized environments.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use crate::interceptor::{Interceptor, InterceptorError};
use crate::pipeline::{EnforcementDecision, EnforcementPipeline, RawRequest};

/// Unix domain socket interceptor.
///
/// Accepts a [`PathBuf`](std::path::PathBuf) pointing to the socket file and
/// manages the full bind / listen / accept / cleanup cycle. Incoming HTTP
/// requests are parsed into
/// [`RawRequest`](crate::normalizer::RawRequest) values and enforced through
/// the [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline) provided
/// in [`Interceptor::run`](super::Interceptor::run).
///
/// Malformed requests that cannot be parsed into a valid `RawRequest` are
/// rejected with a structured DENY carrying reason `MALFORMED_REQUEST`
/// (fail-closed).
pub struct UnixSocketInterceptor {
    /// Path to the Unix domain socket file.
    path: PathBuf,
    /// Reference to the enforcement pipeline, set when the interceptor is
    /// running.
    pipeline: Option<Arc<EnforcementPipeline>>,
}

impl UnixSocketInterceptor {
    /// Create a new [`UnixSocketInterceptor`] with the given socket path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            pipeline: None,
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
        pipeline: Arc<EnforcementPipeline>,
        cancel: CancellationToken,
    ) -> Result<(), InterceptorError> {
        self.pipeline = Some(pipeline);
        // Remove stale socket if present
        let _ = std::fs::remove_file(&self.path);
        let listener = UnixListener::bind(&self.path)
            .map_err(|_| InterceptorError::BindFailed("Channel closed".to_string()))?;

        let pipeline = self
            .pipeline
            .as_ref()
            .ok_or_else(|| InterceptorError::ServerError("pipeline not set".to_string()))?;

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((stream, _socket_addr)) = accepted {
                        let pipeline = Arc::clone(pipeline);
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(stream, pipeline).await {
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
    pipeline: Arc<EnforcementPipeline>,
) -> Result<(), InterceptorError> {
    let io = TokioIo::new(socket);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let pipeline = Arc::clone(&pipeline);
                async move { handle_request(req, &pipeline).await }
            }),
        )
        .await
        .map_err(|e| InterceptorError::ServerError(format!("HTTP connection error: {e}")))
}

/// Convert an incoming hyper request into a [`RawRequest`], run it through
/// the enforcement pipeline, and return the appropriate HTTP response.
///
/// Malformed requests (missing host, unreadable body) are rejected with
/// `403 MALFORMED_REQUEST` (fail-closed).
async fn handle_request(
    req: Request<Incoming>,
    pipeline: &EnforcementPipeline,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let raw = match build_raw_request(req).await {
        Ok(r) => r,
        Err(detail) => return Ok(deny_response(StatusCode::FORBIDDEN, &detail)),
    };

    let session_id = raw
        .headers
        .get("x-firma-session-id")
        .cloned()
        .unwrap_or_default();

    let decision = pipeline.enforce(&raw, &session_id).await;

    let response = match decision {
        EnforcementDecision::Allow { .. } | EnforcementDecision::Passthrough { .. } => {
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from_static(b"ALLOW")))
                .unwrap_or_else(|_| {
                    deny_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                })
        }
        EnforcementDecision::Deny { reason, detail, .. } => {
            deny_response(StatusCode::FORBIDDEN, &format!("{reason}: {detail}"))
        }
    };

    Ok(response)
}

/// Build a [`RawRequest`] from a hyper [`Request`].
///
/// # Errors
///
/// Returns a detail string suitable for a `MALFORMED_REQUEST` denial when the
/// host cannot be resolved or the body cannot be read.
async fn build_raw_request(req: Request<Incoming>) -> Result<RawRequest, String> {
    let method = req.method().to_string();
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

    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string())))
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

/// Build a structured denial HTTP response.
fn deny_response(status: StatusCode, detail: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::copy_from_slice(detail.as_bytes())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use super::*;
    use crate::audit::builder::EventBuilder;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, IntentNormalizer,
        MappingTable,
    };

    // ── helpers ────────────────────────────────────────────────────────

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

    const TEST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----";

    fn test_event_builder() -> EventBuilder {
        EventBuilder::new(TEST_KEY_PEM).unwrap_or_else(|e| panic!("{e}"))
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

    /// Builds a pipeline that ALLOWs POST requests to any host at the given
    /// path. Uses a wildcard host pattern (`*`).
    fn test_pipeline_allow(path: &str) -> Arc<EnforcementPipeline> {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
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

        Arc::new(EnforcementPipeline::new(
            normalizer,
            capability_validator,
            constraint_enforcer,
            tx,
            test_event_builder(),
        ))
    }

    /// Builds a pipeline that DENYs classified requests (empty capability map).
    /// Uses `default_protected: true` so every host is protected.
    fn test_pipeline_deny_all() -> Arc<EnforcementPipeline> {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "llm.inference".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(
            normalizer,
            capability_validator,
            constraint_enforcer,
            tx,
            test_event_builder(),
        ))
    }

    /// Builds a pipeline where only `api.openai.com` is mapped and
    /// `default_protected` is false, so unmapped hosts pass through.
    fn test_pipeline_passthrough() -> Arc<EnforcementPipeline> {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "llm.inference".to_string(),
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
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(
            normalizer,
            capability_validator,
            constraint_enforcer,
            tx,
            test_event_builder(),
        ))
    }

    /// Returns a unique temporary socket path for a test.
    fn temp_socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("firma_test_{name}_{}.sock", std::process::id()))
    }

    /// Starts the Unix socket interceptor and waits for it to be ready.
    async fn start_interceptor(
        path: &Path,
        pipeline: Arc<EnforcementPipeline>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<Result<(), InterceptorError>> {
        let interceptor = UnixSocketInterceptor::new(path.to_path_buf());
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(pipeline, cancel_clone).await });

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
        #[allow(clippy::unwrap_used)]
        let stream = stream.as_mut().unwrap();

        #[allow(clippy::unwrap_used)]
        stream.write_all(request.as_bytes()).await.unwrap();

        // Read the full response. The server writes the response after
        // processing the request; read until the server closes the
        // connection or the timeout fires.
        let mut buf = Vec::with_capacity(8192);
        let read_result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut tmp = [0u8; 4096];
            loop {
                match stream.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
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
            {
                if let Ok(expected) = val.trim().parse::<usize>() {
                    return body.len() >= expected;
                }
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
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, pipeline, cancel.clone()).await;

        let request = "POST /v1/chat/completions HTTP/1.1\r\n\
                        Host: api.openai.com\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {}";

        let (status, body) = uds_request(&sock, request).await;
        assert_eq!(status, 200, "expected 200 OK for allowed request");
        assert_eq!(body, "ALLOW");

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_denies_when_no_capability() {
        let sock = temp_socket_path("deny_cap");
        let pipeline = test_pipeline_deny_all();
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, pipeline, cancel.clone()).await;

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
    async fn test_uds_denies_unclassified_intent() {
        let sock = temp_socket_path("deny_unclass");
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, pipeline, cancel.clone()).await;

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
        let pipeline = test_pipeline_passthrough();
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, pipeline, cancel.clone()).await;

        let request = "GET /anything HTTP/1.1\r\n\
                        Host: not-protected.example.com\r\n\
                        \r\n";

        let (status, body) = uds_request(&sock, request).await;
        assert_eq!(
            status, 200,
            "non-protected host should passthrough (200), got {status}"
        );
        assert_eq!(body, "ALLOW");

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_denies_missing_host() {
        let sock = temp_socket_path("no_host");
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, pipeline, cancel.clone()).await;

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
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, pipeline, cancel.clone()).await;

        let json_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\n\
             Host: api.openai.com\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {json_body}",
            json_body.len()
        );

        let (status, body) = uds_request(&sock, &request).await;
        assert_eq!(status, 200, "request with body should be allowed");
        assert_eq!(body, "ALLOW");

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_handles_multiple_sequential_connections() {
        let sock = temp_socket_path("multi");
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, pipeline, cancel.clone()).await;

        let request = "POST /v1/chat/completions HTTP/1.1\r\n\
                        Host: api.openai.com\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {}";

        // Send three sequential requests on separate connections.
        for i in 0..3 {
            let (status, body) = uds_request(&sock, request).await;
            assert_eq!(status, 200, "connection {i}: expected 200 OK, got {status}");
            assert_eq!(body, "ALLOW", "connection {i}: unexpected body");
        }

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_uds_cleans_up_socket_on_shutdown() {
        let sock = temp_socket_path("cleanup");
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let cancel = CancellationToken::new();
        let handle = start_interceptor(&sock, pipeline, cancel.clone()).await;

        assert!(sock.exists(), "socket file should exist while running");

        cancel.cancel();
        #[allow(clippy::unwrap_used)]
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

        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let cancel = CancellationToken::new();

        // Cannot use start_interceptor here because the stale regular file
        // satisfies `path.exists()` immediately. Instead, manually start
        // and wait for a successful connection.
        let interceptor = UnixSocketInterceptor::new(sock.clone());
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(pipeline, cancel_clone).await });

        // Wait until we can actually connect to the socket.
        for _ in 0..50 {
            if UnixStream::connect(&sock).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // The interceptor should have removed the stale file and bound
        // successfully.
        let request = "POST /v1/chat/completions HTTP/1.1\r\n\
                        Host: api.openai.com\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        {}";

        let (status, _) = uds_request(&sock, request).await;
        assert_eq!(
            status, 200,
            "interceptor should work after removing stale socket"
        );

        cancel.cancel();
        let _ = handle.await;
    }
}
