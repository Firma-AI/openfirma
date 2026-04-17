//! Request handler.
//!
//! Owns the post-enforcement call path shared by all interceptors:
//! enforcement, dispatch for allowed traffic, denial translation, and audit
//! payload emission.

use std::collections::HashMap;
use std::sync::Arc;

use firma_core::DenyReason;
use tokio::sync::mpsc;

use crate::audit::AuditPayload;
use crate::pipeline::{EnforcementDecision, EnforcementPipeline, RawRequest};

/// Response produced by the transport-agnostic request handler.
#[derive(Debug)]
pub enum HandledResponse {
    /// Request was allowed and the target replied.
    Ok(DispatchedResponse),
    /// Non-protected request was forwarded without enforcement.
    Passthrough(DispatchedResponse),
    /// Request was blocked before dispatch.
    Deny {
        /// Denial reason selected by the enforcement pipeline.
        reason: DenyReason,
        /// Human-readable denial detail.
        detail: String,
    },
}

/// Serialize a denial into the canonical JSON body used by HTTP-facing
/// interceptors.
#[must_use]
pub fn deny_body_json(reason: DenyReason, detail: &str) -> Vec<u8> {
    serde_json::json!({
        "reason": reason,
        "detail": detail,
    })
    .to_string()
    .into_bytes()
}

/// Response returned by the current raw-forward placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchedResponse {
    /// Target HTTP status code.
    pub status: u16,
    /// Target response headers.
    pub headers: HashMap<String, String>,
    /// Target response body.
    pub body: Vec<u8>,
}

/// Shared handler used by every interceptor.
pub struct RequestHandler {
    audit_sink_sender: mpsc::Sender<AuditPayload>,
    http_client: reqwest::Client,
    pipeline: Arc<EnforcementPipeline>,
}

impl RequestHandler {
    /// Constructs a request handler from the enforcement pipeline and audit
    /// payload channel.
    #[must_use]
    pub fn new(
        pipeline: Arc<EnforcementPipeline>,
        audit_sink_sender: mpsc::Sender<AuditPayload>,
    ) -> Self {
        Self {
            audit_sink_sender,
            http_client: reqwest::Client::new(),
            pipeline,
        }
    }

    /// Handles one normalized transport request.
    ///
    /// The handler emits exactly one audit payload per call after dispatch
    /// work has completed for allow and passthrough outcomes.
    pub async fn handle(&self, request: RawRequest, session_id: &str) -> HandledResponse {
        let (decision, audit_payload) = self.pipeline.enforce(&request, session_id).await;

        let response = match decision {
            EnforcementDecision::Allow { .. } => {
                HandledResponse::Ok(self.raw_forward(&request).await)
            }
            EnforcementDecision::Passthrough { .. } => {
                HandledResponse::Passthrough(self.raw_forward(&request).await)
            }
            EnforcementDecision::Deny { reason, detail, .. } => {
                HandledResponse::Deny { reason, detail }
            }
        };

        if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
            tracing::error!("failed to send audit event: {err}");
        }

        response
    }

    async fn raw_forward(&self, request: &RawRequest) -> DispatchedResponse {
        match self.send_raw_request(request).await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!("raw forward failed: {err}");
                DispatchedResponse {
                    status: 502,
                    headers: HashMap::new(),
                    body: format!("BAD_GATEWAY: {err}").into_bytes(),
                }
            }
        }
    }

    async fn send_raw_request(
        &self,
        request: &RawRequest,
    ) -> Result<DispatchedResponse, reqwest::Error> {
        let scheme = if request.is_https { "https" } else { "http" };
        let url = format!("{scheme}://{}{}", request.host, request.path);
        let method =
            reqwest::Method::from_bytes(request.method.as_bytes()).unwrap_or(reqwest::Method::GET);

        let mut builder = self.http_client.request(method, url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }

        let response = builder.send().await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
            .collect();
        let body = response.bytes().await?.to_vec();

        Ok(DispatchedResponse {
            status,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::{CapabilityClaims, RevocationStore, TokenError, TokenVerifier};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, IntentNormalizer,
        MappingTable, NullCredentialInjector, PipelineArgs,
    };

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
            session_id: "sess_001".to_string(),
            action_set: vec!["llm.inference".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    fn test_pipeline(
        rules: Vec<MappingRuleConfig>,
        default_protected: bool,
        has_capability: bool,
    ) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile { rules };
        let table = MappingTable::from_config(&file, &registry, default_protected)
            .unwrap_or_else(|e| panic!("{e}"));
        let entries = if has_capability {
            vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]
        } else {
            Vec::new()
        };

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer: IntentNormalizer::new(table),
            capability_validator: CapabilityValidator::new(
                CapabilityMap::new(entries),
                Box::new(MockVerifier { claims }),
                Box::new(NoRevocations),
                Duration::from_secs(0),
            ),
            constraint_enforcer: ConstraintEnforcer::new(Box::new(AllowAllPolicy)),
            credential_injector: Box::new(NullCredentialInjector),
        }))
    }

    fn allow_rule() -> MappingRuleConfig {
        MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "*".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }
    }

    async fn mock_upstream() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        #[expect(clippy::unwrap_used, reason = "test helper requires bound listener")]
        let listener = listener.unwrap();
        #[expect(clippy::unwrap_used, reason = "test helper requires bound address")]
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
                            let response = "HTTP/1.1 201 Created\r\nx-test: ok\r\nContent-Length: 2\r\n\r\nOK";
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

    fn raw_request(host: String, method: &str) -> RawRequest {
        RawRequest {
            method: method.to_string(),
            host,
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(b"{}".to_vec()),
            is_https: false,
        }
    }

    #[tokio::test]
    async fn test_handle_allow_forwards_and_emits_audit() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(test_pipeline(vec![allow_rule()], true, true), tx);

        let response = handler
            .handle(
                raw_request(format!("127.0.0.1:{}", upstream_addr.port()), "POST"),
                "sess_allow",
            )
            .await;

        match response {
            HandledResponse::Ok(dispatched) => {
                assert_eq!(dispatched.status, 201);
                assert_eq!(dispatched.body, b"OK");
                assert_eq!(dispatched.headers.get("x-test"), Some(&"ok".to_string()));
            }
            other => panic!("expected ok response, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_allow");
        assert_eq!(payload.decision, 1);
        assert!(rx.try_recv().is_err());
        upstream_cancel.cancel();
    }

    #[tokio::test]
    async fn test_handle_deny_skips_forward_and_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(test_pipeline(vec![allow_rule()], true, false), tx);

        let response = handler
            .handle(raw_request("127.0.0.1:9".to_string(), "POST"), "sess_deny")
            .await;

        match response {
            HandledResponse::Deny { reason, detail } => {
                assert_eq!(reason, DenyReason::TokenInvalid);
                assert!(!detail.is_empty());
            }
            other => panic!("expected deny response, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_deny");
        assert_eq!(payload.decision, 2);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_passthrough_forwards_and_emits_audit() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(test_pipeline(vec![allow_rule()], false, true), tx);

        let response = handler
            .handle(
                raw_request(format!("127.0.0.1:{}", upstream_addr.port()), "GET"),
                "sess_passthrough",
            )
            .await;

        match response {
            HandledResponse::Passthrough(dispatched) => {
                assert_eq!(dispatched.status, 201);
                assert_eq!(dispatched.body, b"OK");
            }
            other => panic!("expected passthrough response, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_passthrough");
        assert_eq!(payload.decision, 1);
        assert!(rx.try_recv().is_err());
        upstream_cancel.cancel();
    }
}
