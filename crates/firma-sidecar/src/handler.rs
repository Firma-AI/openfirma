//! Request handler.
//!
//! Owns the post-enforcement call path shared by all interceptors:
//! enforcement, dispatch for allowed traffic, denial translation, and audit
//! payload emission.

use std::collections::HashMap;
use std::sync::Arc;

use firma_core::{
    ActionParams, ConnectorError, ConnectorResponse, DenyReason, ExecutionEnvelope,
    ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams, InjectedCredentials, TransportView,
};
use tokio::sync::mpsc;

use crate::audit::AuditPayload;
use crate::connector::ConnectorRegistry;
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
    /// Request was approved by enforcement but the dispatch could not
    /// complete. The agent-visible outcome is a gateway-timeout class
    /// error; the token state stays `ACTIVE` (no terminal transition).
    Aborted {
        /// Typed abort reason.
        reason: AbortReason,
        /// Human-readable abort detail.
        detail: String,
    },
}

/// Reason an approved call was aborted before producing a target
/// response.
///
/// The variant surface is intentionally small in V1. Later tasks (009)
/// add authority-driven and revocation-driven aborts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// Connector exceeded its configured timeout.
    ///
    /// Covers both upstream call timeouts and rate-limiter queue
    /// waits bounded by the connector timeout.
    ConnectorTimeout,
}

impl AbortReason {
    /// Canonical reason code string used in audit events and in the
    /// JSON body returned to the agent.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConnectorTimeout => "CONNECTOR_TIMEOUT",
        }
    }
}

/// Serialize a denial into the canonical JSON body used by HTTP-facing
/// interceptors.
#[must_use]
pub fn deny_body_json(reason: DenyReason, detail: &str) -> Vec<u8> {
    serde_json::json!({
        "denied": true,
        "reason": reason,
        "detail": detail,
    })
    .to_string()
    .into_bytes()
}

/// Serialize an abort into the canonical JSON body used by HTTP-facing
/// interceptors.
///
/// Agents key off the `aborted` boolean flag to distinguish abort
/// responses from upstream-reported errors.
#[must_use]
pub fn abort_body_json(reason: AbortReason, detail: &str) -> Vec<u8> {
    serde_json::json!({
        "aborted": true,
        "reason": reason.code(),
        "detail": detail,
    })
    .to_string()
    .into_bytes()
}

/// Test-only helper that builds an [`Arc<ConnectorRegistry>`] whose
/// default is the generic HTTP connector with 30s timeout.
#[cfg(test)]
pub(crate) fn test_connector_registry() -> Arc<ConnectorRegistry> {
    let default = crate::connector::provider::GenericHttpConnector::default_for_unconfigured()
        .expect("default connector should build in tests");
    Arc::new(ConnectorRegistry::new(Arc::new(default)))
}

/// Connector-side metadata captured after dispatch so the handler
/// can enrich the audit payload with the call outcome (status,
/// latency, body size) and, when needed, override the pipeline's
/// pre-dispatch decision (connector-originated DENY / ABORT).
struct DispatchOutcome {
    decision_override: Option<DecisionOverride>,
    dispatch_status: i32,
    dispatch_latency_us: i64,
    response_size: i64,
}

/// Proto-wire decision + `deny_reason` string applied to the audit
/// payload when the connector layer overrides the pipeline's Allow
/// outcome.
struct DecisionOverride {
    decision: i32,
    deny_reason: String,
}

impl DispatchOutcome {
    /// Produces a [`DispatchOutcome`] for a connector-originated DENY
    /// (network / invalid-request). No upstream response was received,
    /// so the numeric fields stay zero.
    fn deny_from_connector(reason: DenyReason, detail: &str) -> Self {
        Self {
            decision_override: Some(DecisionOverride {
                decision: crate::pipeline::DECISION_DENY,
                deny_reason: format!("{reason}: {detail}"),
            }),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
        }
    }

    /// Applies the outcome to the audit payload in place.
    fn enrich(self, payload: &mut AuditPayload) {
        payload.dispatch_status = self.dispatch_status;
        payload.dispatch_latency_us = self.dispatch_latency_us;
        payload.response_size = self.response_size;
        if let Some(decision) = self.decision_override {
            payload.decision = decision.decision;
            payload.deny_reason = decision.deny_reason;
        }
    }
}

fn dispatch_latency_us(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

fn i64_from_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Extracts the host portion of a resource URL for connector
/// selection.
///
/// Returns `None` when the resource cannot be parsed as an absolute
/// URL; callers default to the registry default in that case.
fn extract_host(resource: &str) -> Option<String> {
    reqwest::Url::parse(resource)
        .ok()
        .and_then(|url| url.host_str().map(std::string::ToString::to_string))
}

fn dispatched_from(response: ConnectorResponse) -> DispatchedResponse {
    DispatchedResponse {
        status: response.status,
        headers: response.headers,
        body: response.body,
    }
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
    connector_registry: Arc<ConnectorRegistry>,
    pipeline: Arc<EnforcementPipeline>,
}

impl RequestHandler {
    /// Constructs a request handler from the enforcement pipeline, the
    /// connector registry, and the audit payload channel.
    #[must_use]
    pub fn new(
        pipeline: Arc<EnforcementPipeline>,
        connector_registry: Arc<ConnectorRegistry>,
        audit_sink_sender: mpsc::Sender<AuditPayload>,
    ) -> Self {
        Self {
            audit_sink_sender,
            connector_registry,
            pipeline,
        }
    }

    /// Handles one normalized transport request.
    ///
    /// The handler emits exactly one audit payload per call after dispatch
    /// work has completed for allow and passthrough outcomes.
    pub async fn handle(&self, request: RawRequest, session_id: &str) -> HandledResponse {
        let (decision, mut audit_payload) = self.pipeline.enforce(&request, session_id).await;

        let response = match decision {
            EnforcementDecision::Allow {
                envelope,
                credentials,
                ..
            } => {
                let (response, outcome) = self.dispatch(*envelope, credentials).await;
                outcome.enrich(&mut audit_payload);
                response
            }
            EnforcementDecision::Passthrough { .. } => {
                let envelope = passthrough_envelope(&request, session_id);
                let (response, outcome) =
                    self.dispatch(envelope, InjectedCredentials::empty()).await;
                outcome.enrich(&mut audit_payload);
                // Re-wrap Ok as Passthrough so callers can distinguish
                // authorized traffic from forwarded non-protected
                // traffic. Deny / Aborted pass through unchanged.
                match response {
                    HandledResponse::Ok(dispatched) => HandledResponse::Passthrough(dispatched),
                    other => other,
                }
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

    /// Dispatches an approved call through the connector registry.
    ///
    /// Returns the [`HandledResponse`] plus a [`DispatchOutcome`] that
    /// captures the raw dispatch metadata needed to enrich the audit
    /// payload (status, latency, response size, decision override on
    /// abort or connector-originated deny).
    async fn dispatch(
        &self,
        envelope: ExecutionEnvelope,
        credentials: InjectedCredentials,
    ) -> (HandledResponse, DispatchOutcome) {
        let host = extract_host(envelope.intent().resource.as_str()).unwrap_or_default();
        let connector = self.connector_registry.select(&host);
        let view = TransportView::new(envelope, credentials);
        match connector.dispatch(&view).await {
            Ok(response) => {
                let outcome = DispatchOutcome {
                    decision_override: None,
                    dispatch_status: i32::from(response.status),
                    dispatch_latency_us: dispatch_latency_us(response.dispatch_latency),
                    response_size: i64_from_usize(response.response_size),
                };
                (HandledResponse::Ok(dispatched_from(response)), outcome)
            }
            Err(ConnectorError::Timeout(duration)) => {
                let detail = format!("connector timeout after {duration:?}");
                let outcome = DispatchOutcome {
                    decision_override: Some(DecisionOverride {
                        decision: crate::pipeline::DECISION_ABORT,
                        deny_reason: format!(
                            "{code}: {detail}",
                            code = AbortReason::ConnectorTimeout.code()
                        ),
                    }),
                    dispatch_status: 0,
                    dispatch_latency_us: 0,
                    response_size: 0,
                };
                (
                    HandledResponse::Aborted {
                        reason: AbortReason::ConnectorTimeout,
                        detail,
                    },
                    outcome,
                )
            }
            Err(ConnectorError::Network(detail)) => {
                let outcome = DispatchOutcome::deny_from_connector(
                    DenyReason::ConnectorNetworkError,
                    &detail,
                );
                (
                    HandledResponse::Deny {
                        reason: DenyReason::ConnectorNetworkError,
                        detail,
                    },
                    outcome,
                )
            }
            Err(ConnectorError::InvalidRequest(detail)) => {
                let outcome = DispatchOutcome::deny_from_connector(
                    DenyReason::ConnectorInvalidRequest,
                    &detail,
                );
                (
                    HandledResponse::Deny {
                        reason: DenyReason::ConnectorInvalidRequest,
                        detail,
                    },
                    outcome,
                )
            }
        }
    }
}

/// Builds a minimal [`ExecutionEnvelope`] for a non-protected
/// (Passthrough) request so it can flow through the same connector
/// dispatch path as authorized traffic.
///
/// No capability token is present for passthrough calls; the envelope
/// carries an empty capability string and a synthetic action class.
fn passthrough_envelope(request: &RawRequest, session_id: &str) -> ExecutionEnvelope {
    let method = parse_http_method(&request.method);
    let scheme = if request.is_https { "https" } else { "http" };
    let resource = format!("{}{}", request.host, request.path);
    let intent = ExecutionIntent {
        action_class: "passthrough".to_string(),
        resource,
        params: ActionParams::Http(HttpParams {
            method,
            headers: request.headers.clone(),
            body: request.body.clone(),
            query: HashMap::new(),
        }),
        raw_transport: scheme.to_string(),
        raw_action_ref: format!("{} {}", request.method, request.path),
    };
    ExecutionEnvelope::new(
        intent,
        String::new(),
        ExecutionMetadata {
            session_id: session_id.to_string(),
            agent_id: String::new(),
            timestamp: chrono::Utc::now(),
            trace_id: None,
            budget_consumed: 0.0,
            risk_score: None,
        },
        None,
    )
}

fn parse_http_method(method: &str) -> HttpMethod {
    match method.to_ascii_uppercase().as_str() {
        "POST" => HttpMethod::POST,
        "PUT" => HttpMethod::PUT,
        "DELETE" => HttpMethod::DELETE,
        "PATCH" => HttpMethod::PATCH,
        "HEAD" => HttpMethod::HEAD,
        "OPTIONS" => HttpMethod::OPTIONS,
        _ => HttpMethod::GET,
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
                std::sync::Arc::new(NoRevocations),
                Duration::from_secs(0),
            ),
            constraint_enforcer: ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy)),
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
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, true),
            test_connector_registry(),
            tx,
        );

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
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, false),
            test_connector_registry(),
            tx,
        );

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
    async fn test_handle_allow_audit_has_dispatch_outcome_fields() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, true),
            test_connector_registry(),
            tx,
        );

        let _ = handler
            .handle(
                raw_request(format!("127.0.0.1:{}", upstream_addr.port()), "POST"),
                "sess_audit",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, 1);
        assert_eq!(payload.dispatch_status, 201);
        assert_eq!(payload.response_size, 2);
        assert!(
            payload.dispatch_latency_us >= 0,
            "dispatch_latency_us must be populated"
        );
        assert!(payload.deny_reason.is_empty());
        upstream_cancel.cancel();
    }

    #[tokio::test]
    async fn test_handle_deny_audit_has_zero_dispatch_fields() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, false),
            test_connector_registry(),
            tx,
        );

        let _ = handler
            .handle(raw_request("127.0.0.1:9".to_string(), "POST"), "sess")
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, 2);
        assert_eq!(payload.dispatch_status, 0);
        assert_eq!(payload.dispatch_latency_us, 0);
        assert_eq!(payload.response_size, 0);
    }

    #[tokio::test]
    async fn test_handle_connector_network_error_denies() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, true),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                // Port 1 is reserved — connect attempt fails reliably.
                raw_request("127.0.0.1:1".to_string(), "POST"),
                "sess_net",
            )
            .await;

        match response {
            HandledResponse::Deny { reason, .. } => {
                assert_eq!(reason, DenyReason::ConnectorNetworkError);
            }
            other => panic!("expected network deny, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, 2);
        assert!(payload.deny_reason.contains("connector network error"));
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn test_handle_connector_timeout_produces_aborted() {
        use crate::connector::provider::{GenericHttpConnector, HttpConnectorConfig};

        // wiremock server that sleeps 2s before responding.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&server)
            .await;

        // Registry whose default connector times out in 100ms — every
        // host (including the wiremock one) goes through it and trips
        // the timeout well before wiremock replies.
        let fast_default = GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: Duration::from_millis(100),
            rate_limit: None,
        })
        .expect("fast default connector should build");
        let registry = Arc::new(crate::connector::ConnectorRegistry::new(Arc::new(
            fast_default,
        )));

        let addr = server.address();
        let host = format!("127.0.0.1:{}", addr.port());

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler =
            RequestHandler::new(test_pipeline(vec![allow_rule()], true, true), registry, tx);

        let response = handler
            .handle(raw_request(host, "POST"), "sess_timeout")
            .await;

        match response {
            HandledResponse::Aborted { reason, detail } => {
                assert_eq!(reason, AbortReason::ConnectorTimeout);
                assert!(detail.contains("connector timeout"));
            }
            other => panic!("expected aborted, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, 3);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_TIMEOUT"),
            "deny_reason should carry CONNECTOR_TIMEOUT prefix, got {:?}",
            payload.deny_reason,
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn test_handle_target_5xx_relayed_as_ok() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, true),
            test_connector_registry(),
            tx,
        );

        let addr = server.address();
        let response = handler
            .handle(
                raw_request(format!("127.0.0.1:{}", addr.port()), "POST"),
                "sess_5xx",
            )
            .await;

        match response {
            HandledResponse::Ok(dispatched) => {
                assert_eq!(dispatched.status, 503);
                assert_eq!(dispatched.body, b"down".to_vec());
            }
            other => panic!("expected ok-with-5xx, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, 1);
        assert_eq!(payload.dispatch_status, 503);
    }

    #[test]
    fn test_abort_body_json_shape_matches_contract() {
        let body = abort_body_json(AbortReason::ConnectorTimeout, "timeout after 100ms");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["aborted"], serde_json::Value::Bool(true));
        assert_eq!(parsed["reason"], "CONNECTOR_TIMEOUT");
        assert_eq!(parsed["detail"], "timeout after 100ms");
    }

    #[test]
    fn test_deny_body_json_shape_matches_contract() {
        let body = deny_body_json(DenyReason::PolicyDenied, "policy X blocked");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["denied"], serde_json::Value::Bool(true));
        assert!(parsed["reason"].is_string());
        assert_eq!(parsed["detail"], "policy X blocked");
    }

    #[tokio::test]
    async fn test_handle_passthrough_forwards_and_emits_audit() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], false, true),
            test_connector_registry(),
            tx,
        );

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
