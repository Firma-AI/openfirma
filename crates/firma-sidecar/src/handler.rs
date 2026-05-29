//! Request handler.
//!
//! Owns the post-enforcement call path shared by all interceptors:
//! enforcement, dispatch for allowed traffic, denial translation, and audit
//! payload emission.

use std::collections::HashMap;
use std::sync::Arc;

use firma_core::{
    ActionParams, AgentId, ConnectorError, ConnectorResponse, DenyReason, ExecutionEnvelope,
    ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams, InjectedCredentials, SessionId,
    TransportView,
};
use tokio::sync::mpsc;

use crate::audit::AuditPayload;
use crate::connector::ConnectorRegistry;
use crate::normalizer::NormalizedEnvelope;
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
        /// Structural context of the denial. `Tool` means the body is
        /// returned as a tool result (agent loop continues); `Api`
        /// means a synchronous terminal failure (HTTP 403 for HTTP
        /// interceptors). See FEP §5.1–§5.2.
        ///
        /// In V1 all wired interceptors serve HTTP-class traffic and
        /// treat both contexts identically (403 + `deny_body_json`)
        /// per the task 008 V1 scope note. The field is populated so
        /// a future tool-call transport can read it without any
        /// further handler/pipeline change.
        // V1 interceptors discard `context` (Tool and Api get the
        // same 403 response). Tests read it. `cfg_attr` keeps the
        // non-test build warning-clean without marking the attribute
        // unfulfilled during test compilation.
        #[cfg_attr(not(test), allow(dead_code))]
        context: DenialContext,
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

/// CONNECT-specific decision surface used by the HTTP proxy interceptor.
#[derive(Debug)]
pub enum ConnectDecision {
    /// CONNECT target is allowed and tunneling may proceed.
    Allow,
    /// CONNECT target is denied before tunnel establishment.
    Deny {
        /// Denial reason selected by the enforcement pipeline.
        reason: DenyReason,
        /// Human-readable denial detail.
        detail: String,
    },
}

/// Authorization result for HTTP upgrade requests (for example WebSocket
/// handshakes) where the interceptor owns upstream byte relay.
#[derive(Debug)]
pub enum UpgradeAuthorization {
    /// Upgrade request is authorized. The interceptor must complete upstream
    /// relay and then call [`RequestHandler::emit_upgrade_audit`].
    Allow {
        /// Credentials injected by policy pipeline for this request.
        credentials: InjectedCredentials,
        /// Pending audit payload captured at authorization time.
        audit_payload: Box<AuditPayload>,
    },
    /// Upgrade request denied by policy pipeline.
    Deny {
        /// Denial reason selected by the enforcement pipeline.
        reason: DenyReason,
        /// Human-readable denial detail.
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

/// Structural context of a denial.
///
/// Derived from the `NormalizedEnvelope` carried on
/// [`EnforcementDecision::Deny`]. Interceptors select the transport
/// response shape from this value without re-inspecting the envelope.
///
/// See FEP §5.1–§5.2 for the behavioural contract:
/// - `Tool`: agent loop continues; body is a structured tool result.
/// - `Api`: synchronous terminal failure; body is the canonical deny
///   JSON (HTTP 403 for HTTP interceptors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialContext {
    /// Denial originated from a tool-call transport.
    Tool,
    /// Denial originated from an API-class transport (HTTP, DB, etc.)
    /// or before normalization produced an envelope (fail-closed).
    Api,
}

/// Maps an [`ActionParams`] variant to its [`DenialContext`].
///
/// `ToolUse` → `Tool`; `Http` / `DbQuery` → `Api`.
#[must_use]
pub fn denial_context_from_params(params: &ActionParams) -> DenialContext {
    match params {
        ActionParams::ToolUse(_) => DenialContext::Tool,
        ActionParams::Http(_) | ActionParams::DbQuery(_) => DenialContext::Api,
    }
}

/// Derives the denial context from a normalized envelope.
///
/// Fail-closed default: when no envelope is available (pre-normalization
/// denial such as `MalformedRequest` or `UnclassifiedIntent`), returns
/// [`DenialContext::Api`] — the hard-block shape. A tool denial on a
/// non-tool call would silently mask the failure.
#[must_use]
pub fn denial_context_of(envelope: Option<&NormalizedEnvelope>) -> DenialContext {
    envelope.map_or(DenialContext::Api, |e| {
        denial_context_from_params(&e.intent.params)
    })
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

/// Serialize a tool-call denial into the canonical JSON body shape
/// defined by FEP §5.1.
///
/// The agent receives this as it would any other tool result; the
/// session continues. No HTTP status semantics are implied — the body
/// is the tool's structured result.
#[must_use]
// Public API reserved for a future tool-call interceptor; V1 has no
// tool-call transport so the function is only called from tests.
#[cfg_attr(not(test), allow(dead_code))]
pub fn tool_denial_body_json(
    reason: DenyReason,
    detail: &str,
    action_class: &str,
    tool_name: &str,
) -> Vec<u8> {
    serde_json::json!({
        "denied": true,
        "reason": reason,
        "action_class": action_class,
        "tool_name": tool_name,
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
                let mut dispatch_envelope = *envelope;
                hydrate_dispatch_http_fields(&mut dispatch_envelope, &request);
                let (response, outcome) = self.dispatch(dispatch_envelope, credentials).await;
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
            EnforcementDecision::Deny {
                reason,
                detail,
                envelope,
                ..
            } => {
                if reason == firma_core::DenyReason::TokenExpired {
                    tracing::warn!(
                        method = %request.method,
                        host = %request.host,
                        path = %request.path,
                        session_id = %session_id,
                        detail = %detail,
                        "request denied because capability token expired; renew token (same session_id) and reload sidecar capability source"
                    );
                }
                let context = denial_context_of(envelope.as_ref());
                HandledResponse::Deny {
                    reason,
                    detail,
                    context,
                }
            }
        };

        if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
            tracing::error!("failed to send audit event: {err}");
        }

        response
    }

    /// Handles CONNECT authorization without performing connector HTTP dispatch.
    ///
    /// On [`ConnectDecision::Allow`], the HTTP proxy interceptor proceeds with
    /// tunnel establishment and byte relay.
    pub async fn handle_connect(&self, request: RawRequest, session_id: &str) -> ConnectDecision {
        let (decision, mut audit_payload) = self.pipeline.enforce(&request, session_id).await;

        let outcome = match decision {
            EnforcementDecision::Allow { .. } | EnforcementDecision::Passthrough { .. } => {
                audit_payload.dispatch_status = 200;
                ConnectDecision::Allow
            }
            EnforcementDecision::Deny { reason, detail, .. } => {
                ConnectDecision::Deny { reason, detail }
            }
        };

        if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
            tracing::error!("failed to send audit event: {err}");
        }

        outcome
    }

    /// Authorizes an HTTP upgrade request without dispatching via the connector
    /// registry.
    ///
    /// Intended for upgraded protocols (for example WebSocket) where dispatch
    /// switches from request/response to long-lived byte relay.
    pub async fn authorize_upgrade(
        &self,
        request: RawRequest,
        session_id: &str,
    ) -> UpgradeAuthorization {
        let (decision, audit_payload) = self.pipeline.enforce(&request, session_id).await;

        match decision {
            EnforcementDecision::Allow { credentials, .. } => UpgradeAuthorization::Allow {
                credentials,
                audit_payload: Box::new(audit_payload),
            },
            EnforcementDecision::Passthrough { .. } => UpgradeAuthorization::Allow {
                credentials: InjectedCredentials::empty(),
                audit_payload: Box::new(audit_payload),
            },
            EnforcementDecision::Deny { reason, detail, .. } => {
                if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                    tracing::error!("failed to send audit event: {err}");
                }
                UpgradeAuthorization::Deny { reason, detail }
            }
        }
    }

    /// Emits audit payload for an authorized HTTP upgrade flow.
    pub async fn emit_upgrade_audit(
        &self,
        mut payload: AuditPayload,
        dispatch_status: u16,
        response_size: usize,
    ) {
        payload.dispatch_status = i32::from(dispatch_status);
        payload.dispatch_latency_us = 0;
        payload.response_size = i64::try_from(response_size).unwrap_or(i64::MAX);
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Emits a synthetic audit event when CONNECT was policy-allowed but
    /// upstream tunnel establishment/relay failed after authorization.
    pub async fn emit_connect_relay_failure_audit(
        &self,
        session_id: &str,
        host: &str,
        detail: &str,
    ) {
        let payload = AuditPayload {
            session_id: session_id.to_string(),
            token_id: String::new(),
            agent_id: String::new(),
            action: "network.connect".to_string(),
            resource: format!("{host}/"),
            decision: crate::pipeline::DECISION_ABORT,
            deny_reason: format!("CONNECT_RELAY_FAILURE: {detail}"),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: String::new(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
        };
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Emits a synthetic DENY audit event for a network-layer denial
    /// raised before the enforcement pipeline runs.
    ///
    /// Covers fail-closed paths an interceptor rejects up front —
    /// malformed requests and strict-MITM preflight failures — that
    /// otherwise return 403 to the client with no audit trail, leaving
    /// the deny invisible to `firma monitor` (FIR-208). No capability was
    /// validated on these paths, so `agent_id` / `token_id` are empty.
    pub async fn emit_synthetic_deny(
        &self,
        session_id: &str,
        action: &str,
        resource: &str,
        reason: DenyReason,
        detail: &str,
    ) {
        let payload = AuditPayload {
            session_id: session_id.to_string(),
            token_id: String::new(),
            agent_id: String::new(),
            action: action.to_string(),
            resource: resource.to_string(),
            decision: crate::pipeline::DECISION_DENY,
            deny_reason: format!("{reason}: {detail}"),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: String::new(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
        };
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
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
        let resource_display = envelope.intent().resource_display();
        let host = extract_host(&resource_display).unwrap_or_default();
        let connector = self.connector_registry.select(&host);
        // Derive the denial context up-front: `TransportView::new`
        // consumes the envelope below, and connector-originated
        // denials need the context to build the response.
        let dispatch_context = denial_context_from_params(&envelope.intent().params);
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
                        context: dispatch_context,
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
                        context: dispatch_context,
                    },
                    outcome,
                )
            }
        }
    }
}

fn hydrate_dispatch_http_fields(envelope: &mut ExecutionEnvelope, request: &RawRequest) {
    let ActionParams::Http(http) = &mut envelope.intent.params else {
        return;
    };
    http.headers.clone_from(&request.headers);
    http.body.clone_from(&request.body);
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
    let mut resource = std::collections::BTreeMap::new();
    resource.insert("host".to_string(), request.host.clone());
    resource.insert("path".to_string(), request.path.clone());
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
    let session_id = session_id
        .parse::<SessionId>()
        .unwrap_or_else(|_| passthrough_session_id());
    ExecutionEnvelope::new(
        intent,
        String::new(),
        ExecutionMetadata {
            session_id,
            agent_id: passthrough_agent_id(),
            timestamp: chrono::Utc::now(),
            trace_id: None,
            budget_consumed: 0.0,
            risk_score: None,
        },
        None,
    )
}

#[expect(
    clippy::expect_used,
    reason = "literal passthrough ids are non-empty by construction; parse cannot fail"
)]
fn passthrough_agent_id() -> AgentId {
    "_passthrough_"
        .parse()
        .expect("literal passthrough agent id is non-empty")
}

#[expect(
    clippy::expect_used,
    reason = "literal passthrough ids are non-empty by construction; parse cannot fail"
)]
fn passthrough_session_id() -> SessionId {
    "_passthrough_"
        .parse()
        .expect("literal passthrough session id is non-empty")
}

fn parse_http_method(method: &str) -> HttpMethod {
    match method.to_ascii_uppercase().as_str() {
        "POST" => HttpMethod::POST,
        "PUT" => HttpMethod::PUT,
        "DELETE" => HttpMethod::DELETE,
        "PATCH" => HttpMethod::PATCH,
        "HEAD" => HttpMethod::HEAD,
        "OPTIONS" => HttpMethod::OPTIONS,
        "CONNECT" => HttpMethod::CONNECT,
        _ => HttpMethod::GET,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::{CapabilityClaims, RevocationStore, TokenError, TokenId, TokenVerifier};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::credential::NullCredentialInjector;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, IntentNormalizer,
        MappingTable, PipelineArgs,
    };

    pub fn test_connector_registry() -> Arc<ConnectorRegistry> {
        let default = crate::connector::provider::GenericHttpConnector::default_for_unconfigured()
            .expect("default connector should build in tests");
        Arc::new(ConnectorRegistry::new(Arc::new(default)))
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

    fn test_claims_for_session(session_id: &str) -> CapabilityClaims {
        CapabilityClaims {
            token_id: "3713c5fc-b569-650c-c780-c64051473370"
                .parse()
                .expect("literal token id"),
            agent_id: "agent_test".parse().expect("literal agent id"),
            session_id: session_id.parse().expect("literal session id"),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
            budget_ceiling: None,
        }
    }

    fn test_pipeline(
        rules: Vec<MappingRuleConfig>,
        default_protected: bool,
        has_capability: bool,
    ) -> Arc<EnforcementPipeline> {
        test_pipeline_for_session(rules, default_protected, has_capability, "sess_001")
    }

    fn test_pipeline_for_session(
        rules: Vec<MappingRuleConfig>,
        default_protected: bool,
        has_capability: bool,
        session_id: &str,
    ) -> Arc<EnforcementPipeline> {
        let claims = test_claims_for_session(session_id);
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
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn allow_rule() -> MappingRuleConfig {
        MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "*".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }
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
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_allow"),
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
            HandledResponse::Deny {
                reason,
                detail,
                context,
            } => {
                assert_eq!(reason, DenyReason::TokenInvalid);
                assert!(!detail.is_empty());
                // Stage 1 TokenInvalid denies carry no envelope, so
                // the handler falls back to Api per the fail-closed
                // default.
                assert_eq!(context, DenialContext::Api);
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
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_audit"),
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
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_net"),
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
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_timeout"),
            registry,
            tx,
        );

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
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_5xx"),
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

    #[test]
    fn tool_denial_body_json_has_documented_shape() {
        let body = tool_denial_body_json(
            DenyReason::PolicyDenied,
            "disallowed by bundle v3",
            "tool.generic",
            "my_tool",
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["denied"], serde_json::Value::Bool(true));
        assert_eq!(
            parsed["reason"],
            serde_json::json!(DenyReason::PolicyDenied)
        );
        assert_eq!(parsed["action_class"], "tool.generic");
        assert_eq!(parsed["tool_name"], "my_tool");
        assert_eq!(parsed["detail"], "disallowed by bundle v3");
    }

    #[test]
    fn deny_body_json_shape_unchanged_by_task_008() {
        let body = deny_body_json(DenyReason::ScopeViolation, "out of scope");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert!(parsed.get("tool_name").is_none());
        assert!(parsed.get("action_class").is_none());
        assert_eq!(parsed["denied"], serde_json::Value::Bool(true));
        assert_eq!(
            parsed["reason"],
            serde_json::json!(DenyReason::ScopeViolation)
        );
        assert_eq!(parsed["detail"], "out of scope");
    }

    #[test]
    fn denial_context_of_tooluse_envelope_is_tool() {
        use firma_core::ToolUseParams;
        let envelope = NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "tool.generic".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("my_tool"),
                params: ActionParams::ToolUse(ToolUseParams {
                    tool_name: "my_tool".to_string(),
                    input: HashMap::new(),
                }),
                raw_transport: "mcp".to_string(),
                raw_action_ref: "my_tool".to_string(),
            },
            timestamp: Utc::now(),
        };
        assert_eq!(denial_context_of(Some(&envelope)), DenialContext::Tool);
    }

    #[test]
    fn denial_context_of_http_envelope_is_api() {
        let envelope = NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "filesystem.read".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from(
                    "https://example.test/resource",
                ),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::GET,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "http".to_string(),
                raw_action_ref: "GET /resource".to_string(),
            },
            timestamp: Utc::now(),
        };
        assert_eq!(denial_context_of(Some(&envelope)), DenialContext::Api);
    }

    #[test]
    fn denial_context_of_dbquery_envelope_is_api() {
        use firma_core::DbQueryParams;
        let envelope = NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "credential.read".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("pg://orders"),
                params: ActionParams::DbQuery(DbQueryParams {
                    query_name: "select_orders".to_string(),
                    bindings: HashMap::new(),
                    db_name: "orders".to_string(),
                    read_only: true,
                }),
                raw_transport: "pg".to_string(),
                raw_action_ref: "SELECT".to_string(),
            },
            timestamp: Utc::now(),
        };
        assert_eq!(denial_context_of(Some(&envelope)), DenialContext::Api);
    }

    #[test]
    fn denial_context_of_none_envelope_is_api_fail_closed() {
        assert_eq!(denial_context_of(None), DenialContext::Api);
    }

    #[test]
    fn handled_response_deny_with_tooluse_envelope_carries_tool_context() {
        // Fabricated-envelope path per FEP §5.1. The handler's Deny
        // arm is a pure mapping over (reason, detail, envelope); this
        // reproduces it exactly and asserts the context field is set
        // to Tool for a ToolUse envelope.
        use firma_core::ToolUseParams;
        let envelope = NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "tool.generic".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("my_tool"),
                params: ActionParams::ToolUse(ToolUseParams {
                    tool_name: "my_tool".to_string(),
                    input: HashMap::new(),
                }),
                raw_transport: "mcp".to_string(),
                raw_action_ref: "my_tool".to_string(),
            },
            timestamp: Utc::now(),
        };
        let response = HandledResponse::Deny {
            reason: DenyReason::PolicyDenied,
            detail: "fabricated tool denial".to_string(),
            context: denial_context_of(Some(&envelope)),
        };
        match response {
            HandledResponse::Deny {
                context,
                reason,
                detail,
            } => {
                assert_eq!(context, DenialContext::Tool);
                assert_eq!(reason, DenyReason::PolicyDenied);
                assert_eq!(detail, "fabricated tool denial");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
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

    #[tokio::test]
    async fn test_emit_synthetic_deny_sends_deny_audit_event() {
        // Regression (FIR-208): pre-pipeline network-layer denials
        // (malformed request, strict-MITM preflight fail-closed) return
        // 403 to the client but historically emitted NO audit event, so
        // they never surfaced in `firma monitor`. emit_synthetic_deny
        // gives those paths an audit record.
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, false),
            test_connector_registry(),
            tx,
        );

        handler
            .emit_synthetic_deny(
                "sess_x",
                "network.connect",
                "exa_mple.com/",
                DenyReason::FailClosed,
                "HTTPS_MITM_SETUP_FAILED: dns resolution failed",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, crate::pipeline::DECISION_DENY);
        assert_eq!(payload.session_id, "sess_x");
        assert_eq!(payload.action, "network.connect");
        assert_eq!(payload.resource, "exa_mple.com/");
        assert!(
            payload.deny_reason.contains("HTTPS_MITM_SETUP_FAILED"),
            "deny_reason should carry the detail, got {:?}",
            payload.deny_reason
        );
        assert!(
            payload.agent_id.is_empty() && payload.token_id.is_empty(),
            "pre-validation denial has no known identity"
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_connect_allow_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(
                vec![MappingRuleConfig {
                    method: Some("CONNECT".to_string()),
                    host: "*".to_string(),
                    path: Some("/".to_string()),
                    action_class: "communication.external.send".to_string(),
                }],
                true,
                true,
            ),
            test_connector_registry(),
            tx,
        );

        let outcome = handler
            .handle_connect(
                RawRequest {
                    method: "CONNECT".to_string(),
                    host: "api.openai.com:443".to_string(),
                    path: "/".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    is_https: true,
                },
                "sess_001",
            )
            .await;

        assert!(matches!(outcome, ConnectDecision::Allow));
        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_001");
        assert_eq!(payload.decision, 1);
        assert_eq!(payload.dispatch_status, 200);
    }

    #[tokio::test]
    async fn test_handle_connect_deny_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(
                vec![MappingRuleConfig {
                    method: Some("CONNECT".to_string()),
                    host: "*".to_string(),
                    path: Some("/".to_string()),
                    action_class: "communication.external.send".to_string(),
                }],
                true,
                false,
            ),
            test_connector_registry(),
            tx,
        );

        let outcome = handler
            .handle_connect(
                RawRequest {
                    method: "CONNECT".to_string(),
                    host: "api.openai.com:443".to_string(),
                    path: "/".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    is_https: true,
                },
                "sess_001",
            )
            .await;

        match outcome {
            ConnectDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenyReason::TokenInvalid);
            }
            other @ ConnectDecision::Allow => panic!("expected connect deny, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_001");
        assert_eq!(payload.decision, 2);
    }
}
