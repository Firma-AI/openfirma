//! Request handler.
//!
//! Owns the post-enforcement call path shared by all interceptors:
//! enforcement, dispatch for allowed traffic, denial translation, and audit
//! payload emission.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use firma_core::envelope::InvalidMethod;
use firma_core::{
    AbortReason, ActionParams, ConnectorError, ConnectorResponse, DenyReason, ExecutionEnvelope,
    ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams, InjectedCredentials, TransportView,
};
use firma_http::HeaderMap;
use firma_identifiers::{AgentId, SessionId};
use tokio::sync::mpsc;

use crate::audit::{AuditPayload, Decision};
use crate::composio::{ComposioAction, ComposioCatalogs, DecodeResult, decode, is_protected_host};
use crate::connector::ConnectorRegistry;
use crate::normalizer::NormalizedEnvelope;
use crate::pipeline::{
    CompositeActionResult, CompositeDisposition, EnforcementDecision, EnforcementPipeline,
    RawRequest, audit_payload_from_decision, monitor_override,
};

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
    /// CONNECT target was authorized, then blocked by a post-ALLOW abort.
    Abort {
        /// Abort reason selected by the enforcement pipeline.
        reason: AbortReason,
        /// Human-readable abort detail.
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
    /// Upgrade request blocked by a post-ALLOW abort.
    Abort {
        /// Abort reason selected by the enforcement pipeline.
        reason: AbortReason,
        /// Human-readable abort detail.
        detail: String,
    },
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
fn denial_context_from_params(params: &ActionParams) -> DenialContext {
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
fn denial_context_of(envelope: Option<&NormalizedEnvelope>) -> DenialContext {
    envelope.map_or(DenialContext::Api, |e| {
        denial_context_from_params(&e.intent.params)
    })
}

/// Serialize a denial into the canonical JSON body used by HTTP-facing
/// interceptors.
#[must_use]
pub(crate) fn deny_body_json(reason: DenyReason, detail: &str) -> Vec<u8> {
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
#[cfg(test)]
fn tool_denial_body_json(
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
pub(crate) fn abort_body_json(reason: AbortReason, detail: &str) -> Vec<u8> {
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
    decision: Decision,
    deny_reason: String,
}

impl DispatchOutcome {
    /// Produces a [`DispatchOutcome`] for a connector-originated ABORT.
    ///
    /// No upstream response was received, so the numeric fields stay zero.
    fn abort_from_connector(reason: AbortReason, detail: &str) -> Self {
        Self {
            decision_override: Some(DecisionOverride {
                decision: Decision::Abort,
                deny_reason: format!("{}: {detail}", reason.code()),
            }),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
        }
    }

    /// Applies the outcome to the audit payload in place.
    fn enrich(self, payload: &mut AuditPayload) {
        self.enrich_ref(payload);
    }

    /// Applies a shared dispatch outcome to one child audit payload.
    fn enrich_ref(&self, payload: &mut AuditPayload) {
        payload.dispatch_status = self.dispatch_status;
        payload.dispatch_latency_us = self.dispatch_latency_us;
        payload.response_size = self.response_size;
        if let Some(decision) = &self.decision_override {
            payload.decision = decision.decision;
            payload.deny_reason.clone_from(&decision.deny_reason);
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
    pub(crate) status: u16,
    /// Target response headers.
    pub(crate) headers: HeaderMap,
    /// Target response body.
    pub(crate) body: Vec<u8>,
}

/// Shared handler used by every interceptor.
pub struct RequestHandler {
    audit_sink_sender: mpsc::Sender<AuditPayload>,
    composio_catalogs: Option<Arc<ComposioCatalogs>>,
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
            composio_catalogs: None,
            connector_registry,
            pipeline,
        }
    }

    /// Install validated pinned Composio catalogs.
    #[must_use]
    pub fn with_composio_catalogs(mut self, catalogs: Arc<ComposioCatalogs>) -> Self {
        self.composio_catalogs = Some(catalogs);
        self
    }

    /// Handles one normalized transport request.
    ///
    /// The handler emits exactly one audit payload per call after dispatch
    /// work has completed for allow and passthrough outcomes.
    #[expect(
        clippy::too_many_lines,
        reason = "the exhaustive decision match owns dispatch and audit finalization"
    )]
    pub async fn handle(&self, request: RawRequest, session_id: &str) -> HandledResponse {
        if let Some(response) = self.handle_composio(&request, session_id).await {
            return response;
        }

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
            EnforcementDecision::Modify {
                envelope,
                credentials,
                modifications,
                ..
            } => {
                self.dispatch_modify(
                    *envelope,
                    &request,
                    credentials,
                    modifications,
                    &mut audit_payload,
                )
                .await
            }
            EnforcementDecision::Passthrough { .. } => {
                match passthrough_envelope(&request, session_id) {
                    Ok(envelope) => {
                        let (response, outcome) =
                            self.dispatch(envelope, InjectedCredentials::empty()).await;
                        outcome.enrich(&mut audit_payload);
                        // Re-wrap Ok as Passthrough so callers can distinguish
                        // authorized traffic from forwarded non-protected
                        // traffic. Deny / Aborted pass through unchanged.
                        if let HandledResponse::Ok(dispatched) = response {
                            HandledResponse::Passthrough(dispatched)
                        } else {
                            response
                        }
                    }
                    Err(err) => handle_error(err),
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
            EnforcementDecision::Abort { reason, detail, .. } => {
                HandledResponse::Aborted { reason, detail }
            }
            EnforcementDecision::StepUp {
                challenge,
                envelope,
                ..
            } => {
                // AARM R4 `STEP_UP` blocks the call. The agent receives a
                // structured denial whose reason tells it to request human
                // approval and retry.
                let context = denial_context_of(envelope.as_ref());
                HandledResponse::Deny {
                    reason: firma_core::DenyReason::StepUpRequired,
                    detail: challenge,
                    context,
                }
            }
            EnforcementDecision::Defer {
                retry_after_ms,
                envelope,
                ..
            } => {
                // AARM R4 `DEFER` blocks the call. The agent receives a
                // structured denial whose reason tells it to retry after
                // the backoff window.
                let context = denial_context_of(envelope.as_ref());
                HandledResponse::Deny {
                    reason: firma_core::DenyReason::Deferred,
                    detail: format!("retry_after_ms: {retry_after_ms}"),
                    context,
                }
            }
        };

        if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
            tracing::error!("failed to send audit event: {err}");
        }

        response
    }

    async fn handle_composio(
        &self,
        request: &RawRequest,
        session_id: &str,
    ) -> Option<HandledResponse> {
        let catalogs = self.composio_catalogs.as_deref()?;
        match decode(request, catalogs) {
            DecodeResult::Unrelated => None,
            DecodeResult::Passthrough => {
                Some(self.handle_composio_passthrough(request, session_id).await)
            }
            DecodeResult::Actions(actions) => Some(
                self.handle_composio_actions(request, session_id, &actions)
                    .await,
            ),
            DecodeResult::Deny(denial) => {
                let decision = EnforcementDecision::Deny {
                    reason: DenyReason::MalformedRequest,
                    stage: crate::enforcement::decision::EnforcementStage::Normalization,
                    detail: format!("{}: {}", denial.code, denial.detail),
                    envelope: None,
                    identity: None,
                };
                let mut audit_payload = audit_payload_from_decision(
                    &decision,
                    request,
                    session_id,
                    std::time::Duration::ZERO,
                    None,
                );
                // Monitor mode observes protocol-level denials too: forward
                // the original request once and keep the would-deny reason in
                // the audit record, matching the pipeline's monitor override.
                if self.pipeline.is_monitor() {
                    monitor_override(&mut audit_payload);
                    return Some(
                        self.forward_composio_observed(request, session_id, audit_payload)
                            .await,
                    );
                }
                self.emit_audit(audit_payload).await;
                Some(response_from_blocking_decision(&decision))
            }
        }
    }

    async fn handle_composio_passthrough(
        &self,
        request: &RawRequest,
        session_id: &str,
    ) -> HandledResponse {
        let decision = EnforcementDecision::Passthrough {
            detail: "recognized Composio non-execution request".to_string(),
        };
        let audit_payload = audit_payload_from_decision(
            &decision,
            request,
            session_id,
            std::time::Duration::ZERO,
            None,
        );
        self.forward_composio_observed(request, session_id, audit_payload)
            .await
    }

    /// Dispatch the original Composio request once with no injected
    /// credentials, enrich and emit the given audit payload, and surface a
    /// successful dispatch as a passthrough response.
    async fn forward_composio_observed(
        &self,
        request: &RawRequest,
        session_id: &str,
        mut audit_payload: AuditPayload,
    ) -> HandledResponse {
        let response = match passthrough_envelope(request, session_id) {
            Ok(envelope) => {
                let (response, outcome) =
                    self.dispatch(envelope, InjectedCredentials::empty()).await;
                outcome.enrich(&mut audit_payload);
                match response {
                    HandledResponse::Ok(dispatched) => HandledResponse::Passthrough(dispatched),
                    other => other,
                }
            }
            Err(err) => handle_error(err),
        };
        self.emit_audit(audit_payload).await;
        response
    }

    async fn handle_composio_actions(
        &self,
        request: &RawRequest,
        session_id: &str,
        actions: &[ComposioAction],
    ) -> HandledResponse {
        let result = self
            .pipeline
            .enforce_composite(request, session_id, actions)
            .await;
        let response = match result.disposition {
            CompositeDisposition::Dispatch {
                transport,
                monitor_override,
            } => {
                let dispatch = match transport {
                    Some((envelope, credentials)) => {
                        let mut dispatch_envelope = *envelope;
                        hydrate_dispatch_http_fields(&mut dispatch_envelope, request);
                        self.dispatch(dispatch_envelope, credentials).await
                    }
                    None => match passthrough_envelope(request, session_id) {
                        Ok(envelope) => self.dispatch(envelope, InjectedCredentials::empty()).await,
                        Err(err) => {
                            let response = handle_error(err);
                            let outcome = DispatchOutcome::abort_from_connector(
                                AbortReason::ConnectorInvalidRequest,
                                "could not construct Composio monitor dispatch",
                            );
                            (response, outcome)
                        }
                    },
                };
                let (response, outcome) = dispatch;
                let mut response = response;
                for child in result.children {
                    self.emit_enriched_composite_audit(child, &outcome).await;
                }
                if monitor_override && let HandledResponse::Ok(dispatched) = response {
                    response = HandledResponse::Passthrough(dispatched);
                }
                return response;
            }
            CompositeDisposition::Block { blocker_index } => {
                result.children.get(blocker_index).map_or_else(
                    || HandledResponse::Deny {
                        reason: DenyReason::FailClosed,
                        detail: "Composio aggregate result had no blocker; failing closed"
                            .to_string(),
                        context: DenialContext::Api,
                    },
                    |child| response_from_blocking_decision(&child.decision),
                )
            }
        };
        for child in result.children {
            self.emit_audit(child.audit_payload).await;
        }
        response
    }

    async fn emit_enriched_composite_audit(
        &self,
        mut child: CompositeActionResult,
        outcome: &DispatchOutcome,
    ) {
        outcome.enrich_ref(&mut child.audit_payload);
        self.emit_audit(child.audit_payload).await;
    }

    async fn emit_audit(&self, payload: AuditPayload) {
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Dispatches a `MODIFY` decision: applies the structural transformation
    /// to the dispatch clone, then forwards to the connector.
    ///
    /// `redact_header` strips the header from the agent-produced request only;
    /// it does not prevent credential injection from adding the same header
    /// back to the outbound request. The redaction is scoped to what the
    /// agent sent, not to what the sidecar injects downstream.
    async fn dispatch_modify(
        &self,
        envelope: ExecutionEnvelope,
        request: &RawRequest,
        credentials: InjectedCredentials,
        modifications: firma_core::ModificationSpec,
        audit_payload: &mut AuditPayload,
    ) -> HandledResponse {
        let mut dispatch_envelope = envelope;
        hydrate_dispatch_http_fields(&mut dispatch_envelope, request);
        // Fail closed: a modification that cannot be applied (e.g. a
        // `redact_header` policy targeting a non-HTTP action) must not
        // fall through to dispatch. Forwarding the unmodified request
        // would leak the header the policy asked to strip, so block
        // instead and override the audit to record the dispatch-level
        // denial rather than the pipeline's pre-dispatch MODIFY outcome.
        if let Err(err) = modifications.apply(&mut dispatch_envelope) {
            tracing::error!(
                error = %err,
                "modification failed to apply; the policy targets HTTP headers \
                 but the action is not HTTP — failing closed"
            );
            let detail = "modification could not be applied; failing closed".to_string();
            audit_payload.decision = Decision::Deny;
            audit_payload.deny_reason = format!("{}: {detail}", DenyReason::FailClosed);
            return HandledResponse::Deny {
                reason: DenyReason::FailClosed,
                detail,
                context: denial_context_from_params(&dispatch_envelope.intent.params),
            };
        }
        let (response, outcome) = self.dispatch(dispatch_envelope, credentials).await;
        outcome.enrich(audit_payload);
        response
    }

    /// Handles CONNECT authorization without performing connector HTTP dispatch.
    ///
    /// On [`ConnectDecision::Allow`], the HTTP proxy interceptor proceeds with
    /// tunnel establishment and byte relay.
    pub(crate) async fn handle_connect(
        &self,
        mut request: RawRequest,
        session_id: &str,
    ) -> ConnectDecision {
        let (decision, mut audit_payload) = self.pipeline.enforce(&request, session_id).await;

        let outcome = match decision {
            EnforcementDecision::Allow { .. } | EnforcementDecision::Passthrough { .. } => {
                audit_payload.dispatch_status = 200;
                ConnectDecision::Allow
            }
            EnforcementDecision::Modify { modifications, .. } => {
                // AARM R4 `MODIFY`: apply the redaction to the request headers
                // before the tunnel is established, so the agent's headers are
                // stripped even for CONNECT. The modification is audit-recorded
                // (decision = `MODIFY`).
                apply_modification_to_request(&modifications, &mut request);
                audit_payload.dispatch_status = 200;
                ConnectDecision::Allow
            }
            EnforcementDecision::Deny { reason, detail, .. } => {
                ConnectDecision::Deny { reason, detail }
            }
            EnforcementDecision::Abort { reason, detail, .. } => {
                ConnectDecision::Abort { reason, detail }
            }
            EnforcementDecision::StepUp { challenge, .. } => ConnectDecision::Deny {
                reason: firma_core::DenyReason::StepUpRequired,
                detail: challenge,
            },
            EnforcementDecision::Defer { retry_after_ms, .. } => ConnectDecision::Deny {
                reason: firma_core::DenyReason::Deferred,
                detail: format!("retry_after_ms: {retry_after_ms}"),
            },
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
        mut request: RawRequest,
        session_id: &str,
    ) -> UpgradeAuthorization {
        if is_protected_host(&request.host) {
            let detail = "Composio protocol upgrades are unsupported".to_string();
            let decision = EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: crate::enforcement::decision::EnforcementStage::Normalization,
                detail: detail.clone(),
                envelope: None,
                identity: None,
            };
            let mut audit_payload = audit_payload_from_decision(
                &decision,
                &request,
                session_id,
                std::time::Duration::ZERO,
                None,
            );
            // Monitor mode observes the upgrade instead of blocking it: the
            // relay proceeds without injected credentials and the audit
            // record keeps the would-deny reason.
            if self.pipeline.is_monitor() {
                monitor_override(&mut audit_payload);
                return UpgradeAuthorization::Allow {
                    credentials: InjectedCredentials::empty(),
                    audit_payload: Box::new(audit_payload),
                };
            }
            if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                tracing::error!("failed to send audit event: {err}");
            }
            return UpgradeAuthorization::Deny {
                reason: DenyReason::FailClosed,
                detail,
            };
        }

        let (decision, audit_payload) = self.pipeline.enforce(&request, session_id).await;

        match decision {
            EnforcementDecision::Allow { credentials, .. } => UpgradeAuthorization::Allow {
                credentials,
                audit_payload: Box::new(audit_payload),
            },
            EnforcementDecision::Modify {
                credentials,
                modifications,
                ..
            } => {
                // AARM R4 `MODIFY`: apply the redaction to the request headers
                // before the upgrade is authorized, so the agent's headers are
                // stripped. The modification is audit-recorded (decision =
                // `MODIFY`).
                apply_modification_to_request(&modifications, &mut request);
                UpgradeAuthorization::Allow {
                    credentials,
                    audit_payload: Box::new(audit_payload),
                }
            }
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
            EnforcementDecision::Abort { reason, detail, .. } => {
                if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                    tracing::error!("failed to send audit event: {err}");
                }
                UpgradeAuthorization::Abort { reason, detail }
            }
            EnforcementDecision::StepUp { challenge, .. } => {
                if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                    tracing::error!("failed to send audit event: {err}");
                }
                UpgradeAuthorization::Deny {
                    reason: firma_core::DenyReason::StepUpRequired,
                    detail: challenge,
                }
            }
            EnforcementDecision::Defer { retry_after_ms, .. } => {
                if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                    tracing::error!("failed to send audit event: {err}");
                }
                UpgradeAuthorization::Deny {
                    reason: firma_core::DenyReason::Deferred,
                    detail: format!("retry_after_ms: {retry_after_ms}"),
                }
            }
        }
    }

    /// Emits audit payload for an authorized HTTP upgrade flow.
    pub(crate) async fn emit_upgrade_audit(
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

    /// Emits an ABORT audit event when an upgrade was policy-allowed but
    /// the upstream relay failed before producing a target response.
    ///
    /// Reuses the verified ALLOW payload (so `agent_id` / `token_id` are
    /// preserved, as the post-ALLOW abort always has an identity) and rewrites
    /// the decision to [`Decision::Abort`]. No upstream response was produced, so
    /// the dispatch fields stay zero.
    pub(crate) async fn emit_upgrade_abort_audit(
        &self,
        mut payload: AuditPayload,
        reason: AbortReason,
        detail: &str,
    ) {
        payload.decision = Decision::Abort;
        payload.deny_reason = format!("{}: {detail}", reason.code());
        payload.dispatch_status = 0;
        payload.dispatch_latency_us = 0;
        payload.response_size = 0;
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Emits a synthetic audit event when CONNECT was policy-allowed but
    /// upstream tunnel establishment/relay failed after authorization.
    pub(crate) async fn emit_connect_relay_failure_audit(
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
            decision: Decision::Abort,
            deny_reason: format!("CONNECT_RELAY_FAILURE: {detail}"),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: String::new(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
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
    pub(crate) async fn emit_synthetic_deny(
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
            decision: Decision::Deny,
            deny_reason: format!("{reason}: {detail}"),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: String::new(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
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
                        decision: Decision::Abort,
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
                let outcome =
                    DispatchOutcome::abort_from_connector(AbortReason::ConnectorFailure, &detail);
                (
                    HandledResponse::Aborted {
                        reason: AbortReason::ConnectorFailure,
                        detail,
                    },
                    outcome,
                )
            }
            Err(ConnectorError::InvalidRequest(detail)) => {
                let outcome = DispatchOutcome::abort_from_connector(
                    AbortReason::ConnectorInvalidRequest,
                    &detail,
                );
                (
                    HandledResponse::Aborted {
                        reason: AbortReason::ConnectorInvalidRequest,
                        detail,
                    },
                    outcome,
                )
            }
        }
    }
}

fn handle_error(err: impl Display) -> HandledResponse {
    HandledResponse::Aborted {
        reason: AbortReason::ConnectorInvalidRequest,
        detail: err.to_string(),
    }
}

fn response_from_blocking_decision(decision: &EnforcementDecision) -> HandledResponse {
    match decision {
        EnforcementDecision::Deny {
            reason,
            detail,
            envelope,
            ..
        } => HandledResponse::Deny {
            reason: *reason,
            detail: detail.clone(),
            context: denial_context_of(envelope.as_ref()),
        },
        EnforcementDecision::Abort { reason, detail, .. } => HandledResponse::Aborted {
            reason: *reason,
            detail: detail.clone(),
        },
        EnforcementDecision::Modify { envelope, .. } => HandledResponse::Deny {
            reason: DenyReason::FailClosed,
            detail: "Composio argument modification is unsupported; failing closed".to_string(),
            context: denial_context_from_params(&envelope.intent().params),
        },
        EnforcementDecision::StepUp {
            challenge,
            envelope,
            ..
        } => HandledResponse::Deny {
            reason: DenyReason::StepUpRequired,
            detail: challenge.clone(),
            context: denial_context_of(envelope.as_ref()),
        },
        EnforcementDecision::Defer {
            retry_after_ms,
            envelope,
            ..
        } => HandledResponse::Deny {
            reason: DenyReason::Deferred,
            detail: format!("retry_after_ms: {retry_after_ms}"),
            context: denial_context_of(envelope.as_ref()),
        },
        EnforcementDecision::Allow { .. } | EnforcementDecision::Passthrough { .. } => {
            HandledResponse::Deny {
                reason: DenyReason::FailClosed,
                detail: "Composio aggregate selected a non-blocking result; failing closed"
                    .to_string(),
                context: DenialContext::Api,
            }
        }
    }
}

/// Copy the transport fields a Composio logical envelope deliberately omits
/// onto the clone that is about to be dispatched.
///
/// The logical envelope carries no headers, body, or query so that raw tool
/// arguments never reach a resource, an audit record, or a log. The connector
/// still has to send the agent's original request, so those fields are
/// restored here, minus the internal `x-firma-*` headers.
///
/// The query is only ever non-empty for the one governed family that is
/// allowed to carry one (account-lifecycle reads); every other governed
/// Composio shape is denied `query_string_unsupported` during decoding. Without
/// this the connector would rebuild the URL from the query-free logical
/// resource and silently drop a pagination cursor.
fn hydrate_dispatch_http_fields(envelope: &mut ExecutionEnvelope, request: &RawRequest) {
    let ActionParams::Http(http) = &mut envelope.intent.params else {
        return;
    };
    // `envelope.intent.params.http.headers` was built by the normalizer's
    // `sanitize_headers` for the audit-trail envelope, which strips
    // sensitive headers like `cookie` and `authorization` so they never
    // reach logs. Dispatch to the upstream connector must still carry
    // those headers, so rebuild from the original `request.headers` here
    // and only strip the internal `x-firma-*` control headers.
    http.headers = strip_firma_headers(&request.headers);
    http.body.clone_from(&request.body);
    if let Some((_, query)) = request.path.split_once('?')
        && !query.is_empty()
    {
        http.query = crate::normalizer::parse_query_string(query);
    }
}

fn strip_firma_headers(headers: &HeaderMap) -> HeaderMap {
    headers
        .iter()
        .filter(|(k, _v)| !k.as_str().starts_with("x-firma-"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Apply a [`ModificationSpec`] redaction to the raw request headers before
/// the caller proceeds with tunnel establishment or protocol upgrade.
///
/// This is used by `handle_connect` and `authorize_upgrade`, which don't go
/// through the connector HTTP dispatch path (and therefore can't apply the
/// modification to a dispatch clone). The redaction is applied directly to
/// the agent's request headers.
fn apply_modification_to_request(
    modifications: &firma_core::ModificationSpec,
    request: &mut RawRequest,
) {
    match modifications {
        firma_core::ModificationSpec::RedactHeader(name) => {
            request.headers.remove(name);
        }
    }
}

/// Builds a minimal [`ExecutionEnvelope`] for a non-protected
/// (Passthrough) request so it can flow through the same connector
/// dispatch path as authorized traffic.
///
/// No capability token is present for passthrough calls; the envelope
/// carries an empty capability string and a synthetic action class.
fn passthrough_envelope<'a>(
    request: &'a RawRequest,
    session_id: &str,
) -> Result<ExecutionEnvelope, InvalidMethod<'a>> {
    let method = HttpMethod::try_from(&request.method)?;
    let scheme = if request.is_https { "https" } else { "http" };
    let mut resource = std::collections::BTreeMap::new();
    resource.insert("host".to_string(), request.host.as_str().to_owned());
    resource.insert("path".to_string(), request.path.clone());
    let headers = strip_firma_headers(&request.headers);
    let intent = ExecutionIntent {
        action_class: "passthrough".to_string(),
        resource,
        params: ActionParams::Http(HttpParams {
            method,
            headers,
            body: request.body.clone(),
            query: HashMap::new(),
        }),
        raw_transport: scheme.to_string(),
        raw_action_ref: format!("{} {}", request.method, request.path),
    };
    let session_id = session_id
        .parse::<SessionId>()
        .unwrap_or_else(|_| passthrough_session_id());
    Ok(ExecutionEnvelope::new(
        intent,
        String::new(),
        ExecutionMetadata {
            session_id,
            agent_id: passthrough_agent_id(),
            timestamp: chrono::Utc::now(),
            trace_id: None,
            risk_score: None,
            thread_id: None,
            parent_action_id: None,
        },
        None,
    ))
}

#[expect(
    clippy::expect_used,
    reason = "literal passthrough ids are non-empty by construction; parse cannot fail"
)]
fn passthrough_agent_id() -> AgentId {
    "agt_01j0000000e008000000000001"
        .parse()
        .expect("literal passthrough agent id is valid")
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

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::Duration;

    use crate::config::TenancyMode;
    use async_trait::async_trait;
    use chrono::Utc;
    use firma_core::{
        CapabilityClaims, Connector, RevocationStore, TokenError, TokenVerifier, TransportView,
    };
    use firma_http::{Authority, Method};
    use firma_identifiers::TokenId;
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

    #[expect(
        clippy::redundant_pub_crate,
        reason = "shared by sibling interceptor test modules"
    )]
    pub(crate) fn test_connector_registry() -> Arc<ConnectorRegistry> {
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

    struct FailingCredentialInjector;

    #[async_trait]
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

    struct InvalidRequestConnector;

    #[async_trait]
    impl Connector for InvalidRequestConnector {
        async fn dispatch(
            &self,
            _view: &TransportView,
        ) -> Result<ConnectorResponse, ConnectorError> {
            Err(ConnectorError::InvalidRequest(
                "cannot translate request".to_string(),
            ))
        }
    }

    fn test_claims_for_session(session_id: &str) -> CapabilityClaims {
        CapabilityClaims {
            token_id: "ctok_01j0000000e008000000000001"
                .parse()
                .expect("literal token id"),
            agent_id: "agt_01j0000000e008000000000001"
                .parse()
                .expect("literal agent id"),
            session_id: session_id.parse().expect("literal session id"),
            action_set: vec!["communication.external.send".to_string()],
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
                Arc::new(MockVerifier { claims }),
                std::sync::Arc::new(NoRevocations),
                Duration::from_secs(0),
                TenancyMode::SingleAgent,
            ),
            constraint_enforcer: ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy)),
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_pipeline_with_failing_credentials(
        rules: Vec<MappingRuleConfig>,
        session_id: &str,
    ) -> Arc<EnforcementPipeline> {
        let claims = test_claims_for_session(session_id);
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile { rules };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer: IntentNormalizer::new(table),
            capability_validator: CapabilityValidator::new(
                CapabilityMap::new(vec![CapabilityEntry {
                    raw_token: "v4.public.test_token".to_string(),
                    claims: claims.clone(),
                }]),
                Arc::new(MockVerifier { claims }),
                std::sync::Arc::new(NoRevocations),
                Duration::from_secs(0),
                TenancyMode::SingleAgent,
            ),
            constraint_enforcer: ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy)),
            credential_injector: Box::new(FailingCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn allow_rule() -> MappingRuleConfig {
        MappingRuleConfig {
            method: Some(Method::POST),
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

    fn raw_request(host: Authority, method: Method) -> RawRequest {
        RawRequest {
            method,
            host,
            path: "/v1/chat/completions".to_string(),
            headers: HeaderMap::new(),
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
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                        .expect("valid authority"),
                    Method::POST,
                ),
                "sess_allow",
            )
            .await;

        match response {
            HandledResponse::Ok(dispatched) => {
                assert_eq!(dispatched.status, 201);
                assert_eq!(dispatched.body, b"OK");
                assert_eq!(
                    dispatched.headers.get("x-test"),
                    Some(&http::HeaderValue::from_static("ok"))
                );
            }
            other => panic!("expected ok response, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_allow");
        assert_eq!(payload.decision, Decision::Allow);
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
            .handle(
                raw_request(Authority::from_static("127.0.0.1:9"), Method::POST),
                "sess_deny",
            )
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
        assert_eq!(payload.decision, Decision::Deny);
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
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                        .expect("valid authority"),
                    Method::POST,
                ),
                "sess_audit",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Allow);
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
            .handle(
                raw_request(Authority::from_static("127.0.0.1:9"), Method::POST),
                "sess",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Deny);
        assert_eq!(payload.dispatch_status, 0);
        assert_eq!(payload.dispatch_latency_us, 0);
        assert_eq!(payload.response_size, 0);
    }

    #[tokio::test]
    async fn test_handle_connector_network_error_aborts() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_net"),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                // Port 1 is reserved — connect attempt fails reliably.
                raw_request(Authority::from_static("127.0.0.1:1"), Method::POST),
                "sess_net",
            )
            .await;

        match response {
            HandledResponse::Aborted { reason, .. } => {
                assert_eq!(reason, AbortReason::ConnectorFailure);
            }
            other => panic!("expected network abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_FAILURE"),
            "deny_reason should carry CONNECTOR_FAILURE prefix, got {:?}",
            payload.deny_reason
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn dispatch_modify_fails_closed_when_target_is_not_http() {
        use firma_core::{ModificationSpec, ToolUseParams};
        // The V1 normalizer only ever produces HTTP params, but a future
        // non-HTTP transport could route a MODIFY decision to
        // `dispatch_modify` with ToolUse params. The policy asked for a
        // header redaction that can't apply to a tool call; forwarding the
        // unmodified request would leak the header the policy said to
        // strip, so the handler must fail closed instead of dispatching.
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, true),
            test_connector_registry(),
            tx,
        );

        let mut audit_payload = AuditPayload {
            session_id: "sess_modify".to_string(),
            token_id: "tok".to_string(),
            agent_id: "agent".to_string(),
            action: "tool.generic".to_string(),
            resource: "my_tool".to_string(),
            decision: Decision::Modify,
            deny_reason: "redacted_header:x-sensitive".to_string(),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: "test-v1".to_string(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
        };

        let envelope = ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "tool.generic".to_string(),
                resource: ExecutionIntent::resource_map_from("my_tool"),
                params: ActionParams::ToolUse(ToolUseParams {
                    tool_name: "my_tool".to_string(),
                    input: HashMap::new(),
                }),
                raw_transport: "mcp".to_string(),
                raw_action_ref: "my_tool".to_string(),
            },
            "v4.public.test_token".to_string(),
            ExecutionMetadata {
                session_id: "sess_modify".parse().expect("literal session id"),
                agent_id: "agt_01j0000000e008000000000001"
                    .parse()
                    .expect("literal agent id"),
                timestamp: Utc::now(),
                trace_id: None,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        );

        let modifications =
            ModificationSpec::parse("redact_header:x-sensitive").expect("valid redact_header spec");
        let request = raw_request(Authority::from_static("127.0.0.1:9"), Method::POST);

        let response = handler
            .dispatch_modify(
                envelope,
                &request,
                InjectedCredentials::empty(),
                modifications,
                &mut audit_payload,
            )
            .await;

        match response {
            HandledResponse::Deny {
                reason,
                detail,
                context,
            } => {
                assert_eq!(reason, DenyReason::FailClosed);
                assert!(
                    detail.contains("modification could not be applied"),
                    "detail should explain the fail-closed reason, got: {detail}"
                );
                assert_eq!(context, DenialContext::Tool);
            }
            other => panic!("expected fail-closed Deny, got {other:?}"),
        }

        // The audit must reflect the dispatch-level denial, not the
        // pipeline's pre-dispatch MODIFY outcome, and the connector must
        // never have been called (dispatch_status stays zero).
        assert_eq!(audit_payload.decision, Decision::Deny);
        assert!(
            audit_payload.deny_reason.contains("fail closed"),
            "audit deny_reason should carry the fail-closed marker, got: {}",
            audit_payload.deny_reason
        );
        assert_eq!(audit_payload.dispatch_status, 0);
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
        let host =
            Authority::from_str(&format!("127.0.0.1:{}", addr.port())).expect("valid authority");

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_timeout"),
            registry,
            tx,
        );

        let response = handler
            .handle(raw_request(host, Method::POST), "sess_timeout")
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
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_TIMEOUT"),
            "deny_reason should carry CONNECTOR_TIMEOUT prefix, got {:?}",
            payload.deny_reason,
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn test_handle_connector_invalid_request_aborts() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_invalid"),
            Arc::new(crate::connector::ConnectorRegistry::new(Arc::new(
                InvalidRequestConnector,
            ))),
            tx,
        );

        let response = handler
            .handle(
                raw_request(
                    Authority::from_static("api.invalid-request.test"),
                    Method::POST,
                ),
                "sess_invalid",
            )
            .await;

        match response {
            HandledResponse::Aborted { reason, detail } => {
                assert_eq!(reason, AbortReason::ConnectorInvalidRequest);
                assert_eq!(detail, "cannot translate request");
            }
            other => panic!("expected invalid-request abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_INVALID_REQUEST"),
            "deny_reason should carry CONNECTOR_INVALID_REQUEST prefix, got {:?}",
            payload.deny_reason
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
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", addr.port()))
                        .expect("valid authority"),
                    Method::POST,
                ),
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
        assert_eq!(payload.decision, Decision::Allow);
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
    fn test_abort_body_json_supports_connector_failure_reason() {
        let body = abort_body_json(AbortReason::ConnectorFailure, "connection refused");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["aborted"], serde_json::Value::Bool(true));
        assert_eq!(parsed["reason"], "CONNECTOR_FAILURE");
        assert_eq!(parsed["detail"], "connection refused");
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
                    headers: HeaderMap::new(),
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
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                        .expect("valid authority"),
                    Method::GET,
                ),
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
        assert_eq!(payload.decision, Decision::Allow);
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
        assert_eq!(payload.decision, Decision::Deny);
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
    async fn test_emit_upgrade_abort_audit_rewrites_decision_and_keeps_identity() {
        // A websocket upgrade is authorized (ALLOW payload with verified
        // identity), then the upstream relay fails. The abort audit must
        // rewrite the decision to ABORT and carry the reason code while
        // preserving the verified agent/token attribution.
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, false),
            test_connector_registry(),
            tx,
        );

        let allow_payload = AuditPayload {
            session_id: "sess_ws".to_string(),
            token_id: "tok_ws".to_string(),
            agent_id: "agent_ws".to_string(),
            action: "communication.external.send".to_string(),
            resource: "api.openai.com/".to_string(),
            // Inbound ALLOW decision; the helper rewrites it.
            decision: Decision::Allow,
            deny_reason: String::new(),
            enforcement_latency_us: 0,
            context_hash: "ctx".to_string(),
            bundle_version: "v1".to_string(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
        };

        handler
            .emit_upgrade_abort_audit(
                allow_payload,
                AbortReason::ConnectorFailure,
                "upstream websocket connect failed: connection refused",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_FAILURE"),
            "deny_reason should carry CONNECTOR_FAILURE prefix, got {:?}",
            payload.deny_reason
        );
        // Verified identity from the ALLOW payload is preserved.
        assert_eq!(payload.agent_id, "agent_ws");
        assert_eq!(payload.token_id, "tok_ws");
        assert_eq!(payload.session_id, "sess_ws");
        assert_eq!(payload.dispatch_status, 0);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_connect_allow_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(
                vec![MappingRuleConfig {
                    method: Some(Method::CONNECT),
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
                    method: Method::CONNECT,
                    host: Authority::from_static("api.openai.com:443"),
                    path: "/".to_string(),
                    headers: HeaderMap::new(),
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
        assert_eq!(payload.decision, Decision::Allow);
        assert_eq!(payload.dispatch_status, 200);
    }

    #[tokio::test]
    async fn test_handle_connect_deny_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(
                vec![MappingRuleConfig {
                    method: Some(Method::CONNECT),
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
                    method: Method::CONNECT,
                    host: Authority::from_static("api.openai.com:443"),
                    path: "/".to_string(),
                    headers: HeaderMap::new(),
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
            other => panic!("expected connect deny, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_001");
        assert_eq!(payload.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_handle_connect_abort_blocks_tunnel_and_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_with_failing_credentials(
                vec![MappingRuleConfig {
                    method: Some(Method::CONNECT),
                    host: "*".to_string(),
                    path: Some("/".to_string()),
                    action_class: "communication.external.send".to_string(),
                }],
                "sess_connect_abort",
            ),
            test_connector_registry(),
            tx,
        );

        let outcome = handler
            .handle_connect(
                RawRequest {
                    method: Method::CONNECT,
                    host: Authority::from_static("api.openai.com:443"),
                    path: "/".to_string(),
                    headers: HeaderMap::new(),
                    body: None,
                    is_https: true,
                },
                "sess_connect_abort",
            )
            .await;

        match outcome {
            ConnectDecision::Abort { reason, detail } => {
                assert_eq!(reason, AbortReason::CredentialInjectionFailed);
                assert!(detail.contains("vault unavailable"));
            }
            other => panic!("expected connect abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_connect_abort");
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload
                .deny_reason
                .starts_with("CREDENTIAL_INJECTION_FAILED"),
            "deny_reason should carry credential abort code, got {:?}",
            payload.deny_reason
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn test_authorize_upgrade_abort_blocks_upgrade_and_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_with_failing_credentials(vec![allow_rule()], "sess_upgrade_abort"),
            test_connector_registry(),
            tx,
        );

        let authorization = handler
            .authorize_upgrade(
                raw_request(Authority::from_static("api.openai.com"), Method::POST),
                "sess_upgrade_abort",
            )
            .await;

        match authorization {
            UpgradeAuthorization::Abort { reason, detail } => {
                assert_eq!(reason, AbortReason::CredentialInjectionFailed);
                assert!(detail.contains("vault unavailable"));
            }
            other => panic!("expected upgrade abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_upgrade_abort");
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload
                .deny_reason
                .starts_with("CREDENTIAL_INJECTION_FAILED"),
            "deny_reason should carry credential abort code, got {:?}",
            payload.deny_reason
        );
        assert_eq!(payload.dispatch_status, 0);
    }
}
