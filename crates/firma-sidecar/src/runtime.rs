//! Runtime integration scaffold for enforcement + execution semantics.
//!
//! This module wires together:
//! - enforcement decision production (`Enforcer`)
//! - response rendering (`EnforcementDispatcher`)
//! - asynchronous in-flight ABORT management (`InFlightAbortManager`)
//!
//! It provides a minimal integration path that can be used by future
//! HTTP/gRPC server handlers.

use firma_proto::RevocationEvent;

use crate::{
    enforcement::decision::EnforcementDecision,
    execution::{AuditEmitter, DispatchOutcome, EnforcementDispatcher, InFlightAbortManager},
    normalizer::RawRequest,
    pipeline::EnforcementPipeline,
};

/// Enforcement decision producer abstraction.
pub trait Enforcer: Send + Sync {
    fn enforce(&self, request: &RawRequest, session_id: &str) -> EnforcementDecision;
}

impl Enforcer for EnforcementPipeline {
    fn enforce(&self, request: &RawRequest, session_id: &str) -> EnforcementDecision {
        Self::enforce(self, request, session_id)
    }
}

/// Lightweight runtime coordinator.
pub struct SidecarRuntime<E, C>
where
    E: Enforcer,
    C: crate::execution::Connector,
{
    enforcer: E,
    dispatcher: EnforcementDispatcher<C>,
    inflight: InFlightAbortManager,
    audit: AuditEmitter,
}

impl<E, C> SidecarRuntime<E, C>
where
    E: Enforcer,
    C: crate::execution::Connector,
{
    #[must_use]
    pub fn new(
        enforcer: E,
        dispatcher: EnforcementDispatcher<C>,
        inflight: InFlightAbortManager,
        audit: AuditEmitter,
    ) -> Self {
        Self {
            enforcer,
            dispatcher,
            inflight,
            audit,
        }
    }

    /// Handle one intercepted request.
    ///
    /// Register in-flight execution for ALLOW decisions and clean it up
    /// deterministically after dispatch.
    pub async fn handle_request(
        &self,
        execution_id: &str,
        request: &RawRequest,
        session_id: &str,
    ) -> DispatchOutcome {
        let decision = self.enforcer.enforce(request, session_id);

        let maybe_reg = match &decision {
            EnforcementDecision::Allow { claims, .. } => Some((
                claims.token_id.clone(),
                claims.session_id.clone(),
                self.inflight
                    .register(execution_id, &claims.token_id, &claims.session_id)
                    .await,
            )),
            EnforcementDecision::Deny { .. } | EnforcementDecision::Passthrough { .. } => None,
        };

        if let Some((_, _, cancel)) = &maybe_reg
            && cancel.is_cancelled()
        {
            self.inflight.complete(execution_id).await;
            return DispatchOutcome::Aborted {
                reason: "execution cancelled before dispatch".to_string(),
            };
        }

        let out = self.dispatcher.dispatch(decision);
        self.inflight.complete(execution_id).await;
        out
    }

    /// Process one incoming revocation stream event.
    ///
    /// Returns number of cancelled in-flight executions (ABORT only).
    pub async fn on_revocation_event(&self, event: &RevocationEvent) -> usize {
        self.inflight.process_proto_event(event, &self.audit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        execution::{
            ApiAuthorizationFailure, AuditEmitter, Connector, ConnectorResponse, DispatchOutcome,
            EnforcementDispatcher, InFlightAbortManager, SidecarAuditEvent,
        },
        normalizer::NormalizedEnvelope,
    };
    use chrono::{DateTime, Utc};
    use firma_core::{
        decision::DenyReason,
        envelope::{
            ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
            HttpParams,
        },
        token::CapabilityClaims,
    };
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::sync::mpsc;

    fn fixed_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap_or_else(|_| panic!("invalid fixed timestamp"))
            .with_timezone(&Utc)
    }

    struct CountingConnector {
        calls: Arc<AtomicUsize>,
    }

    impl CountingConnector {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Connector for CountingConnector {
        fn execute(&self, _envelope: &ExecutionEnvelope) -> ConnectorResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ConnectorResponse {
                status_code: 200,
                body: "forwarded".to_string(),
            }
        }
    }

    struct FakeEnforcer {
        decision: EnforcementDecision,
    }

    impl Enforcer for FakeEnforcer {
        fn enforce(&self, _request: &RawRequest, _session_id: &str) -> EnforcementDecision {
            self.decision_from_template()
        }
    }

    impl FakeEnforcer {
        fn decision_from_template(&self) -> EnforcementDecision {
            match &self.decision {
                EnforcementDecision::Allow { claims, envelope } => EnforcementDecision::Allow {
                    claims: claims.clone(),
                    envelope: envelope.clone(),
                },
                EnforcementDecision::Deny {
                    reason,
                    stage,
                    detail,
                    envelope,
                } => EnforcementDecision::Deny {
                    reason: *reason,
                    stage: *stage,
                    detail: detail.clone(),
                    envelope: envelope.clone(),
                },
                EnforcementDecision::Passthrough { detail } => EnforcementDecision::Passthrough {
                    detail: detail.clone(),
                },
            }
        }
    }

    fn allow_decision() -> EnforcementDecision {
        let claims = CapabilityClaims {
            token_id: "tok-1".to_string(),
            agent_id: "agent".to_string(),
            session_id: "sess-a".to_string(),
            action_set: vec!["http.get".to_string()],
            resource_scope: "*".to_string(),
            issued_at: fixed_time(),
            expiry: fixed_time(),
            context_hash: String::new(),
        };

        let envelope = ExecutionEnvelope {
            intent: ExecutionIntent {
                action_class: "http.get".to_string(),
                resource: "api.example.com/data".to_string(),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::GET,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "GET /data".to_string(),
            },
            capability: "v4.public.test".to_string(),
            metadata: ExecutionMetadata {
                session_id: "sess-a".to_string(),
                agent_id: "agent".to_string(),
                timestamp: fixed_time(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            provenance: None,
        };

        EnforcementDecision::Allow {
            claims,
            envelope: Box::new(envelope),
        }
    }

    fn deny_tool_decision() -> EnforcementDecision {
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyDenied,
            stage: crate::enforcement::decision::EnforcementStage::ConstraintEnforcement(
                crate::enforcement::decision::ConstraintEnforcementStage::PolicyEvaluation,
            ),
            detail: "denied".to_string(),
            envelope: Some(NormalizedEnvelope {
                intent: ExecutionIntent {
                    action_class: "tool.exec".to_string(),
                    resource: "tool".to_string(),
                    params: ActionParams::Http(HttpParams {
                        method: HttpMethod::POST,
                        headers: HashMap::new(),
                        body: None,
                        query: HashMap::new(),
                    }),
                    raw_transport: "tool".to_string(),
                    raw_action_ref: "tool call".to_string(),
                },
                timestamp: fixed_time(),
            }),
        }
    }

    fn test_request() -> RawRequest {
        RawRequest {
            method: "GET".to_string(),
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        }
    }

    #[tokio::test]
    async fn runtime_uses_dispatcher_for_tool_deny_semantics() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let audit = AuditEmitter::new(tx);
        let connector = CountingConnector::new();
        let dispatcher = EnforcementDispatcher::new(connector, audit.clone());

        let runtime = SidecarRuntime::new(
            FakeEnforcer {
                decision: deny_tool_decision(),
            },
            dispatcher,
            InFlightAbortManager::new(),
            audit,
        );

        let out = runtime
            .handle_request("exec-1", &test_request(), "sess-a")
            .await;

        assert!(matches!(out, DispatchOutcome::ToolResult { .. }));

        let event = rx.recv().await.unwrap_or_else(|| panic!("missing audit"));
        assert!(matches!(event, SidecarAuditEvent::DenyTool { .. }));
    }

    #[tokio::test]
    async fn runtime_allow_invokes_connector() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let audit = AuditEmitter::new(tx);
        let connector = CountingConnector::new();
        let calls = connector.calls.clone();
        let dispatcher = EnforcementDispatcher::new(connector, audit.clone());

        let runtime = SidecarRuntime::new(
            FakeEnforcer {
                decision: allow_decision(),
            },
            dispatcher,
            InFlightAbortManager::new(),
            audit,
        );

        let out = runtime
            .handle_request("exec-allow", &test_request(), "sess-a")
            .await;

        assert!(matches!(out, DispatchOutcome::Forwarded { .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn runtime_processes_abort_revocation_events() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let audit = AuditEmitter::new(tx);
        let connector = CountingConnector::new();
        let dispatcher = EnforcementDispatcher::new(connector, audit.clone());
        let inflight = InFlightAbortManager::new();
        let token = inflight.register("exec-1", "tok-1", "sess-a").await;

        let runtime = SidecarRuntime::new(
            FakeEnforcer {
                decision: allow_decision(),
            },
            dispatcher,
            inflight,
            audit,
        );

        let event = RevocationEvent {
            token_id: "tok-1".to_string(),
            reason: "ABORT".to_string(),
            timestamp: None,
        };

        let cancelled = runtime.on_revocation_event(&event).await;
        assert_eq!(cancelled, 1);
        assert!(token.is_cancelled());
    }

    #[test]
    fn api_deny_failure_type_is_available_for_runtime_consumers() {
        let failure = ApiAuthorizationFailure {
            status_code: 403,
            reason: DenyReason::PolicyDenied,
            message: "authorization denied".to_string(),
        };
        assert_eq!(failure.status_code, 403);
    }
}
