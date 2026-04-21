//! Execution-layer response semantics and async ABORT handling.
//!
//! This module sits above enforcement evaluation and implements FEP runtime
//! semantics for how DENY decisions are surfaced:
//! - Tool transport: structured tool result, agent loop continues.
//! - API transport: hard authorization failure response, connector not invoked.
//!
//! It also implements asynchronous in-flight ABORT cancellation keyed by
//! token/session, independent from `EnforcementDecision`.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use firma_core::{
    SessionId, TokenId, decision::DenyReason, envelope::ExecutionEnvelope,
    session::InvalidSessionIdError, token::InvalidTokenIdError,
};
use firma_proto::RevocationEvent;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc::UnboundedSender};
use tokio_util::sync::CancellationToken;

use crate::enforcement::decision::EnforcementDecision;

/// Errors produced when parsing a proto [`RevocationEvent`] into a typed
/// [`RevocationSignal`].
#[derive(Debug, thiserror::Error)]
pub enum RevocationSignalError {
    #[error("invalid token_id in revocation event: {0}")]
    InvalidTokenId(#[from] InvalidTokenIdError),
    #[error("invalid session_id in revocation event: {0}")]
    InvalidSessionId(#[from] InvalidSessionIdError),
}

/// Runtime surface for a denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenySurface {
    Tool,
    Api,
}

/// Structured tool output returned on tool denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolUseResult {
    pub denied: bool,
    pub is_error: bool,
    pub reason: DenyReason,
    pub content: String,
}

/// Hard authorization failure returned for API denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiAuthorizationFailure {
    pub status_code: u16,
    pub reason: DenyReason,
    pub message: String,
}

/// Denial output rendered at response layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyOutput {
    Tool(ToolUseResult),
    Api(ApiAuthorizationFailure),
}

/// Audit event emitted asynchronously for deny/abort outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarAuditEvent {
    DenyTool {
        reason: DenyReason,
        timestamp: DateTime<Utc>,
    },
    DenyApi {
        reason: DenyReason,
        timestamp: DateTime<Utc>,
    },
    Abort {
        token_id: Option<TokenId>,
        session_id: Option<SessionId>,
        reason: String,
        timestamp: DateTime<Utc>,
    },
}

/// Non-blocking audit emitter using an async channel.
#[derive(Clone)]
pub struct AuditEmitter {
    tx: UnboundedSender<SidecarAuditEvent>,
}

impl AuditEmitter {
    #[must_use]
    pub fn new(tx: UnboundedSender<SidecarAuditEvent>) -> Self {
        Self { tx }
    }

    pub fn emit_async(&self, event: SidecarAuditEvent) {
        let _ = self.tx.send(event);
    }
}

/// Connector abstraction used by dispatcher.
pub trait Connector: Send + Sync {
    fn execute(&self, envelope: &ExecutionEnvelope) -> ConnectorResponse;
}

/// Minimal connector response for execution tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorResponse {
    pub status_code: u16,
    pub body: String,
}

/// Final execution-layer output returned to caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    ToolResult(ToolUseResult),
    ApiDenied(ApiAuthorizationFailure),
    Aborted { reason: String },
    Forwarded(ConnectorResponse),
}

/// Maps enforcement decisions to runtime behavior.
pub struct EnforcementDispatcher<C: Connector> {
    connector: C,
    audit: AuditEmitter,
}

impl<C: Connector> EnforcementDispatcher<C> {
    #[must_use]
    pub fn new(connector: C, audit: AuditEmitter) -> Self {
        Self { connector, audit }
    }

    /// Dispatch enforcement output with transport-specific DENY semantics.
    #[must_use]
    pub fn dispatch(&self, decision: EnforcementDecision) -> DispatchOutcome {
        match decision {
            EnforcementDecision::Allow { envelope, .. } => {
                DispatchOutcome::Forwarded(self.connector.execute(&envelope))
            }
            EnforcementDecision::Passthrough { .. } => {
                DispatchOutcome::Forwarded(ConnectorResponse {
                    status_code: 200,
                    body: "passthrough".to_string(),
                })
            }
            EnforcementDecision::Deny {
                reason, envelope, ..
            } => {
                let (surface, timestamp) = match envelope {
                    Some(env) => (
                        deny_surface_from_transport(&env.intent.raw_transport),
                        env.timestamp,
                    ),
                    None => (DenySurface::Api, Utc::now()),
                };

                match surface {
                    DenySurface::Tool => {
                        self.audit
                            .emit_async(SidecarAuditEvent::DenyTool { reason, timestamp });
                        DispatchOutcome::ToolResult(ToolUseResult {
                            denied: true,
                            is_error: true,
                            reason,
                            content: format!("DENY: {reason}"),
                        })
                    }
                    DenySurface::Api => {
                        self.audit
                            .emit_async(SidecarAuditEvent::DenyApi { reason, timestamp });
                        DispatchOutcome::ApiDenied(ApiAuthorizationFailure {
                            status_code: 403,
                            reason,
                            message: format!("authorization denied: {reason}"),
                        })
                    }
                }
            }
        }
    }
}

/// Detect deny surface from normalized transport.
#[must_use]
pub fn deny_surface_from_transport(raw_transport: &str) -> DenySurface {
    let transport = raw_transport.to_ascii_lowercase();
    if transport.starts_with("tool") || transport.starts_with("mcp") {
        DenySurface::Tool
    } else {
        DenySurface::Api
    }
}

/// `WatchRevocations` semantic signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationSignal {
    Revoked {
        token_id: TokenId,
        reason: String,
    },
    Abort {
        token_id: Option<TokenId>,
        session_id: Option<SessionId>,
        reason: String,
    },
}

impl RevocationSignal {
    /// Parse a proto [`RevocationEvent`] into a typed signal.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationSignalError`] if `token_id` is not a valid UUID or
    /// `session_id` extracted from the reason string is not a valid session ID.
    pub fn from_proto(event: &RevocationEvent) -> Result<Self, RevocationSignalError> {
        let reason_upper = event.reason.to_ascii_uppercase();
        if reason_upper.starts_with("ABORT") {
            let token_id = if event.token_id.is_empty() {
                None
            } else {
                Some(event.token_id.parse::<TokenId>()?)
            };
            let session_id = parse_session_hint(&event.reason)
                .map(|s| s.parse::<SessionId>())
                .transpose()?;
            Ok(Self::Abort {
                token_id,
                session_id,
                reason: event.reason.clone(),
            })
        } else {
            Ok(Self::Revoked {
                token_id: event.token_id.parse::<TokenId>()?,
                reason: event.reason.clone(),
            })
        }
    }
}

fn parse_session_hint(reason: &str) -> Option<String> {
    let marker = "session_id=";
    let start = reason.find(marker)? + marker.len();
    let tail = &reason[start..];
    let end = tail.find([' ', ';', ',']).unwrap_or(tail.len());
    let value = tail[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[derive(Debug, Clone)]
struct ExecutionEntry {
    token_id: TokenId,
    session_id: SessionId,
    cancel: CancellationToken,
}

#[derive(Default)]
struct InFlightState {
    executions: HashMap<String, ExecutionEntry>,
    token_index: HashMap<TokenId, HashSet<String>>,
    session_index: HashMap<SessionId, HashSet<String>>,
}

/// Manages in-flight executions and async ABORT cancellation.
#[derive(Default)]
pub struct InFlightAbortManager {
    state: RwLock<InFlightState>,
}

impl InFlightAbortManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an execution and return its cancellation token.
    pub async fn register(
        &self,
        execution_id: &str,
        token_id: &TokenId,
        session_id: &SessionId,
    ) -> CancellationToken {
        let cancel = CancellationToken::new();
        let entry = ExecutionEntry {
            token_id: *token_id,
            session_id: session_id.clone(),
            cancel: cancel.clone(),
        };

        let mut state = self.state.write().await;
        state
            .executions
            .insert(execution_id.to_string(), entry.clone());
        state
            .token_index
            .entry(*token_id)
            .or_default()
            .insert(execution_id.to_string());
        state
            .session_index
            .entry(session_id.clone())
            .or_default()
            .insert(execution_id.to_string());

        cancel
    }

    /// Mark execution complete and remove cancellation indexes.
    pub async fn complete(&self, execution_id: &str) {
        let mut state = self.state.write().await;
        if let Some(entry) = state.executions.remove(execution_id) {
            remove_index(&mut state.token_index, &entry.token_id, execution_id);
            remove_index(&mut state.session_index, &entry.session_id, execution_id);
        }
    }

    /// Process revocation stream signal and cancel matching in-flight work for ABORT.
    pub async fn process_signal(&self, signal: RevocationSignal, audit: &AuditEmitter) -> usize {
        match signal {
            RevocationSignal::Revoked { .. } => 0,
            RevocationSignal::Abort {
                token_id,
                session_id,
                reason,
            } => {
                let cancelled = self
                    .abort_matching(token_id.as_ref(), session_id.as_ref())
                    .await;
                audit.emit_async(SidecarAuditEvent::Abort {
                    token_id,
                    session_id,
                    reason,
                    timestamp: Utc::now(),
                });
                cancelled
            }
        }
    }

    /// Parse and process a proto revocation event in one step.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationSignalError`] if the proto event carries an
    /// unparseable `token_id` or `session_id`.
    pub async fn process_proto_event(
        &self,
        event: &RevocationEvent,
        audit: &AuditEmitter,
    ) -> Result<usize, RevocationSignalError> {
        let signal = RevocationSignal::from_proto(event)?;
        Ok(self.process_signal(signal, audit).await)
    }

    async fn abort_matching(
        &self,
        token_id: Option<&TokenId>,
        session_id: Option<&SessionId>,
    ) -> usize {
        let mut ids = HashSet::new();
        let mut cancels = Vec::new();

        let state = self.state.read().await;
        if let Some(token_id) = token_id
            && let Some(found) = state.token_index.get(token_id)
        {
            ids.extend(found.iter().cloned());
        }
        if let Some(session_id) = session_id
            && let Some(found) = state.session_index.get(session_id)
        {
            ids.extend(found.iter().cloned());
        }

        for id in &ids {
            if let Some(entry) = state.executions.get(id)
                && !entry.cancel.is_cancelled()
            {
                cancels.push(entry.cancel.clone());
            }
        }

        drop(state);

        for cancel in &cancels {
            cancel.cancel();
        }

        ids.len()
    }
}

fn remove_index<K>(index: &mut HashMap<K, HashSet<String>>, key: &K, execution_id: &str)
where
    K: Eq + std::hash::Hash,
{
    if let Some(values) = index.get_mut(key) {
        values.remove(execution_id);
        if values.is_empty() {
            index.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::decision::{
        ConstraintEnforcementStage, EnforcementDecision, EnforcementStage,
    };
    use crate::normalizer::NormalizedEnvelope;
    use chrono::DateTime;
    use firma_core::envelope::{ActionParams, ExecutionIntent, HttpMethod, HttpParams};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::mpsc;

    fn fixed_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn deny_decision(raw_transport: &str) -> EnforcementDecision {
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyDenied,
            stage: EnforcementStage::ConstraintEnforcement(
                ConstraintEnforcementStage::PolicyEvaluation,
            ),
            detail: "policy denied".to_string(),
            envelope: Some(NormalizedEnvelope {
                intent: ExecutionIntent {
                    action_class: "tool.exec".to_string(),
                    resource: "resource".to_string(),
                    params: ActionParams::Http(HttpParams {
                        method: HttpMethod::POST,
                        headers: HashMap::new(),
                        body: None,
                        query: HashMap::new(),
                    }),
                    raw_transport: raw_transport.to_string(),
                    raw_action_ref: "ref".to_string(),
                },
                timestamp: fixed_time(),
            }),
        }
    }

    #[derive(Clone)]
    struct CountingConnector {
        calls: Arc<AtomicUsize>,
    }

    impl CountingConnector {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Connector for CountingConnector {
        fn execute(&self, _envelope: &ExecutionEnvelope) -> ConnectorResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ConnectorResponse {
                status_code: 200,
                body: "ok".to_string(),
            }
        }
    }

    #[tokio::test]
    async fn tool_deny_returns_structured_value_and_no_connector_call() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let connector = CountingConnector::new();
        let dispatcher = EnforcementDispatcher::new(connector.clone(), AuditEmitter::new(tx));

        let result = dispatcher.dispatch(deny_decision("tool"));

        match result {
            DispatchOutcome::ToolResult(value) => {
                assert!(value.denied);
                assert!(value.is_error);
                assert_eq!(value.reason, DenyReason::PolicyDenied);
            }
            _ => panic!("expected tool deny output"),
        }

        assert_eq!(connector.calls(), 0);

        let event = rx.recv().await.unwrap();
        assert!(matches!(event, SidecarAuditEvent::DenyTool { .. }));
    }

    #[tokio::test]
    async fn api_deny_returns_hard_failure_and_no_connector_call() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let connector = CountingConnector::new();
        let dispatcher = EnforcementDispatcher::new(connector.clone(), AuditEmitter::new(tx));

        let result = dispatcher.dispatch(deny_decision("https"));

        match result {
            DispatchOutcome::ApiDenied(value) => {
                assert_eq!(value.status_code, 403);
                assert_eq!(value.reason, DenyReason::PolicyDenied);
            }
            _ => panic!("expected api deny output"),
        }

        assert_eq!(connector.calls(), 0);

        let event = rx.recv().await.unwrap();
        assert!(matches!(event, SidecarAuditEvent::DenyApi { .. }));
    }

    #[test]
    fn tool_surface_detection_uses_transport() {
        assert_eq!(deny_surface_from_transport("tool"), DenySurface::Tool);
        assert_eq!(deny_surface_from_transport("mcp_tool"), DenySurface::Tool);
        assert_eq!(deny_surface_from_transport("https"), DenySurface::Api);
        assert_eq!(deny_surface_from_transport("db"), DenySurface::Api);
    }

    #[tokio::test]
    async fn abort_signal_cancels_all_matching_inflight_for_token_or_session() {
        let tok1 = TokenId::new();
        let tok2 = TokenId::new();
        let sess_a: SessionId = "sess-a".parse().unwrap();
        let manager = InFlightAbortManager::new();
        let token_cancel = manager.register("exec-1", &tok1, &sess_a).await;
        let session_cancel = manager.register("exec-2", &tok2, &sess_a).await;

        let (tx, mut rx) = mpsc::unbounded_channel();
        let audit = AuditEmitter::new(tx);

        let cancelled = manager
            .process_signal(
                RevocationSignal::Abort {
                    token_id: Some(tok1),
                    session_id: Some(sess_a),
                    reason: "ABORT session_id=sess-a".to_string(),
                },
                &audit,
            )
            .await;

        assert_eq!(cancelled, 2);
        assert!(token_cancel.is_cancelled());
        assert!(session_cancel.is_cancelled());

        let event = rx.recv().await.unwrap();
        assert!(matches!(event, SidecarAuditEvent::Abort { .. }));
    }

    #[tokio::test]
    async fn abort_signal_by_token_only_cancels_matching_execution() {
        let tok1 = TokenId::new();
        let tok2 = TokenId::new();
        let sess_a: SessionId = "sess-a".parse().unwrap();
        let sess_b: SessionId = "sess-b".parse().unwrap();
        let manager = InFlightAbortManager::new();
        let token_cancel = manager.register("exec-1", &tok1, &sess_a).await;
        let other_cancel = manager.register("exec-2", &tok2, &sess_b).await;

        let (tx, _rx) = mpsc::unbounded_channel();
        let audit = AuditEmitter::new(tx);

        let cancelled = manager
            .process_signal(
                RevocationSignal::Abort {
                    token_id: Some(tok1),
                    session_id: None,
                    reason: "ABORT token".to_string(),
                },
                &audit,
            )
            .await;

        assert_eq!(cancelled, 1);
        assert!(token_cancel.is_cancelled());
        assert!(!other_cancel.is_cancelled());
    }

    #[tokio::test]
    async fn abort_signal_by_session_only_cancels_all_session_executions() {
        let sess_a: SessionId = "sess-a".parse().unwrap();
        let sess_b: SessionId = "sess-b".parse().unwrap();
        let manager = InFlightAbortManager::new();
        let first = manager.register("exec-1", &TokenId::new(), &sess_a).await;
        let second = manager.register("exec-2", &TokenId::new(), &sess_a).await;
        let third = manager.register("exec-3", &TokenId::new(), &sess_b).await;

        let (tx, _rx) = mpsc::unbounded_channel();
        let audit = AuditEmitter::new(tx);

        let cancelled = manager
            .process_signal(
                RevocationSignal::Abort {
                    token_id: None,
                    session_id: Some(sess_a),
                    reason: "ABORT session".to_string(),
                },
                &audit,
            )
            .await;

        assert_eq!(cancelled, 2);
        assert!(first.is_cancelled());
        assert!(second.is_cancelled());
        assert!(!third.is_cancelled());
    }

    #[tokio::test]
    async fn revoked_signal_does_not_abort_inflight() {
        let tok1 = TokenId::new();
        let sess_a: SessionId = "sess-a".parse().unwrap();
        let manager = InFlightAbortManager::new();
        let token_cancel = manager.register("exec-1", &tok1, &sess_a).await;

        let (tx, _rx) = mpsc::unbounded_channel();
        let audit = AuditEmitter::new(tx);

        let cancelled = manager
            .process_signal(
                RevocationSignal::Revoked {
                    token_id: tok1,
                    reason: "REVOKED".to_string(),
                },
                &audit,
            )
            .await;

        assert_eq!(cancelled, 0);
        assert!(!token_cancel.is_cancelled());
    }

    #[test]
    fn abort_proto_parsing_extracts_abort_semantics() {
        let tok = TokenId::new();
        let event = RevocationEvent {
            token_id: tok.to_string(),
            reason: "ABORT session_id=sess-a".to_string(),
            timestamp: None,
        };

        let signal = RevocationSignal::from_proto(&event).unwrap();
        assert_eq!(
            signal,
            RevocationSignal::Abort {
                token_id: Some(tok),
                session_id: Some("sess-a".parse().unwrap()),
                reason: "ABORT session_id=sess-a".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn abort_proto_event_path_cancels_inflight() {
        let tok = TokenId::new();
        let sess_a: SessionId = "sess-a".parse().unwrap();
        let manager = InFlightAbortManager::new();
        let token_cancel = manager.register("exec-1", &tok, &sess_a).await;

        let (tx, _rx) = mpsc::unbounded_channel();
        let audit = AuditEmitter::new(tx);

        let event = RevocationEvent {
            token_id: tok.to_string(),
            reason: "ABORT".to_string(),
            timestamp: None,
        };

        let cancelled = manager.process_proto_event(&event, &audit).await.unwrap();
        assert_eq!(cancelled, 1);
        assert!(token_cancel.is_cancelled());
    }
}
