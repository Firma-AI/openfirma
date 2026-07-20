//! Local-exec governance request handler.
//!
//! [`LocalExecHandler::decide`] is the entry point for governance decisions:
//!
//! - **Fresh request** (no `approval_token`): apply the configured
//!   [`DefaultAction`] and, when the action is `PendingHitl`, issue a new
//!   approval token in [`TokenState::Pending`](super::token_store::TokenState)
//!   state bound to the request context.
//! - **Retry with token** (`approval_token` present): validate the token against
//!   the store. [`TokenValidationResult::Valid`] produces `allow`;
//!   [`TokenValidationResult::Pending`] produces `pending_hitl` (keep polling);
//!   every other state is a fail-closed `deny`.
//!
//! [`LocalExecHandler::decide_management`] handles operator approval and
//! revocation commands over the same UDS endpoint:
//!
//! - `local.exec.approve` — transitions a `Pending` token to `Approved`,
//!   making it consumable by the next `firma-run` retry.
//! - `local.exec.revoke` — transitions a `Pending` or `Approved` token to
//!   `Revoked`, permanently blocking the corresponding execution.
//!
//! All deny paths include a human-readable `reason` string so operators can
//! diagnose why a launch was blocked.

use std::sync::Arc;
use std::time::Duration;

use firma_runtime_state::SandboxId;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::token_store::{
    ApproveResult, InMemoryTokenStore, RevokeResult, TokenStore, TokenValidationResult,
};

// ---------------------------------------------------------------------------
// Governance wire types
// ---------------------------------------------------------------------------

/// JSON request received from `firma-run` over the local-exec UDS endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalExecRequest {
    pub action: String,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub sandbox_id: SandboxId,
    pub session_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub profile: String,
    pub hitl_mode: String,
    #[serde(default)]
    pub budget_state_ref: Option<String>,
    /// SHA-256 fingerprint computed by `firma-run`. The sidecar recomputes
    /// independently and checks both match before issuing or consuming a token.
    #[serde(default)]
    pub request_fingerprint: Option<String>,
    /// Present only on retry attempts — the token ID issued in a prior
    /// `pending_hitl` response.
    #[serde(default)]
    pub approval_token: Option<String>,
}

/// Outcome of a governance decision, serialized as a `snake_case` string on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalExecDecision {
    Allow,
    Deny,
    PendingHitl,
}

/// JSON response sent back to `firma-run`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalExecResponse {
    pub decision: LocalExecDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Management wire types
// ---------------------------------------------------------------------------

/// JSON request sent by an operator (or `firma token` CLI) to approve or
/// revoke a pending approval token.
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalExecManagementRequest {
    /// `"local.exec.approve"` or `"local.exec.revoke"`.
    pub action: String,
    /// Opaque token ID returned in the original `pending_hitl` response.
    pub token_id: String,
}

/// Outcome of a management operation, serialized as a `snake_case` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementOutcome {
    Ok,
    NotFound,
    AlreadyConsumed,
    AlreadyRevoked,
    Expired,
    UnsupportedAction,
}

/// JSON response sent back to the operator after a management command.
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalExecManagementResponse {
    pub outcome: ManagementOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Policy applied to every fresh local-exec request (no approval token).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    /// Allow all executions unconditionally.
    Allow,
    /// Deny all executions unconditionally.
    Deny,
    /// Require human approval via the HITL token flow.
    PendingHitl,
}

/// Construction arguments for [`LocalExecHandler`].
pub struct LocalExecHandlerConfig {
    pub default_action: DefaultAction,
    /// Sandbox identity this endpoint serves. `None` leaves standalone
    /// Sidecars unbound.
    pub expected_sandbox_id: Option<SandboxId>,
    /// Time-to-live for issued approval tokens. Only used by
    /// [`LocalExecHandler::new`] when constructing the default
    /// [`InMemoryTokenStore`]; ignored when using [`LocalExecHandler::with_store`].
    pub token_ttl: Duration,
    /// Suggested retry interval returned to `firma-run` in `pending_hitl`
    /// responses (milliseconds).
    pub retry_after_ms: u64,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Stateful handler for local-exec governance and management requests.
///
/// Holds an <code>Arc&lt;dyn [TokenStore]&gt;</code> and is safe to share across
/// connections. The default store is [`InMemoryTokenStore`]; alternative
/// backends (Redis, distributed stores, test doubles) are injected via
/// [`LocalExecHandler::with_store`].
pub struct LocalExecHandler {
    config: LocalExecHandlerConfig,
    token_store: Arc<dyn TokenStore>,
}

impl LocalExecHandler {
    /// Build a handler using the default [`InMemoryTokenStore`].
    #[must_use]
    pub fn new(config: LocalExecHandlerConfig) -> Self {
        let store = InMemoryTokenStore::new(config.token_ttl);
        Self {
            config,
            token_store: Arc::new(store),
        }
    }

    /// Build a handler with a custom token store.
    #[must_use]
    pub fn with_store(config: LocalExecHandlerConfig, store: Arc<dyn TokenStore>) -> Self {
        Self {
            config,
            token_store: store,
        }
    }

    /// Return a shared reference to the token store.
    ///
    /// Exposed so the background pruning task can hold an `Arc` to the same
    /// store without cloning the handler.
    #[must_use]
    pub fn token_store(&self) -> Arc<dyn TokenStore> {
        Arc::clone(&self.token_store)
    }

    /// Produce a governance decision for one local-exec request.
    pub fn decide(&self, request: &LocalExecRequest) -> LocalExecResponse {
        if let Some(expected) = self.config.expected_sandbox_id
            && request.sandbox_id != expected
        {
            tracing::warn!(
                expected_sandbox_id = %expected,
                request_sandbox_id = %request.sandbox_id,
                "local-exec sandbox identity mismatch; failing closed"
            );
            return deny("sandbox identity does not match this sidecar");
        }

        if request.action != "local.exec" {
            tracing::warn!(
                action = %request.action,
                session_id = %request.session_id,
                "local-exec handler received unexpected action; failing closed"
            );
            return deny("unsupported action for local-exec endpoint");
        }

        if let Some(token_id) = &request.approval_token {
            return self.handle_token_retry(request, token_id);
        }

        self.handle_fresh_request(request)
    }

    /// Process an operator management command (approve or revoke).
    pub fn decide_management(
        &self,
        request: &LocalExecManagementRequest,
    ) -> LocalExecManagementResponse {
        match request.action.as_str() {
            "local.exec.approve" => {
                let result = self.token_store.approve(&request.token_id);
                tracing::info!(
                    token_id = %request.token_id,
                    result = ?result,
                    "local-exec management: approve"
                );
                management_response_from_approve(result)
            }
            "local.exec.revoke" => {
                let result = self.token_store.revoke(&request.token_id);
                tracing::info!(
                    token_id = %request.token_id,
                    result = ?result,
                    "local-exec management: revoke"
                );
                management_response_from_revoke(result)
            }
            _ => {
                tracing::warn!(
                    action = %request.action,
                    "local-exec management: unsupported action"
                );
                LocalExecManagementResponse {
                    outcome: ManagementOutcome::UnsupportedAction,
                    reason: Some(format!(
                        "unsupported management action '{}'",
                        request.action
                    )),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal governance decision paths
    // -----------------------------------------------------------------------

    fn handle_fresh_request(&self, request: &LocalExecRequest) -> LocalExecResponse {
        match self.config.default_action {
            DefaultAction::Allow => {
                tracing::info!(
                    executable = %request.executable,
                    session_id = %request.session_id,
                    sandbox_id = %request.sandbox_id,
                    "local-exec allowed by policy"
                );
                LocalExecResponse {
                    decision: LocalExecDecision::Allow,
                    reason: Some("policy allows execution".to_string()),
                    approval_token: None,
                    retry_after_ms: None,
                }
            }
            DefaultAction::Deny => {
                tracing::warn!(
                    executable = %request.executable,
                    session_id = %request.session_id,
                    sandbox_id = %request.sandbox_id,
                    "local-exec denied by policy"
                );
                deny("policy denies execution")
            }
            DefaultAction::PendingHitl => {
                let fingerprint = compute_fingerprint(request);
                let token_id = self.token_store.issue(
                    fingerprint,
                    request.session_id.clone(),
                    request.sandbox_id,
                    request.agent_id.clone(),
                );
                tracing::info!(
                    executable = %request.executable,
                    session_id = %request.session_id,
                    sandbox_id = %request.sandbox_id,
                    token_id = %token_id,
                    "local-exec pending HITL approval; token issued — operator must approve"
                );
                LocalExecResponse {
                    decision: LocalExecDecision::PendingHitl,
                    reason: Some("awaiting human approval".to_string()),
                    approval_token: Some(token_id),
                    retry_after_ms: Some(self.config.retry_after_ms),
                }
            }
        }
    }

    fn handle_token_retry(&self, request: &LocalExecRequest, token_id: &str) -> LocalExecResponse {
        let fingerprint = compute_fingerprint(request);

        if let Some(client_fp) = &request.request_fingerprint
            && *client_fp != fingerprint
        {
            tracing::warn!(
                session_id = %request.session_id,
                sandbox_id = %request.sandbox_id,
                "local-exec token retry: client fingerprint mismatch; failing closed"
            );
            return deny("request fingerprint mismatch on token retry");
        }

        let result = self.token_store.validate_and_consume(
            token_id,
            &fingerprint,
            &request.session_id,
            &request.sandbox_id,
            request.agent_id.as_deref(),
        );

        match result {
            TokenValidationResult::Valid => {
                tracing::info!(
                    executable = %request.executable,
                    session_id = %request.session_id,
                    sandbox_id = %request.sandbox_id,
                    "local-exec allowed after HITL approval token consumed"
                );
                LocalExecResponse {
                    decision: LocalExecDecision::Allow,
                    reason: Some("approval token validated and consumed".to_string()),
                    approval_token: None,
                    retry_after_ms: None,
                }
            }
            TokenValidationResult::Pending => {
                tracing::info!(
                    session_id = %request.session_id,
                    token_id = %token_id,
                    "local-exec token retry: awaiting operator approval"
                );
                LocalExecResponse {
                    decision: LocalExecDecision::PendingHitl,
                    reason: Some("awaiting operator approval".to_string()),
                    approval_token: Some(token_id.to_string()),
                    retry_after_ms: Some(self.config.retry_after_ms),
                }
            }
            TokenValidationResult::Revoked => {
                tracing::warn!(
                    session_id = %request.session_id,
                    token_id = %token_id,
                    "local-exec token retry: token revoked by operator"
                );
                deny("approval token revoked by operator")
            }
            TokenValidationResult::Unknown => {
                tracing::warn!(session_id = %request.session_id, "local-exec token retry: token unknown");
                deny("approval token not found")
            }
            TokenValidationResult::Expired => {
                tracing::warn!(session_id = %request.session_id, "local-exec token retry: token expired");
                deny("approval token expired")
            }
            TokenValidationResult::AlreadyConsumed => {
                tracing::warn!(session_id = %request.session_id, "local-exec token retry: replay attempt on consumed token");
                deny("approval token already consumed (single-use enforcement)")
            }
            TokenValidationResult::FingerprintMismatch => {
                tracing::warn!(session_id = %request.session_id, "local-exec token retry: fingerprint mismatch");
                deny("approval token fingerprint mismatch — request context changed")
            }
            TokenValidationResult::ContextMismatch => {
                tracing::warn!(session_id = %request.session_id, "local-exec token retry: context mismatch (session/sandbox/agent)");
                deny("approval token context mismatch (session, sandbox, or agent)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn deny(reason: &str) -> LocalExecResponse {
    LocalExecResponse {
        decision: LocalExecDecision::Deny,
        reason: Some(reason.to_string()),
        approval_token: None,
        retry_after_ms: None,
    }
}

fn management_response_from_approve(result: ApproveResult) -> LocalExecManagementResponse {
    let (outcome, reason) = match result {
        ApproveResult::Ok => (ManagementOutcome::Ok, None),
        ApproveResult::NotFound => (ManagementOutcome::NotFound, Some("token not found")),
        ApproveResult::AlreadyConsumed => (
            ManagementOutcome::AlreadyConsumed,
            Some("token was already consumed by firma-run"),
        ),
        ApproveResult::AlreadyRevoked => (
            ManagementOutcome::AlreadyRevoked,
            Some("token was already revoked"),
        ),
        ApproveResult::Expired => (ManagementOutcome::Expired, Some("token has expired")),
    };
    LocalExecManagementResponse {
        outcome,
        reason: reason.map(str::to_string),
    }
}

fn management_response_from_revoke(result: RevokeResult) -> LocalExecManagementResponse {
    let (outcome, reason) = match result {
        RevokeResult::Ok => (ManagementOutcome::Ok, None),
        RevokeResult::NotFound => (ManagementOutcome::NotFound, Some("token not found")),
        RevokeResult::AlreadyConsumed => (
            ManagementOutcome::AlreadyConsumed,
            Some("token was already consumed by firma-run"),
        ),
        RevokeResult::Expired => (ManagementOutcome::Expired, Some("token has expired")),
    };
    LocalExecManagementResponse {
        outcome,
        reason: reason.map(str::to_string),
    }
}

/// Compute the canonical request fingerprint.
///
/// Must stay in sync with `compute_request_fingerprint` in
/// `firma-run/src/mediator.rs` — both sides must produce the same hash for the
/// same logical request.
fn compute_fingerprint(request: &LocalExecRequest) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(request.executable.as_bytes());
    hasher.update(b"\0");
    for arg in &request.args {
        hasher.update(arg.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(request.session_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(request.sandbox_id.to_string().as_bytes());
    hasher.update(b"\0");
    if let Some(agent_id) = &request.agent_id {
        hasher.update(agent_id.as_bytes());
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn config(action: DefaultAction) -> LocalExecHandlerConfig {
        LocalExecHandlerConfig {
            default_action: action,
            expected_sandbox_id: None,
            token_ttl: Duration::from_mins(1),
            retry_after_ms: 500,
        }
    }

    fn request() -> LocalExecRequest {
        LocalExecRequest {
            action: "local.exec".to_string(),
            executable: "/usr/bin/python3".to_string(),
            args: vec!["script.py".to_string()],
            sandbox_id: "sbx_01j0000000e008000000000001"
                .parse()
                .expect("valid sandbox ID fixture"),
            session_id: "sess_1".to_string(),
            agent_id: Some("agent_1".to_string()),
            profile: "generic".to_string(),
            hitl_mode: "async_token".to_string(),
            budget_state_ref: None,
            request_fingerprint: None,
            approval_token: None,
        }
    }

    #[test]
    fn allow_policy_allows() {
        let h = LocalExecHandler::new(config(DefaultAction::Allow));
        let resp = h.decide(&request());
        assert_eq!(resp.decision, LocalExecDecision::Allow);
    }

    #[test]
    fn deny_policy_denies() {
        let h = LocalExecHandler::new(config(DefaultAction::Deny));
        let resp = h.decide(&request());
        assert_eq!(resp.decision, LocalExecDecision::Deny);
    }

    #[test]
    fn pending_hitl_issues_token() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let resp = h.decide(&request());
        assert_eq!(resp.decision, LocalExecDecision::PendingHitl);
        assert!(resp.approval_token.is_some());
        assert_eq!(resp.retry_after_ms, Some(500));
    }

    #[test]
    fn token_retry_pending_until_approved() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();

        // Retry before approval — still pending.
        let mut retry = request();
        retry.approval_token = Some(token.clone());
        let resp = h.decide(&retry);
        assert_eq!(resp.decision, LocalExecDecision::PendingHitl);
        assert_eq!(resp.approval_token.as_deref(), Some(token.as_str()));

        // Operator approves.
        h.token_store().approve(&token);

        // Retry after approval — allowed.
        let resp = h.decide(&retry);
        assert_eq!(resp.decision, LocalExecDecision::Allow);
    }

    #[test]
    fn token_retry_succeeds_once_after_approval() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();
        h.token_store().approve(&token);

        let mut retry = request();
        retry.approval_token = Some(token);
        let resp = h.decide(&retry);
        assert_eq!(resp.decision, LocalExecDecision::Allow);
    }

    #[test]
    fn token_replay_denied() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();
        h.token_store().approve(&token);

        let mut retry = request();
        retry.approval_token = Some(token);
        assert_eq!(h.decide(&retry).decision, LocalExecDecision::Allow);
        assert_eq!(h.decide(&retry).decision, LocalExecDecision::Deny);
    }

    #[test]
    fn revoked_token_denied() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();
        h.token_store().revoke(&token);

        let mut retry = request();
        retry.approval_token = Some(token);
        let resp = h.decide(&retry);
        assert_eq!(resp.decision, LocalExecDecision::Deny);
        assert!(resp.reason.unwrap_or_default().contains("revoked"));
    }

    #[test]
    fn token_context_mismatch_denied() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();

        let mut retry = request();
        retry.approval_token = Some(token);
        retry.sandbox_id = "sbx_01j0000000e008000000000002"
            .parse()
            .expect("valid sandbox ID fixture");
        assert_eq!(h.decide(&retry).decision, LocalExecDecision::Deny);
    }

    #[test]
    fn client_fingerprint_mismatch_denied() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();

        let mut retry = request();
        retry.approval_token = Some(token);
        retry.request_fingerprint = Some("deadbeef".to_string());
        assert_eq!(h.decide(&retry).decision, LocalExecDecision::Deny);
    }

    #[test]
    fn unknown_action_denied() {
        let h = LocalExecHandler::new(config(DefaultAction::Allow));
        let mut req = request();
        req.action = "network.connect".to_string();
        assert_eq!(h.decide(&req).decision, LocalExecDecision::Deny);
    }

    #[test]
    fn management_approve_ok() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();

        let mgmt = LocalExecManagementRequest {
            action: "local.exec.approve".to_string(),
            token_id: token,
        };
        let resp = h.decide_management(&mgmt);
        assert_eq!(resp.outcome, ManagementOutcome::Ok);
    }

    #[test]
    fn management_revoke_ok() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();

        let mgmt = LocalExecManagementRequest {
            action: "local.exec.revoke".to_string(),
            token_id: token,
        };
        let resp = h.decide_management(&mgmt);
        assert_eq!(resp.outcome, ManagementOutcome::Ok);
    }

    #[test]
    fn management_approve_not_found() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let mgmt = LocalExecManagementRequest {
            action: "local.exec.approve".to_string(),
            token_id: "no-such-token".to_string(),
        };
        assert_eq!(
            h.decide_management(&mgmt).outcome,
            ManagementOutcome::NotFound
        );
    }

    #[test]
    fn management_unsupported_action() {
        let h = LocalExecHandler::new(config(DefaultAction::Allow));
        let mgmt = LocalExecManagementRequest {
            action: "local.exec.delete".to_string(),
            token_id: "tok".to_string(),
        };
        assert_eq!(
            h.decide_management(&mgmt).outcome,
            ManagementOutcome::UnsupportedAction
        );
    }
}
