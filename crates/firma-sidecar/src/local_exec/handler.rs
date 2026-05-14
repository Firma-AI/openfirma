//! Local-exec governance request handler.
//!
//! [`LocalExecHandler::decide`] is the single entry point for local-exec
//! governance decisions. It enforces the full token lifecycle:
//!
//! - **Fresh request** (no `approval_token`): apply the configured
//!   [`DefaultAction`] and, when the action is `PendingHitl`, issue a new
//!   approval token bound to the request context.
//! - **Retry with token** (`approval_token` present): validate the token
//!   against the store. Only [`TokenValidationResult::Valid`] produces an
//!   `allow`; every other state is a fail-closed `deny`.
//!
//! All deny paths include a human-readable `reason` string so operators can
//! diagnose why a launch was blocked.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::token_store::{InMemoryTokenStore, TokenValidationResult};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// JSON request received from `firma-run` over the local-exec UDS endpoint.
///
/// Mirrors `MediatorRequest` on the client side. All fields that `firma-run`
/// always serializes are required; optional fields use `Option`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalExecRequest {
    pub action: String,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub sandbox_id: String,
    pub session_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub profile: String,
    pub hitl_mode: String,
    #[serde(default)]
    pub budget_state_ref: Option<String>,
    /// SHA-256 fingerprint computed by `firma-run`. The sidecar recomputes
    /// the same fingerprint independently and checks both match before issuing
    /// or consuming a token.
    #[serde(default)]
    pub request_fingerprint: Option<String>,
    /// Present only on retry attempts — the token originally issued in a prior
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
    /// Time-to-live for issued approval tokens.
    pub token_ttl: Duration,
    /// Suggested retry interval returned to `firma-run` in `pending_hitl`
    /// responses (milliseconds).
    pub retry_after_ms: u64,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Stateful handler for local-exec governance requests.
///
/// The handler owns the [`InMemoryTokenStore`] and is safe to share across
/// connections via [`Arc`].
pub struct LocalExecHandler {
    config: LocalExecHandlerConfig,
    token_store: Arc<InMemoryTokenStore>,
}

impl LocalExecHandler {
    /// Build a handler from the given config.
    #[must_use]
    pub fn new(config: LocalExecHandlerConfig) -> Self {
        let store = InMemoryTokenStore::new(config.token_ttl);
        Self {
            config,
            token_store: Arc::new(store),
        }
    }

    /// Return a reference to the underlying token store.
    ///
    /// Exposed so the background pruning task can hold an `Arc` to the same
    /// store without cloning the handler.
    #[must_use]
    pub fn token_store(&self) -> Arc<InMemoryTokenStore> {
        Arc::clone(&self.token_store)
    }

    /// Produce a governance decision for one local-exec request.
    ///
    /// This is the only entry point; it is synchronous and has no I/O.
    pub fn decide(&self, request: &LocalExecRequest) -> LocalExecResponse {
        // Validate action field: only "local.exec" is accepted.
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

    // -----------------------------------------------------------------------
    // Internal decision paths
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
                    request.sandbox_id.clone(),
                    request.agent_id.clone(),
                );
                tracing::info!(
                    executable = %request.executable,
                    session_id = %request.session_id,
                    sandbox_id = %request.sandbox_id,
                    "local-exec pending HITL approval; token issued"
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

        // If the client supplied a pre-computed fingerprint, verify it matches
        // our independent computation (defense-in-depth; mismatch = tamper).
        if let Some(client_fp) = &request.request_fingerprint {
            if *client_fp != fingerprint {
                tracing::warn!(
                    session_id = %request.session_id,
                    sandbox_id = %request.sandbox_id,
                    "local-exec token retry: client fingerprint mismatch; failing closed"
                );
                return deny("request fingerprint mismatch on token retry");
            }
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
            TokenValidationResult::Unknown => {
                tracing::warn!(
                    session_id = %request.session_id,
                    "local-exec token retry: token unknown"
                );
                deny("approval token not found")
            }
            TokenValidationResult::Expired => {
                tracing::warn!(
                    session_id = %request.session_id,
                    "local-exec token retry: token expired"
                );
                deny("approval token expired")
            }
            TokenValidationResult::AlreadyConsumed => {
                tracing::warn!(
                    session_id = %request.session_id,
                    "local-exec token retry: replay attempt on consumed token"
                );
                deny("approval token already consumed (single-use enforcement)")
            }
            TokenValidationResult::FingerprintMismatch => {
                tracing::warn!(
                    session_id = %request.session_id,
                    "local-exec token retry: fingerprint mismatch"
                );
                deny("approval token fingerprint mismatch — request context changed")
            }
            TokenValidationResult::ContextMismatch => {
                tracing::warn!(
                    session_id = %request.session_id,
                    "local-exec token retry: context mismatch (session/sandbox/agent)"
                );
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

/// Compute the canonical request fingerprint from the fields that uniquely
/// identify a local-exec call within a session/sandbox/agent context.
///
/// This must stay in sync with `compute_request_fingerprint` in
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
    hasher.update(request.sandbox_id.as_bytes());
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn config(action: DefaultAction) -> LocalExecHandlerConfig {
        LocalExecHandlerConfig {
            default_action: action,
            token_ttl: Duration::from_secs(60),
            retry_after_ms: 500,
        }
    }

    fn request() -> LocalExecRequest {
        LocalExecRequest {
            action: "local.exec".to_string(),
            executable: "/usr/bin/python3".to_string(),
            args: vec!["script.py".to_string()],
            sandbox_id: "sbx_1".to_string(),
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
    fn token_retry_succeeds_once() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        assert_eq!(pending.decision, LocalExecDecision::PendingHitl);
        let token = pending.approval_token.unwrap();

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

        let mut retry = request();
        retry.approval_token = Some(token.clone());
        let first = h.decide(&retry);
        assert_eq!(first.decision, LocalExecDecision::Allow);

        retry.approval_token = Some(token);
        let second = h.decide(&retry);
        assert_eq!(second.decision, LocalExecDecision::Deny);
        assert!(
            second
                .reason
                .unwrap_or_default()
                .contains("already consumed")
        );
    }

    #[test]
    fn token_context_mismatch_denied() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();

        let mut retry = request();
        retry.approval_token = Some(token);
        retry.sandbox_id = "sbx_OTHER".to_string();
        let resp = h.decide(&retry);
        assert_eq!(resp.decision, LocalExecDecision::Deny);
    }

    #[test]
    fn client_fingerprint_mismatch_denied() {
        let h = LocalExecHandler::new(config(DefaultAction::PendingHitl));
        let pending = h.decide(&request());
        let token = pending.approval_token.unwrap();

        let mut retry = request();
        retry.approval_token = Some(token);
        retry.request_fingerprint = Some("deadbeef".to_string());
        let resp = h.decide(&retry);
        assert_eq!(resp.decision, LocalExecDecision::Deny);
    }

    #[test]
    fn unknown_action_denied() {
        let h = LocalExecHandler::new(config(DefaultAction::Allow));
        let mut req = request();
        req.action = "network.connect".to_string();
        let resp = h.decide(&req);
        assert_eq!(resp.decision, LocalExecDecision::Deny);
    }
}
