//! Approval token state machine for HITL local-exec governance.
//!
//! The [`TokenStore`] trait defines the contract. Tokens go through:
//!
//! ```text
//! Pending  → Approved   (operator explicitly approves via management API)
//! Pending  → Revoked    (operator explicitly revokes via management API)
//! Pending  → Expired    (TTL elapsed before operator decision)
//! Approved → Consumed   (single successful validate_and_consume call)
//! Approved → Expired    (TTL elapsed before firma-run retried after approval)
//! ```
//!
//! Every property listed in the architecture spec is enforced:
//! - **Short-lived**: tokens carry an absolute expiry.
//! - **Single-use**: the `Consumed` transition is atomic; a second call returns
//!   [`TokenValidationResult::AlreadyConsumed`].
//! - **Server-side tracked**: state lives in the store, never on the wire.
//! - **Context-bound**: each token is bound to the fingerprint, `session_id`,
//!   `sandbox_id`, and optionally `agent_id` that were present at issuance.
//!   Any mismatch returns [`TokenValidationResult::ContextMismatch`] or
//!   [`TokenValidationResult::FingerprintMismatch`].
//! - **Operator-gated**: `Pending` tokens return [`TokenValidationResult::Pending`]
//!   on retry until an operator explicitly approves them. Only
//!   [`TokenState::Approved`] tokens are consumable.
//!
//! The default implementation is [`InMemoryTokenStore`]. Alternative backends
//! (Redis, distributed stores, test doubles) implement [`TokenStore`] and are
//! passed to [`super::handler::LocalExecHandler`] via
//! [`super::handler::LocalExecHandler::with_store`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use firma_runtime_state::SandboxId;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Token state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// Issued and awaiting operator approval — not yet consumable by `firma-run`.
    Pending,
    /// Operator approved; ready for a single consumption by `firma-run`.
    Approved,
    /// Successfully consumed by a `validate_and_consume` call. Terminal.
    Consumed,
    /// TTL elapsed before consumption. Terminal.
    Expired,
    /// Explicitly revoked by an operator before consumption. Terminal.
    Revoked,
}

// ---------------------------------------------------------------------------
// Internal token record
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct HitlToken {
    fingerprint: String,
    session_id: String,
    sandbox_id: SandboxId,
    agent_id: Option<String>,
    expires_at: Instant,
    state: TokenState,
}

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

/// Outcome of a [`TokenStore::validate_and_consume`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValidationResult {
    /// Token is approved, valid, and has been atomically consumed. Caller may proceed.
    Valid,
    /// Token ID not found in the store (unknown or already pruned).
    Unknown,
    /// Token exists but has not yet been approved by an operator. Caller should retry later.
    Pending,
    /// Token TTL elapsed before this call.
    Expired,
    /// Token was already consumed by a prior call (replay attempt).
    AlreadyConsumed,
    /// Token was explicitly revoked by an operator.
    Revoked,
    /// The request fingerprint does not match the one bound at issuance.
    FingerprintMismatch,
    /// `session_id`, `sandbox_id`, or `agent_id` do not match the bound values.
    ContextMismatch,
}

// ---------------------------------------------------------------------------
// Approve / revoke results
// ---------------------------------------------------------------------------

/// Outcome of a [`TokenStore::approve`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveResult {
    /// Token transitioned to `Approved` (or was already `Approved` — idempotent).
    Ok,
    /// Token ID not found.
    NotFound,
    /// Token was already consumed before the approval arrived.
    AlreadyConsumed,
    /// Token was already revoked.
    AlreadyRevoked,
    /// Token expired before the approval arrived.
    Expired,
}

/// Outcome of a [`TokenStore::revoke`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeResult {
    /// Token transitioned to `Revoked` (or was already `Revoked` — idempotent).
    Ok,
    /// Token ID not found.
    NotFound,
    /// Token was already consumed; revocation has no further effect.
    AlreadyConsumed,
    /// Token already expired.
    Expired,
}

// ---------------------------------------------------------------------------
// Token store trait
// ---------------------------------------------------------------------------

/// Contract for an approval token store.
///
/// Implementations must be `Send + Sync` so they can be shared behind an
/// [`Arc`](std::sync::Arc) across connection-handler tasks.
///
/// The default implementation is [`InMemoryTokenStore`]. Custom backends
/// (Redis, distributed stores, test doubles) implement this trait and are
/// passed to [`super::handler::LocalExecHandler::with_store`].
pub trait TokenStore: Send + Sync {
    /// Issue a new approval token in [`TokenState::Pending`] state and return
    /// its opaque ID.
    ///
    /// The token is not consumable until an operator calls [`approve`](Self::approve).
    fn issue(
        &self,
        fingerprint: String,
        session_id: String,
        sandbox_id: SandboxId,
        agent_id: Option<String>,
    ) -> String;

    /// Validate and atomically consume a token.
    ///
    /// Returns [`TokenValidationResult::Valid`] exactly once for a given token,
    /// and only after an operator has approved it. Returns
    /// [`TokenValidationResult::Pending`] while awaiting operator approval.
    /// Every other outcome is a fail-closed denial.
    fn validate_and_consume(
        &self,
        token_id: &str,
        fingerprint: &str,
        session_id: &str,
        sandbox_id: &SandboxId,
        agent_id: Option<&str>,
    ) -> TokenValidationResult;

    /// Approve a pending token, making it consumable by `firma-run`.
    ///
    /// Idempotent: approving an already-[`TokenState::Approved`] token returns
    /// [`ApproveResult::Ok`].
    fn approve(&self, token_id: &str) -> ApproveResult;

    /// Revoke a pending or approved token, preventing any future consumption.
    ///
    /// Idempotent: revoking an already-[`TokenState::Revoked`] token returns
    /// [`RevokeResult::Ok`].
    fn revoke(&self, token_id: &str) -> RevokeResult;

    /// Remove records past their expiry grace window.
    ///
    /// Called periodically by the background pruning task. Backends with
    /// native TTL support (e.g. Redis `EXPIRE`) may leave this as a no-op.
    fn prune_expired(&self) {}
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// In-memory, mutex-protected approval token store.
///
/// Tokens are identified by UUID v4 strings. All state transitions are atomic
/// under the internal [`Mutex`]. There is no external database dependency.
///
/// Call [`TokenStore::prune_expired`] periodically (e.g., from a background
/// task) to reclaim memory. Tokens are retained for a brief grace window after
/// expiry so that the store can distinguish `Expired` from `Unknown` on a late
/// retry.
pub struct InMemoryTokenStore {
    tokens: Mutex<HashMap<String, HitlToken>>,
    ttl: Duration,
    /// Grace window after expiry during which the record is kept so that
    /// late retries receive `Expired` rather than `Unknown`.
    expiry_grace: Duration,
}

/// Lock a mutex, recovering from a poisoned guard rather than panicking.
fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl InMemoryTokenStore {
    /// Create a new store. `ttl` is the lifetime of each issued token.
    #[must_use]
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            ttl,
            expiry_grace: Duration::from_mins(5),
        }
    }

    /// Issue a new approval token in [`TokenState::Pending`] state.
    fn issue(
        &self,
        fingerprint: String,
        session_id: String,
        sandbox_id: SandboxId,
        agent_id: Option<String>,
    ) -> String {
        let token_id = Uuid::new_v4().to_string();
        let token = HitlToken {
            fingerprint,
            session_id,
            sandbox_id,
            agent_id,
            expires_at: Instant::now() + self.ttl,
            state: TokenState::Pending,
        };
        let mut guard = lock_or_recover(&self.tokens);
        guard.insert(token_id.clone(), token);
        token_id
    }

    /// Validate and atomically consume a token.
    ///
    /// Only [`TokenState::Approved`] tokens can be consumed.
    /// [`TokenState::Pending`] tokens return [`TokenValidationResult::Pending`]
    /// so `firma-run` knows to keep polling until the operator approves or the
    /// TTL expires. Context binding is checked for both `Pending` and `Approved`
    /// tokens to fail-close on mismatched retries.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "explicit lock scope keeps token state transitions atomic before returning derived results"
    )]
    fn validate_and_consume(
        &self,
        token_id: &str,
        fingerprint: &str,
        session_id: &str,
        sandbox_id: &SandboxId,
        agent_id: Option<&str>,
    ) -> TokenValidationResult {
        {
            let mut guard = lock_or_recover(&self.tokens);

            let Some(token) = guard.get_mut(token_id) else {
                return TokenValidationResult::Unknown;
            };

            // Terminal states — no further transition possible.
            match token.state {
                TokenState::Consumed => return TokenValidationResult::AlreadyConsumed,
                TokenState::Revoked => return TokenValidationResult::Revoked,
                TokenState::Expired => return TokenValidationResult::Expired,
                TokenState::Pending | TokenState::Approved => {}
            }

            if Instant::now() >= token.expires_at {
                token.state = TokenState::Expired;
                return TokenValidationResult::Expired;
            }

            // Context binding checked for both Pending and Approved.
            if token.fingerprint != fingerprint {
                return TokenValidationResult::FingerprintMismatch;
            }
            if token.session_id != session_id || token.sandbox_id != *sandbox_id {
                return TokenValidationResult::ContextMismatch;
            }
            if let Some(stored_agent) = &token.agent_id
                && agent_id != Some(stored_agent.as_str())
            {
                return TokenValidationResult::ContextMismatch;
            }

            if token.state == TokenState::Pending {
                return TokenValidationResult::Pending;
            }

            // Approved → Consumed (atomic single-use).
            token.state = TokenState::Consumed;
        }
        TokenValidationResult::Valid
    }

    /// Approve a pending token, making it consumable by `firma-run`.
    ///
    /// Idempotent on [`TokenState::Approved`].
    #[expect(
        clippy::significant_drop_tightening,
        reason = "explicit lock scope keeps token state transitions atomic before returning derived results"
    )]
    fn approve(&self, token_id: &str) -> ApproveResult {
        let mut guard = lock_or_recover(&self.tokens);

        let Some(token) = guard.get_mut(token_id) else {
            return ApproveResult::NotFound;
        };

        match token.state {
            TokenState::Pending => {
                if Instant::now() >= token.expires_at {
                    token.state = TokenState::Expired;
                    return ApproveResult::Expired;
                }
                token.state = TokenState::Approved;
                ApproveResult::Ok
            }
            TokenState::Approved => ApproveResult::Ok,
            TokenState::Consumed => ApproveResult::AlreadyConsumed,
            TokenState::Revoked => ApproveResult::AlreadyRevoked,
            TokenState::Expired => ApproveResult::Expired,
        }
    }

    /// Revoke a pending or approved token, preventing any future consumption.
    ///
    /// Idempotent on [`TokenState::Revoked`].
    #[expect(
        clippy::significant_drop_tightening,
        reason = "explicit lock scope keeps token state transitions atomic before returning derived results"
    )]
    fn revoke(&self, token_id: &str) -> RevokeResult {
        let mut guard = lock_or_recover(&self.tokens);

        let Some(token) = guard.get_mut(token_id) else {
            return RevokeResult::NotFound;
        };

        match token.state {
            TokenState::Pending | TokenState::Approved => {
                if Instant::now() >= token.expires_at {
                    token.state = TokenState::Expired;
                    return RevokeResult::Expired;
                }
                token.state = TokenState::Revoked;
                RevokeResult::Ok
            }
            TokenState::Revoked => RevokeResult::Ok,
            TokenState::Consumed => RevokeResult::AlreadyConsumed,
            TokenState::Expired => RevokeResult::Expired,
        }
    }

    /// Remove records that are past their expiry grace window.
    fn prune_expired(&self) {
        let now = Instant::now();
        let mut guard = lock_or_recover(&self.tokens);
        guard
            .retain(|_, token| now.saturating_duration_since(token.expires_at) < self.expiry_grace);
    }

    /// Return the number of live (non-pruned) records. Intended for tests and metrics.
    #[cfg(test)]
    fn len(&self) -> usize {
        lock_or_recover(&self.tokens).len()
    }

    /// Whether the store has no live records. Intended for tests and metrics.
    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock_or_recover(&self.tokens).is_empty()
    }
}

impl TokenStore for InMemoryTokenStore {
    fn issue(
        &self,
        fingerprint: String,
        session_id: String,
        sandbox_id: SandboxId,
        agent_id: Option<String>,
    ) -> String {
        self.issue(fingerprint, session_id, sandbox_id, agent_id)
    }

    fn validate_and_consume(
        &self,
        token_id: &str,
        fingerprint: &str,
        session_id: &str,
        sandbox_id: &SandboxId,
        agent_id: Option<&str>,
    ) -> TokenValidationResult {
        self.validate_and_consume(token_id, fingerprint, session_id, sandbox_id, agent_id)
    }

    fn approve(&self, token_id: &str) -> ApproveResult {
        self.approve(token_id)
    }

    fn revoke(&self, token_id: &str) -> RevokeResult {
        self.revoke(token_id)
    }

    fn prune_expired(&self) {
        self.prune_expired();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox_id() -> SandboxId {
        "sbx_01j0000000e008000000000001"
            .parse()
            .expect("valid sandbox ID fixture")
    }

    fn other_sandbox_id() -> SandboxId {
        "sbx_01j0000000e008000000000002"
            .parse()
            .expect("valid sandbox ID fixture")
    }

    fn store() -> InMemoryTokenStore {
        InMemoryTokenStore::new(Duration::from_mins(1))
    }

    fn issue_token(store: &InMemoryTokenStore) -> String {
        store.issue(
            "fp_abc".to_string(),
            "sess_1".to_string(),
            sandbox_id(),
            Some("agent_1".to_string()),
        )
    }

    #[test]
    fn pending_token_not_consumable_without_approval() {
        let s = store();
        let id = issue_token(&s);
        let result =
            s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(result, TokenValidationResult::Pending);
    }

    #[test]
    fn approved_token_consumed_once() {
        let s = store();
        let id = issue_token(&s);
        assert_eq!(s.approve(&id), ApproveResult::Ok);

        let result =
            s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(result, TokenValidationResult::Valid);

        let result =
            s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(result, TokenValidationResult::AlreadyConsumed);
    }

    #[test]
    fn approve_is_idempotent() {
        let s = store();
        let id = issue_token(&s);
        assert_eq!(s.approve(&id), ApproveResult::Ok);
        assert_eq!(s.approve(&id), ApproveResult::Ok);
    }

    #[test]
    fn revoked_pending_token_denied() {
        let s = store();
        let id = issue_token(&s);
        assert_eq!(s.revoke(&id), RevokeResult::Ok);
        let result =
            s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(result, TokenValidationResult::Revoked);
    }

    #[test]
    fn revoked_approved_token_denied() {
        let s = store();
        let id = issue_token(&s);
        assert_eq!(s.approve(&id), ApproveResult::Ok);
        assert_eq!(s.revoke(&id), RevokeResult::Ok);
        let result =
            s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(result, TokenValidationResult::Revoked);
    }

    #[test]
    fn revoke_is_idempotent() {
        let s = store();
        let id = issue_token(&s);
        assert_eq!(s.revoke(&id), RevokeResult::Ok);
        assert_eq!(s.revoke(&id), RevokeResult::Ok);
    }

    #[test]
    fn revoke_consumed_token_returns_already_consumed() {
        let s = store();
        let id = issue_token(&s);
        s.approve(&id);
        s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(s.revoke(&id), RevokeResult::AlreadyConsumed);
    }

    #[test]
    fn approve_consumed_token_returns_already_consumed() {
        let s = store();
        let id = issue_token(&s);
        s.approve(&id);
        s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(s.approve(&id), ApproveResult::AlreadyConsumed);
    }

    #[test]
    fn approve_revoked_token_returns_already_revoked() {
        let s = store();
        let id = issue_token(&s);
        s.revoke(&id);
        assert_eq!(s.approve(&id), ApproveResult::AlreadyRevoked);
    }

    #[test]
    fn unknown_token_rejected() {
        let s = store();
        let result = s.validate_and_consume("no-such-token", "fp", "sess", &sandbox_id(), None);
        assert_eq!(result, TokenValidationResult::Unknown);
    }

    #[test]
    fn unknown_token_approve_returns_not_found() {
        let s = store();
        assert_eq!(s.approve("no-such-token"), ApproveResult::NotFound);
    }

    #[test]
    fn unknown_token_revoke_returns_not_found() {
        let s = store();
        assert_eq!(s.revoke("no-such-token"), RevokeResult::NotFound);
    }

    #[test]
    fn expired_token_rejected() {
        let s = InMemoryTokenStore::new(Duration::ZERO);
        let id = issue_token(&s);
        std::thread::sleep(Duration::from_millis(1));
        let result =
            s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(result, TokenValidationResult::Expired);
    }

    #[test]
    fn fingerprint_mismatch_rejected() {
        let s = store();
        let id = issue_token(&s);
        let result =
            s.validate_and_consume(&id, "fp_WRONG", "sess_1", &sandbox_id(), Some("agent_1"));
        assert_eq!(result, TokenValidationResult::FingerprintMismatch);
    }

    #[test]
    fn session_mismatch_rejected() {
        let s = store();
        let id = issue_token(&s);
        let result =
            s.validate_and_consume(&id, "fp_abc", "sess_WRONG", &sandbox_id(), Some("agent_1"));
        assert_eq!(result, TokenValidationResult::ContextMismatch);
    }

    #[test]
    fn sandbox_mismatch_rejected() {
        let s = store();
        let id = issue_token(&s);
        let result = s.validate_and_consume(
            &id,
            "fp_abc",
            "sess_1",
            &other_sandbox_id(),
            Some("agent_1"),
        );
        assert_eq!(result, TokenValidationResult::ContextMismatch);
    }

    #[test]
    fn agent_mismatch_rejected() {
        let s = store();
        let id = issue_token(&s);
        let result =
            s.validate_and_consume(&id, "fp_abc", "sess_1", &sandbox_id(), Some("agent_WRONG"));
        assert_eq!(result, TokenValidationResult::ContextMismatch);
    }

    #[test]
    fn token_without_agent_id_validates_without_agent() {
        let s = store();
        let id = s.issue("fp".to_string(), "sess".to_string(), sandbox_id(), None);
        s.approve(&id);
        let result = s.validate_and_consume(&id, "fp", "sess", &sandbox_id(), None);
        assert_eq!(result, TokenValidationResult::Valid);
    }

    #[test]
    fn prune_removes_fully_expired_records() {
        let s = InMemoryTokenStore {
            tokens: std::sync::Mutex::new(HashMap::new()),
            ttl: Duration::ZERO,
            expiry_grace: Duration::ZERO,
        };
        let _ = issue_token(&s);
        std::thread::sleep(Duration::from_millis(1));
        s.prune_expired();
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn prune_retains_live_tokens() {
        let s = store();
        let _ = issue_token(&s);
        s.prune_expired();
        assert_eq!(s.len(), 1);
    }
}
