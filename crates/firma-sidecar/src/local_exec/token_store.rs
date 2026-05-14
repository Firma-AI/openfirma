//! Approval token state machine for HITL local-exec governance.
//!
//! A token issued by [`InMemoryTokenStore::issue`] goes through these states:
//!
//! ```text
//! Pending → Consumed  (single successful validate_and_consume call)
//! Pending → Expired   (TTL elapsed before consumption)
//! ```
//!
//! Every property listed in the architecture spec is enforced:
//! - **Short-lived**: tokens carry an absolute `expires_at` instant.
//! - **Single-use**: the state transition to `Consumed` is atomic under the
//!   store's internal mutex; a second call on the same token returns
//!   [`TokenValidationResult::AlreadyConsumed`].
//! - **Server-side tracked**: state lives in process memory, never on the wire.
//! - **Context-bound**: each token is bound to the fingerprint, `session_id`,
//!   `sandbox_id`, and optionally `agent_id` that were present at issuance time.
//!   Any mismatch returns [`TokenValidationResult::ContextMismatch`] or
//!   [`TokenValidationResult::FingerprintMismatch`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

// ---------------------------------------------------------------------------
// Token state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    Pending,
    Consumed,
    Expired,
}

// ---------------------------------------------------------------------------
// Internal token record
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct HitlToken {
    fingerprint: String,
    session_id: String,
    sandbox_id: String,
    agent_id: Option<String>,
    expires_at: Instant,
    state: TokenState,
}

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

/// Outcome of a [`InMemoryTokenStore::validate_and_consume`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValidationResult {
    /// Token is valid; has been atomically consumed. Caller may proceed.
    Valid,
    /// Token ID not found in the store (unknown or already pruned).
    Unknown,
    /// Token TTL elapsed before this call.
    Expired,
    /// Token was already consumed by a prior call (replay attempt).
    AlreadyConsumed,
    /// The request fingerprint does not match the one bound at issuance.
    FingerprintMismatch,
    /// `session_id`, `sandbox_id`, or `agent_id` do not match the bound values.
    ContextMismatch,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// In-memory, mutex-protected approval token store.
///
/// Tokens are identified by UUID v4 strings. All state transitions are atomic
/// under the internal [`Mutex`]. There is no external database dependency.
///
/// Call [`InMemoryTokenStore::prune_expired`] periodically (e.g., from a
/// background task) to reclaim memory. Tokens are retained for a brief grace
/// window after expiry so that the store can distinguish `Expired` from
/// `Unknown` on a late retry.
pub struct InMemoryTokenStore {
    tokens: Mutex<HashMap<String, HitlToken>>,
    ttl: Duration,
    /// Grace window after expiry during which the record is kept so that
    /// late retries receive `Expired` rather than `Unknown`.
    expiry_grace: Duration,
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl InMemoryTokenStore {
    /// Create a new store. `ttl` is the lifetime of each issued token.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            ttl,
            expiry_grace: Duration::from_secs(300),
        }
    }

    /// Issue a new approval token bound to the given context.
    ///
    /// Returns the opaque token ID string to be sent to the caller. The token
    /// is `Pending` and valid for `ttl` seconds from now.
    pub fn issue(
        &self,
        fingerprint: String,
        session_id: String,
        sandbox_id: String,
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
    /// On [`TokenValidationResult::Valid`] the token transitions to `Consumed`
    /// and the caller may proceed with execution. Every other result is a
    /// fail-closed denial.
    pub fn validate_and_consume(
        &self,
        token_id: &str,
        fingerprint: &str,
        session_id: &str,
        sandbox_id: &str,
        agent_id: Option<&str>,
    ) -> TokenValidationResult {
        let mut guard = lock_or_recover(&self.tokens);

        let Some(token) = guard.get_mut(token_id) else {
            return TokenValidationResult::Unknown;
        };

        if token.state == TokenState::Consumed {
            return TokenValidationResult::AlreadyConsumed;
        }

        if Instant::now() >= token.expires_at {
            token.state = TokenState::Expired;
            return TokenValidationResult::Expired;
        }

        // Context binding — all must match exactly.
        if token.fingerprint != fingerprint {
            return TokenValidationResult::FingerprintMismatch;
        }
        if token.session_id != session_id || token.sandbox_id != sandbox_id {
            return TokenValidationResult::ContextMismatch;
        }
        if let Some(stored_agent) = &token.agent_id {
            if agent_id != Some(stored_agent.as_str()) {
                return TokenValidationResult::ContextMismatch;
            }
        }

        // Atomic single-use consumption.
        token.state = TokenState::Consumed;
        TokenValidationResult::Valid
    }

    /// Remove records that are past their expiry grace window.
    ///
    /// Safe to call from a background task at any interval; the mutex is held
    /// only during the retain scan.
    pub fn prune_expired(&self) {
        let now = Instant::now();
        let mut guard = lock_or_recover(&self.tokens);
        // Retain tokens that are still within the expiry grace window.
        // `saturating_duration_since` returns 0 for unexpired tokens, so
        // they are always kept; expired tokens are kept until the grace
        // window elapses to allow `Expired` to be returned instead of `Unknown`.
        guard.retain(|_, token| now.saturating_duration_since(token.expires_at) < self.expiry_grace);
    }

    /// Return the number of live (non-pruned) records. Intended for tests and
    /// metrics.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        lock_or_recover(&self.tokens).len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn store() -> InMemoryTokenStore {
        InMemoryTokenStore::new(Duration::from_secs(60))
    }

    fn issue_token(store: &InMemoryTokenStore) -> String {
        store.issue(
            "fp_abc".to_string(),
            "sess_1".to_string(),
            "sbx_1".to_string(),
            Some("agent_1".to_string()),
        )
    }

    #[test]
    fn valid_token_consumed_once() {
        let s = store();
        let id = issue_token(&s);

        let result = s.validate_and_consume(&id, "fp_abc", "sess_1", "sbx_1", Some("agent_1"));
        assert_eq!(result, TokenValidationResult::Valid);

        // Second call must be rejected — single-use.
        let result = s.validate_and_consume(&id, "fp_abc", "sess_1", "sbx_1", Some("agent_1"));
        assert_eq!(result, TokenValidationResult::AlreadyConsumed);
    }

    #[test]
    fn unknown_token_rejected() {
        let s = store();
        let result = s.validate_and_consume("no-such-token", "fp", "sess", "sbx", None);
        assert_eq!(result, TokenValidationResult::Unknown);
    }

    #[test]
    fn expired_token_rejected() {
        let s = InMemoryTokenStore::new(Duration::ZERO);
        let id = issue_token(&s);
        // Even with zero TTL the token expires at Instant::now() + ZERO, which
        // may already be in the past by the time validate_and_consume runs.
        // Sleep 1ms to ensure expiry.
        std::thread::sleep(Duration::from_millis(1));
        let result = s.validate_and_consume(&id, "fp_abc", "sess_1", "sbx_1", Some("agent_1"));
        assert_eq!(result, TokenValidationResult::Expired);
    }

    #[test]
    fn fingerprint_mismatch_rejected() {
        let s = store();
        let id = issue_token(&s);
        let result = s.validate_and_consume(&id, "fp_WRONG", "sess_1", "sbx_1", Some("agent_1"));
        assert_eq!(result, TokenValidationResult::FingerprintMismatch);
    }

    #[test]
    fn session_mismatch_rejected() {
        let s = store();
        let id = issue_token(&s);
        let result = s.validate_and_consume(&id, "fp_abc", "sess_WRONG", "sbx_1", Some("agent_1"));
        assert_eq!(result, TokenValidationResult::ContextMismatch);
    }

    #[test]
    fn sandbox_mismatch_rejected() {
        let s = store();
        let id = issue_token(&s);
        let result = s.validate_and_consume(&id, "fp_abc", "sess_1", "sbx_WRONG", Some("agent_1"));
        assert_eq!(result, TokenValidationResult::ContextMismatch);
    }

    #[test]
    fn agent_mismatch_rejected() {
        let s = store();
        let id = issue_token(&s);
        let result = s.validate_and_consume(&id, "fp_abc", "sess_1", "sbx_1", Some("agent_WRONG"));
        assert_eq!(result, TokenValidationResult::ContextMismatch);
    }

    #[test]
    fn token_without_agent_id_validates_without_agent() {
        let s = store();
        let id = s.issue(
            "fp".to_string(),
            "sess".to_string(),
            "sbx".to_string(),
            None,
        );
        let result = s.validate_and_consume(&id, "fp", "sess", "sbx", None);
        assert_eq!(result, TokenValidationResult::Valid);
    }

    #[test]
    fn prune_removes_fully_expired_records() {
        let s = InMemoryTokenStore {
            tokens: Mutex::new(HashMap::new()),
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
