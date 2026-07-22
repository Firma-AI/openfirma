//! Per-session runtime state for Stage 2 quantitative constraint enforcement.
//!
//! V1 stores action count and `risk_score` per `SessionId`. Storage is
//! in-memory with LRU eviction by default; a
//! file-backed persistent backend is available via
//! [`crate::enforcement::session::PersistentSessionStateStore`]
//! (selected by `constraint_enforcement.session_state_backend = "persistent"`).
//!
//! The default in-memory store (`LruSessionStateStore`) evicts the
//! least-recently-used session when capacity is exceeded, resetting an
//! evicted session's counters on next access. Since Cedar policies in V1
//! are monotone (`action_count > N` denies as count grows), eviction can
//! only move a denying session back toward allowing — acceptable for V1
//! scope. The capacity is configurable via
//! `constraint_enforcement.session_state_capacity`; the persistent backend
//! preserves state across eviction and restart.

use std::num::NonZeroUsize;
use std::sync::Mutex;

use firma_core::SessionId;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Categorical outcome of an evaluated action, recorded into a session's
/// prior-action history so later decisions can observe what the agent has
/// already done (AARM R2 G3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// Request authorized and dispatched.
    Allow,
    /// Request authorized with a modification applied before dispatch.
    Modify,
    /// Request denied by policy or scope check.
    Deny,
    /// Request blocked pending human approval / stronger auth.
    StepUp,
    /// Request deferred pending additional context.
    Defer,
    /// Request was authorized then aborted (e.g. credential injection failed).
    Abort,
}

/// One entry in the bounded prior-action history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionOutcome {
    /// Canonical action class of the evaluated action.
    pub action_class: String,
    /// Resource display string (`host` + `path`) of the evaluated action.
    pub resource: String,
    /// Categorical decision outcome.
    pub outcome: Outcome,
}

/// Maximum number of prior-action outcomes retained per session. Bounded
/// to keep the hot path deterministic and memory growth capped (AARM R2 G3).
pub(crate) const HISTORY_CAP: usize = 8;

/// Runtime signals sourced from the session store and passed into
/// Stage 2 for Cedar context construction.
///
/// Built by the pipeline on every admitted request, used by
/// `ConstraintEnforcer::build_context()` and then reused to populate
/// the outgoing `ExecutionMetadata` so audit and enforcement see the
/// same numbers. Carries the bounded prior-action history so policies
/// can reason about what the session has already attempted.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RuntimeSignals {
    /// Number of calls observed in the current session, including this
    /// one. First call in a session is 1.
    pub action_count: u64,
    /// Static or pre-computed numeric risk attribute. V1 placeholder
    /// = 0.0.
    pub risk_score: f64,
    /// Cumulative number of denied actions in this session (AARM R2 G3).
    pub deny_count: u64,
    /// Bounded prior-action history (most recent first appended); the
    /// Cedar context derives `prior_action_classes` and `last_resource`
    /// from it.
    pub history: Vec<ActionOutcome>,
    /// Most recent provenance chain anchor from the prior admitted
    /// action (AARM R2 G2). `None` when no prior action has been admitted
    /// yet. Read BEFORE `advance_provenance` to capture the parent action
    /// id for the current envelope.
    pub last_provenance: Option<String>,
}

impl RuntimeSignals {
    /// `risk_score` as a Cedar `Long` — floor-rounded.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "conversion intentionally floors risk score into Cedar Long semantics"
    )]
    pub fn risk_score_long(&self) -> i64 {
        // Fail-closed: NaN risk collapses to the most-positive Long so
        // `context.risk_score > N` policies always deny.
        if self.risk_score.is_nan() {
            return i64::MAX;
        }
        self.risk_score.floor() as i64
    }
}

/// Per-session runtime state used by Stage 2.
///
/// Implementations must be `Send + Sync` — the pipeline holds them in
/// an `Arc` and every request reads/writes through a shared reference.
pub trait SessionStateStore: Send + Sync {
    /// Record an admitted call for `session_id` and return the new
    /// action count (1 for the first call in a session).
    fn record_action(&self, session_id: &SessionId) -> u64;

    /// Read the current signals for `session_id`. Returns defaults
    /// (all zeros, empty history) if the session is unknown.
    fn signals(&self, session_id: &SessionId) -> RuntimeSignals;

    /// Record the outcome of the just-evaluated action into the
    /// session's bounded prior-action history (AARM R2 G3). Called
    /// after the decision is known so subsequent calls see prior
    /// action classes, resources, and deny outcomes. Does NOT affect
    /// the current decision (no feedback), preserving determinism.
    fn record_outcome(
        &self,
        session_id: &SessionId,
        action_class: &str,
        resource: &str,
        outcome: Outcome,
    );

    /// Advance the session's tamper-evident provenance chain (AARM R2 G2)
    /// and return the new anchor. The new value is
    /// `hex(SHA256(prev || context_hash || action_class || resource))`,
    /// where `prev` is the session's previous provenance (empty for the
    /// first admitted action). Stored as the session's `last_provenance`
    /// so the next admitted action chains to it. Called on the admitted
    /// (Allow/Modify) path only; denied/deferred actions do not extend
    /// the provenance chain. Returns an empty string if the store is
    /// unavailable (graceful degradation — provenance is attestational,
    /// not policy-binding).
    fn advance_provenance(
        &self,
        session_id: &SessionId,
        context_hash: &str,
        action_class: &str,
        resource: &str,
    ) -> String;
}

/// Compute the next provenance anchor from the previous one and the
/// current action's binding fields. Deterministic and side-effect-free;
/// callers persist the result as the session's `last_provenance`.
#[must_use]
pub(crate) fn next_provenance(
    prev: Option<&str>,
    context_hash: &str,
    action_class: &str,
    resource: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev.unwrap_or("").as_bytes());
    hasher.update(b"\n");
    hasher.update(context_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(action_class.as_bytes());
    hasher.update(b"\n");
    hasher.update(resource.as_bytes());
    hex::encode(hasher.finalize())
}

/// Default capacity — 8192 active sessions per sidecar process. Tuned
/// for V1 single-process deployments; overridable via
/// `constraint_enforcement.session_state_capacity` in `firma.toml`.
const DEFAULT_CAPACITY: usize = 8192;

/// In-memory LRU-capped `SessionStateStore` for V1. Single-process only.
pub struct LruSessionStateStore {
    inner: Mutex<LruCache<SessionId, SessionRecord>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub(crate) struct SessionRecord {
    pub(crate) action_count: u64,
    pub(crate) risk_score: f64,
    pub(crate) deny_count: u64,
    pub(crate) history: Vec<ActionOutcome>,
    /// Anchor of the most recent admitted action's provenance chain
    /// (AARM R2 G2). `None` until the first Allow/Modify. Forwarded to
    /// the next admitted action so the chain links prior calls.
    #[serde(default)]
    pub(crate) last_provenance: Option<String>,
}

impl SessionRecord {
    /// Append an outcome to the bounded history, evicting the oldest
    /// entry when the cap is exceeded (FIFO ring).
    pub(crate) fn push_outcome(
        &mut self,
        action_class: String,
        resource: String,
        outcome: Outcome,
    ) {
        if matches!(outcome, Outcome::Deny) {
            self.deny_count = self.deny_count.saturating_add(1);
        }
        if self.history.len() >= HISTORY_CAP {
            self.history.remove(0);
        }
        self.history.push(ActionOutcome {
            action_class,
            resource,
            outcome,
        });
    }
}

impl LruSessionStateStore {
    /// Construct with an explicit capacity (minimum 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Construct with the default capacity (`DEFAULT_CAPACITY`).
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl Default for LruSessionStateStore {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

impl SessionStateStore for LruSessionStateStore {
    fn record_action(&self, session_id: &SessionId) -> u64 {
        let Ok(mut guard) = self.inner.lock() else {
            // Mutex poisoned — treat as a fresh call. Stage 2 will
            // still fail-closed if policies require higher counts.
            return 1;
        };
        let record = guard.get_or_insert_mut(session_id.clone(), SessionRecord::default);
        record.action_count = record.action_count.saturating_add(1);
        record.action_count
    }

    fn signals(&self, session_id: &SessionId) -> RuntimeSignals {
        let Ok(guard) = self.inner.lock() else {
            return RuntimeSignals::default();
        };
        guard
            .peek(session_id)
            .map_or_else(RuntimeSignals::default, |r| RuntimeSignals {
                action_count: r.action_count,
                risk_score: r.risk_score,
                deny_count: r.deny_count,
                history: r.history.clone(),
                last_provenance: r.last_provenance.clone(),
            })
    }

    fn record_outcome(
        &self,
        session_id: &SessionId,
        action_class: &str,
        resource: &str,
        outcome: Outcome,
    ) {
        let Ok(mut guard) = self.inner.lock() else {
            // Mutex poisoned — best-effort: skip recording. The in-memory
            // state is unavailable, consistent with the other methods.
            return;
        };
        let record = guard.get_or_insert_mut(session_id.clone(), SessionRecord::default);
        record.push_outcome(action_class.to_string(), resource.to_string(), outcome);
    }

    fn advance_provenance(
        &self,
        session_id: &SessionId,
        context_hash: &str,
        action_class: &str,
        resource: &str,
    ) -> String {
        let Ok(mut guard) = self.inner.lock() else {
            // Mutex poisoned — return empty (attestational, not policy-binding).
            return String::new();
        };
        let record = guard.get_or_insert_mut(session_id.clone(), SessionRecord::default);
        let new = next_provenance(
            record.last_provenance.as_deref(),
            context_hash,
            action_class,
            resource,
        );
        record.last_provenance = Some(new.clone());
        new
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::float_cmp)]
    use super::*;
    use firma_core::SessionId;

    fn sid(s: &str) -> SessionId {
        s.parse().expect("valid session id")
    }

    #[test]
    fn record_action_returns_monotonic_count() {
        let store = LruSessionStateStore::new(16);
        assert_eq!(store.record_action(&sid("sess_a")), 1);
        assert_eq!(store.record_action(&sid("sess_a")), 2);
        assert_eq!(store.record_action(&sid("sess_a")), 3);
    }

    #[test]
    fn record_action_isolates_sessions() {
        let store = LruSessionStateStore::new(16);
        assert_eq!(store.record_action(&sid("sess_a")), 1);
        assert_eq!(store.record_action(&sid("sess_b")), 1);
        assert_eq!(store.record_action(&sid("sess_a")), 2);
    }

    #[test]
    fn runtime_signals_defaults_for_unknown_session() {
        let store = LruSessionStateStore::new(16);
        let signals = store.signals(&sid("never_seen"));
        assert_eq!(signals.action_count, 0);
        assert_eq!(signals.risk_score, 0.0);
    }

    #[test]
    fn runtime_signals_reflects_recorded_actions() {
        let store = LruSessionStateStore::new(16);
        store.record_action(&sid("sess_a"));
        store.record_action(&sid("sess_a"));
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.action_count, 2);
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let store = LruSessionStateStore::new(2);
        store.record_action(&sid("sess_a"));
        store.record_action(&sid("sess_b"));
        store.record_action(&sid("sess_c")); // evicts sess_a
        // sess_a re-inserts at count 1
        assert_eq!(store.record_action(&sid("sess_a")), 1);
    }

    #[test]
    fn risk_score_nan_fails_closed() {
        let signals = RuntimeSignals {
            action_count: 0,
            risk_score: f64::NAN,
            ..RuntimeSignals::default()
        };
        assert_eq!(signals.risk_score_long(), i64::MAX);
    }

    #[test]
    fn lru_session_state_store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LruSessionStateStore>();
    }

    // -- Prior-action history (AARM R2 G3) ----------------------------------

    #[test]
    fn record_outcome_appends_to_history() {
        let store = LruSessionStateStore::new(16);
        store.record_action(&sid("sess_a"));
        store.record_outcome(
            &sid("sess_a"),
            "communication.external.send",
            "api.example.com/",
            Outcome::Allow,
        );
        store.record_outcome(&sid("sess_a"), "filesystem.delete", "host/x", Outcome::Deny);
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.history.len(), 2);
        assert_eq!(
            signals.history[0].action_class,
            "communication.external.send"
        );
        assert_eq!(signals.history[0].outcome, Outcome::Allow);
        assert_eq!(signals.history[1].outcome, Outcome::Deny);
        assert_eq!(signals.deny_count, 1);
    }

    #[test]
    fn deny_count_accumulates_only_denials() {
        let store = LruSessionStateStore::new(16);
        store.record_action(&sid("sess_a"));
        store.record_outcome(&sid("sess_a"), "a", "r", Outcome::Allow);
        store.record_outcome(&sid("sess_a"), "b", "r", Outcome::Deny);
        store.record_outcome(&sid("sess_a"), "c", "r", Outcome::StepUp);
        store.record_outcome(&sid("sess_a"), "d", "r", Outcome::Deny);
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.deny_count, 2);
    }

    #[test]
    fn history_is_bounded_to_cap() {
        let store = LruSessionStateStore::new(16);
        store.record_action(&sid("sess_a"));
        // Push more than HISTORY_CAP entries; the oldest must be evicted.
        for i in 0..(HISTORY_CAP + 3) {
            let class = format!("action{i}");
            store.record_outcome(&sid("sess_a"), &class, "r", Outcome::Allow);
        }
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.history.len(), HISTORY_CAP);
        // First three (action0..action2) evicted; action3 is now the head.
        assert_eq!(signals.history[0].action_class, "action3");
        assert_eq!(
            signals.history[HISTORY_CAP - 1].action_class,
            format!("action{}", HISTORY_CAP + 2)
        );
    }

    #[test]
    fn record_outcome_isolates_sessions() {
        let store = LruSessionStateStore::new(16);
        store.record_action(&sid("sess_a"));
        store.record_action(&sid("sess_b"));
        store.record_outcome(&sid("sess_a"), "a", "r", Outcome::Deny);
        let a = store.signals(&sid("sess_a"));
        let b = store.signals(&sid("sess_b"));
        assert_eq!(a.deny_count, 1);
        assert_eq!(a.history.len(), 1);
        assert_eq!(b.deny_count, 0);
        assert!(b.history.is_empty());
    }

    #[test]
    fn unknown_session_signals_have_empty_history() {
        let store = LruSessionStateStore::new(16);
        let signals = store.signals(&sid("never_seen"));
        assert_eq!(signals.deny_count, 0);
        assert!(signals.history.is_empty());
    }
}
