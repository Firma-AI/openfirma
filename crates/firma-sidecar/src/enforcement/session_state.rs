//! Per-session runtime state for Stage 2 quantitative constraint enforcement.
//!
//! V1 stores three signals per `SessionId`: action count (monotonic
//! counter incremented on every admitted request), `budget_consumed`
//! (cumulative, placeholder 0.0 in V1), `risk_score` (placeholder 0.0 in
//! V1). Storage is in-memory with LRU eviction — V1 runs single-process.
//!
//! Eviction resets an evicted session's counters on next access. Since
//! Cedar policies in V1 are monotone (`action_count > N` denies as count
//! grows), eviction can only move a denying session back toward allowing
//! — acceptable for V1 scope. Document when this is upgraded to a
//! persistent or cluster-shared store.

use std::num::NonZeroUsize;
use std::sync::Mutex;

use firma_core::SessionId;
use lru::LruCache;

/// Runtime signals sourced from the session store and passed into
/// Stage 2 for Cedar context construction.
///
/// Built by the pipeline on every admitted request, used by
/// `ConstraintEnforcer::build_context()` and then reused to populate
/// the outgoing `ExecutionMetadata` so audit and enforcement see the
/// same numbers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeSignals {
    /// Number of calls observed in the current session, including this
    /// one. First call in a session is 1.
    pub action_count: u64,
    /// Cumulative budget used in this session. V1 placeholder = 0.0.
    pub budget_consumed: f64,
    /// Static or pre-computed numeric risk attribute. V1 placeholder
    /// = 0.0.
    pub risk_score: f64,
}

impl RuntimeSignals {
    /// Compute `budget_remaining` as a Cedar `Long` (i64). `None`
    /// ceiling means unbounded → emit `i64::MAX`. Otherwise emit
    /// `floor(ceiling - budget_consumed)` clamped to `i64`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn budget_remaining_long(&self, ceiling: Option<f64>) -> i64 {
        let Some(ceiling) = ceiling else {
            return i64::MAX;
        };
        // Fail-closed: any NaN input collapses to the most-negative Long
        // so `context.budget_remaining < N` policies always deny.
        if ceiling.is_nan() || self.budget_consumed.is_nan() {
            return i64::MIN;
        }
        let remaining = (ceiling - self.budget_consumed).floor();
        if remaining >= i64::MAX as f64 {
            i64::MAX
        } else if remaining <= i64::MIN as f64 {
            i64::MIN
        } else {
            remaining as i64
        }
    }

    /// `risk_score` as a Cedar `Long` — floor-rounded.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
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
    /// (all zeros) if the session is unknown.
    fn signals(&self, session_id: &SessionId) -> RuntimeSignals;
}

/// Default capacity — 8192 active sessions per sidecar process. Tuned
/// for V1 single-process deployments; make configurable if needed.
const DEFAULT_CAPACITY: usize = 8192;

/// In-memory LRU-capped `SessionStateStore` for V1. Single-process only.
pub struct LruSessionStateStore {
    inner: Mutex<LruCache<SessionId, SessionRecord>>,
}

#[derive(Debug, Clone, Copy)]
struct SessionRecord {
    action_count: u64,
    budget_consumed: f64,
    risk_score: f64,
}

impl SessionRecord {
    const fn zero() -> Self {
        Self {
            action_count: 0,
            budget_consumed: 0.0,
            risk_score: 0.0,
        }
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
        let record = guard.get_or_insert_mut(session_id.clone(), SessionRecord::zero);
        record.action_count = record.action_count.saturating_add(1);
        record.action_count
    }

    fn signals(&self, session_id: &SessionId) -> RuntimeSignals {
        let Ok(guard) = self.inner.lock() else {
            return RuntimeSignals {
                action_count: 0,
                budget_consumed: 0.0,
                risk_score: 0.0,
            };
        };
        guard.peek(session_id).map_or(
            RuntimeSignals {
                action_count: 0,
                budget_consumed: 0.0,
                risk_score: 0.0,
            },
            |r| RuntimeSignals {
                action_count: r.action_count,
                budget_consumed: r.budget_consumed,
                risk_score: r.risk_score,
            },
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
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
        assert_eq!(signals.budget_consumed, 0.0);
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
    fn runtime_signals_remaining_unbounded_when_ceiling_none() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 0.0,
            risk_score: 0.0,
        };
        assert_eq!(signals.budget_remaining_long(None), i64::MAX);
    }

    #[test]
    fn runtime_signals_remaining_subtracts_consumed_and_floors() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 12.75,
            risk_score: 0.0,
        };
        assert_eq!(signals.budget_remaining_long(Some(100.0)), 87);
    }

    #[test]
    fn runtime_signals_remaining_goes_negative_when_overspent() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 150.0,
            risk_score: 0.0,
        };
        assert_eq!(signals.budget_remaining_long(Some(100.0)), -50);
    }

    #[test]
    fn budget_remaining_nan_ceiling_fails_closed() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 0.0,
            risk_score: 0.0,
        };
        assert_eq!(signals.budget_remaining_long(Some(f64::NAN)), i64::MIN);
    }

    #[test]
    fn budget_remaining_nan_consumed_fails_closed() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: f64::NAN,
            risk_score: 0.0,
        };
        assert_eq!(signals.budget_remaining_long(Some(100.0)), i64::MIN);
    }

    #[test]
    fn risk_score_nan_fails_closed() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 0.0,
            risk_score: f64::NAN,
        };
        assert_eq!(signals.risk_score_long(), i64::MAX);
    }

    #[test]
    fn lru_session_state_store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LruSessionStateStore>();
    }
}
