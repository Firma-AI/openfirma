//! Per-session runtime state for Stage 2 quantitative constraint enforcement.
//!
//! V1 stores per `SessionId`: action count (monotonic counter incremented on
//! every admitted request), `budget_consumed` (cumulative, updated after every
//! ALLOW), `risk_score` (placeholder 0.0 in V1), `session_transfer_count`
//! (total transfers in the session), and a per-payee timestamp log used to
//! compute `same_payee_count_30m`.
//!
//! Storage is in-memory with LRU eviction — V1 runs single-process.
//!
//! Eviction resets an evicted session's counters on next access. Since
//! Cedar policies in V1 are monotone (`action_count > N` denies as count
//! grows), eviction can only move a denying session back toward allowing
//! — acceptable for V1 scope. Document when this is upgraded to a
//! persistent or cluster-shared store.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use firma_core::SessionId;
use lru::LruCache;

/// Window used for `same_payee_count_30m` queries.
pub const PAYEE_WINDOW: Duration = Duration::from_secs(30 * 60);
/// Window used for transfer velocity checks.
pub const TRANSFER_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Window used for daily cumulative amount checks.
pub const DAILY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

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
    /// Cumulative budget used in this session. Incremented after each ALLOW.
    pub budget_consumed: f64,
    /// Static or pre-computed numeric risk attribute. V1 placeholder = 0.0.
    pub risk_score: f64,
    /// Total number of transfer-type actions admitted in this session.
    pub session_transfer_count: u64,
    /// Amount of the current transfer in cents; zero for non-transfer actions.
    pub transfer_amount: i64,
    /// Prior admitted transfer amount total in the daily window, in cents.
    pub daily_cumulative_amount: i64,
    /// Prior admitted transfer count in the 10-minute window.
    pub transfers_last_10m: u64,
    /// Prior admitted transfer count to the same payee in the 30-minute window.
    pub same_payee_count_30m: u64,
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

    /// Add `cost` to the cumulative `budget_consumed` for `session_id`.
    /// Called after each ALLOW so the next call's budget check sees the
    /// updated spend.
    fn add_budget_cost(&self, session_id: &SessionId, cost: f64);

    /// Record an admitted transfer-type action for `session_id` toward
    /// `payee` at time `at`.
    fn record_transfer(&self, session_id: &SessionId, payee: &str, amount: i64, at: Instant);

    /// Count transfer-type actions toward `payee` within `window` of `now`
    /// for `session_id`. Used to populate `same_payee_count_30m` in Cedar
    /// context.
    fn same_payee_count(
        &self,
        session_id: &SessionId,
        payee: &str,
        now: Instant,
        window: Duration,
    ) -> u64;

    /// Sum transfer amounts within `window` of `now` for `session_id`.
    fn cumulative_transfer_amount(
        &self,
        session_id: &SessionId,
        now: Instant,
        window: Duration,
    ) -> i64;

    /// Count transfer actions within `window` of `now` for `session_id`.
    fn transfer_count_in_window(
        &self,
        session_id: &SessionId,
        now: Instant,
        window: Duration,
    ) -> u64;
}

/// Default capacity — 8192 active sessions per sidecar process. Tuned
/// for V1 single-process deployments; make configurable if needed.
const DEFAULT_CAPACITY: usize = 8192;

/// In-memory LRU-capped `SessionStateStore` for V1. Single-process only.
pub struct LruSessionStateStore {
    inner: Mutex<LruCache<SessionId, SessionRecord>>,
}

#[derive(Debug)]
struct SessionRecord {
    action_count: u64,
    budget_consumed: f64,
    risk_score: f64,
    session_transfer_count: u64,
    transfers: Vec<TransferRecord>,
}

#[derive(Debug, Clone)]
struct TransferRecord {
    payee: String,
    amount: i64,
    at: Instant,
}

impl SessionRecord {
    fn zero() -> Self {
        Self {
            action_count: 0,
            budget_consumed: 0.0,
            risk_score: 0.0,
            session_transfer_count: 0,
            transfers: Vec::new(),
        }
    }
}

fn signal_defaults() -> RuntimeSignals {
    RuntimeSignals {
        action_count: 0,
        budget_consumed: 0.0,
        risk_score: 0.0,
        session_transfer_count: 0,
        transfer_amount: 0,
        daily_cumulative_amount: 0,
        transfers_last_10m: 0,
        same_payee_count_30m: 0,
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
            return signal_defaults();
        };
        guard
            .peek(session_id)
            .map_or(signal_defaults(), |r| RuntimeSignals {
                action_count: r.action_count,
                budget_consumed: r.budget_consumed,
                risk_score: r.risk_score,
                session_transfer_count: r.session_transfer_count,
                transfer_amount: 0,
                daily_cumulative_amount: 0,
                transfers_last_10m: 0,
                same_payee_count_30m: 0,
            })
    }

    fn add_budget_cost(&self, session_id: &SessionId, cost: f64) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let record = guard.get_or_insert_mut(session_id.clone(), SessionRecord::zero);
        record.budget_consumed += cost;
    }

    fn record_transfer(&self, session_id: &SessionId, payee: &str, amount: i64, at: Instant) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let record = guard.get_or_insert_mut(session_id.clone(), SessionRecord::zero);
        record.session_transfer_count = record.session_transfer_count.saturating_add(1);
        record.transfers.push(TransferRecord {
            payee: payee.to_string(),
            amount,
            at,
        });
    }

    fn same_payee_count(
        &self,
        session_id: &SessionId,
        payee: &str,
        now: Instant,
        window: Duration,
    ) -> u64 {
        let Ok(guard) = self.inner.lock() else {
            return 0;
        };
        let Some(record) = guard.peek(session_id) else {
            return 0;
        };
        let count = record
            .transfers
            .iter()
            .filter(|t| t.payee == payee && now.saturating_duration_since(t.at) <= window)
            .count();
        u64::try_from(count).unwrap_or(u64::MAX)
    }

    fn cumulative_transfer_amount(
        &self,
        session_id: &SessionId,
        now: Instant,
        window: Duration,
    ) -> i64 {
        let Ok(guard) = self.inner.lock() else {
            return 0;
        };
        let Some(record) = guard.peek(session_id) else {
            return 0;
        };
        record
            .transfers
            .iter()
            .filter(|t| now.saturating_duration_since(t.at) <= window)
            .fold(0i64, |acc, t| acc.saturating_add(t.amount))
    }

    fn transfer_count_in_window(
        &self,
        session_id: &SessionId,
        now: Instant,
        window: Duration,
    ) -> u64 {
        let Ok(guard) = self.inner.lock() else {
            return 0;
        };
        let Some(record) = guard.peek(session_id) else {
            return 0;
        };
        let count = record
            .transfers
            .iter()
            .filter(|t| now.saturating_duration_since(t.at) <= window)
            .count();
        u64::try_from(count).unwrap_or(u64::MAX)
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
        assert_eq!(signals.session_transfer_count, 0);
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
            session_transfer_count: 0,
            transfer_amount: 0,
            daily_cumulative_amount: 0,
            transfers_last_10m: 0,
            same_payee_count_30m: 0,
        };
        assert_eq!(signals.budget_remaining_long(None), i64::MAX);
    }

    #[test]
    fn runtime_signals_remaining_subtracts_consumed_and_floors() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 12.75,
            risk_score: 0.0,
            session_transfer_count: 0,
            transfer_amount: 0,
            daily_cumulative_amount: 0,
            transfers_last_10m: 0,
            same_payee_count_30m: 0,
        };
        assert_eq!(signals.budget_remaining_long(Some(100.0)), 87);
    }

    #[test]
    fn runtime_signals_remaining_goes_negative_when_overspent() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 150.0,
            risk_score: 0.0,
            session_transfer_count: 0,
            transfer_amount: 0,
            daily_cumulative_amount: 0,
            transfers_last_10m: 0,
            same_payee_count_30m: 0,
        };
        assert_eq!(signals.budget_remaining_long(Some(100.0)), -50);
    }

    #[test]
    fn budget_remaining_nan_ceiling_fails_closed() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 0.0,
            risk_score: 0.0,
            session_transfer_count: 0,
            transfer_amount: 0,
            daily_cumulative_amount: 0,
            transfers_last_10m: 0,
            same_payee_count_30m: 0,
        };
        assert_eq!(signals.budget_remaining_long(Some(f64::NAN)), i64::MIN);
    }

    #[test]
    fn budget_remaining_nan_consumed_fails_closed() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: f64::NAN,
            risk_score: 0.0,
            session_transfer_count: 0,
            transfer_amount: 0,
            daily_cumulative_amount: 0,
            transfers_last_10m: 0,
            same_payee_count_30m: 0,
        };
        assert_eq!(signals.budget_remaining_long(Some(100.0)), i64::MIN);
    }

    #[test]
    fn risk_score_nan_fails_closed() {
        let signals = RuntimeSignals {
            action_count: 0,
            budget_consumed: 0.0,
            risk_score: f64::NAN,
            session_transfer_count: 0,
            transfer_amount: 0,
            daily_cumulative_amount: 0,
            transfers_last_10m: 0,
            same_payee_count_30m: 0,
        };
        assert_eq!(signals.risk_score_long(), i64::MAX);
    }

    #[test]
    fn lru_session_state_store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LruSessionStateStore>();
    }

    // ===== Budget cost tracking =====

    #[test]
    fn add_budget_cost_updates_consumed() {
        let store = LruSessionStateStore::new(16);
        store.record_action(&sid("sess_a"));
        store.add_budget_cost(&sid("sess_a"), 10.0);
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.budget_consumed, 10.0);
    }

    #[test]
    fn add_budget_cost_accumulates_across_calls() {
        let store = LruSessionStateStore::new(16);
        store.record_action(&sid("sess_a"));
        store.add_budget_cost(&sid("sess_a"), 1.0);
        store.add_budget_cost(&sid("sess_a"), 1.0);
        store.add_budget_cost(&sid("sess_a"), 1.0);
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.budget_consumed, 3.0);
    }

    #[test]
    fn add_budget_cost_isolates_sessions() {
        let store = LruSessionStateStore::new(16);
        store.record_action(&sid("sess_a"));
        store.record_action(&sid("sess_b"));
        store.add_budget_cost(&sid("sess_a"), 5.0);
        assert_eq!(store.signals(&sid("sess_b")).budget_consumed, 0.0);
    }

    // ===== Transfer tracking and session boundary =====

    #[test]
    fn session_transfer_count_starts_at_zero_for_new_session() {
        let store = LruSessionStateStore::new(16);
        // sess_a has some transfers
        let now = Instant::now();
        store.record_transfer(&sid("sess_a"), "payee_x", 100, now);
        store.record_transfer(&sid("sess_a"), "payee_x", 100, now);
        assert_eq!(store.signals(&sid("sess_a")).session_transfer_count, 2);

        // sess_b is a fresh session boundary — count must be 0
        let signals_b = store.signals(&sid("sess_b"));
        assert_eq!(
            signals_b.session_transfer_count, 0,
            "new session must start with session_transfer_count = 0"
        );
    }

    #[test]
    fn session_transfer_count_increments_per_transfer() {
        let store = LruSessionStateStore::new(16);
        let now = Instant::now();
        store.record_transfer(&sid("sess_a"), "payee_x", 100, now);
        store.record_transfer(&sid("sess_a"), "payee_y", 100, now);
        store.record_transfer(&sid("sess_a"), "payee_x", 100, now);
        assert_eq!(store.signals(&sid("sess_a")).session_transfer_count, 3);
    }

    // ===== same_payee_count_30m sliding window =====

    #[test]
    fn same_payee_count_returns_zero_for_unknown_session() {
        let store = LruSessionStateStore::new(16);
        let count =
            store.same_payee_count(&sid("never_seen"), "payee_x", Instant::now(), PAYEE_WINDOW);
        assert_eq!(count, 0);
    }

    #[test]
    fn same_payee_count_within_window() {
        let store = LruSessionStateStore::new(16);
        let now = Instant::now();
        store.record_transfer(&sid("sess_a"), "payee_x", 100, now);
        store.record_transfer(&sid("sess_a"), "payee_x", 100, now);
        store.record_transfer(&sid("sess_a"), "payee_y", 100, now); // different payee

        let count = store.same_payee_count(&sid("sess_a"), "payee_x", now, PAYEE_WINDOW);
        assert_eq!(count, 2, "only payee_x transfers should be counted");
    }

    #[test]
    fn same_payee_count_30m_window_expires_after_window() {
        let store = LruSessionStateStore::new(16);

        // Record two transfers 35 minutes in the past (outside 30m window).
        let past = Instant::now()
            .checked_sub(Duration::from_secs(35 * 60))
            .expect("instant arithmetic");
        store.record_transfer(&sid("sess_a"), "payee_x", 100, past);
        store.record_transfer(&sid("sess_a"), "payee_x", 100, past);

        // Record one transfer just now (inside window).
        let now = Instant::now();
        store.record_transfer(&sid("sess_a"), "payee_x", 100, now);

        let count = store.same_payee_count(&sid("sess_a"), "payee_x", now, PAYEE_WINDOW);
        assert_eq!(
            count, 1,
            "transfers older than 30m must not count in the sliding window"
        );
    }

    #[test]
    fn same_payee_count_all_expired_returns_zero() {
        let store = LruSessionStateStore::new(16);

        // All transfers 31 minutes ago — past the 30m window.
        let past = Instant::now()
            .checked_sub(Duration::from_secs(31 * 60))
            .expect("instant arithmetic");
        store.record_transfer(&sid("sess_a"), "payee_x", 100, past);
        store.record_transfer(&sid("sess_a"), "payee_x", 100, past);

        let count = store.same_payee_count(&sid("sess_a"), "payee_x", Instant::now(), PAYEE_WINDOW);
        assert_eq!(count, 0, "all transfers expired; window must return 0");
    }
}
