//! Background capability-token refresher for `firma run`.
//!
//! The per-session capability seed minted at startup carries a short TTL
//! (default 15 min, [`super::issue::DEFAULT_TTL_SECONDS`]). Without renewal the
//! sidecar's Stage 1 validation begins denying every protected call once the
//! token expires, stalling long agent sessions.
//!
//! [`CapabilityRefresher`] spawns a background thread that re-calls the
//! Authority's `IssueCapability` RPC — reusing the same session identity and
//! credentials assembled at startup, so no interactive re-auth occurs — and
//! atomically rewrites the seed file before expiry. Picking the rewritten seed
//! up in a *running* sidecar requires the sidecar's own capability-source
//! reload, which lands separately — it is not part of this crate. Without it the
//! refreshed token only benefits a sidecar (re)started after the rewrite.
//!
//! Fail-closed: if the Authority is unreachable the refresher retries with
//! capped backoff but never serves a stale token itself. While a refresh is
//! outstanding the old token simply expires and the sidecar denies, exactly as
//! it would without a refresher.

// M-PANIC-IS-STOP: no unwrap/expect/panic outside tests.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::issue::{self, IssueParams};
use crate::error::RunError;

/// Initial retry backoff after a failed re-mint.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Maximum retry backoff after repeated re-mint failures.
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Floor on the scheduled wait between refreshes. Guards against a tight
/// re-mint loop (hammering the Authority with zero delay) when the token TTL is
/// pathologically short relative to `grace_seconds`, where [`compute_wait`]
/// would otherwise return [`Duration::ZERO`] on every successful cycle.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Owns the background refresh thread. Dropping it stops the thread and joins.
pub struct CapabilityRefresher {
    stop_tx: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl CapabilityRefresher {
    /// Spawn the refresher for a freshly minted seed.
    ///
    /// `initial_expiry` is the expiry of the token just written to `out_path`;
    /// the first refresh is scheduled from it. `refresh_ratio` (0.0, 1.0) sets
    /// how far into the remaining lifetime to renew; `grace_seconds` caps the
    /// schedule so a renewal always fires at least that long before expiry.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Capability`] if the refresh thread cannot be spawned.
    pub fn spawn(
        params: IssueParams,
        out_path: PathBuf,
        initial_expiry: DateTime<Utc>,
        refresh_ratio: f64,
        grace_seconds: u64,
    ) -> Result<Self, RunError> {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        let grace = Duration::from_secs(grace_seconds);
        let handle = thread::Builder::new()
            .name("firma-run-capability-refresh".to_string())
            .spawn(move || {
                run_refresh_loop(
                    &params,
                    &out_path,
                    initial_expiry,
                    refresh_ratio,
                    grace,
                    &stop_rx,
                );
            })
            .map_err(|error| RunError::Capability(format!("spawn refresh thread: {error}")))?;

        Ok(Self {
            stop_tx: Some(stop_tx),
            handle: Some(handle),
        })
    }
}

impl Drop for CapabilityRefresher {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Refresh loop body. Returns when a stop signal is received (or the sender is
/// dropped). Runs on the background thread.
fn run_refresh_loop(
    params: &IssueParams,
    out_path: &Path,
    mut expiry: DateTime<Utc>,
    refresh_ratio: f64,
    grace: Duration,
    stop_rx: &mpsc::Receiver<()>,
) {
    let mut backoff = BACKOFF_INITIAL;
    loop {
        // Floor the scheduled wait so a successful re-mint can never spin the
        // loop with zero delay (see `MIN_REFRESH_INTERVAL`).
        let wait = compute_wait(expiry, Utc::now(), refresh_ratio, grace).max(MIN_REFRESH_INTERVAL);
        match stop_rx.recv_timeout(wait) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {}
        }

        match issue::mint_and_write_seed(params, out_path) {
            Ok(seed) => {
                expiry = seed.expiry;
                backoff = BACKOFF_INITIAL;
                tracing::info!(
                    token_id = %seed.token_id,
                    expiry = %seed.expiry,
                    "capability token refreshed before expiry"
                );
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "capability token refresh failed; retrying (token fails closed if it expires \
                     before a refresh succeeds)"
                );
                // Back off exponentially between retries: once past the refresh
                // point `compute_wait` returns ~0 (floored to `MIN_REFRESH_INTERVAL`),
                // so without this the retry cadence would stay at the 1s floor.
                match stop_rx.recv_timeout(backoff) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
                    Err(RecvTimeoutError::Timeout) => {}
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// Duration to wait before the next refresh attempt.
///
/// Renews at `refresh_ratio` of the remaining lifetime, but never later than
/// `grace_seconds` before expiry. Returns [`Duration::ZERO`] when the token is
/// already within the grace window (refresh immediately).
fn compute_wait(
    expiry: DateTime<Utc>,
    now: DateTime<Utc>,
    refresh_ratio: f64,
    grace: Duration,
) -> Duration {
    let remaining = (expiry - now).to_std().unwrap_or(Duration::ZERO);
    let latest = remaining.saturating_sub(grace);
    let wait = remaining.mul_f64(refresh_ratio);
    wait.min(latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn wait_is_ratio_of_remaining_lifetime() {
        // 100s remaining, ratio 0.6, grace 30 → refresh at 60s.
        let wait = compute_wait(t(100), t(0), 0.60, Duration::from_secs(30));
        assert_eq!(wait, Duration::from_mins(1));
    }

    #[test]
    fn wait_capped_by_grace_window() {
        // 100s remaining, ratio 0.95 would refresh at 95s (only 5s before
        // expiry); grace 30 pulls it back to 70s.
        let wait = compute_wait(t(100), t(0), 0.95, Duration::from_secs(30));
        assert_eq!(wait, Duration::from_secs(70));
    }

    #[test]
    fn wait_zero_inside_grace_window() {
        // Only 10s remaining, grace 30 → refresh immediately.
        let wait = compute_wait(t(10), t(0), 0.60, Duration::from_secs(30));
        assert_eq!(wait, Duration::ZERO);
    }

    #[test]
    fn wait_zero_when_already_expired() {
        let wait = compute_wait(t(0), t(100), 0.60, Duration::from_secs(30));
        assert_eq!(wait, Duration::ZERO);
    }
}
