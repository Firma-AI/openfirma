//! Exponential reconnect backoff with bounded jitter.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rngs::SmallRng;
use rand::{Rng as _, SeedableRng as _};

/// Exponential backoff for reconnect loops.
pub(super) struct ExponentialBackoff {
    min: Duration,
    max: Duration,
    current: Duration,
    rng: SmallRng,
}

impl ExponentialBackoff {
    /// Build a new backoff using `min` as the first delay and `max` as cap.
    #[must_use]
    pub(super) fn new(min: Duration, max: Duration) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                duration.as_secs() ^ u64::from(duration.subsec_nanos())
            });
        Self {
            min,
            max: max.max(min),
            current: min,
            rng: SmallRng::seed_from_u64(seed),
        }
    }

    /// Return the next jittered delay and advance the internal state.
    ///
    /// Applies symmetric jitter within ±15% of the current base so reconnect
    /// storms spread out in both directions rather than biasing upward.
    pub(super) fn next(&mut self) -> Duration {
        let base = self.current.min(self.max);
        let jitter = self.rng.random_range(0.85..=1.15);
        let delay = base.mul_f64(jitter).min(self.max);
        self.current = base.saturating_mul(2).min(self.max);
        delay
    }

    /// Reset to the minimum delay.
    pub(super) fn reset(&mut self) {
        self.current = self.min;
    }
}
