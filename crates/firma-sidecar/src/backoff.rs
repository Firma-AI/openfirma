//! Exponential reconnect backoff with bounded jitter.

use std::time::Duration;

use firma_config_utils::NonZeroDuration;

use rand::rngs::SmallRng;
use rand::{Rng as _, SeedableRng as _};

/// Exponential backoff for reconnect loops.
pub struct ExponentialBackoff {
    min: Duration,
    max: Duration,
    current: Duration,
    rng: SmallRng,
}

impl ExponentialBackoff {
    /// Build a new backoff using `min` as the first delay and `max` as cap.
    #[must_use]
    pub fn new(min: NonZeroDuration, max: NonZeroDuration) -> Self {
        let (min, max) = (min.duration(), max.duration());
        Self {
            min,
            max: max.max(min),
            current: min,
            rng: SmallRng::from_os_rng(),
        }
    }

    /// Return the next jittered delay and advance the internal state.
    ///
    /// Applies symmetric jitter within ±15% of the current base so reconnect
    /// storms spread out in both directions rather than biasing upward.
    pub fn next(&mut self) -> Duration {
        let base = self.current.min(self.max);
        let jitter = self.rng.random_range(0.85..=1.15);
        let delay = base.mul_f64(jitter).min(self.max);
        self.current = base.saturating_mul(2).min(self.max);
        delay
    }

    /// Reset to the minimum delay.
    pub fn reset(&mut self) {
        self.current = self.min;
    }
}
