//! Schema for `[sidecar.revocation]`.
//!
//! Schema value types own the non-zero capacities; `firma-sidecar` validates
//! that the false-positive rate falls in `(0, 1)` and builds its revocation
//! store configuration from these values.

use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};

/// TOML-facing revocation cache config.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationConfig {
    /// Expected distinct revoked tokens the bloom is sized for.
    #[serde(default = "default_capacity")]
    pub capacity: NonZeroUsize,
    /// Target false positive rate.
    #[serde(default = "default_fpr")]
    pub fpr: f64,
    /// Capacity of the confirmed-positive LRU cache.
    #[serde(default = "default_lru_capacity")]
    pub lru_capacity: NonZeroUsize,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            capacity: default_capacity(),
            fpr: default_fpr(),
            lru_capacity: default_lru_capacity(),
        }
    }
}

const fn default_capacity() -> NonZeroUsize {
    const { NonZeroUsize::new(1_000_000).unwrap() }
}

const fn default_fpr() -> f64 {
    0.0001
}

const fn default_lru_capacity() -> NonZeroUsize {
    const { NonZeroUsize::new(100_000).unwrap() }
}
