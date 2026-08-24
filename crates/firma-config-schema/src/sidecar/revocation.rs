//! Schema for `[sidecar.revocation]`.
//!
//! Representation only. `firma-sidecar` validates these values (capacity and
//! LRU size must be non-zero; the false-positive rate must fall in `(0, 1)`)
//! and builds its revocation store configuration from them.

use serde::{Deserialize, Serialize};

/// TOML-facing revocation cache config.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct RevocationConfig {
    /// Expected distinct revoked tokens the bloom is sized for.
    #[serde(default = "default_capacity")]
    pub capacity: usize,
    /// Target false positive rate.
    #[serde(default = "default_fpr")]
    pub fpr: f64,
    /// Capacity of the confirmed-positive LRU cache.
    #[serde(default = "default_lru_capacity")]
    pub lru_capacity: usize,
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

const fn default_capacity() -> usize {
    1_000_000
}

const fn default_fpr() -> f64 {
    0.0001
}

const fn default_lru_capacity() -> usize {
    100_000
}
