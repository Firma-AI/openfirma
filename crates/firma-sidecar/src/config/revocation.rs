//! `[revocation]` configuration section.

use serde::Deserialize;

use crate::enforcement::revocation::RevocationConfig as StoreConfig;

/// TOML-facing revocation cache config.
#[derive(Debug, Clone, Copy, Deserialize)]
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

impl RevocationConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.capacity == 0 {
            return Err("revocation.capacity must be > 0".into());
        }
        if !(self.fpr > 0.0 && self.fpr < 1.0) {
            return Err("revocation.fpr must be in (0.0, 1.0)".into());
        }
        if self.lru_capacity == 0 {
            return Err("revocation.lru_capacity must be > 0".into());
        }
        Ok(())
    }
}

impl From<RevocationConfig> for StoreConfig {
    fn from(config: RevocationConfig) -> Self {
        Self {
            capacity: config.capacity,
            fpr: config.fpr,
            lru_capacity: config.lru_capacity,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_valid() {
        assert!(RevocationConfig::default().validate().is_ok());
    }

    #[test]
    fn zero_capacity_rejected() {
        let config = RevocationConfig {
            capacity: 0,
            ..RevocationConfig::default()
        };
        let error = config.validate().unwrap_err();
        assert!(error.contains("revocation.capacity"));
    }

    #[test]
    fn fpr_out_of_range_rejected() {
        for bad in [0.0_f64, 1.0_f64, -0.1_f64, 1.5_f64, f64::NAN] {
            let config = RevocationConfig {
                fpr: bad,
                ..RevocationConfig::default()
            };
            assert!(config.validate().is_err(), "fpr {bad} should be rejected");
        }
    }

    #[test]
    fn zero_lru_capacity_rejected() {
        let config = RevocationConfig {
            lru_capacity: 0,
            ..RevocationConfig::default()
        };
        assert!(config.validate().is_err());
    }
}
