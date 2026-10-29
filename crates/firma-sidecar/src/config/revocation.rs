//! `[sidecar.revocation]` configuration section.

use std::num::NonZeroUsize;

use firma_config_schema::sidecar::revocation::RevocationConfig as SchemaRevocationConfig;

use crate::enforcement::revocation::{FalsePositiveRate, RevocationConfig as StoreConfig};

/// Validated revocation cache config.
#[derive(Debug, Clone, Copy)]
pub struct RevocationConfig {
    /// Expected distinct revoked tokens the bloom is sized for.
    pub(crate) capacity: NonZeroUsize,
    /// Target false positive rate.
    pub(crate) fpr: FalsePositiveRate,
    /// Capacity of the confirmed-positive LRU cache.
    pub(crate) lru_capacity: NonZeroUsize,
}

/// Error validating a [`RevocationConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RevocationConfigError {
    /// `fpr` was not within the open interval `(0.0, 1.0)`.
    #[error("revocation.fpr must be in (0.0, 1.0)")]
    FprOutOfRange,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        let d = StoreConfig::default();
        Self {
            capacity: d.capacity,
            fpr: d.fpr,
            lru_capacity: d.lru_capacity,
        }
    }
}

impl TryFrom<SchemaRevocationConfig> for RevocationConfig {
    type Error = RevocationConfigError;

    fn try_from(schema: SchemaRevocationConfig) -> Result<Self, Self::Error> {
        let fpr = FalsePositiveRate::new(schema.fpr).ok_or(RevocationConfigError::FprOutOfRange)?;
        Ok(Self {
            capacity: schema.capacity,
            fpr,
            lru_capacity: schema.lru_capacity,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(fpr: f64) -> SchemaRevocationConfig {
        SchemaRevocationConfig {
            fpr,
            ..SchemaRevocationConfig::default()
        }
    }

    #[test]
    fn fpr_out_of_range_rejected() {
        for bad in [0.0_f64, 1.0_f64, -0.1_f64, 1.5_f64, f64::NAN] {
            assert!(
                matches!(
                    RevocationConfig::try_from(schema(bad)),
                    Err(RevocationConfigError::FprOutOfRange)
                ),
                "fpr {bad} should be rejected"
            );
        }
    }
}
