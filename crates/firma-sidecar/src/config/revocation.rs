//! `[sidecar.revocation]` configuration section.

use firma_config_schema::sidecar::revocation::RevocationConfig as SchemaRevocationConfig;

use crate::enforcement::revocation::RevocationConfig as StoreConfig;

/// Validated revocation cache config.
#[derive(Debug, Clone, Copy)]
pub struct RevocationConfig {
    /// Expected distinct revoked tokens the bloom is sized for.
    pub(crate) capacity: usize,
    /// Target false positive rate.
    pub(crate) fpr: f64,
    /// Capacity of the confirmed-positive LRU cache.
    pub(crate) lru_capacity: usize,
}

/// Error validating a [`RevocationConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RevocationConfigError {
    /// `capacity` was zero.
    #[error("revocation.capacity must be > 0")]
    ZeroCapacity,
    /// `fpr` was not within the open interval `(0.0, 1.0)`.
    #[error("revocation.fpr must be in (0.0, 1.0)")]
    FprOutOfRange,
    /// `lru_capacity` was zero.
    #[error("revocation.lru_capacity must be > 0")]
    ZeroLruCapacity,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            capacity: 1_000_000,
            fpr: 0.0001,
            lru_capacity: 100_000,
        }
    }
}

impl TryFrom<SchemaRevocationConfig> for RevocationConfig {
    type Error = RevocationConfigError;

    fn try_from(schema: SchemaRevocationConfig) -> Result<Self, Self::Error> {
        if schema.capacity == 0 {
            return Err(RevocationConfigError::ZeroCapacity);
        }
        if !(schema.fpr > 0.0 && schema.fpr < 1.0) {
            return Err(RevocationConfigError::FprOutOfRange);
        }
        if schema.lru_capacity == 0 {
            return Err(RevocationConfigError::ZeroLruCapacity);
        }
        Ok(Self {
            capacity: schema.capacity,
            fpr: schema.fpr,
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

    fn schema(capacity: usize, fpr: f64, lru_capacity: usize) -> SchemaRevocationConfig {
        SchemaRevocationConfig {
            capacity,
            fpr,
            lru_capacity,
        }
    }

    #[test]
    fn defaults_valid() {
        let d = RevocationConfig::default();
        assert!(RevocationConfig::try_from(schema(d.capacity, d.fpr, d.lru_capacity)).is_ok());
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            RevocationConfig::try_from(schema(0, 0.0001, 100_000)),
            Err(RevocationConfigError::ZeroCapacity)
        ));
    }

    #[test]
    fn fpr_out_of_range_rejected() {
        for bad in [0.0_f64, 1.0_f64, -0.1_f64, 1.5_f64, f64::NAN] {
            assert!(
                matches!(
                    RevocationConfig::try_from(schema(1_000_000, bad, 100_000)),
                    Err(RevocationConfigError::FprOutOfRange)
                ),
                "fpr {bad} should be rejected"
            );
        }
    }

    #[test]
    fn zero_lru_capacity_rejected() {
        assert!(matches!(
            RevocationConfig::try_from(schema(1_000_000, 0.0001, 0)),
            Err(RevocationConfigError::ZeroLruCapacity)
        ));
    }
}
