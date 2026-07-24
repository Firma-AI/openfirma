//! Revocation cache: bloom filter + LRU store.
//!
//! Implements [`firma_core::RevocationStore`] for the sidecar. See
//! `docs/tasks/006-revocation-cache.md`.
//!
//! # Behavior
//!
//! - `is_revoked`: bloom-miss -> `Ok(false)` fast path. Bloom-hit -> LRU
//!   lookup. LRU-hit -> `Ok(true)`. LRU-miss on bloom-positive (either a
//!   bloom false positive or an evicted LRU entry) -> `Ok(true)`, to honor
//!   the spec's "REVOKED is terminal" invariant.
//! - `add_revocation`: bloom insert + LRU insert. Idempotent.
//! - V1 never returns `Err`; the trait's `Result` is kept for forward
//!   compatibility.

#[path = "revocation/bloom.rs"]
pub(crate) mod bloom;
#[path = "revocation/lru.rs"]
pub(crate) mod lru;
#[path = "revocation/metrics.rs"]
pub(crate) mod metrics;

use firma_core::{RevocationStore, TokenError, TokenId};

use self::bloom::AtomicBloom;
use self::lru::LruSet;
use self::metrics::{RevocationMetrics, RevocationMetricsSnapshot};

/// Configuration for [`BloomLruRevocationStore`].
#[derive(Debug, Clone, Copy)]
pub struct RevocationConfig {
    /// Expected distinct revoked tokens the bloom is sized for.
    pub capacity: usize,
    /// Target false positive rate. Must be `0.0 < fpr < 1.0`.
    pub fpr: f64,
    /// Capacity of the confirmed-positive LRU cache.
    pub lru_capacity: usize,
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

/// Two-layer revocation store: atomic bloom filter + LRU cache.
#[derive(Debug)]
pub struct BloomLruRevocationStore {
    bloom: AtomicBloom,
    lru: LruSet,
    metrics: RevocationMetrics,
}

impl BloomLruRevocationStore {
    /// Construct a new revocation store with the given configuration.
    #[must_use]
    pub fn new(cfg: RevocationConfig) -> Self {
        Self {
            bloom: AtomicBloom::new(cfg.capacity, cfg.fpr),
            lru: LruSet::new(cfg.lru_capacity),
            metrics: RevocationMetrics::default(),
        }
    }

    /// Snapshot of metrics counters.
    #[must_use]
    pub fn metrics(&self) -> RevocationMetricsSnapshot {
        self.metrics.snapshot()
    }
}

impl RevocationStore for BloomLruRevocationStore {
    fn is_revoked(&self, token_id: &TokenId) -> Result<bool, TokenError> {
        let key = token_id.to_string();
        if !self.bloom.contains(&key) {
            return Ok(false);
        }
        self.metrics.record_bloom_hit();
        if self.lru.contains(&key) {
            self.metrics.record_lru_hit();
        } else {
            self.metrics.record_lru_miss();
        }
        Ok(true)
    }

    fn add_revocation(&self, token_id: &TokenId) -> Result<(), TokenError> {
        let key = token_id.to_string();
        self.bloom.insert(&key);
        self.lru.insert(key.clone());
        self.metrics.record_revocation();
        let snap = self.metrics.snapshot();
        tracing::info!(
            token_id = %key,
            bloom_hits = snap.bloom_hits,
            lru_hits = snap.lru_hits,
            bloom_positive_lru_miss = snap.bloom_positive_lru_miss,
            revocations_total = snap.revocations_total,
            "revocation added"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    fn small_store() -> BloomLruRevocationStore {
        BloomLruRevocationStore::new(RevocationConfig {
            capacity: 1_000,
            fpr: 0.001,
            lru_capacity: 4,
        })
    }

    #[test]
    fn unknown_token_not_revoked() {
        let store = small_store();
        let result = store.is_revoked(&TokenId::generate());
        assert_eq!(result.ok(), Some(false));
    }

    #[test]
    fn added_token_is_revoked() -> Result<(), TokenError> {
        let store = small_store();
        let id = TokenId::generate();
        store.add_revocation(&id)?;
        assert_eq!(store.is_revoked(&id).ok(), Some(true));
        Ok(())
    }

    #[test]
    fn bloom_hit_lru_miss_returns_revoked() -> Result<(), TokenError> {
        let store = small_store();
        let ids: Vec<TokenId> = (0..5).map(|_| TokenId::generate()).collect();
        for id in &ids {
            store.add_revocation(id)?;
        }
        assert_eq!(store.is_revoked(&ids[0]).ok(), Some(true));
        let snapshot = store.metrics();
        assert!(snapshot.bloom_positive_lru_miss >= 1);
        Ok(())
    }

    #[test]
    fn idempotent_add_revocation() -> Result<(), TokenError> {
        let store = small_store();
        let id = TokenId::generate();
        store.add_revocation(&id)?;
        store.add_revocation(&id)?;
        assert_eq!(store.is_revoked(&id).ok(), Some(true));
        assert_eq!(store.metrics().revocations_total, 2);
        Ok(())
    }

    #[test]
    fn concurrent_reads_and_writes_no_panic() {
        let store = Arc::new(BloomLruRevocationStore::new(RevocationConfig {
            capacity: 10_000,
            fpr: 0.001,
            lru_capacity: 1_000,
        }));

        let deadline = Instant::now() + Duration::from_millis(200);
        let mut handles = Vec::new();
        for _ in 0..4 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let mut i = 0_u64;
                while Instant::now() < deadline {
                    let id = TokenId::generate();
                    let _ = store.is_revoked(&id);
                    if i.is_multiple_of(8) {
                        let _ = store.add_revocation(&id);
                    }
                    i = i.wrapping_add(1);
                }
            }));
        }
        for handle in handles {
            if let Err(payload) = handle.join() {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

#[cfg(test)]
mod proptests {
    use std::collections::HashSet;

    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn members_always_revoked(count in 1usize..200) {
            let members: Vec<TokenId> = (0..count).map(|_| TokenId::generate()).collect();
            let store = BloomLruRevocationStore::new(RevocationConfig {
                capacity: 10_000,
                fpr: 0.001,
                lru_capacity: members.len().max(1),
            });
            for member in &members {
                prop_assert!(store.add_revocation(member).is_ok());
            }
            for member in &members {
                prop_assert_eq!(store.is_revoked(member).ok(), Some(true));
            }
        }

        #[test]
        #[expect(
            clippy::cast_precision_loss,
            reason = "Empirical false-positive rate calculation is test-only."
        )]
        fn non_members_mostly_not_revoked(count in 100usize..500) {
            let members: Vec<TokenId> = (0..count).map(|_| TokenId::generate()).collect();
            let member_set: HashSet<TokenId> = members.iter().copied().collect();
            let store = BloomLruRevocationStore::new(RevocationConfig {
                capacity: 10_000,
                fpr: 0.001,
                lru_capacity: members.len(),
            });
            for member in &members {
                prop_assert!(store.add_revocation(member).is_ok());
            }
            let mut false_positives = 0_usize;
            let samples = 2_000_usize;
            for _ in 0..samples {
                let candidate = TokenId::generate();
                if member_set.contains(&candidate) {
                    continue;
                }
                if store.is_revoked(&candidate).ok() == Some(true) {
                    false_positives += 1;
                }
            }
            let fpr = false_positives as f64 / samples as f64;
            prop_assert!(fpr <= 0.01, "empirical FPR {fpr} > 10x configured (0.001)");
        }
    }
}
