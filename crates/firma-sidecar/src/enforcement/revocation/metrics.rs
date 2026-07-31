//! Atomic counters for the revocation cache.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub(super) struct RevocationMetrics {
    bloom_hits: AtomicU64,
    lru_hits: AtomicU64,
    bloom_positive_lru_miss: AtomicU64,
    revocations_total: AtomicU64,
}

/// Snapshot of revocation cache counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationMetricsSnapshot {
    /// Bloom-positive lookups.
    pub bloom_hits: u64,
    /// Bloom-positive lookups confirmed by the LRU.
    pub lru_hits: u64,
    /// Bloom-positive lookups missing the LRU.
    pub bloom_positive_lru_miss: u64,
    /// Calls to `add_revocation`.
    pub revocations_total: u64,
}

impl RevocationMetrics {
    pub(super) fn record_bloom_hit(&self) {
        self.bloom_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_lru_hit(&self) {
        self.lru_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_lru_miss(&self) {
        self.bloom_positive_lru_miss.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_revocation(&self) {
        self.revocations_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> RevocationMetricsSnapshot {
        RevocationMetricsSnapshot {
            bloom_hits: self.bloom_hits.load(Ordering::Relaxed),
            lru_hits: self.lru_hits.load(Ordering::Relaxed),
            bloom_positive_lru_miss: self.bloom_positive_lru_miss.load(Ordering::Relaxed),
            revocations_total: self.revocations_total.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_and_snapshot() {
        let metrics = RevocationMetrics::default();
        metrics.record_bloom_hit();
        metrics.record_bloom_hit();
        metrics.record_lru_hit();
        metrics.record_revocation();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.bloom_hits, 2);
        assert_eq!(snapshot.lru_hits, 1);
        assert_eq!(snapshot.bloom_positive_lru_miss, 0);
        assert_eq!(snapshot.revocations_total, 1);
    }
}
