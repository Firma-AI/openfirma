//! Lock-free atomic bloom filter.

use std::sync::atomic::{AtomicU64, Ordering};

use xxhash_rust::xxh3::xxh3_128;

#[derive(Debug)]
pub(super) struct AtomicBloom {
    bits: Vec<AtomicU64>,
    bit_count: u64,
    hash_count: u32,
}

impl AtomicBloom {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "Bloom filter sizing uses the standard floating-point formula, then clamps to sane minimums."
    )]
    pub(super) fn new(capacity: usize, fpr: f64) -> Self {
        let capacity = capacity.max(1);
        let fpr = if fpr.is_finite() && (0.0..1.0).contains(&fpr) {
            fpr
        } else {
            0.0001
        };
        let n = capacity as f64;
        let ln2 = std::f64::consts::LN_2;
        let bit_count_float = -(n * fpr.ln()) / (ln2 * ln2);
        let bit_count = (bit_count_float.ceil() as u64).max(64);
        let hash_count = ((bit_count_float / n) * ln2).ceil() as u32;
        let word_count = bit_count.div_ceil(64) as usize;
        let bits = (0..word_count).map(|_| AtomicU64::new(0)).collect();
        Self {
            bits,
            bit_count,
            hash_count: hash_count.max(1),
        }
    }

    fn hashes(key: &str) -> (u64, u64) {
        let hash = xxh3_128(key.as_bytes());
        let first = (hash & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        let second = (hash >> 64) as u64;
        (first, second)
    }

    pub(super) fn insert(&self, key: &str) {
        let (first, second) = Self::hashes(key);
        for index in 0..self.hash_count {
            let bit = first.wrapping_add(u64::from(index).wrapping_mul(second)) % self.bit_count;
            let word = (bit / 64) as usize;
            let mask = 1_u64 << (bit % 64);
            self.bits[word].fetch_or(mask, Ordering::Relaxed);
        }
    }

    pub(super) fn contains(&self, key: &str) -> bool {
        let (first, second) = Self::hashes(key);
        for index in 0..self.hash_count {
            let bit = first.wrapping_add(u64::from(index).wrapping_mul(second)) % self.bit_count;
            let word = (bit / 64) as usize;
            let mask = 1_u64 << (bit % 64);
            if self.bits[word].load(Ordering::Relaxed) & mask == 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn insert_then_contains_returns_true() {
        let bloom = AtomicBloom::new(1_000, 0.01);
        bloom.insert("abc");
        assert!(bloom.contains("abc"));
    }

    #[test]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Empirical false-positive rate calculation is test-only."
    )]
    fn unknown_returns_false_most_of_the_time() {
        let bloom = AtomicBloom::new(10_000, 0.01);
        for i in 0..10_000 {
            bloom.insert(&format!("member-{i}"));
        }
        let mut false_positives = 0_u64;
        let samples = 10_000_u64;
        for i in 0..samples {
            if bloom.contains(&format!("nonmember-{i}")) {
                false_positives += 1;
            }
        }
        let fpr = false_positives as f64 / samples as f64;
        assert!(
            fpr <= 0.02,
            "empirical FPR {fpr} exceeds 2x configured (0.01)"
        );
    }

    #[test]
    fn idempotent_insert() {
        let bloom = AtomicBloom::new(100, 0.01);
        bloom.insert("x");
        bloom.insert("x");
        assert!(bloom.contains("x"));
    }

    #[test]
    fn concurrent_insert_and_check_no_panic() {
        let bloom = Arc::new(AtomicBloom::new(10_000, 0.001));
        let writer = {
            let bloom = Arc::clone(&bloom);
            thread::spawn(move || {
                for i in 0..5_000 {
                    bloom.insert(&format!("k-{i}"));
                }
            })
        };
        let reader = {
            let bloom = Arc::clone(&bloom);
            thread::spawn(move || {
                for i in 0..5_000 {
                    let _ = bloom.contains(&format!("k-{i}"));
                }
            })
        };
        if let Err(payload) = writer.join() {
            std::panic::resume_unwind(payload);
        }
        if let Err(payload) = reader.join() {
            std::panic::resume_unwind(payload);
        }
    }
}
