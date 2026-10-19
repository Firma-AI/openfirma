//! LRU set wrapper used to hold confirmed revoked token IDs.

use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;

#[derive(Debug)]
pub(super) struct LruSet {
    inner: Mutex<LruCache<String, ()>>,
}

impl LruSet {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub(super) fn insert(&self, key: String) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.put(key, ());
        }
    }

    pub(super) fn contains(&self, key: &str) -> bool {
        self.inner
            .lock()
            .is_ok_and(|mut guard| guard.get(key).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_contains_returns_true() {
        let set = LruSet::new(NonZeroUsize::new(10).unwrap());
        set.insert("a".to_string());
        assert!(set.contains("a"));
    }

    #[test]
    fn eviction_drops_oldest_when_full() {
        let set = LruSet::new(NonZeroUsize::new(2).unwrap());
        set.insert("a".to_string());
        set.insert("b".to_string());
        set.insert("c".to_string());
        assert!(!set.contains("a"), "'a' should have been evicted");
        assert!(set.contains("b"));
        assert!(set.contains("c"));
    }
}
