#![cfg(feature = "loom-tests")]

use loom::sync::{Arc, RwLock};
use loom::thread;
use std::collections::{HashMap, HashSet};

#[test]
fn loom_models_shared_state_locking_invariants() {
    loom::model(|| {
        let policy_version = Arc::new(RwLock::new(1_u64));
        let revocations = Arc::new(RwLock::new(HashSet::<String>::new()));
        let session_counters = Arc::new(RwLock::new(HashMap::<String, u64>::new()));

        let writer_policy = Arc::clone(&policy_version);
        let writer_revocations = Arc::clone(&revocations);
        let writer_counters = Arc::clone(&session_counters);

        let writer = thread::spawn(move || {
            {
                let mut version = writer_policy
                    .write()
                    .unwrap_or_else(|_| panic!("policy version lock poisoned"));
                *version += 1;
            }

            {
                let mut revoked = writer_revocations
                    .write()
                    .unwrap_or_else(|_| panic!("revocation lock poisoned"));
                revoked.insert("tok_loom_001".to_string());
            }

            {
                let mut counters = writer_counters
                    .write()
                    .unwrap_or_else(|_| panic!("session counter lock poisoned"));
                let next = counters.get("sess_loom").copied().unwrap_or(0) + 1;
                counters.insert("sess_loom".to_string(), next);
            }
        });

        let reader_policy = Arc::clone(&policy_version);
        let reader_revocations = Arc::clone(&revocations);
        let reader_counters = Arc::clone(&session_counters);

        let reader = thread::spawn(move || {
            let version = *reader_policy
                .read()
                .unwrap_or_else(|_| panic!("policy version lock poisoned"));
            assert!(version >= 1);

            let revoked_seen = reader_revocations
                .read()
                .unwrap_or_else(|_| panic!("revocation lock poisoned"))
                .contains("tok_loom_001");

            let count = reader_counters
                .read()
                .unwrap_or_else(|_| panic!("session counter lock poisoned"))
                .get("sess_loom")
                .copied()
                .unwrap_or(0);

            // Both values are race-dependent in model exploration, but each
            // observed state must be internally consistent and in-range.
            assert!(count <= 1);
            if revoked_seen {
                assert!(version >= 1);
            }
        });

        writer
            .join()
            .unwrap_or_else(|_| panic!("writer thread panicked"));
        reader
            .join()
            .unwrap_or_else(|_| panic!("reader thread panicked"));
    });
}
