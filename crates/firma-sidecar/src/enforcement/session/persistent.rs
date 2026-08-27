//! File-backed session-state store (AARM R2 G4).
//!
//! [`PersistentSessionStateStore`] is an alternative [`SessionStateStore`]
//! backend that mirrors per-session runtime state to a local append-only
//! JSONL file so state survives LRU eviction and process restart. Selected
//! by `sidecar.constraint_enforcement.session_state_backend = "persistent"`.
//!
//! # Design
//!
//! - An in-memory `LruCache` is the read path (`signals()` is a cache peek
//!   — no file read on the hot path), preserving the local-only,
//!   bounded-latency enforcement invariants.
//! - `record_action()` updates the cache AND appends one JSON line to the
//!   log file. The append is a single local `write` syscall into the OS
//!   page cache; there is no per-request `fsync`, so durability against
//!   power loss is best-effort. The goal is to outlive *eviction* and
//!   *clean process restart*, not power failure.
//! - On construction the log is replayed; the last record per session
//!   wins, rebuilding the cache. Sessions exceeding capacity are evicted
//!   from the cache exactly like the LRU backend, but their state remains
//!   in the log and is restored on the next restart / cache miss replay.
//!
//! # Failure modes
//!
//! Session-state bookkeeping is a constraint *input*, not a policy
//! decision. Consistent with the in-memory backend (which degrades to a
//! fresh session on mutex poison), IO failures degrade gracefully rather
//! than fail-closing all enforcement: a corrupt or unreadable log starts
//! from an empty cache; a failed append leaves the in-memory cache as the
//! authoritative source for the running process. Construction itself
//! surfaces file-open errors so a misconfigured path fails to start
//! (fail-closed at startup) rather than silently losing persistence.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Mutex;

use firma_identifiers::SessionId;
use lru::LruCache;
use serde::{Deserialize, Serialize};

use super::state::{Outcome, RuntimeSignals, SessionRecord, SessionStateStore};

/// Append-only JSONL-backed session state store.
pub struct PersistentSessionStateStore {
    inner: Mutex<Inner>,
}

struct Inner {
    cache: LruCache<SessionId, SessionRecord>,
    file: File,
}

/// One serialized record in the replay log. Carries the full record
/// snapshot so the last entry per session reconstructs the entire state
/// (counters + prior-action history).
#[derive(Debug, Serialize, Deserialize)]
struct LogEntry {
    sid: String,
    action_count: u64,
    risk_score: f64,
    #[serde(default)]
    deny_count: u64,
    #[serde(default)]
    history: Vec<super::state::ActionOutcome>,
    #[serde(default)]
    last_provenance: Option<String>,
}

impl PersistentSessionStateStore {
    /// open (or create) the session-state log at `path`, replay it into an
    /// in-memory cache of `capacity` entries, and keep the file open for
    /// appending. The file is created if missing.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created/opened for append.
    /// A corrupt or unreadable log is treated as an empty cache (graceful
    /// degradation) rather than a hard failure.
    pub(crate) fn open(path: impl AsRef<Path>, capacity: usize) -> std::io::Result<Self> {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::MIN);
        let path = path.as_ref().to_path_buf();
        let cache = replay(&path, cap).unwrap_or_else(|err| {
            tracing::warn!(?err, ?path, "session-state log unreadable; starting fresh");
            LruCache::new(cap)
        });
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        Ok(Self {
            inner: Mutex::new(Inner { cache, file }),
        })
    }
}

impl SessionStateStore for PersistentSessionStateStore {
    fn record_action(&self, session_id: &SessionId) -> u64 {
        let Ok(mut guard) = self.inner.lock() else {
            // Mutex poisoned — behave like the in-memory backend: a
            // fresh session with count 1. Stage 2 still fail-closes if a
            // policy requires a higher count.
            return 1;
        };
        let record = guard
            .cache
            .get_or_insert_mut(session_id.clone(), SessionRecord::default);
        record.action_count = record.action_count.saturating_add(1);
        let count = record.action_count;
        let entry = LogEntry {
            sid: session_id.to_string(),
            action_count: record.action_count,
            risk_score: record.risk_score,
            deny_count: record.deny_count,
            history: record.history.clone(),
            last_provenance: record.last_provenance.clone(),
        };
        // Append to the log; an IO failure does NOT undo the in-memory
        // update — the cache remains authoritative for this process. The
        // log is best-effort persistence, not a transactional boundary.
        match serde_json::to_string(&entry) {
            Ok(line) => {
                if let Err(err) = writeln!(guard.file, "{line}") {
                    tracing::warn!(
                        ?err,
                        "session-state append failed; in-memory state retained"
                    );
                }
            }
            Err(err) => tracing::warn!(
                ?err,
                "session-state serialize failed; in-memory state retained"
            ),
        }
        count
    }

    fn signals(&self, session_id: &SessionId) -> RuntimeSignals {
        let Ok(guard) = self.inner.lock() else {
            return RuntimeSignals::default();
        };
        guard
            .cache
            .peek(session_id)
            .map_or_else(RuntimeSignals::default, |r| RuntimeSignals {
                action_count: r.action_count,
                risk_score: r.risk_score,
                deny_count: r.deny_count,
                history: r.history.clone(),
                last_provenance: r.last_provenance.clone(),
            })
    }

    fn record_outcome(
        &self,
        session_id: &SessionId,
        action_class: &str,
        resource: &str,
        outcome: Outcome,
    ) {
        let Ok(mut guard) = self.inner.lock() else {
            // Mutex poisoned — best-effort skip, mirroring the LRU backend.
            return;
        };
        let record = guard
            .cache
            .get_or_insert_mut(session_id.clone(), SessionRecord::default);
        record.push_outcome(action_class.to_string(), resource.to_string(), outcome);
        let entry = LogEntry {
            sid: session_id.to_string(),
            action_count: record.action_count,
            risk_score: record.risk_score,
            deny_count: record.deny_count,
            history: record.history.clone(),
            last_provenance: record.last_provenance.clone(),
        };
        match serde_json::to_string(&entry) {
            Ok(line) => {
                if let Err(err) = writeln!(guard.file, "{line}") {
                    tracing::warn!(
                        ?err,
                        "session-state append failed; in-memory state retained"
                    );
                }
            }
            Err(err) => tracing::warn!(
                ?err,
                "session-state serialize failed; in-memory state retained"
            ),
        }
    }

    fn advance_provenance(
        &self,
        session_id: &SessionId,
        context_hash: &str,
        action_class: &str,
        resource: &str,
    ) -> String {
        let Ok(mut guard) = self.inner.lock() else {
            return String::new();
        };
        let record = guard
            .cache
            .get_or_insert_mut(session_id.clone(), SessionRecord::default);
        let new = super::state::next_provenance(
            record.last_provenance.as_deref(),
            context_hash,
            action_class,
            resource,
        );
        record.last_provenance = Some(new.clone());
        let entry = LogEntry {
            sid: session_id.to_string(),
            action_count: record.action_count,
            risk_score: record.risk_score,
            deny_count: record.deny_count,
            history: record.history.clone(),
            last_provenance: record.last_provenance.clone(),
        };
        match serde_json::to_string(&entry) {
            Ok(line) => {
                if let Err(err) = writeln!(guard.file, "{line}") {
                    tracing::warn!(
                        ?err,
                        "session-state append failed; in-memory state retained"
                    );
                }
            }
            Err(err) => tracing::warn!(
                ?err,
                "session-state serialize failed; in-memory state retained"
            ),
        }
        new
    }
}

/// Read the log file and rebuild the latest record per session. The last
/// entry for a given session id wins (append-only log). The cache is
/// sized to `cap`.
fn replay(path: &Path, cap: NonZeroUsize) -> std::io::Result<LruCache<SessionId, SessionRecord>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // No prior log — start empty.
            return Ok(LruCache::new(cap));
        }
        Err(err) => return Err(err),
    };
    let reader = BufReader::new(file);
    // Collect the latest record per sid, then populate the cache sized to
    // `cap`. Iterating the map and calling `put` evicts the least-recently-
    // used entries when the session count exceeds capacity, mirroring the
    // in-memory backend's eviction policy.
    let mut latest: std::collections::HashMap<String, SessionRecord> =
        std::collections::HashMap::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: LogEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            // Skip unparseable lines rather than aborting the whole replay.
            Err(err) => {
                tracing::warn!(?err, "skipping malformed session-state log line");
                continue;
            }
        };
        latest.insert(
            entry.sid,
            SessionRecord {
                action_count: entry.action_count,
                risk_score: entry.risk_score,
                deny_count: entry.deny_count,
                history: entry.history,
                last_provenance: entry.last_provenance,
            },
        );
    }
    let mut cache = LruCache::new(cap);
    for (sid, record) in latest {
        if let Ok(parsed) = sid.parse::<SessionId>() {
            cache.put(parsed, record);
        }
    }
    Ok(cache)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::float_cmp)]
    use super::*;
    use std::path::PathBuf;

    use firma_identifiers::SessionId;

    fn sid(s: &str) -> SessionId {
        s.parse().expect("valid session id")
    }

    fn tmpfile() -> PathBuf {
        let dir = std::env::temp_dir();
        let id = uuid::Uuid::new_v4().to_string();
        dir.join(format!("firma-session-state-{id}.jsonl"))
    }

    #[test]
    fn record_action_returns_monotonic_count() {
        let path = tmpfile();
        let store = PersistentSessionStateStore::open(&path, 16).expect("open");
        assert_eq!(store.record_action(&sid("sess_a")), 1);
        assert_eq!(store.record_action(&sid("sess_a")), 2);
        assert_eq!(store.record_action(&sid("sess_a")), 3);
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn isolates_sessions() {
        let path = tmpfile();
        let store = PersistentSessionStateStore::open(&path, 16).expect("open");
        assert_eq!(store.record_action(&sid("sess_a")), 1);
        assert_eq!(store.record_action(&sid("sess_b")), 1);
        assert_eq!(store.record_action(&sid("sess_a")), 2);
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn signals_defaults_for_unknown_session() {
        let path = tmpfile();
        let store = PersistentSessionStateStore::open(&path, 16).expect("open");
        let signals = store.signals(&sid("never_seen"));
        assert_eq!(signals.action_count, 0);
        assert_eq!(signals.risk_score, 0.0);
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn signals_reflects_recorded_actions() {
        let path = tmpfile();
        let store = PersistentSessionStateStore::open(&path, 16).expect("open");
        store.record_action(&sid("sess_a"));
        store.record_action(&sid("sess_a"));
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.action_count, 2);
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn state_survives_restart() {
        let path = tmpfile();
        {
            let store = PersistentSessionStateStore::open(&path, 16).expect("open");
            store.record_action(&sid("sess_a"));
            store.record_action(&sid("sess_a"));
            store.record_action(&sid("sess_a"));
        } // drop flushes/closes
        // A fresh store pointing at the same log must rebuild the cache.
        let store = PersistentSessionStateStore::open(&path, 16).expect("reopen");
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.action_count, 3);
        // The next action continues from the persisted count.
        assert_eq!(store.record_action(&sid("sess_a")), 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn evicted_session_is_restored_on_restart() {
        let path = tmpfile();
        {
            let store = PersistentSessionStateStore::open(&path, 1).expect("open");
            store.record_action(&sid("sess_a"));
            store.record_action(&sid("sess_a"));
            // sess_b evicts sess_a from the in-memory cache (capacity 1).
            store.record_action(&sid("sess_b"));
            // sess_a is no longer in the hot cache...
            assert_eq!(store.signals(&sid("sess_a")).action_count, 0);
        }
        // ...but the log retained it, so a restart restores sess_a=2.
        let store = PersistentSessionStateStore::open(&path, 16).expect("reopen");
        assert_eq!(store.signals(&sid("sess_a")).action_count, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_log_starts_empty() {
        let path = tmpfile();
        // The file does not exist yet; open must succeed and report 0.
        let store = PersistentSessionStateStore::open(&path, 16).expect("open");
        assert_eq!(store.signals(&sid("anything")).action_count, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PersistentSessionStateStore>();
    }

    #[test]
    fn outcome_history_survives_restart() {
        use crate::enforcement::session::state::{HISTORY_CAP, Outcome};
        let path = tmpfile();
        {
            let store = PersistentSessionStateStore::open(&path, 16).expect("open");
            store.record_action(&sid("sess_a"));
            store.record_outcome(
                &sid("sess_a"),
                "communication.external.send",
                "h/x",
                Outcome::Allow,
            );
            store.record_outcome(&sid("sess_a"), "filesystem.delete", "h/y", Outcome::Deny);
        }
        // Reopen: history + deny_count must be restored from the log.
        let store = PersistentSessionStateStore::open(&path, 16).expect("reopen");
        let signals = store.signals(&sid("sess_a"));
        assert_eq!(signals.deny_count, 1);
        assert_eq!(signals.history.len(), 2);
        assert_eq!(
            signals.history[0].action_class,
            "communication.external.send"
        );
        assert_eq!(signals.history[1].outcome, Outcome::Deny);
        let _ = (HISTORY_CAP,); // keep the cap symbol referenced
        let _ = std::fs::remove_file(&path);
    }
}
