use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;

use crate::error::AuthorityError;
use firma_core::token::TokenId;

/// An event representing the revocation of a capability token.
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    pub token_id: TokenId,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

/// In-memory revocation store with file-based ingestion.
///
/// The revocation file is the source of truth. In-memory state is always derived
/// from the file via [`RevocationStoreWatcher`], which handles reloading and
/// broadcasting to live subscribers.
#[derive(Clone)]
pub struct RevocationStore {
    /// Revoked token IDs mapped to their revocation entries.
    entries: Arc<RwLock<HashMap<TokenId, RevocationEntry>>>,
    /// Ordered log for replay (FR-6: replay events after `since`).
    log: Arc<RwLock<Vec<RevocationEntry>>>,
    /// Path to the revocation file.
    revocation_file: PathBuf,
}

impl RevocationStore {
    /// Create a new revocation store, loading any existing entries from file.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityError` if the file exists but cannot be read.
    pub fn new(revocation_file: &Path) -> Result<Self, AuthorityError> {
        let store = Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            log: Arc::new(RwLock::new(Vec::new())),
            revocation_file: revocation_file.to_path_buf(),
        };

        // Load existing revocations from file (if it exists and is non-empty).
        // `load_from_content` uses blocking_write and must not be called in an
        // async context, so we skip it when the file has no parseable lines.
        if revocation_file.is_file() {
            let content = std::fs::read_to_string(revocation_file).map_err(|e| {
                AuthorityError::RevocationError {
                    reason: format!(
                        "cannot read revocation file {}: {e}",
                        revocation_file.display()
                    ),
                }
            })?;
            if content.lines().any(|l| !l.trim().is_empty()) {
                let count = store.load_from_content(&content);
                tracing::info!(count, "loaded existing revocations from file");
            }
        }

        Ok(store)
    }

    /// Load revocations from file content (one token ID per line).
    /// Returns the number of new entries added.
    fn load_from_content(&self, content: &str) -> usize {
        let mut entries = self.entries.blocking_write();
        let mut log = self.log.blocking_write();
        let mut count = 0;

        for (line_number, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(token_id) = line.parse() else {
                tracing::warn!(line_number, %line, "invalid token_id in revocation file, ignoring");
                continue;
            };

            if entries.contains_key(&token_id) {
                continue;
            }
            let entry = RevocationEntry {
                token_id,
                reason: "file-based revocation".to_string(),
                timestamp: Utc::now(),
            };
            entries.insert(token_id, entry.clone());
            log.push(entry);
            count += 1;
        }

        count
    }

    /// Revoke a token by appending its ID to the revocation file.
    ///
    /// The file is the source of truth: the [`RevocationStoreWatcher`] detects the
    /// change, updates in-memory state, and broadcasts to live subscribers. There is a
    /// brief latency between this call returning and `is_revoked` reflecting the change.
    ///
    /// Idempotent: if the token is already tracked in memory the file write is skipped.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityError` if the revocation file cannot be opened or written to.
    #[allow(dead_code, reason = "called via gRPC revocation path")]
    pub async fn revoke(&self, token_id: TokenId, reason: &str) -> Result<(), AuthorityError> {
        if self.entries.read().await.contains_key(&token_id) {
            tracing::debug!(%token_id, "duplicate revocation ignored");
            return Ok(());
        }

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.revocation_file)
            .await
            .map_err(|e| AuthorityError::RevocationError {
                reason: format!(
                    "cannot open revocation file {}: {e}",
                    self.revocation_file.display()
                ),
            })?;

        file.write_all(format!("{token_id}\n").as_bytes())
            .await
            .map_err(|e| AuthorityError::RevocationError {
                reason: format!("cannot write to revocation file: {e}"),
            })?;

        tracing::info!(%token_id, %reason, "token written to revocation file; watcher will update memory");
        Ok(())
    }

    /// Check if a token has been revoked.
    #[allow(dead_code, reason = "public API used by sidecar integration")]
    pub async fn is_revoked(&self, token_id: TokenId) -> bool {
        self.entries.read().await.contains_key(&token_id)
    }

    /// Get all revocation events after the given timestamp (for stream replay).
    pub async fn events_since(&self, since: DateTime<Utc>) -> Vec<RevocationEntry> {
        self.log
            .read()
            .await
            .iter()
            .filter(|e| e.timestamp > since)
            .cloned()
            .collect()
    }

    /// Reload revocations from the file on disk.
    ///
    /// Returns the newly-added entries so that callers (e.g. [`RevocationStoreWatcher`])
    /// can broadcast them to live subscribers.
    async fn reload_from_file(&self) -> Result<Vec<RevocationEntry>, AuthorityError> {
        let content = match tokio::fs::read_to_string(&self.revocation_file).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(AuthorityError::RevocationError {
                    reason: format!(
                        "cannot read revocation file {}: {e}",
                        self.revocation_file.display()
                    ),
                });
            }
        };

        let mut new_entries = Vec::new();
        let mut entries = self.entries.write().await;
        let mut log = self.log.write().await;

        for line in content.lines() {
            let s = line.trim();
            if s.is_empty() {
                continue;
            }
            let Ok(token_id) = s.parse() else {
                tracing::warn!(token_id = %s, "invalid token_id in revocation file, ignoring");
                continue;
            };

            if entries.contains_key(&token_id) {
                continue;
            }
            let entry = RevocationEntry {
                token_id,
                reason: "file-based revocation".to_string(),
                timestamp: Utc::now(),
            };
            entries.insert(token_id, entry.clone());
            log.push(entry.clone());
            new_entries.push(entry);
        }

        Ok(new_entries)
    }

    /// Watch the revocation file for changes and reload automatically.
    ///
    /// Only [`notify::event::EventKind::Modify`] and [`notify::event::EventKind::Create`] events
    /// trigger a reload. Returns a [`RevocationStoreWatcher`]: keep it alive for the watch to stay
    /// active. Dropping it stops the file watch and the reload task.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityError` if the OS file watcher cannot be created or registered.
    pub fn watch(&self) -> Result<RevocationStoreWatcher, AuthorityError> {
        use notify::Watcher as _;

        let path = self.revocation_file.clone();
        let this = self.clone();
        let (tx_signal, mut rx_signal) = tokio::sync::mpsc::channel::<()>(16);
        let (tx_broadcast, _) = broadcast::channel(1024);
        let tx_for_task = tx_broadcast.clone();

        let watch_path = path.clone();
        let mut watcher = notify::recommended_watcher(
            move |res: notify::Result<notify::Event>| match res {
                Ok(event)
                    if matches!(
                        event.kind,
                        notify::event::EventKind::Modify(_)
                            | notify::event::EventKind::Create(_)
                    ) =>
                {
                    tracing::info!(path = %watch_path.display(), "revocation file changed; reloading");
                    let _ = tx_signal.try_send(());
                }
                Err(error) => tracing::error!(?error, "revocation file watch error"),
                _ => {}
            },
        )
        .map_err(|e| AuthorityError::WatchFailed { reason: e.to_string() })?;

        watcher
            .watch(&path, notify::RecursiveMode::NonRecursive)
            .map_err(|e| AuthorityError::WatchFailed {
                reason: e.to_string(),
            })?;

        let task = tokio::spawn(async move {
            while rx_signal.recv().await.is_some() {
                match this.reload_from_file().await {
                    Ok(new_entries) => {
                        for entry in new_entries {
                            if let Ok(n) = tx_for_task.send(entry) {
                                tracing::debug!(receivers = n, "revocation event broadcast")
                            } else {
                                tracing::debug!(
                                    "no active revocation subscribers; event not broadcast"
                                )
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "revocation file reload failed; keeping previous state");
                    }
                }
            }
        });

        Ok(RevocationStoreWatcher {
            _watcher: watcher,
            task,
            tx: tx_broadcast,
        })
    }
}

/// Owns the file watcher and reload task for a [`RevocationStore`].
/// Dropping this handle stops the file watch and the reload task.
pub struct RevocationStoreWatcher {
    _watcher: notify::RecommendedWatcher,
    task: JoinHandle<()>,
    tx: broadcast::Sender<RevocationEntry>,
}

impl RevocationStoreWatcher {
    /// Subscribe to new revocation events as they are ingested from the file.
    pub fn subscribe(&self) -> broadcast::Receiver<RevocationEntry> {
        self.tx.subscribe()
    }

    /// Abort the background reload task immediately.
    #[expect(dead_code, reason = "explicit shutdown hook for callers that need it")]
    pub fn abort(&self) {
        self.task.abort();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_new_revocation_store_empty() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        let store = RevocationStore::new(&file);
        assert!(store.is_ok());
    }

    #[test]
    fn test_load_existing_revocations() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        let id1 = TokenId::new();
        let id2 = TokenId::new();
        std::fs::write(&file, format!("{id1}\n{id2}\n")).unwrap_or_else(|e| panic!("{e}"));

        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));
        assert!(store.entries.blocking_read().contains_key(&id1));
        assert!(store.entries.blocking_read().contains_key(&id2));
    }

    #[test]
    fn test_load_ignores_empty_lines() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        let id1 = TokenId::new();
        let id2 = TokenId::new();
        std::fs::write(&file, format!("{id1}\n\n  \n{id2}\n")).unwrap_or_else(|e| panic!("{e}"));

        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(store.entries.blocking_read().len(), 2);
    }

    /// `revoke()` writes to file; the watcher updates memory and broadcasts.
    /// After the first broadcast the ID is in memory, so a second `revoke()` is
    /// a no-op (idempotency check passes in-memory) and the entry count stays 1.
    #[tokio::test]
    async fn test_revoke_idempotent() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap_or_else(|e| panic!("{e}"));

        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));
        let watcher = store.watch().unwrap_or_else(|e| panic!("{e}"));
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        store
            .revoke(id, "test")
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        // Wait for the watcher to update in-memory state.
        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for revocation event"))
            .unwrap_or_else(|e| panic!("{e}"));

        // In-memory idempotency: second revoke is a no-op, no second file write.
        store
            .revoke(id, "test again")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(store.entries.read().await.len(), 1);
    }

    #[tokio::test]
    async fn test_is_revoked() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap_or_else(|e| panic!("{e}"));

        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));
        let watcher = store.watch().unwrap_or_else(|e| panic!("{e}"));
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        assert!(!store.is_revoked(id).await);

        store
            .revoke(id, "test")
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for revocation event"))
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(store.is_revoked(id).await);
    }

    #[tokio::test]
    async fn test_events_since() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap_or_else(|e| panic!("{e}"));

        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));
        let watcher = store.watch().unwrap_or_else(|e| panic!("{e}"));
        let mut rx = watcher.subscribe();

        let before = Utc::now() - chrono::Duration::seconds(1);
        let id1 = TokenId::new();
        let id2 = TokenId::new();

        // Write both IDs at once so one file event triggers a single reload for both.
        tokio::fs::write(&file, format!("{id1}\n{id2}\n"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        // Collect exactly 2 broadcast entries.
        for _ in 0..2 {
            tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout waiting for revocation event"))
                .unwrap_or_else(|e| panic!("{e}"));
        }

        let events = store.events_since(before).await;
        assert_eq!(events.len(), 2);

        let future = Utc::now() + chrono::Duration::seconds(1);
        assert!(store.events_since(future).await.is_empty());
    }

    #[tokio::test]
    async fn watch_reloads_on_file_change() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");

        // new() creates the file (empty) via create(true). Truncate it to ensure
        // load_from_content is skipped (blocking_write is not safe in async context).
        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(&file, "").unwrap_or_else(|e| panic!("{e}"));
        let watcher = store.watch().unwrap_or_else(|e| panic!("{e}"));
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        std::fs::write(&file, format!("{id}\n")).unwrap_or_else(|e| panic!("{e}"));

        // The broadcast event is the completion signal — no polling needed.
        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for revocation event"))
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(store.is_revoked(id).await);
    }

    #[tokio::test]
    async fn watch_subscribe_receives_new_entries() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");

        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));

        std::fs::write(&file, "").unwrap_or_else(|e| panic!("{e}"));
        let watcher = store.watch().unwrap_or_else(|e| panic!("{e}"));
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        std::fs::write(&file, format!("{id}\n")).unwrap_or_else(|e| panic!("{e}"));

        let entry = tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for revocation event"))
            .unwrap_or_else(|e| panic!("{e}"));

        assert_eq!(entry.token_id, id);
    }
}
