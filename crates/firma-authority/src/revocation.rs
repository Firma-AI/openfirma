use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, RwLock};

use crate::error::AuthorityError;

/// An event representing the revocation of a capability token.
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    pub token_id: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

/// In-memory revocation store with file-based ingestion and broadcast support.
///
/// Maintains a log of revocation events and broadcasts new events to all
/// connected `WatchRevocations` streams (FR-6, FR-7).
pub struct RevocationStore {
    /// Revoked token IDs mapped to their revocation entries.
    entries: Arc<RwLock<HashMap<String, RevocationEntry>>>,
    /// Ordered log for replay (FR-6: replay events after `since`).
    log: Arc<RwLock<Vec<RevocationEntry>>>,
    /// Broadcast channel for new revocation events.
    tx: broadcast::Sender<RevocationEntry>,
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
        let (tx, _rx) = broadcast::channel(1024);
        let store = Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            log: Arc::new(RwLock::new(Vec::new())),
            tx,
            revocation_file: revocation_file.to_path_buf(),
        };

        // Load existing revocations from file (if it exists)
        if revocation_file.is_file() {
            let content =
                std::fs::read_to_string(revocation_file).map_err(|e| {
                    AuthorityError::RevocationError {
                        reason: format!(
                            "cannot read revocation file {}: {e}",
                            revocation_file.display()
                        ),
                    }
                })?;
            let count = store.load_from_content(&content);
            tracing::info!(count, "loaded existing revocations from file");
        }

        Ok(store)
    }

    /// Load revocations from file content (one token ID per line).
    /// Returns the number of new entries added.
    fn load_from_content(&self, content: &str) -> usize {
        let mut entries = self.entries.blocking_write();
        let mut log = self.log.blocking_write();
        let mut count = 0;

        for line in content.lines() {
            let token_id = line.trim();
            if token_id.is_empty() || entries.contains_key(token_id) {
                continue;
            }
            let entry = RevocationEntry {
                token_id: token_id.to_string(),
                reason: "file-based revocation".to_string(),
                timestamp: Utc::now(),
            };
            entries.insert(token_id.to_string(), entry.clone());
            log.push(entry);
            count += 1;
        }

        count
    }

    /// Revoke a token by ID. Idempotent — duplicate revocations are no-ops.
    #[allow(dead_code)] // Called via gRPC and file watcher paths
    pub async fn revoke(&self, token_id: &str, reason: &str) {
        let mut entries = self.entries.write().await;
        if entries.contains_key(token_id) {
            tracing::debug!(token_id, "duplicate revocation ignored");
            return;
        }

        let entry = RevocationEntry {
            token_id: token_id.to_string(),
            reason: reason.to_string(),
            timestamp: Utc::now(),
        };

        entries.insert(token_id.to_string(), entry.clone());
        self.log.write().await.push(entry.clone());

        // Broadcast to watchers — ignore send errors (no receivers is fine)
        let _ = self.tx.send(entry);

        tracing::info!(token_id, reason, "token revoked");
    }

    /// Check if a token has been revoked.
    #[allow(dead_code)] // Public API used by sidecar integration
    pub async fn is_revoked(&self, token_id: &str) -> bool {
        self.entries.read().await.contains_key(token_id)
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

    /// Subscribe to new revocation events.
    pub fn subscribe(&self) -> broadcast::Receiver<RevocationEntry> {
        self.tx.subscribe()
    }

    /// Reload revocations from the file on disk. Called by file watcher.
    pub async fn reload_from_file(&self) -> Result<(), AuthorityError> {
        if !self.revocation_file.is_file() {
            return Ok(());
        }

        let content = tokio::fs::read_to_string(&self.revocation_file)
            .await
            .map_err(|e| AuthorityError::RevocationError {
                reason: format!(
                    "cannot read revocation file {}: {e}",
                    self.revocation_file.display()
                ),
            })?;

        let mut new_entries = Vec::new();
        {
            let mut entries = self.entries.write().await;
            let mut log = self.log.write().await;

            for line in content.lines() {
                let token_id = line.trim();
                if token_id.is_empty() || entries.contains_key(token_id) {
                    continue;
                }
                let entry = RevocationEntry {
                    token_id: token_id.to_string(),
                    reason: "file-based revocation".to_string(),
                    timestamp: Utc::now(),
                };
                entries.insert(token_id.to_string(), entry.clone());
                log.push(entry.clone());
                new_entries.push(entry);
            }
        }

        for entry in new_entries {
            let _ = self.tx.send(entry);
        }

        Ok(())
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
        std::fs::write(&file, "tok_001\ntok_002\n").unwrap_or_else(|e| panic!("{e}"));

        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));
        assert!(store.entries.blocking_read().contains_key("tok_001"));
        assert!(store.entries.blocking_read().contains_key("tok_002"));
    }

    #[test]
    fn test_load_ignores_empty_lines() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "tok_001\n\n  \ntok_002\n").unwrap_or_else(|e| panic!("{e}"));

        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(store.entries.blocking_read().len(), 2);
    }

    #[tokio::test]
    async fn test_revoke_idempotent() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));

        store.revoke("tok_001", "test").await;
        store.revoke("tok_001", "test again").await;
        assert_eq!(store.entries.read().await.len(), 1);
    }

    #[tokio::test]
    async fn test_is_revoked() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));

        assert!(!store.is_revoked("tok_001").await);
        store.revoke("tok_001", "test").await;
        assert!(store.is_revoked("tok_001").await);
    }

    #[tokio::test]
    async fn test_events_since() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let file = dir.path().join("revocations.txt");
        let store = RevocationStore::new(&file).unwrap_or_else(|e| panic!("{e}"));

        let before = Utc::now() - chrono::Duration::seconds(1);
        store.revoke("tok_001", "test").await;
        store.revoke("tok_002", "test").await;

        let events = store.events_since(before).await;
        assert_eq!(events.len(), 2);

        let future = Utc::now() + chrono::Duration::seconds(1);
        let events = store.events_since(future).await;
        assert!(events.is_empty());
    }
}
