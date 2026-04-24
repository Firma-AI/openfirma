use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use chrono::{DateTime, Duration, Utc};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;

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
///
/// File format: `token_id\trevoked_at_rfc3339\treason\n` (one entry per line).
/// Legacy lines containing only a bare token ID are accepted for backward
/// compatibility; they get `Utc::now()` as their revocation timestamp, which
/// is conservative (treats them as freshly revoked rather than potentially
/// expirable).
///
/// Entries whose `revoked_at + token_ttl < now` are considered expired: the
/// token would fail the expiry check in Stage 1 regardless of revocation status,
/// so they can be safely ignored and removed via [`RevocationStore::compact_file`].
#[derive(Clone)]
pub struct RevocationStore {
    /// Revoked token IDs mapped to their revocation entries.
    entries: Arc<RwLock<HashMap<TokenId, RevocationEntry>>>,
    /// Ordered log for replay (FR-6: replay events after `since`).
    log: Arc<RwLock<Vec<RevocationEntry>>>,
    /// Path to the revocation file.
    revocation_file: PathBuf,
    /// Maximum token TTL issued by this Authority. Entries older than this
    /// are expired and can be trimmed from the file.
    token_ttl: Duration,
}

impl RevocationStore {
    /// Create a new revocation store, loading any existing entries from file.
    ///
    /// `token_ttl` is the maximum lifetime of tokens issued by this Authority.
    /// Entries older than `token_ttl` are skipped on load (they are already expired).
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read.
    pub fn try_new(revocation_file: &Path, token_ttl: Duration) -> Result<Self> {
        let store = Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            log: Arc::new(RwLock::new(Vec::new())),
            revocation_file: revocation_file.to_path_buf(),
            token_ttl,
        };

        // Load existing revocations from file (if it exists and is non-empty).
        // `load_from_content` uses blocking_write and must not be called in an
        // async context, so we skip it when the file has no parseable lines.
        if revocation_file.is_file() {
            let content = std::fs::read_to_string(revocation_file).with_context(|| {
                format!("cannot read revocation file {}", revocation_file.display())
            })?;
            if content.lines().any(|l| !l.trim().is_empty()) {
                let count = store.load_from_content(&content);
                tracing::info!(count, "loaded existing revocations from file");
            }
        }

        Ok(store)
    }

    /// Parse a single line from the revocation file into a [`RevocationEntry`].
    ///
    /// Accepts both the current format (`token_id\trevoked_at_rfc3339\treason`)
    /// and the legacy format (bare `token_id`). Returns `None` for blank or
    /// unparseable lines.
    fn parse_line(line: &str, fallback_timestamp: DateTime<Utc>) -> Option<RevocationEntry> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        // Split into at most 3 parts on the first two tabs.
        let mut parts = line.splitn(3, '\t');
        let raw_id = parts.next()?;
        let token_id = raw_id.parse::<TokenId>().ok()?;

        let (timestamp, reason) = match (parts.next(), parts.next()) {
            (Some(raw_ts), Some(reason)) => {
                let ts = DateTime::parse_from_rfc3339(raw_ts)
                    .map_or(fallback_timestamp, |dt| dt.with_timezone(&Utc));
                (ts, reason.to_string())
            }
            _ => (fallback_timestamp, "file-based revocation".to_string()),
        };

        Some(RevocationEntry {
            token_id,
            reason,
            timestamp,
        })
    }

    /// Returns `true` if the revocation entry is old enough that the token
    /// would fail the expiry check in Stage 1 regardless of revocation status.
    fn is_expired(&self, entry: &RevocationEntry, now: DateTime<Utc>) -> bool {
        entry.timestamp + self.token_ttl < now
    }

    /// Load revocations from file content. Skips expired entries.
    /// Returns the number of new entries added.
    fn load_from_content(&self, content: &str) -> usize {
        let mut entries = self.entries.blocking_write();
        let mut log = self.log.blocking_write();
        let now = Utc::now();
        let mut count = 0;

        for (line_number, line) in content.lines().enumerate() {
            let Some(entry) = Self::parse_line(line, now) else {
                if !line.trim().is_empty() {
                    tracing::warn!(
                        line_number,
                        line,
                        "unparseable line in revocation file, ignoring"
                    );
                }
                continue;
            };

            if self.is_expired(&entry, now) {
                tracing::debug!(token_id = %entry.token_id, "skipping expired revocation entry on load");
                continue;
            }

            if entries.contains_key(&entry.token_id) {
                continue;
            }
            entries.insert(entry.token_id, entry.clone());
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
    /// Returns an error if the revocation file cannot be opened or written to.
    pub async fn revoke(&self, token_id: TokenId, reason: &str) -> Result<()> {
        if self.entries.read().await.contains_key(&token_id) {
            tracing::debug!(%token_id, "duplicate revocation ignored");
            return Ok(());
        }

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.revocation_file)
            .await
            .with_context(|| {
                format!(
                    "cannot open revocation file {}",
                    self.revocation_file.display()
                )
            })?;

        let revoked_at = Utc::now();
        let line = format!("{token_id}\t{}\t{reason}\n", revoked_at.to_rfc3339());
        file.write_all(line.as_bytes())
            .await
            .context("cannot write to revocation file")?;

        tracing::info!(%token_id, %reason, %revoked_at, "token written to revocation file; watcher will update memory");
        Ok(())
    }

    /// Check if a token has been revoked.
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
    async fn reload_from_file(&self) -> Result<Vec<RevocationEntry>> {
        let content = match tokio::fs::read_to_string(&self.revocation_file).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "cannot read revocation file {}",
                        self.revocation_file.display()
                    )
                });
            }
        };

        let now = Utc::now();
        let mut new_entries = Vec::new();
        let mut entries = self.entries.write().await;
        let mut log = self.log.write().await;

        for line in content.lines() {
            let Some(entry) = Self::parse_line(line, now) else {
                if !line.trim().is_empty() {
                    tracing::warn!(line, "unparseable line in revocation file, ignoring");
                }
                continue;
            };

            if self.is_expired(&entry, now) {
                tracing::debug!(token_id = %entry.token_id, "skipping expired revocation entry on reload");
                continue;
            }

            if entries.contains_key(&entry.token_id) {
                continue;
            }
            entries.insert(entry.token_id, entry.clone());
            log.push(entry.clone());
            new_entries.push(entry);
        }

        Ok(new_entries)
    }

    /// Rewrite the revocation file, dropping entries that have expired.
    ///
    /// An entry is considered expired when `revoked_at + token_ttl < now`:
    /// the token would fail Stage 1 expiry checks regardless of its revocation
    /// status, so the entry is no longer needed. This prevents unbounded file
    /// growth for long-running deployments.
    ///
    /// The file watcher will detect the rewrite and trigger a reload, which is
    /// a no-op since the same non-expired entries are already in memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub async fn compact_file(&self) -> Result<()> {
        let now = Utc::now();
        let entries = self.entries.read().await;
        let mut lines: Vec<String> = entries
            .values()
            .filter(|e| !self.is_expired(e, now))
            .map(|e| {
                format!(
                    "{}\t{}\t{}\n",
                    e.token_id,
                    e.timestamp.to_rfc3339(),
                    e.reason
                )
            })
            .collect();
        drop(entries);
        lines.sort_unstable();
        let content: String = lines.concat();
        tokio::fs::write(&self.revocation_file, content)
            .await
            .with_context(|| {
                format!(
                    "cannot compact revocation file {}",
                    self.revocation_file.display()
                )
            })?;
        tracing::info!(path = %self.revocation_file.display(), "revocation file compacted");
        Ok(())
    }

    /// Watch the revocation file for changes and reload automatically.
    ///
    /// Only [`notify::event::EventKind::Modify`] and [`notify::event::EventKind::Create`] events
    /// trigger a reload. Returns a [`RevocationStoreWatcher`]: keep it alive for the watch to stay
    /// active. Dropping it stops the file watch and the reload task.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS file watcher cannot be created or registered.
    pub fn watch(&self) -> Result<RevocationStoreWatcher> {
        use notify::Watcher as _;

        let path = self.revocation_file.clone();
        let watch_root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
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
                    if !event.paths.iter().any(|event_path| event_path == &watch_path) {
                        return;
                    }
                    tracing::info!(path = %watch_path.display(), "revocation file changed; reloading");
                    let _ = tx_signal.try_send(());
                }
                Err(error) => tracing::error!(?error, "revocation file watch error"),
                _ => {}
            },
        )
        .context("failed to create revocation file watcher")?;

        watcher
            .watch(&watch_root, notify::RecursiveMode::NonRecursive)
            .with_context(|| {
                format!(
                    "failed to watch revocation path root {}",
                    watch_root.display()
                )
            })?;

        let task = tokio::spawn(async move {
            while rx_signal.recv().await.is_some() {
                match this.reload_from_file().await {
                    Ok(new_entries) => {
                        for entry in new_entries {
                            if let Ok(n) = tx_for_task.send(entry) {
                                tracing::debug!(receivers = n, "revocation event broadcast");
                            } else {
                                tracing::debug!(
                                    "no active revocation subscribers; event not broadcast"
                                );
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
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<RevocationEntry> {
        self.tx.subscribe()
    }

    /// Abort the background reload task immediately.
    pub fn abort(&self) {
        self.task.abort();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn ttl_1h() -> Duration {
        Duration::seconds(3600)
    }

    fn store(file: &Path) -> RevocationStore {
        RevocationStore::try_new(file, ttl_1h()).unwrap()
    }

    #[test]
    fn new_revocation_store_empty() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        assert!(RevocationStore::try_new(&file, ttl_1h()).is_ok());
    }

    #[test]
    fn load_existing_revocations_legacy_format() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id1 = TokenId::new();
        let id2 = TokenId::new();
        std::fs::write(&file, format!("{id1}\n{id2}\n")).unwrap();

        let s = store(&file);
        assert!(s.entries.blocking_read().contains_key(&id1));
        assert!(s.entries.blocking_read().contains_key(&id2));
    }

    #[test]
    fn load_existing_revocations_new_format() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id = TokenId::new();
        let ts = Utc::now().to_rfc3339();
        std::fs::write(&file, format!("{id}\t{ts}\texplicit reason\n")).unwrap();

        let s = store(&file);
        let entries = s.entries.blocking_read();
        let entry = entries.get(&id).unwrap();
        assert_eq!(entry.reason, "explicit reason");
    }

    #[test]
    fn load_ignores_empty_lines() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id1 = TokenId::new();
        let id2 = TokenId::new();
        std::fs::write(&file, format!("{id1}\n\n  \n{id2}\n")).unwrap();

        assert_eq!(store(&file).entries.blocking_read().len(), 2);
    }

    #[test]
    fn expired_entries_skipped_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id = TokenId::new();
        // Revoked 2 hours ago, TTL is 1 hour → expired.
        let old_ts = (Utc::now() - Duration::hours(2)).to_rfc3339();
        std::fs::write(&file, format!("{id}\t{old_ts}\told revocation\n")).unwrap();

        assert!(
            store(&file).entries.blocking_read().is_empty(),
            "expired entry must not load"
        );
    }

    #[test]
    fn non_expired_entries_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id = TokenId::new();
        // Revoked 30 minutes ago, TTL is 1 hour → still valid.
        let recent_ts = (Utc::now() - Duration::minutes(30)).to_rfc3339();
        std::fs::write(&file, format!("{id}\t{recent_ts}\trecent reason\n")).unwrap();

        assert!(store(&file).entries.blocking_read().contains_key(&id));
    }

    /// `revoke()` writes to file; the watcher updates memory and broadcasts.
    /// After the first broadcast the ID is in memory, so a second `revoke()` is
    /// a no-op (idempotency check passes in-memory) and the entry count stays 1.
    #[tokio::test]
    async fn revoke_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap();

        let s = store(&file);
        let watcher = s.watch().unwrap();
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        s.revoke(id, "test").await.unwrap();

        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();

        s.revoke(id, "test again").await.unwrap();
        assert_eq!(s.entries.read().await.len(), 1);
    }

    #[tokio::test]
    async fn revoke_writes_timestamp_and_reason() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap();

        let s = store(&file);
        let watcher = s.watch().unwrap();
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        s.revoke(id, "security breach").await.unwrap();

        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();

        let content = std::fs::read_to_string(&file).unwrap();
        let line = content.lines().next().unwrap();
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        assert_eq!(parts.len(), 3, "line must have 3 tab-separated fields");
        assert!(
            parts[1].contains('T'),
            "second field must be an ISO 8601 timestamp"
        );
        assert_eq!(parts[2], "security breach");
    }

    #[tokio::test]
    async fn is_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap();

        let s = store(&file);
        let watcher = s.watch().unwrap();
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        assert!(!s.is_revoked(id).await);

        s.revoke(id, "test").await.unwrap();

        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(s.is_revoked(id).await);
    }

    #[tokio::test]
    async fn events_since() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap();

        let s = store(&file);
        let watcher = s.watch().unwrap();
        let mut rx = watcher.subscribe();

        let before = Utc::now() - chrono::Duration::seconds(1);
        let id1 = TokenId::new();
        let id2 = TokenId::new();

        // Write both IDs at once so one file event triggers a single reload for both.
        tokio::fs::write(&file, format!("{id1}\n{id2}\n"))
            .await
            .unwrap();

        for _ in 0..2 {
            tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
                .await
                .unwrap()
                .unwrap();
        }

        let events = s.events_since(before).await;
        assert_eq!(events.len(), 2);

        let future = Utc::now() + chrono::Duration::seconds(1);
        assert!(s.events_since(future).await.is_empty());
    }

    #[tokio::test]
    async fn compact_file_removes_expired() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");

        let id_old = TokenId::new();
        let id_new = TokenId::new();
        let old_ts = (Utc::now() - Duration::hours(2)).to_rfc3339();
        let new_ts = (Utc::now() - Duration::minutes(30)).to_rfc3339();
        std::fs::write(
            &file,
            format!("{id_new}\t{new_ts}\tkeep\n{id_old}\t{old_ts}\tdrop\n"),
        )
        .unwrap();

        // store() calls blocking_write; spawn_blocking keeps it off the async executor.
        let file_clone = file.clone();
        let s = tokio::task::spawn_blocking(move || store(&file_clone))
            .await
            .unwrap();
        s.compact_file().await.unwrap();

        let content = std::fs::read_to_string(&file).unwrap();
        assert!(
            content.contains(&id_new.to_string()),
            "non-expired entry must be kept"
        );
        assert!(
            !content.contains(&id_old.to_string()),
            "expired entry must be removed"
        );
    }

    #[tokio::test]
    async fn watch_reloads_on_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");

        let s = store(&file);
        let watcher = s.watch().unwrap();
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        std::fs::write(&file, format!("{id}\n")).unwrap();

        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(s.is_revoked(id).await);
    }

    #[tokio::test]
    async fn watch_subscribe_receives_new_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");

        let s = store(&file);
        std::fs::write(&file, "").unwrap();
        let watcher = s.watch().unwrap();
        let mut rx = watcher.subscribe();

        let id = TokenId::new();
        std::fs::write(&file, format!("{id}\n")).unwrap();

        let entry = tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(entry.token_id, id);
    }
}
