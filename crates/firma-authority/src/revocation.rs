use std::collections::HashMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use chrono::{DateTime, Duration, Utc};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;

use firma_identifiers::TokenId;

/// How long a revocation stays in the delivered set past the point its token
/// must have expired.
///
/// Stage 1 compares a token's expiry against the Sidecar's own clock with no
/// leeway, so a Sidecar running behind the Authority still accepts a token the
/// Authority considers expired. Without this the set would drop a revocation
/// exactly as its token expires — zero margin for a token revoked the instant
/// it was issued. It assumes skew stays inside the margin; nothing measures it.
const REVOCATION_SET_SKEW_MARGIN: Duration = Duration::minutes(5);

/// An event representing the revocation of a capability token.
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    pub(crate) token_id: TokenId,
    pub(crate) reason: String,
    pub(crate) timestamp: DateTime<Utc>,
}

/// In-memory revocation store with file-based ingestion.
///
/// The revocation file is the source of truth. In-memory state is always derived
/// from the file via [`RevocationStoreWatcher`], which handles reloading and
/// broadcasting to live subscribers.
///
/// File format: `token_id\trevoked_at_rfc3339\treason\n` (one entry per line).
/// Lines containing only a bare canonical `ctok` ID are accepted; they get
/// `Utc::now()` as their revocation timestamp, which is conservative (treats
/// them as freshly revoked rather than potentially expirable). Legacy raw UUID
/// capability IDs are invalid and are not loaded.
///
/// Entries whose `revoked_at + token_ttl + REVOCATION_SET_SKEW_MARGIN < now`
/// are considered expired: the token would fail the expiry check in Stage 1 on
/// every clock within the margin, regardless of revocation status, so they can
/// be safely ignored and removed via [`RevocationStore::compact_file`].
#[derive(Clone)]
pub struct RevocationStore {
    /// Internal state
    state: Arc<RwLock<RevocationState>>,
    /// Path to the revocation file.
    revocation_file: PathBuf,
    /// Maximum token TTL issued by this Authority. Entries older than this
    /// are expired and can be trimmed from the file.
    token_ttl: Duration,
    /// Clock-skew allowance added to `token_ttl` before an entry is expired.
    skew_margin: Duration,
}

#[derive(Default)]
struct RevocationState {
    /// Revoked token IDs mapped to their revocation entries.
    entries: HashMap<TokenId, RevocationEntry>,
}

impl RevocationStore {
    /// Create a new revocation store, loading any existing entries from file.
    ///
    /// `token_ttl` is the maximum lifetime of tokens issued by this Authority.
    /// Entries past `token_ttl` plus [`REVOCATION_SET_SKEW_MARGIN`] are skipped
    /// on load: the tokens they name are expired on every clock in range.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read.
    pub fn try_new(revocation_file: &Path, token_ttl: Duration) -> Result<Self> {
        let store = Self {
            state: Arc::default(),
            revocation_file: revocation_file.to_path_buf(),
            token_ttl,
            skew_margin: REVOCATION_SET_SKEW_MARGIN,
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
    /// and the bare canonical `token_id` format. Returns `None` for blank or
    /// unparseable lines, including legacy raw UUID IDs.
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
    /// would fail the expiry check in Stage 1 on every clock within
    /// [`REVOCATION_SET_SKEW_MARGIN`], regardless of revocation status.
    /// Every path that decides an entry is past use — load, reload, the
    /// delivered set, and file compaction — asks this, so an entry cannot
    /// leave one of them while another still expects it.
    fn is_expired(&self, entry: &RevocationEntry, now: DateTime<Utc>) -> bool {
        entry.timestamp + self.token_ttl + self.skew_margin < now
    }

    /// Shortens the skew margin so a test can reach the expiry boundary
    /// without waiting out the production one.
    #[cfg(test)]
    fn with_skew_margin(mut self, skew_margin: Duration) -> Self {
        self.skew_margin = skew_margin;
        self
    }

    /// Load revocations from file content. Skips expired entries.
    /// Returns the number of new entries added.
    fn load_from_content(&self, content: &str) -> usize {
        let mut state = self.state.blocking_write();
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

            if state.entries.contains_key(&entry.token_id) {
                continue;
            }
            state.entries.insert(entry.token_id, entry);
            count += 1;
        }

        drop(state);
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
        if self.state.read().await.entries.contains_key(&token_id) {
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
        self.state.read().await.entries.contains_key(&token_id)
    }

    /// Every revocation still worth sending, oldest-first.
    ///
    /// This is the whole set `WatchRevocations` sends, not a delta, bounded by
    /// the same [`RevocationStore::is_expired`] rule that governs loading and
    /// file compaction. The filter runs here because entries are never removed
    /// from memory — compaction rewrites the file alone — so without it the
    /// set would be bounded only by process lifetime, and every revocation
    /// ever ingested would grow the message sent on every change.
    pub(crate) async fn current_set(&self) -> Vec<RevocationEntry> {
        let now = Utc::now();
        let mut entries: Vec<_> = self
            .state
            .read()
            .await
            .entries
            .values()
            .filter(|entry| !self.is_expired(entry, now))
            .cloned()
            .collect();
        entries.sort_unstable_by_key(|entry| (entry.timestamp, entry.token_id));
        entries
    }

    /// Reload revocations from the file on disk.
    ///
    /// Returns the newly-added entries so that [`RevocationStoreWatcher`] can
    /// tell a reload that changed the set from one that did not.
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
        let mut state = self.state.write().await;

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

            if state.entries.contains_key(&entry.token_id) {
                continue;
            }
            state.entries.insert(entry.token_id, entry.clone());
            new_entries.push(entry);
        }

        drop(state);
        Ok(new_entries)
    }

    /// Rewrite the revocation file, dropping entries that have expired.
    ///
    /// An entry is considered expired when
    /// `revoked_at + token_ttl + REVOCATION_SET_SKEW_MARGIN < now`: the token
    /// would fail Stage 1 expiry checks on every clock within the margin,
    /// regardless of its revocation status, so the entry is no longer needed. This prevents unbounded file
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
        let mut lines = {
            let state = self.state.read().await;
            state
                .entries
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
                .collect::<Vec<_>>()
        };
        lines.sort_unstable();
        let content: String = lines.concat();
        let compact_revocation_future = async {
            let mut file = tokio::fs::File::create(&self.revocation_file).await?;
            file.write_all(content.as_ref()).await?;
            file.sync_all().await?;
            Ok::<_, anyhow::Error>(())
        };
        compact_revocation_future.await.with_context(|| {
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
    pub(crate) fn watch(self) -> Result<RevocationStoreWatcher> {
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

        // macOS FSEvents reports canonical paths (e.g. `/private/var/...`) while
        // the user-supplied path may be the symlinked form (`/var/...`). Match by
        // file name within the watched directory; `RecursiveMode::NonRecursive`
        // limits events to direct children, so this stays unambiguous.
        let watch_file_name = path.file_name().map(std::ffi::OsString::from);
        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
                Ok(event)
                    if matches!(
                        event.kind,
                        notify::event::EventKind::Modify(_) | notify::event::EventKind::Create(_)
                    ) =>
                {
                    let matches_target = event.paths.iter().any(|event_path| {
                        event_path == &path
                            || (watch_file_name.is_some()
                                && event_path.file_name() == watch_file_name.as_deref())
                    });
                    if !matches_target {
                        return;
                    }
                    tracing::info!(path = %path.display(), "revocation file changed; reloading");
                    let _ = tx_signal.try_send(());
                }
                Err(error) => tracing::error!(?error, "revocation file watch error"),
                _ => {}
            })
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
                    // One signal per reload, however many entries it added:
                    // subscribers re-read the whole set, so a signal per entry
                    // would resend that same set once for each.
                    Ok(new_entries) if new_entries.is_empty() => {}
                    Ok(_) => {
                        if let Ok(n) = tx_for_task.send(()) {
                            tracing::debug!(receivers = n, "revocation change signalled");
                        } else {
                            tracing::debug!(
                                "no active revocation subscribers; change not signalled"
                            );
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
            _task: task,
            store: self,
            tx: tx_broadcast,
        })
    }
}

/// Owns the file watcher and reload task for a [`RevocationStore`].
/// Dropping this handle stops the file watch and the reload task.
pub struct RevocationStoreWatcher {
    _watcher: notify::RecommendedWatcher,
    _task: JoinHandle<()>,
    store: RevocationStore,
    tx: broadcast::Sender<()>,
}

impl Deref for RevocationStoreWatcher {
    type Target = RevocationStore;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl RevocationStoreWatcher {
    /// Subscribe to a signal raised once for every reload that ingests at
    /// least one new revocation from the file.
    #[must_use]
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

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
        let id1 = TokenId::generate();
        let id2 = TokenId::generate();
        std::fs::write(&file, format!("{id1}\n{id2}\n")).unwrap();

        let s = store(&file);
        let entries = &s.state.blocking_read().entries;
        assert!(entries.contains_key(&id1));
        assert!(entries.contains_key(&id2));
    }

    #[test]
    fn load_existing_revocations_new_format() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id = TokenId::generate();
        let ts = Utc::now().to_rfc3339();
        std::fs::write(&file, format!("{id}\t{ts}\texplicit reason\n")).unwrap();

        let s = store(&file);
        let reason = {
            let entries = &s.state.blocking_read().entries;
            entries.get(&id).unwrap().reason.clone()
        };
        assert_eq!(reason, "explicit reason");
    }

    #[test]
    fn load_ignores_empty_lines() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id1 = TokenId::generate();
        let id2 = TokenId::generate();
        std::fs::write(&file, format!("{id1}\n\n  \n{id2}\n")).unwrap();

        let s = store(&file);
        let entries = &s.state.blocking_read().entries;
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn expired_entries_skipped_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id = TokenId::generate();
        // Revoked 2 hours ago, TTL is 1 hour → expired.
        let old_ts = (Utc::now() - Duration::hours(2)).to_rfc3339();
        std::fs::write(&file, format!("{id}\t{old_ts}\told revocation\n")).unwrap();

        let s = store(&file);
        let entries = &s.state.blocking_read().entries;
        assert!(entries.is_empty(), "expired entry must not load");
    }

    #[test]
    fn non_expired_entries_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let id = TokenId::generate();
        // Revoked 30 minutes ago, TTL is 1 hour → still valid.
        let recent_ts = (Utc::now() - Duration::minutes(30)).to_rfc3339();
        std::fs::write(&file, format!("{id}\t{recent_ts}\trecent reason\n")).unwrap();

        let s = store(&file);
        let entries = &s.state.blocking_read().entries;
        assert!(entries.contains_key(&id));
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
        let s = s.watch().unwrap();
        let mut rx = s.subscribe();

        let id = TokenId::generate();
        s.revoke(id, "test").await.unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        s.revoke(id, "test again").await.unwrap();
        let entries = &s.state.read().await.entries;
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn revoke_writes_timestamp_and_reason() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap();

        let s = store(&file);
        let s = s.watch().unwrap();
        let mut rx = s.subscribe();

        let id = TokenId::generate();
        s.revoke(id, "security breach").await.unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
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
        let s = s.watch().unwrap();
        let mut rx = s.subscribe();

        let id = TokenId::generate();
        assert!(!s.is_revoked(id).await);

        s.revoke(id, "test").await.unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(s.is_revoked(id).await);
    }

    /// The delivered set is filtered at read time, by `token_ttl` plus the
    /// production margin: entries stay resident, so only this filter keeps an
    /// expired revocation off the wire. Written against literal offsets so
    /// shrinking the margin fails here rather than passing by construction.
    #[tokio::test]
    async fn current_set_keeps_an_entry_through_the_skew_margin() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        let ttl = Duration::seconds(900);
        let inside = TokenId::generate();
        let outside = TokenId::generate();
        let now = Utc::now();
        // Both are past the TTL. `inside` is four minutes past it, which a
        // five-minute margin must still cover; `outside` is six.
        std::fs::write(
            &file,
            format!(
                "{inside}\t{}\tinside the margin\n{outside}\t{}\tpast the margin\n",
                (now - ttl - Duration::minutes(4)).to_rfc3339(),
                (now - ttl - Duration::minutes(6)).to_rfc3339(),
            ),
        )
        .unwrap();

        // `try_new` loads with a blocking lock, so it cannot run on the test
        // runtime's thread.
        let loaded = file.clone();
        let s =
            tokio::task::spawn_blocking(move || RevocationStore::try_new(&loaded, ttl).unwrap())
                .await
                .unwrap();

        let tokens: HashSet<_> = s
            .current_set()
            .await
            .iter()
            .map(|entry| entry.token_id)
            .collect();
        assert_eq!(
            tokens,
            HashSet::from([inside]),
            "the margin must outlive the TTL, and only by itself"
        );
        assert!(
            s.is_revoked(inside).await,
            "entries stay held; only the delivered set is filtered"
        );
    }

    /// Loading filters by the same rule, so an entry only becomes stale while
    /// resident — which is the case only this read-time filter covers.
    #[tokio::test]
    async fn current_set_drops_an_entry_that_expires_while_resident() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap();
        let ttl = Duration::seconds(1);
        // An empty file skips the blocking load, so this is safe here.
        let s = RevocationStore::try_new(&file, ttl)
            .unwrap()
            .with_skew_margin(Duration::seconds(1));
        let s = s.watch().unwrap();
        let mut rx = s.subscribe();

        let id = TokenId::generate();
        tokio::fs::write(&file, format!("{id}\n")).await.unwrap();
        tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(s.current_set().await.len(), 1);

        tokio::time::sleep(tokio::time::Duration::from_millis(2_400)).await;

        assert!(
            s.current_set().await.is_empty(),
            "an entry past the TTL and the margin must leave the delivered set"
        );
        assert!(
            s.is_revoked(id).await,
            "the entry is still held: only the delivered set is filtered"
        );
    }

    #[tokio::test]
    async fn current_set_holds_every_ingested_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");
        std::fs::write(&file, "").unwrap();

        let s = store(&file);
        assert!(s.current_set().await.is_empty());
        let s = s.watch().unwrap();
        let mut rx = s.subscribe();

        let id1 = TokenId::generate();
        let id2 = TokenId::generate();

        // Write both IDs at once so one file event triggers a single reload for both.
        tokio::fs::write(&file, format!("{id1}\n{id2}\n"))
            .await
            .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        let set = s.current_set().await;
        assert_eq!(set.len(), 2);
        let tokens: HashSet<_> = set.iter().map(|entry| entry.token_id).collect();
        assert_eq!(tokens, HashSet::from([id1, id2]));
    }

    #[tokio::test]
    async fn compact_file_removes_expired() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.txt");

        let id_old = TokenId::generate();
        let id_new = TokenId::generate();
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
        let s = s.watch().unwrap();
        let mut rx = s.subscribe();

        let id = TokenId::generate();
        std::fs::write(&file, format!("{id}\n")).unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(s.is_revoked(id).await);
    }
}
