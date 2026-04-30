//! Append-only file audit sink.
//!
//! Each [`ExecutionEvent`](crate::audit::ExecutionEvent) is serialized
//! as a single JSON line and appended to the configured file path. The
//! file is opened in create + append mode at startup; if the file
//! already exists, new events are appended without truncating.
//!
//! # Error handling
//!
//! - **Startup**: if the file cannot be opened (permissions, missing
//!   parent directory, etc.) the sink returns
//!   [`AuditSinkError::BindFailed`](crate::audit::AuditSinkError::BindFailed)
//!   immediately.
//! - **Serialization**: events that fail to serialize are logged at
//!   `warn` level and skipped. The enforcement pipeline must never be
//!   blocked by an audit formatting error.
//! - **I/O writes**: individual write failures are logged at `error`
//!   level and skipped. The sink does not abort on a single failed
//!   write — transient errors (e.g. disk pressure) are tolerated so
//!   that subsequent events still have a chance to land.

use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

use crate::audit::{AuditSink, ExecutionEvent};

/// Audit sink that writes JSON-lines to a file.
#[derive(Debug)]
pub struct FileAuditSink {
    path: PathBuf,
}

impl FileAuditSink {
    /// Constructs a new [`FileAuditSink`] writing to `path`.
    pub fn new<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self::from(path.as_ref())
    }

    /// Serialize and append a single event to `file`. Serialization
    /// and I/O failures are logged and skipped.
    async fn emit(file: &mut tokio::fs::File, event: &ExecutionEvent) {
        let serialized = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(err) => {
                tracing::warn!(
                    event_id = %event.event_id,
                    "failed to serialize audit event: {err}"
                );
                return;
            }
        };

        let line = format!("{serialized}\n");
        match file.write_all(line.as_bytes()).await {
            Ok(()) => {
                tracing::debug!(
                    event_id = %event.event_id,
                    "successfully wrote audit event to file"
                );
            }
            Err(err) => {
                tracing::error!(
                    event_id = %event.event_id,
                    "failed to write audit event to file: {err}"
                );
            }
        }
    }
}

impl From<PathBuf> for FileAuditSink {
    fn from(path: PathBuf) -> Self {
        Self { path }
    }
}

impl From<&Path> for FileAuditSink {
    fn from(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl AuditSink for FileAuditSink {
    async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<crate::audit::ExecutionEvent>,
        exit: tokio_util::sync::CancellationToken,
    ) -> Result<(), crate::audit::AuditSinkError> {
        tracing::debug!("Starting FileAuditSink with path={}", self.path.display());
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| crate::audit::AuditSinkError::BindFailed(e.to_string()))?;
        tracing::debug!("FileAuditSink successfully opened file");

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    Self::emit(&mut file, &event).await;
                }
                () = exit.cancelled() => {
                    // Drain any remaining buffered events before
                    // shutting down.
                    while let Some(event) = rx.recv().await {
                        Self::emit(&mut file, &event).await;
                    }
                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn sample_event(id: &str) -> ExecutionEvent {
        ExecutionEvent {
            event_id: id.to_string(),
            session_id: "sess-1".parse().expect("literal session id"),
            token_id: "2acea42e-bb57-44d6-3ad3-aad955ec50af"
                .parse()
                .expect("literal token id"),
            agent_id: "agent-1".parse().expect("literal agent id"),
            action: "http_get".to_string(),
            resource: "https://api.example.com/v1".to_string(),
            decision: 1,
            deny_reason: String::new(),
            enforcement_latency_us: 42,
            context_hash: "abc123".to_string(),
            bundle_version: "v1".to_string(),
            timestamp: Some(1_700_000_000_000_000_000),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            signature: vec![0xDE, 0xAD],
        }
    }

    #[tokio::test]
    async fn test_sink_writes_events_to_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("failed to create tempdir: {e}"));
        let path = dir.path().join("audit.jsonl");

        let (tx, rx) = mpsc::channel(16);
        let exit = CancellationToken::new();

        let sink = FileAuditSink::new(&path);
        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        tx.send(sample_event("evt-1")).await.ok();
        tx.send(sample_event("evt-2")).await.ok();

        exit.cancel();
        drop(tx);

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
        assert!(
            result.ok().and_then(std::result::Result::ok).is_some(),
            "sink should return Ok(())"
        );

        let contents = tokio::fs::read_to_string(&path)
            .await
            .unwrap_or_else(|e| panic!("failed to read audit file: {e}"));
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 JSON lines");
        assert!(
            lines[0].contains("evt-1"),
            "first line should contain evt-1"
        );
        assert!(
            lines[1].contains("evt-2"),
            "second line should contain evt-2"
        );
    }

    #[tokio::test]
    async fn test_sink_appends_to_existing_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("failed to create tempdir: {e}"));
        let path = dir.path().join("audit.jsonl");

        // Pre-populate with one line.
        tokio::fs::write(&path, "existing-line\n")
            .await
            .unwrap_or_else(|e| panic!("failed to write seed: {e}"));

        let (tx, rx) = mpsc::channel(16);
        let exit = CancellationToken::new();

        let sink = FileAuditSink::new(&path);
        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        let send_result = tx.send(sample_event("evt-append")).await;
        assert!(
            send_result.is_ok(),
            "failed to enqueue appended event: {send_result:?}"
        );

        exit.cancel();
        drop(tx);

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
        assert!(
            result.ok().and_then(std::result::Result::ok).is_some(),
            "sink should return Ok(())"
        );

        let contents = tokio::fs::read_to_string(&path)
            .await
            .unwrap_or_else(|e| panic!("failed to read: {e}"));
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "should have seed line + appended event");
        assert_eq!(lines[0], "existing-line");
        assert!(
            lines[1].contains("evt-append"),
            "appended line should contain evt-append"
        );
    }

    #[tokio::test]
    async fn test_sink_returns_bind_error_for_invalid_path() {
        let path = PathBuf::from("/nonexistent/dir/that/does/not/exist/audit.jsonl");

        let (_tx, rx) = mpsc::channel::<ExecutionEvent>(1);
        let exit = CancellationToken::new();

        let sink = FileAuditSink::new(&path);
        let result = sink.run(rx, exit).await;

        assert!(result.is_err(), "should fail to open file");
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::audit::AuditSinkError::BindFailed(_)),
            "error should be BindFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_sink_returns_ok_when_channel_empty() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("failed to create tempdir: {e}"));
        let path = dir.path().join("empty.jsonl");

        let (tx, rx) = mpsc::channel::<ExecutionEvent>(1);
        let exit = CancellationToken::new();

        let sink = FileAuditSink::new(&path);
        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        drop(tx);
        exit.cancel();

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
    }

    #[test]
    fn test_from_path_buf() {
        let sink = FileAuditSink::from(PathBuf::from("/tmp/audit.jsonl"));
        assert_eq!(sink.path, PathBuf::from("/tmp/audit.jsonl"));
    }

    #[test]
    fn test_from_path_ref() {
        let sink = FileAuditSink::from(Path::new("/var/log/audit.jsonl"));
        assert_eq!(sink.path, PathBuf::from("/var/log/audit.jsonl"));
    }
}
