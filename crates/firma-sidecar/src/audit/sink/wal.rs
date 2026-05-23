//! Write-ahead log audit sink with gRPC streaming.
//!
//! Combines a gRPC client-streaming RPC with a local append-only file
//! that acts as a bounded retry queue. The sink operates in two modes:
//!
//! - **Streaming** — events are forwarded directly to the remote
//!   [`AuditService`] over gRPC, identical to [`GrpcAuditSink`].
//! - **Buffering** — when the gRPC endpoint is unreachable or the
//!   stream breaks, events are appended to a local WAL file. On every
//!   incoming event the sink attempts to reconnect; on success it
//!   replays the buffered events and switches back to streaming mode.
//!
//! The WAL file is bounded by [`wal_max_bytes`]. When an append would
//! exceed the cap the oldest events are compacted away and a counter of
//! dropped events is emitted via [`tracing`].
//!
//! [`GrpcAuditSink`]: super::GrpcAuditSink
//! [`wal_max_bytes`]: WalAuditSink::wal_max_bytes

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use firma_proto::firma::v1::audit_service_client::AuditServiceClient;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tonic::transport::Channel;

use crate::audit::{AuditSink, AuditSinkError, ExecutionEvent};

/// Audit sink that streams events over gRPC with local WAL fallback.
#[derive(Debug)]
pub struct WalAuditSink {
    /// Remote audit service endpoint URL.
    endpoint: String,
    /// Path to the local WAL file.
    wal_path: PathBuf,
    /// Maximum WAL file size in bytes. When exceeded the oldest events
    /// are compacted away.
    wal_max_bytes: u64,
}

impl WalAuditSink {
    /// Constructs a new [`WalAuditSink`].
    pub fn new(
        endpoint: impl Into<String>,
        wal_path: impl AsRef<Path>,
        wal_max_bytes: u64,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            wal_path: wal_path.as_ref().to_path_buf(),
            wal_max_bytes,
        }
    }

    /// Attempts to connect to the audit service endpoint.
    async fn connect(&self) -> Result<AuditServiceClient<Channel>, tonic::transport::Error> {
        AuditServiceClient::connect(self.endpoint.clone()).await
    }

    /// Appends a serialized JSON line to the WAL file, compacting if
    /// the size cap would be exceeded.
    ///
    /// Returns the number of events dropped during compaction (0 when
    /// no compaction was needed).
    async fn wal_append(
        file: &mut tokio::fs::File,
        wal_size: &mut u64,
        wal_max_bytes: u64,
        event: &ExecutionEvent,
    ) -> u64 {
        let serialized = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(err) => {
                tracing::warn!(
                    event_id = %event.event_id,
                    "failed to serialize audit event for WAL: {err}"
                );
                return 0;
            }
        };

        let line = format!("{serialized}\n");
        let line_len = line.len() as u64;

        // Compact if this append would exceed the cap.
        let dropped = if *wal_size + line_len > wal_max_bytes {
            Self::wal_compact(file, wal_size, wal_max_bytes / 2).await
        } else {
            0u64
        };

        // Write at EOF explicitly instead of relying on append-mode
        // file semantics, which can be platform-specific when mixed
        // with seek/read/truncate during compaction.
        let write_result = if file.seek(std::io::SeekFrom::End(0)).await.is_ok() {
            file.write_all(line.as_bytes()).await
        } else {
            Err(std::io::Error::other(
                "failed to seek WAL to end before write",
            ))
        };

        match write_result {
            Ok(()) => *wal_size += line_len,
            Err(err) => {
                tracing::error!(
                    event_id = %event.event_id,
                    "failed to write audit event to WAL: {err}"
                );
            }
        }

        dropped
    }

    /// Rewrites the WAL file, keeping only the newest events that fit
    /// within `target_bytes`. Returns the number of events dropped.
    async fn wal_compact(file: &mut tokio::fs::File, wal_size: &mut u64, target_bytes: u64) -> u64 {
        use tokio::io::AsyncReadExt;

        // Read the entire WAL into memory.
        if file.seek(std::io::SeekFrom::Start(0)).await.is_err() {
            return 0;
        }
        let mut buf = String::new();
        if file.read_to_string(&mut buf).await.is_err() {
            return 0;
        }

        let lines: Vec<&str> = buf.lines().collect();
        let total = lines.len() as u64;

        // Walk backwards from the newest event and keep lines until we
        // would exceed the target size.
        let mut kept = Vec::new();
        let mut kept_bytes = 0u64;
        for line in lines.iter().rev() {
            let line_bytes = (line.len() + 1) as u64; // +1 for newline
            if kept_bytes + line_bytes > target_bytes {
                break;
            }
            kept.push(*line);
            kept_bytes += line_bytes;
        }
        kept.reverse();

        let dropped = total - kept.len() as u64;

        // Rewrite the file with only the kept lines.
        //
        // Important: this file descriptor may be opened with O_APPEND.
        // In that mode, writes are forced to end-of-file regardless of
        // seek position, so "seek + write + truncate" can produce
        // inconsistent compaction results. Truncate first, then write.
        if file.set_len(0).await.is_err() {
            return 0;
        }
        if file.seek(std::io::SeekFrom::Start(0)).await.is_err() {
            return 0;
        }
        // Build the new contents and write at once.
        let new_contents = kept.iter().fold(String::new(), |mut acc, l| {
            let _ = writeln!(acc, "{l}");
            acc
        });
        let new_len = new_contents.len() as u64;
        let write_ok = file.write_all(new_contents.as_bytes()).await.is_ok();
        if write_ok {
            let _ = file.sync_data().await;
            *wal_size = new_len;
        }

        if dropped > 0 {
            tracing::warn!(dropped, "WAL compaction dropped oldest events");
        }

        dropped
    }

    /// Reads all events from the WAL file, returning them as domain
    /// events. Lines that fail to deserialize are skipped with a
    /// warning.
    async fn wal_read_all(path: &Path) -> Vec<ExecutionEvent> {
        let Ok(contents) = tokio::fs::read_to_string(path).await else {
            return Vec::new();
        };

        contents
            .lines()
            .filter_map(|line| {
                serde_json::from_str::<ExecutionEvent>(line)
                    .map_err(|err| {
                        tracing::warn!("skipping malformed WAL line: {err}");
                    })
                    .ok()
            })
            .collect()
    }

    /// Truncates the WAL file back to zero bytes.
    async fn wal_truncate(path: &Path) {
        if let Err(err) = tokio::fs::write(path, b"").await {
            tracing::error!("failed to truncate WAL file: {err}");
        }
    }
}

/// Type alias for the gRPC stream sender and the spawned RPC task
/// handle.
type StreamState = (
    tokio::sync::mpsc::Sender<firma_proto::firma::v1::ExecutionEvent>,
    tokio::task::JoinHandle<
        Result<tonic::Response<firma_proto::firma::v1::StreamEventsResponse>, tonic::Status>,
    >,
);

/// Mutable run-loop state threaded through the event-handling helpers.
struct RunCtx {
    stream: Option<StreamState>,
    wal_file: tokio::fs::File,
    wal_size: u64,
    total_dropped: u64,
}

impl AuditSink for WalAuditSink {
    async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<ExecutionEvent>,
        exit: tokio_util::sync::CancellationToken,
    ) -> Result<(), AuditSinkError> {
        tracing::debug!(
            endpoint = %self.endpoint,
            wal_path = %self.wal_path.display(),
            "starting WalAuditSink"
        );

        let mut ctx = self.init_ctx().await?;

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    self.handle_event(&mut ctx, &event).await;
                }
                () = exit.cancelled() => {
                    self.drain_events(&mut ctx, &mut rx).await;
                    break;
                }
            }
        }

        Self::close_stream(ctx.stream).await;

        if ctx.total_dropped > 0 {
            tracing::warn!(
                total_dropped = ctx.total_dropped,
                "WalAuditSink dropped events due to WAL cap"
            );
        }

        tracing::debug!("stopping WalAuditSink");
        Ok(())
    }
}

impl WalAuditSink {
    /// Opens the WAL file, connects to gRPC (best-effort), and replays
    /// any pre-existing WAL events.
    async fn init_ctx(&self) -> Result<RunCtx, AuditSinkError> {
        let wal_file = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&self.wal_path)
            .await
            .map_err(|e| AuditSinkError::BindFailed(format!("cannot open WAL file: {e}")))?;

        let metadata = wal_file
            .metadata()
            .await
            .map_err(|e| AuditSinkError::BindFailed(format!("cannot stat WAL file: {e}")))?;

        let mut ctx = RunCtx {
            stream: self.try_open_stream().await,
            wal_file,
            wal_size: metadata.len(),
            total_dropped: 0,
        };

        // Replay buffered WAL events if we managed to connect.
        self.replay_wal(&mut ctx).await;

        Ok(ctx)
    }

    /// Replays WAL events through the active gRPC stream. On success
    /// the WAL file is truncated; on failure the stream state is left
    /// intact so the caller can detect the broken connection.
    async fn replay_wal(&self, ctx: &mut RunCtx) {
        let Some((ref stream_tx, _)) = ctx.stream else {
            return;
        };

        let buffered = Self::wal_read_all(&self.wal_path).await;
        if buffered.is_empty() {
            return;
        }

        tracing::info!(count = buffered.len(), "replaying WAL events to gRPC");
        for event in buffered {
            let proto = firma_proto::firma::v1::ExecutionEvent::from(event);
            if stream_tx.send(proto).await.is_err() {
                tracing::warn!("gRPC stream broke during WAL replay");
                return;
            }
        }

        Self::wal_truncate(&self.wal_path).await;
        ctx.wal_size = 0;
    }

    /// Processes a single event: streams via gRPC if possible,
    /// otherwise falls back to the WAL and attempts a reconnect.
    async fn handle_event(&self, ctx: &mut RunCtx, event: &ExecutionEvent) {
        if Self::try_stream_send(ctx.stream.as_ref(), event).await {
            return;
        }

        // gRPC is down — buffer to WAL.
        if ctx.stream.take().is_some() {
            tracing::warn!("gRPC stream lost; switching to WAL buffering");
        }

        let dropped = Self::wal_append(
            &mut ctx.wal_file,
            &mut ctx.wal_size,
            self.wal_max_bytes,
            event,
        )
        .await;
        ctx.total_dropped += dropped;

        // Attempt reconnect + replay.
        if let Some(new_state) = self
            .try_reconnect(&self.wal_path, &mut ctx.wal_file, &mut ctx.wal_size)
            .await
        {
            ctx.stream = Some(new_state);
        }
    }

    /// Drains remaining channel events on shutdown, buffering to WAL
    /// when the gRPC stream is unavailable.
    async fn drain_events(
        &self,
        ctx: &mut RunCtx,
        rx: &mut tokio::sync::mpsc::Receiver<ExecutionEvent>,
    ) {
        while let Some(event) = rx.recv().await {
            if Self::try_stream_send(ctx.stream.as_ref(), &event).await {
                continue;
            }

            if ctx.stream.take().is_some() {
                tracing::warn!("gRPC stream lost during drain; buffering to WAL");
            }

            let dropped = Self::wal_append(
                &mut ctx.wal_file,
                &mut ctx.wal_size,
                self.wal_max_bytes,
                &event,
            )
            .await;
            ctx.total_dropped += dropped;
        }
    }

    /// Attempts to send `event` over the gRPC stream. Returns `true`
    /// if the send succeeded.
    async fn try_stream_send(stream: Option<&StreamState>, event: &ExecutionEvent) -> bool {
        let Some((stream_tx, _)) = stream else {
            return false;
        };
        let proto = firma_proto::firma::v1::ExecutionEvent::from(event.clone());
        stream_tx.send(proto).await.is_ok()
    }

    /// Half-closes the gRPC stream and logs the server response.
    async fn close_stream(state: Option<StreamState>) {
        let Some((stream_tx, rpc_handle)) = state else {
            return;
        };
        drop(stream_tx);
        match rpc_handle.await {
            Ok(Ok(response)) => {
                let resp = response.into_inner();
                tracing::info!(
                    last_event_id = %resp.last_event_id,
                    events_received = resp.events_received,
                    "WAL gRPC stream closed successfully"
                );
            }
            Ok(Err(status)) => {
                tracing::error!(
                    code = %status.code(),
                    message = %status.message(),
                    "WAL gRPC stream closed with error"
                );
            }
            Err(join_err) => {
                tracing::error!("WAL gRPC stream task panicked: {join_err}");
            }
        }
    }

    /// Opens a new gRPC stream, returning the channel sender and task
    /// handle, or `None` if the connection fails.
    async fn try_open_stream(&self) -> Option<StreamState> {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!("gRPC connect failed: {err}; starting in WAL mode");
                return None;
            }
        };

        let (tx, stream_rx) =
            tokio::sync::mpsc::channel::<firma_proto::firma::v1::ExecutionEvent>(256);
        let stream = tokio_stream::wrappers::ReceiverStream::new(stream_rx);
        let handle = tokio::spawn(async move { client.stream_events(stream).await });

        tracing::debug!("gRPC stream opened");
        Some((tx, handle))
    }

    /// Attempts to reconnect to gRPC. On success, replays buffered WAL
    /// events and truncates the WAL file.
    async fn try_reconnect(
        &self,
        wal_path: &Path,
        wal_file: &mut tokio::fs::File,
        wal_size: &mut u64,
    ) -> Option<StreamState> {
        let state = self.try_open_stream().await?;

        let buffered = Self::wal_read_all(wal_path).await;
        if !buffered.is_empty() {
            tracing::info!(
                count = buffered.len(),
                "replaying WAL events after reconnect"
            );
            for event in buffered {
                let proto = firma_proto::firma::v1::ExecutionEvent::from(event);
                if state.0.send(proto).await.is_err() {
                    tracing::warn!("gRPC broke during reconnect replay; staying in WAL mode");
                    return None;
                }
            }
        }

        Self::wal_truncate(wal_path).await;
        *wal_size = 0;
        let _ = wal_file.seek(std::io::SeekFrom::Start(0)).await;

        Some(state)
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
            sandbox_id: String::new(),
            signature: vec![0xDE, 0xAD],
        }
    }

    #[test]
    fn test_new_stores_fields() {
        let sink = WalAuditSink::new(
            "https://audit.example.com",
            "/var/lib/firma/wal",
            100 * 1024 * 1024,
        );
        assert_eq!(sink.endpoint, "https://audit.example.com");
        assert_eq!(sink.wal_path, PathBuf::from("/var/lib/firma/wal"));
        assert_eq!(sink.wal_max_bytes, 100 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_sink_falls_back_to_wal_when_grpc_unreachable() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let wal_path = dir.path().join("wal.jsonl");

        let sink = WalAuditSink::new("http://127.0.0.1:1", &wal_path, 10 * 1024 * 1024);
        let (tx, rx) = mpsc::channel(16);
        let exit = CancellationToken::new();

        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        tx.send(sample_event("evt-wal-1")).await.ok();
        tx.send(sample_event("evt-wal-2")).await.ok();

        // Give the sink a moment to process.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        exit.cancel();
        drop(tx);

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
        assert!(
            result.ok().and_then(std::result::Result::ok).is_some(),
            "sink should return Ok(())"
        );

        // Events should be buffered in the WAL file.
        let contents = tokio::fs::read_to_string(&wal_path)
            .await
            .unwrap_or_else(|e| panic!("read WAL: {e}"));
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 WAL lines");
        assert!(lines[0].contains("evt-wal-1"));
        assert!(lines[1].contains("evt-wal-2"));
    }

    #[tokio::test]
    async fn test_sink_returns_bind_error_for_invalid_wal_path() {
        let sink = WalAuditSink::new(
            "http://127.0.0.1:1",
            "/nonexistent/dir/wal.jsonl",
            10 * 1024 * 1024,
        );
        let (_tx, rx) = mpsc::channel::<ExecutionEvent>(1);
        let exit = CancellationToken::new();

        let result = sink.run(rx, exit).await;

        assert!(result.is_err(), "should fail to open WAL");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AuditSinkError::BindFailed(_)),
            "error should be BindFailed, got: {err}"
        );
    }

    #[tokio::test]
    #[allow(
        clippy::similar_names,
        reason = "_a / _b suffixes are descriptive here"
    )]
    async fn test_wal_compaction_drops_oldest_events() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let wal_path = dir.path().join("compact.jsonl");

        // Build concrete events first, then size the cap from their
        // actual serialized lengths. This keeps the trigger condition
        // deterministic across platforms/runs even if line sizes differ.
        let event_a = sample_event("a");
        let event_b = sample_event("b");
        let event_c = sample_event("c");

        let line_a_len = (serde_json::to_string(&event_a)
            .unwrap_or_else(|e| panic!("serialize a: {e}"))
            .len()
            + 1) as u64; // +1 for newline
        let line_b_len = (serde_json::to_string(&event_b)
            .unwrap_or_else(|e| panic!("serialize b: {e}"))
            .len()
            + 1) as u64; // +1 for newline

        // Cap to exactly the first two appends. The third append must
        // exceed this and therefore trigger compaction.
        let cap = line_a_len + line_b_len;

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&wal_path)
            .await
            .unwrap_or_else(|e| panic!("open: {e}"));

        let mut wal_size = 0u64;

        // Append three events.
        WalAuditSink::wal_append(&mut file, &mut wal_size, cap, &event_a).await;
        WalAuditSink::wal_append(&mut file, &mut wal_size, cap, &event_b).await;
        let _dropped = WalAuditSink::wal_append(&mut file, &mut wal_size, cap, &event_c).await;

        let contents = tokio::fs::read_to_string(&wal_path)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        let lines: Vec<&str> = contents.lines().collect();

        // After compaction + append of "c", the oldest event(s) should
        // be gone and "c" should be present.
        assert!(
            lines.iter().any(|l| l.contains("\"c\"")),
            "newest event 'c' should be in WAL"
        );
        assert!(
            !lines.iter().any(|l| l.contains("\"a\"")),
            "oldest event 'a' should have been compacted away"
        );
        assert!(
            lines.len() <= 2,
            "WAL should contain at most 2 lines after compaction, found {}",
            lines.len()
        );
        assert!(
            wal_size <= cap,
            "WAL size {wal_size} should be within cap {cap}"
        );
    }

    #[tokio::test]
    async fn test_sink_returns_ok_when_channel_empty() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let wal_path = dir.path().join("empty.jsonl");

        let sink = WalAuditSink::new("http://127.0.0.1:1", &wal_path, 10 * 1024 * 1024);
        let (tx, rx) = mpsc::channel::<ExecutionEvent>(1);
        let exit = CancellationToken::new();

        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        drop(tx);
        exit.cancel();

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
    }
}
