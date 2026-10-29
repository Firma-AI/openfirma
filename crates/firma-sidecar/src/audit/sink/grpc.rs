//! Durable client-streaming gRPC audit sink.
//!
//! Combines a gRPC client-streaming RPC with a local append-only file
//! that acts as a bounded retry queue. The sink operates in two modes:
//!
//! - **Streaming** — events are forwarded directly to the remote
//!   [`AuditService`](firma_protobuf::v1::audit_service_client::AuditServiceClient)
//!   over gRPC.
//! - **Buffering** — when the gRPC endpoint is unreachable or the
//!   stream breaks, events are appended to a local buffer file and a
//!   reconnect is scheduled. On reconnect the buffered events are
//!   replayed and the sink switches back to streaming mode.
//!
//! # Never blocking the agent
//!
//! Audit delivery sits behind a bounded channel that the request handler
//! writes to with an awaiting send, so a stalled sink becomes back-pressure
//! on the enforcement path. Two rules keep that from happening:
//!
//! - Connects never run on the event path. Reconnects are driven by a
//!   deadline arm of the run loop, so handling an event is always a local
//!   file append.
//! - Every connect is bounded by [`CONNECT_TIMEOUT`], so an endpoint that
//!   blackholes packets fails on a known deadline rather than on the
//!   operating system's TCP timeout.
//! - Live sends never wait for stream capacity. A collector that stays
//!   connected but stops reading fills the stream channel; awaiting a slot
//!   there would park the run loop and push back through the audit channel
//!   into the handler. A channel still full across a yield is treated as a
//!   broken stream instead, which falls back to buffering.
//! - Shutdown is bounded by [`SHUTDOWN_ACK_TIMEOUT`], so a collector that
//!   never answers the half-close cannot hold process exit open.
//!
//! One wait is bounded rather than absent: a replay runs on the run loop, so
//! while it is in flight no event is consumed, for at most
//! [`REPLAY_SEND_TIMEOUT`] plus the configured `audit.replay_ack_timeout`.
//! Events queue in the audit channel meanwhile and are handled when it
//! returns. Removing the wait entirely means replaying off the run loop,
//! which needs the buffer to be rotated rather than truncated so a concurrent
//! append cannot be cleared by an acknowledgment that never covered it.
//!
//! Shutdown does not wait out that bound. Every wait in the reconnect arm —
//! the connect, the replay send, the acknowledgment — races the sink's
//! cancellation token, so cancelling abandons the attempt and leaves the
//! buffer for the next process instead of holding exit for up to a collector's
//! worth of silence.
//!
//! Attempts are spaced by [`ExponentialBackoff`] between
//! [`RECONNECT_MIN_BACKOFF`] and [`RECONNECT_MAX_BACKOFF`], matching the
//! Authority stream clients.
//!
//! # What "durable" covers
//!
//! Durable across an **outage**, not across a mid-stream break:
//!
//! - **Covered.** Events that arrive while the endpoint is unreachable are on
//!   disk before the sink treats them as handled, and they stay there until
//!   the server acknowledges all of them. Replay opens its own stream, sends
//!   the batch, half-closes, and waits for the
//!   [`StreamEventsResponse`](firma_protobuf::v1::StreamEventsResponse); the
//!   buffer is cleared only once `events_received` covers the whole batch, so
//!   a replay that dies midway — or one a collector persists only part of —
//!   leaves the events on disk for the next attempt.
//! - **Not covered.** Events handed to a live stream never reach the disk, and
//!   the RPC summarizes only on half-close, so events already queued into a
//!   stream that then breaks are lost. Closing that gap means writing every
//!   event to the buffer before streaming it, or per-event acknowledgment the
//!   current `AuditService` contract does not offer.
//!
//!   A collector that stops reading reaches this case without anything
//!   crashing, so the loss is counted rather than merely described: the queue
//!   depth of each abandoned stream is added up and reported on shutdown,
//!   separately from the events the buffer cap evicted.
//!
//! The buffer file is bounded by [`buffer_max_bytes`]. When an append would
//! exceed the cap the oldest events are compacted away and a counter of
//! dropped events is emitted via [`tracing`].
//!
//! [`buffer_max_bytes`]: GrpcAuditSink::buffer_max_bytes

use std::fmt::Write as _;
use std::future::Future;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::Duration;

use firma_config_schema::sidecar::audit::AuditConfig as SchemaAuditConfig;
use firma_config_utils::NonZeroDuration;
use firma_protobuf::v1::audit_service_client::AuditServiceClient;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use super::metadata::stream_events_request;
use super::{create_private_dir_all, execution_event_to_proto};
use crate::audit::{AuditSink, AuditSinkError, ExecutionEvent};
use crate::authority_credentials::SidecarCredential;
use crate::backoff::ExponentialBackoff;
use crate::config::AuditServiceUrl;

/// Upper bound on a single connect attempt.
///
/// Without an explicit bound, a filtered or blackholed endpoint leaves the
/// connect pending until the operating system's TCP timeout — minutes on
/// common Linux defaults — which would stall the audit channel and, through
/// it, the enforcement path. Matches the Authority client default.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// First delay after a failed connect.
const RECONNECT_MIN_BACKOFF: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_millis(250));

/// Ceiling on the reconnect delay.
const RECONNECT_MAX_BACKOFF: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_secs(30));

/// How long a stream must stay up before its reconnect counts as recovered.
///
/// A stream that opens and immediately breaks is a flapping collector, not a
/// recovery. Resetting the backoff on the open alone turns every such flap
/// into an immediate redial, so the retry rate follows the event rate instead
/// of the backoff schedule.
const HEALTHY_STREAM_LIFETIME: Duration = Duration::from_secs(10);

/// Upper bound on waiting for stream capacity while replaying the buffer.
const REPLAY_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on waiting for the server to answer the closing half-close.
///
/// Shutdown has nothing left to salvage — the events are either acknowledged
/// or already lost with the stream — so the wait exists only to log what the
/// server persisted. A collector that accepts the close and never answers must
/// not hold process exit for it.
const SHUTDOWN_ACK_TIMEOUT: Duration = Duration::from_secs(5);

// Legacy collectors can ignore evidence fields. Such records require the WAL
// sink's evidence-aware RPC, even when they were retained by an earlier process.
fn require_legacy_event(event: &ExecutionEvent) -> Result<(), AuditSinkError> {
    if event.run_evidence.is_some() {
        return Err(AuditSinkError::ServerError(
            "run evidence requires the wal audit sink; buffered grpc uses the legacy RPC".into(),
        ));
    }
    Ok(())
}

/// Runs `work`, giving up on it if `exit` fires first.
///
/// Returns `None` when the cancellation won. Every wait the reconnect arm
/// performs goes through here: that arm owns the run loop while it runs, so a
/// wait it cannot abandon is a wait shutdown has to sit through.
async fn until_cancelled<F: Future>(exit: &CancellationToken, work: F) -> Option<F::Output> {
    tokio::select! {
        biased;
        () = exit.cancelled() => None,
        output = work => Some(output),
    }
}

/// Audit sink that streams events over gRPC with a local buffer fallback.
#[derive(Debug)]
pub struct GrpcAuditSink {
    /// Remote audit service endpoint URL.
    endpoint: AuditServiceUrl,
    /// Path to the local buffer file.
    buffer_path: PathBuf,
    /// Maximum buffer file size in bytes. When exceeded the oldest events
    /// are compacted away.
    buffer_max_bytes: NonZeroU64,
    credentials: Option<SidecarCredential>,
    /// How `endpoint` is dialed, over TLS once [`Self::with_tls`] set it.
    dial: Endpoint,
    /// Upper bound on waiting for the server to acknowledge a replay.
    ///
    /// [`CONNECT_TIMEOUT`] covers the dial, not the response. A collector that
    /// accepts a stream and never answers would otherwise hold the run loop —
    /// and with it every event queued behind it — open-endedly.
    replay_ack_timeout: NonZeroDuration,
}

impl GrpcAuditSink {
    /// Constructs a new [`GrpcAuditSink`].
    pub(crate) fn new(
        endpoint: AuditServiceUrl,
        buffer_path: impl AsRef<Path>,
        buffer_max_bytes: NonZeroU64,
    ) -> Self {
        Self {
            dial: Endpoint::from(endpoint.uri().clone()),
            endpoint,
            buffer_path: buffer_path.as_ref().to_path_buf(),
            buffer_max_bytes,
            credentials: None,
            replay_ack_timeout: SchemaAuditConfig::default().replay_ack_timeout,
        }
    }

    /// Sets `audit.replay_ack_timeout`.
    pub(crate) const fn with_replay_ack_timeout(mut self, timeout: NonZeroDuration) -> Self {
        self.replay_ack_timeout = timeout;
        self
    }

    pub(crate) fn with_credentials(
        mut self,
        credentials: Option<SidecarCredential>,
    ) -> Result<Self, AuditSinkError> {
        stream_events_request((), credentials.as_ref())?;
        self.credentials = credentials;
        Ok(self)
    }

    /// Dials the endpoint over TLS with `tls`.
    ///
    /// # Errors
    ///
    /// Returns the tonic error when `tls` is unusable, for instance because
    /// no trusted roots could be loaded.
    pub(crate) fn with_tls(
        mut self,
        tls: ClientTlsConfig,
    ) -> Result<Self, tonic::transport::Error> {
        self.dial = self.dial.tls_config(tls)?;
        Ok(self)
    }

    /// Attempts to connect to the audit service endpoint, bounded by
    /// [`CONNECT_TIMEOUT`].
    async fn connect(&self) -> Result<AuditServiceClient<Channel>, tonic::transport::Error> {
        let endpoint = self.dial.clone().connect_timeout(CONNECT_TIMEOUT);
        endpoint.connect().await.map(AuditServiceClient::new)
    }

    /// Appends a serialized JSON line to the buffer file, compacting if
    /// the size cap would be exceeded.
    ///
    /// Returns the number of events dropped during compaction (0 when
    /// no compaction was needed).
    ///
    /// # Errors
    ///
    /// Returns the write error when the event could not be put on disk. The
    /// buffer is the sink's only durability guarantee while the stream is
    /// down, so a failed append is not a dropped event to count — it is the
    /// sink no longer being durable, and the caller must stop rather than
    /// keep reporting events as handled.
    async fn buffer_append(
        file: &mut tokio::fs::File,
        buffer_size: &mut u64,
        buffer_max_bytes: NonZeroU64,
        event: &ExecutionEvent,
    ) -> Result<u64, std::io::Error> {
        let serialized = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(err) => {
                // Serialization depends on the event, not on the buffer: the
                // next event may well serialize, so this is a skip and not a
                // durability failure.
                tracing::warn!(
                    event_id = %event.event_id,
                    "failed to serialize audit event for the local buffer: {err}"
                );
                return Ok(0);
            }
        };

        let line = format!("{serialized}\n");
        let line_len = line.len() as u64;

        // Compact if this append would exceed the cap.
        let dropped = if *buffer_size + line_len > buffer_max_bytes.get() {
            Self::buffer_compact(file, buffer_size, buffer_max_bytes.get() / 2).await
        } else {
            0u64
        };

        // Write at EOF explicitly instead of relying on append-mode
        // file semantics, which can be platform-specific when mixed
        // with seek/read/truncate during compaction.
        let write_result = if file.seek(std::io::SeekFrom::End(0)).await.is_ok() {
            match file.write_all(line.as_bytes()).await {
                // Replays read the buffer through a separate file descriptor, so
                // the append must be externally visible before returning.
                Ok(()) => file.flush().await,
                Err(err) => Err(err),
            }
        } else {
            Err(std::io::Error::other(
                "failed to seek audit buffer to end before write",
            ))
        };

        write_result?;
        *buffer_size += line_len;

        Ok(dropped)
    }

    /// Rewrites the buffer file, keeping only the newest events that fit
    /// within `target_bytes`. Returns the number of events dropped.
    async fn buffer_compact(
        file: &mut tokio::fs::File,
        buffer_size: &mut u64,
        target_bytes: u64,
    ) -> u64 {
        use tokio::io::AsyncReadExt;

        // Read the entire buffer into memory.
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
        // would exceed the target size. Always keep at least the newest
        // event so compaction can never produce an empty buffer — losing the
        // most recent audit signal is strictly worse than exceeding the
        // soft target.
        let mut kept = Vec::new();
        let mut kept_bytes = 0u64;
        for line in lines.iter().rev() {
            let line_bytes = (line.len() + 1) as u64; // +1 for newline
            if kept_bytes + line_bytes > target_bytes && !kept.is_empty() {
                break;
            }
            kept.push(*line);
            kept_bytes += line_bytes;
        }
        kept.reverse();

        let dropped = total - kept.len() as u64;

        // Rewrite the file with only the kept lines.
        //
        // The descriptor is deliberately not opened with O_APPEND — see
        // [`init_ctx`](GrpcAuditSink::init_ctx) — so this rewrite can position
        // itself. Truncate before seeking anyway: setting the length first
        // leaves no stale tail behind a shorter rewrite.
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
            *buffer_size = new_len;
        }

        if dropped > 0 {
            tracing::warn!(dropped, "audit buffer compaction dropped oldest events");
        }

        dropped
    }

    /// Reads all events from the buffer file, returning them as domain
    /// events. Lines that fail to deserialize are skipped with a
    /// warning.
    async fn buffer_read_all(path: &Path) -> Vec<ExecutionEvent> {
        let Ok(contents) = tokio::fs::read_to_string(path).await else {
            return Vec::new();
        };

        contents
            .lines()
            .filter_map(|line| {
                serde_json::from_str::<ExecutionEvent>(line)
                    .map_err(|err| {
                        tracing::warn!("skipping malformed audit buffer line: {err}");
                    })
                    .ok()
            })
            .collect()
    }

    /// Truncates the buffer file back to zero bytes.
    async fn buffer_truncate(path: &Path) {
        if let Err(err) = tokio::fs::write(path, b"").await {
            tracing::error!("failed to truncate audit buffer file: {err}");
        }
    }
}

/// Type alias for the gRPC stream sender and the spawned RPC task
/// handle.
type StreamState = (
    tokio::sync::mpsc::Sender<firma_protobuf::v1::ExecutionEvent>,
    tokio::task::JoinHandle<
        Result<tonic::Response<firma_protobuf::v1::StreamEventsResponse>, tonic::Status>,
    >,
);

/// Mutable run-loop state threaded through the event-handling helpers.
struct RunCtx {
    stream: Option<StreamState>,
    buffer_file: tokio::fs::File,
    buffer_size: u64,
    total_dropped: u64,
    /// Events lost with abandoned streams, as opposed to evicted by the cap.
    /// Counted separately because the two have different remedies: a bigger
    /// buffer fixes one, a collector that keeps reading fixes the other.
    total_abandoned: u64,
    /// Spacing between connect attempts, reset once a stream proves healthy.
    backoff: ExponentialBackoff,
    /// When the next connect attempt becomes due. Only consulted while
    /// `stream` is `None`.
    reconnect_at: Instant,
    /// When the current stream opened, used to tell a recovery from a flap.
    stream_opened_at: Option<Instant>,
}

impl AuditSink for GrpcAuditSink {
    async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<ExecutionEvent>,
        exit: tokio_util::sync::CancellationToken,
    ) -> Result<(), AuditSinkError> {
        tracing::debug!(
            endpoint = %self.endpoint,
            buffer_path = %self.buffer_path.display(),
            "starting GrpcAuditSink"
        );

        let mut ctx = self.init_ctx().await?;

        let outcome = loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    if let Err(err) = self.handle_event(&mut ctx, &event).await {
                        break Err(err);
                    }
                }
                // Absolute deadline, so re-creating the sleep on every loop
                // iteration does not push the attempt further out.
                () = tokio::time::sleep_until(ctx.reconnect_at), if ctx.stream.is_none() => {
                    self.attempt_reconnect(&mut ctx, &exit).await;
                }
                () = exit.cancelled() => {
                    break self.drain_events(&mut ctx, &mut rx).await;
                }
            }
        };

        Self::close_stream(ctx.stream).await;

        if ctx.total_dropped > 0 {
            tracing::warn!(
                total_dropped = ctx.total_dropped,
                "GrpcAuditSink dropped events due to the buffer cap"
            );
        }

        if ctx.total_abandoned > 0 {
            tracing::warn!(
                total_abandoned = ctx.total_abandoned,
                "GrpcAuditSink lost events queued into streams that broke before acknowledgment"
            );
        }

        tracing::debug!("stopping GrpcAuditSink");
        outcome
    }
}

impl GrpcAuditSink {
    /// Opens the buffer file and schedules an immediate first connect.
    ///
    /// Startup never waits on the network: the first attempt runs through
    /// the run loop's reconnect arm, so events arriving before the audit
    /// service is reachable are buffered rather than blocked.
    ///
    /// The parent directory is created, and both it and the buffer file are
    /// created private on Unix. The buffer holds the same events the `file`
    /// sink writes — they name resources, agents, and tokens — so it gets the
    /// same treatment rather than whatever the umask happens to be.
    ///
    /// The file is opened read-write without `O_APPEND`. Appends position
    /// themselves at end-of-file explicitly, and compaction rewrites the file
    /// from the start through the same descriptor; append mode would force
    /// that rewrite back to the end.
    async fn init_ctx(&self) -> Result<RunCtx, AuditSinkError> {
        if let Some(parent) = self
            .buffer_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            create_private_dir_all(parent).map_err(|e| {
                AuditSinkError::BindFailed(format!(
                    "cannot create audit buffer directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let mut options = tokio::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let buffer_file = options.open(&self.buffer_path).await.map_err(|e| {
            AuditSinkError::BindFailed(format!("cannot open audit buffer file: {e}"))
        })?;

        let metadata = buffer_file.metadata().await.map_err(|e| {
            AuditSinkError::BindFailed(format!("cannot stat audit buffer file: {e}"))
        })?;
        // Empty buffers have no retained evidence. Do not read them to EOF:
        // devices such as `/dev/full` report zero length but never finish reading.
        if metadata.len() > 0 {
            for event in Self::buffer_read_all(&self.buffer_path).await {
                require_legacy_event(&event)?;
            }
        }

        Ok(RunCtx {
            stream: None,
            buffer_file,
            buffer_size: metadata.len(),
            total_dropped: 0,
            total_abandoned: 0,
            backoff: ExponentialBackoff::new(RECONNECT_MIN_BACKOFF, RECONNECT_MAX_BACKOFF),
            reconnect_at: Instant::now(),
            stream_opened_at: None,
        })
    }

    /// Runs one connect attempt, replaying any buffered events before
    /// accepting live traffic again. Failure schedules the next attempt.
    async fn attempt_reconnect(&self, ctx: &mut RunCtx, exit: &CancellationToken) {
        if let Some(stream) = self.reconnect(ctx, exit).await {
            ctx.stream = Some(stream);
            // The backoff is not reset here: an open proves only that the
            // collector answered a dial. It is reset once the stream has
            // carried traffic for `HEALTHY_STREAM_LIFETIME`.
            ctx.stream_opened_at = Some(Instant::now());
            return;
        }

        let delay = ctx.backoff.next();
        ctx.reconnect_at = Instant::now() + delay;
        tracing::debug!(
            backoff_ms = delay.as_millis(),
            "audit service unreachable; retrying"
        );
    }

    /// Drains the buffer to the audit service, then opens the live stream.
    ///
    /// Returns `None` when either step fails, leaving the buffer untouched
    /// so the next attempt replays the same events.
    ///
    /// The buffer is read only after a connect has already succeeded. Reading
    /// first would pull the whole file — up to `buffer_max_bytes` — into
    /// memory on every backoff tick of an outage, just to discard it when the
    /// dial fails.
    async fn reconnect(&self, ctx: &mut RunCtx, exit: &CancellationToken) -> Option<StreamState> {
        if ctx.buffer_size > 0 {
            self.replay_acknowledged(ctx, exit).await?;
        }

        until_cancelled(exit, self.try_open_stream())
            .await
            .flatten()
    }

    /// Replays the buffer on a dedicated stream and clears it once the server
    /// acknowledges every event.
    ///
    /// The batch gets its own short-lived RPC because
    /// [`StreamEventsResponse`](firma_protobuf::v1::StreamEventsResponse)
    /// only arrives on half-close. Holding the buffer until that response
    /// lands is what makes a failed replay non-destructive.
    ///
    /// Returns `None` when the replay did not complete, leaving the buffer for
    /// the next attempt.
    async fn replay_acknowledged(&self, ctx: &mut RunCtx, exit: &CancellationToken) -> Option<()> {
        // Connect before reading: see [`reconnect`](Self::reconnect).
        let (stream_tx, rpc_handle) = until_cancelled(exit, self.try_open_stream())
            .await
            .flatten()?;

        let events = Self::buffer_read_all(&self.buffer_path).await;
        let count = events.len();
        tracing::info!(count, "replaying buffered audit events");

        for event in events {
            let proto = execution_event_to_proto(event);
            // Bounded like the acknowledgment: a collector that opens a stream
            // and stops reading would otherwise park the run loop here, which
            // is the same stall the response deadline exists to prevent.
            let sent = until_cancelled(exit, stream_tx.send_timeout(proto, REPLAY_SEND_TIMEOUT));
            match sent.await {
                Some(Ok(())) => {}
                Some(Err(err)) => {
                    tracing::warn!(
                        count,
                        "gRPC stream did not accept the replay ({err}); keeping buffer"
                    );
                    rpc_handle.abort();
                    return None;
                }
                None => {
                    tracing::debug!(count, "audit sink cancelled mid-replay; keeping buffer");
                    rpc_handle.abort();
                    return None;
                }
            }
        }

        // Half-close so the server summarizes what it persisted.
        drop(stream_tx);
        let mut rpc_handle = rpc_handle;
        let joined = until_cancelled(
            exit,
            tokio::time::timeout(self.replay_ack_timeout.duration(), &mut rpc_handle),
        )
        .await;
        let Some(joined) = joined else {
            tracing::debug!(
                count,
                "audit sink cancelled while waiting for the replay acknowledgment; keeping buffer"
            );
            rpc_handle.abort();
            return None;
        };
        let acknowledged = match joined {
            Ok(Ok(Ok(response))) => Self::replay_is_complete(response.get_ref(), count),
            Ok(Ok(Err(status))) => {
                tracing::warn!(
                    code = %status.code(),
                    message = %status.message(),
                    count,
                    "replay was not acknowledged; keeping buffer"
                );
                false
            }
            Ok(Err(join_err)) => {
                tracing::error!("audit replay task panicked: {join_err}");
                false
            }
            Err(_elapsed) => {
                tracing::warn!(
                    count,
                    timeout = ?self.replay_ack_timeout.duration(),
                    "audit service accepted the replay but never acknowledged it; keeping buffer"
                );
                // Dropping the handle would only detach the task: it would go
                // on awaiting a response that never comes, holding its
                // connection, once per reconnect for as long as the collector
                // stays quiet.
                rpc_handle.abort();
                false
            }
        };

        if !acknowledged {
            return None;
        }

        Self::buffer_truncate(&self.buffer_path).await;
        ctx.buffer_size = 0;
        Some(())
    }

    /// Reports whether the server acknowledged the whole replayed batch.
    ///
    /// A collector that persists two of three events answers with a success
    /// status all the same; clearing the buffer on the status alone would drop
    /// the third. The count is the only completeness signal the response
    /// carries.
    ///
    /// A count that is not a possible number of events — the field is a
    /// signed `i64` on the wire — is treated as no acknowledgment at all.
    /// Saturating it instead would read as "everything arrived" and clear the
    /// buffer on the word of a collector that is plainly misreporting.
    fn replay_is_complete(
        response: &firma_protobuf::v1::StreamEventsResponse,
        sent: usize,
    ) -> bool {
        let Ok(received) = usize::try_from(response.events_received) else {
            tracing::warn!(
                sent,
                events_received = response.events_received,
                "audit service reported an impossible acknowledgment count; keeping buffer"
            );
            return false;
        };
        if received < sent {
            tracing::warn!(
                sent,
                events_received = response.events_received,
                last_event_id = %response.last_event_id,
                "audit service acknowledged fewer events than were replayed; keeping buffer"
            );
            return false;
        }
        tracing::info!(
            last_event_id = %response.last_event_id,
            events_received = response.events_received,
            "buffered audit events acknowledged"
        );
        true
    }

    /// Processes a single event: streams via gRPC if possible, otherwise
    /// appends it to the local buffer.
    ///
    /// Deliberately does no network work — see the module-level note on
    /// never blocking the agent.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSinkError::ServerError`] when the event reached neither
    /// the stream nor the buffer.
    async fn handle_event(
        &self,
        ctx: &mut RunCtx,
        event: &ExecutionEvent,
    ) -> Result<(), AuditSinkError> {
        require_legacy_event(event)?;
        if Self::try_stream_send(ctx.stream.as_ref(), event).await {
            return Ok(());
        }

        // gRPC is down — buffer locally and let the reconnect arm recover.
        if let Some(lost) = ctx.stream.take() {
            ctx.total_abandoned += Self::abandoned_event_count(&lost);
            tracing::warn!("gRPC stream lost; switching to local buffering");
            Self::close_lost_stream(lost);
            Self::schedule_reconnect_after_loss(ctx);
        }

        let dropped = self
            .append_to_buffer(&mut ctx.buffer_file, &mut ctx.buffer_size, event)
            .await?;
        ctx.total_dropped += dropped;
        Ok(())
    }

    /// Appends `event` to the buffer, translating a failed write into the
    /// sink's unrecoverable error.
    ///
    /// A buffer that cannot be written is not a degraded mode: with the stream
    /// down there is nowhere else for the event to go, so continuing would
    /// report events as audited while silently discarding them.
    async fn append_to_buffer(
        &self,
        file: &mut tokio::fs::File,
        buffer_size: &mut u64,
        event: &ExecutionEvent,
    ) -> Result<u64, AuditSinkError> {
        Self::buffer_append(file, buffer_size, self.buffer_max_bytes, event)
            .await
            .map_err(|err| {
                AuditSinkError::ServerError(format!(
                    "cannot append audit event {} to the buffer at {}: {err}",
                    event.event_id,
                    self.buffer_path.display()
                ))
            })
    }

    /// Counts the events a lost stream takes with it.
    ///
    /// Events queued into the stream channel are not on disk — that is the gap
    /// the module docs call out — and when the stream is abandoned they are
    /// gone without the collector having acknowledged them. The queue depth is
    /// the only measure of that loss the sender side can take, so it is taken
    /// before the stream is handed off to be closed.
    ///
    /// Approximate by construction: outstanding permits count as occupied
    /// slots, and the RPC task may drain more while this runs.
    fn abandoned_event_count(state: &StreamState) -> u64 {
        let (stream_tx, _) = state;
        (stream_tx.max_capacity() - stream_tx.capacity()) as u64
    }

    /// Closes a stream that was lost mid-run without blocking the event path.
    ///
    /// Dropping the state instead would detach the RPC task; awaiting it here
    /// would put a network wait back on the path that must stay local.
    fn close_lost_stream(state: StreamState) {
        tokio::spawn(Self::close_stream(Some(state)));
    }

    /// Schedules the next connect after a stream was lost.
    ///
    /// A stream that survived [`HEALTHY_STREAM_LIFETIME`] was a working
    /// connection, so recovery starts over from the minimum delay. One that
    /// broke sooner is a flapping collector: keeping the backoff growing is
    /// what stops the redial rate from tracking the event rate.
    fn schedule_reconnect_after_loss(ctx: &mut RunCtx) {
        let healthy = ctx
            .stream_opened_at
            .take()
            .is_some_and(|opened_at| opened_at.elapsed() >= HEALTHY_STREAM_LIFETIME);

        if healthy {
            ctx.backoff.reset();
            ctx.reconnect_at = Instant::now();
            return;
        }

        let delay = ctx.backoff.next();
        ctx.reconnect_at = Instant::now() + delay;
        tracing::debug!(
            backoff_ms = delay.as_millis(),
            "gRPC stream did not stay up long enough to count as recovered; backing off"
        );
    }

    /// Drains remaining channel events on shutdown, buffering locally
    /// when the gRPC stream is unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSinkError::ServerError`] when a drained event reached
    /// neither the stream nor the buffer.
    async fn drain_events(
        &self,
        ctx: &mut RunCtx,
        rx: &mut tokio::sync::mpsc::Receiver<ExecutionEvent>,
    ) -> Result<(), AuditSinkError> {
        while let Some(event) = rx.recv().await {
            require_legacy_event(&event)?;
            if Self::try_stream_send(ctx.stream.as_ref(), &event).await {
                continue;
            }

            if let Some(lost) = ctx.stream.take() {
                ctx.stream_opened_at = None;
                ctx.total_abandoned += Self::abandoned_event_count(&lost);
                tracing::warn!("gRPC stream lost during drain; buffering locally");
                Self::close_lost_stream(lost);
            }

            let dropped = self
                .append_to_buffer(&mut ctx.buffer_file, &mut ctx.buffer_size, &event)
                .await?;
            ctx.total_dropped += dropped;
        }

        Ok(())
    }

    /// Attempts to hand `event` to the gRPC stream. Returns `true` if the
    /// event was queued for the stream.
    ///
    /// Never waits for capacity. The channel backs onto a collector that may
    /// be connected yet not reading, and waiting there would propagate all
    /// the way into the enforcement path — so a full channel counts as a
    /// broken stream and the caller falls back to the buffer.
    ///
    /// A full channel is retried once across a yield before that verdict. The
    /// RPC task drains the channel on this same runtime, so a burst that
    /// merely outran it empties as soon as it is scheduled; without the retry
    /// a healthy collector loses its stream to a scheduling order. The yield
    /// cannot park — it is one pass of the scheduler, not a wait on the
    /// collector.
    async fn try_stream_send(stream: Option<&StreamState>, event: &ExecutionEvent) -> bool {
        use tokio::sync::mpsc::error::TrySendError;

        let Some((stream_tx, _)) = stream else {
            return false;
        };
        let proto = match stream_tx.try_send(execution_event_to_proto(event.clone())) {
            Ok(()) => return true,
            Err(TrySendError::Full(proto)) => proto,
            Err(TrySendError::Closed(_)) => return false,
        };

        tokio::task::yield_now().await;
        match stream_tx.try_send(proto) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                tracing::warn!(
                    event_id = %event.event_id,
                    "audit service is not reading the stream; treating it as broken"
                );
                false
            }
            Err(TrySendError::Closed(_)) => false,
        }
    }

    /// Half-closes the gRPC stream and logs the server response.
    ///
    /// Bounded by [`SHUTDOWN_ACK_TIMEOUT`]: the response is only a log line,
    /// and a collector that never sends one must not keep the sink alive.
    async fn close_stream(state: Option<StreamState>) {
        let Some((stream_tx, mut rpc_handle)) = state else {
            return;
        };
        drop(stream_tx);
        let Ok(joined) = tokio::time::timeout(SHUTDOWN_ACK_TIMEOUT, &mut rpc_handle).await else {
            tracing::warn!(
                timeout_s = SHUTDOWN_ACK_TIMEOUT.as_secs(),
                "audit service did not answer the stream close; abandoning it"
            );
            rpc_handle.abort();
            return;
        };
        match joined {
            Ok(Ok(response)) => {
                let resp = response.into_inner();
                tracing::info!(
                    last_event_id = %resp.last_event_id,
                    events_received = resp.events_received,
                    "gRPC audit stream closed successfully"
                );
            }
            Ok(Err(status)) => {
                tracing::error!(
                    code = %status.code(),
                    message = %status.message(),
                    "gRPC audit stream closed with error"
                );
            }
            Err(join_err) => {
                tracing::error!("gRPC audit stream task panicked: {join_err}");
            }
        }
    }

    /// Opens a new gRPC stream, returning the channel sender and task
    /// handle, or `None` if the connection fails.
    async fn try_open_stream(&self) -> Option<StreamState> {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(
                    endpoint = %self.endpoint,
                    "gRPC connect failed: {err}; buffering audit events locally"
                );
                return None;
            }
        };

        let (tx, stream_rx) = tokio::sync::mpsc::channel::<firma_protobuf::v1::ExecutionEvent>(256);
        let stream = tokio_stream::wrappers::ReceiverStream::new(stream_rx);
        let request = stream_events_request(stream, self.credentials.as_ref()).ok()?;
        let handle = tokio::spawn(async move { client.stream_events(request).await });

        tracing::debug!("gRPC stream opened");
        Some((tx, handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{buffered_ids, sample_event, wait_until};

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    const TEST_BUFFER_MAX_BYTES: NonZeroU64 = NonZeroU64::new(10 * 1024 * 1024).unwrap();

    fn unreachable_url() -> AuditServiceUrl {
        "http://127.0.0.1:1".parse().unwrap()
    }

    #[tokio::test]
    async fn test_sink_falls_back_to_buffer_when_grpc_unreachable() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let buffer_path = dir.path().join("buffer.jsonl");

        let sink = GrpcAuditSink::new(unreachable_url(), &buffer_path, TEST_BUFFER_MAX_BYTES);
        let (tx, rx) = mpsc::channel(16);
        let exit = CancellationToken::new();

        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        tx.send(sample_event("evt-buffered-1")).await.ok();
        tx.send(sample_event("evt-buffered-2")).await.ok();

        let path_for_wait = buffer_path.clone();
        wait_until("both events to reach the buffer", move || {
            buffered_ids(&path_for_wait).len() == 2
        })
        .await;

        exit.cancel();
        drop(tx);

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
        assert!(
            result.ok().and_then(std::result::Result::ok).is_some(),
            "sink should return Ok(())"
        );

        // Events should be buffered locally rather than dropped.
        let contents = tokio::fs::read_to_string(&buffer_path)
            .await
            .unwrap_or_else(|e| panic!("read buffer: {e}"));
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 buffered lines");
        assert!(lines[0].contains("evt-buffered-1"));
        assert!(lines[1].contains("evt-buffered-2"));
    }

    /// The buffer is the only place an event can go while the stream is down,
    /// so a write that fails is the sink losing durability, not a recoverable
    /// hiccup: the run has to end instead of reporting further events as
    /// handled.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_sink_fails_when_the_buffer_cannot_be_written() {
        use pretty_assertions::assert_matches;

        // `/dev/full` opens like any file and fails every write with ENOSPC,
        // which is the full-filesystem case without needing a full filesystem.
        let sink = GrpcAuditSink::new(unreachable_url(), "/dev/full", TEST_BUFFER_MAX_BYTES);
        let (tx, rx) = mpsc::channel(16);

        let handle = tokio::spawn(async move { sink.run(rx, CancellationToken::new()).await });

        tx.send(sample_event("evt-no-space"))
            .await
            .unwrap_or_else(|e| panic!("enqueue event: {e}"));

        let result = handle.await.unwrap_or_else(|e| panic!("join sink: {e}"));
        let err = result.expect_err("an unwritable buffer must end the run");
        assert_matches!(
            err,
            AuditSinkError::ServerError(ref message)
                if message.contains("evt-no-space") && message.contains("/dev/full")
        );
    }

    #[tokio::test]
    async fn test_sink_returns_bind_error_for_invalid_buffer_path() {
        // A regular file stands in for a parent that cannot be a directory on
        // any platform. A merely absent parent is no longer unusable: the sink
        // creates it.
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let blocker = dir.path().join("not-a-directory");
        tokio::fs::write(&blocker, b"")
            .await
            .unwrap_or_else(|e| panic!("write blocker: {e}"));

        let sink = GrpcAuditSink::new(
            unreachable_url(),
            blocker.join("buffer.jsonl"),
            TEST_BUFFER_MAX_BYTES,
        );
        let (_tx, rx) = mpsc::channel::<ExecutionEvent>(1);
        let exit = CancellationToken::new();

        let result = sink.run(rx, exit).await;

        assert!(result.is_err(), "should fail to open the buffer file");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AuditSinkError::BindFailed(_)),
            "error should be BindFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_buffer_compaction_drops_oldest_events() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let buffer_path = dir.path().join("compact.jsonl");

        // Build concrete events first, then size the cap from their
        // actual serialized lengths.
        let event_a = sample_event("a");
        let event_b = sample_event("b");
        let event_c = sample_event("c");

        let one_line_len = (serde_json::to_string(&event_a)
            .unwrap_or_else(|e| panic!("serialize a: {e}"))
            .len()
            + 1) as u64; // +1 for newline

        // Cap holds at least 2 lines (with spare bytes to avoid an exact
        // boundary) but NOT 3. This guarantees the 3rd append triggers
        // compaction while giving the compaction target enough room to
        // keep exactly 1 line unambiguously.
        let cap = NonZeroU64::new(2 * one_line_len + one_line_len / 2).unwrap();

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&buffer_path)
            .await
            .unwrap_or_else(|e| panic!("open: {e}"));

        let mut buffer_size = 0u64;

        // Append three events. The first two should fit within cap;
        // the third triggers compaction.
        let dropped_a = GrpcAuditSink::buffer_append(&mut file, &mut buffer_size, cap, &event_a)
            .await
            .unwrap_or_else(|e| panic!("append a: {e}"));
        assert_eq!(dropped_a, 0, "first append should not trigger compaction");
        let dropped_b = GrpcAuditSink::buffer_append(&mut file, &mut buffer_size, cap, &event_b)
            .await
            .unwrap_or_else(|e| panic!("append b: {e}"));
        assert_eq!(dropped_b, 0, "second append should not trigger compaction");
        let dropped_c = GrpcAuditSink::buffer_append(&mut file, &mut buffer_size, cap, &event_c)
            .await
            .unwrap_or_else(|e| panic!("append c: {e}"));
        assert!(
            dropped_c > 0,
            "third append should trigger compaction and drop at least one event"
        );

        let contents = tokio::fs::read_to_string(&buffer_path)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        let event_ids: Vec<String> = contents
            .lines()
            .map(|line| {
                serde_json::from_str::<ExecutionEvent>(line)
                    .unwrap_or_else(|e| panic!("deserialize buffered event: {e}"))
                    .event_id
            })
            .collect();

        assert_eq!(event_ids, ["b", "c"]);
        assert!(
            buffer_size <= cap.get(),
            "buffer size {buffer_size} should be within cap {cap}"
        );
    }

    #[tokio::test]
    async fn test_buffer_compaction_always_keeps_newest_event() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let buffer_path = dir.path().join("keep-newest.jsonl");

        // Verify that compaction never produces an empty buffer, even
        // when the compaction target is smaller than a single line.
        // This tests the "always keep at least the newest event"
        // invariant: dropping the most recent audit signal is worse
        // than briefly exceeding the soft target.
        let event = sample_event("survivor");

        let one_line_len = (serde_json::to_string(&event)
            .unwrap_or_else(|e| panic!("serialize: {e}"))
            .len()
            + 1) as u64;

        // Cap holds exactly one line. The second append triggers
        // compaction with target_bytes = cap/2 < one line.
        let cap = NonZeroU64::new(one_line_len).unwrap();

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&buffer_path)
            .await
            .unwrap_or_else(|e| panic!("open: {e}"));

        let mut buffer_size = 0u64;
        GrpcAuditSink::buffer_append(&mut file, &mut buffer_size, cap, &event)
            .await
            .unwrap_or_else(|e| panic!("first append: {e}"));
        GrpcAuditSink::buffer_append(&mut file, &mut buffer_size, cap, &event)
            .await
            .unwrap_or_else(|e| panic!("second append: {e}"));

        let contents = tokio::fs::read_to_string(&buffer_path)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        let lines: Vec<&str> = contents.lines().collect();
        assert!(
            !lines.is_empty(),
            "compaction must keep at least the newest event (buffer should not be empty)"
        );
        assert!(
            lines.iter().any(|l| l.contains("\"survivor\"")),
            "newest event should survive compaction even when it exceeds target_bytes"
        );
    }

    #[tokio::test]
    async fn test_sink_returns_ok_when_channel_empty() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let buffer_path = dir.path().join("empty.jsonl");

        let sink = GrpcAuditSink::new(unreachable_url(), &buffer_path, TEST_BUFFER_MAX_BYTES);
        let (tx, rx) = mpsc::channel::<ExecutionEvent>(1);
        let exit = CancellationToken::new();

        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        drop(tx);
        exit.cancel();

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
    }

    /// The count comes from the collector, and clearing the buffer is
    /// irreversible, so a count that cannot describe a batch has to read as
    /// "not acknowledged" rather than as "all of it".
    #[test]
    fn an_impossible_acknowledgment_count_is_not_an_acknowledgment() {
        let response = |events_received| firma_protobuf::v1::StreamEventsResponse {
            last_event_id: "evt-2".to_string(),
            events_received,
            durably_persisted: false,
        };

        assert!(!GrpcAuditSink::replay_is_complete(&response(-1), 2));
        assert!(!GrpcAuditSink::replay_is_complete(&response(1), 2));
        assert!(GrpcAuditSink::replay_is_complete(&response(2), 2));
    }

    #[tokio::test]
    async fn test_stream_send_to_a_full_stream_reads_as_a_broken_stream() {
        // A slow collector applies back-pressure through the 256-slot stream
        // channel. The run loop must treat a full channel as a broken stream
        // (buffer locally + reconnect) rather than await capacity: awaiting
        // stalls event handling, fills the bounded audit channel, and blocks
        // the enforcement path through the handler's awaiting send. The only
        // wait the send performs is a yield — see `try_stream_send` — so the
        // deadline here is generous and still bites on a send that parks.
        let (tx, _never_polled) = mpsc::channel::<firma_protobuf::v1::ExecutionEvent>(1);
        tx.send(execution_event_to_proto(sample_event("evt-fill")))
            .await
            .expect("the single slot fills");
        // `_never_polled` is never polled, like a collector that accepts the
        // RPC but stops consuming it.
        let rpc_handle = tokio::spawn(async {
            Err::<tonic::Response<firma_protobuf::v1::StreamEventsResponse>, tonic::Status>(
                tonic::Status::unknown("test placeholder"),
            )
        });
        let state = (tx, rpc_handle);

        let sent = tokio::time::timeout(
            Duration::from_millis(500),
            GrpcAuditSink::try_stream_send(Some(&state), &sample_event("evt-live")),
        )
        .await
        .expect("a full stream channel must not stall the run loop");
        assert!(
            !sent,
            "a full stream must read as a send failure so the event is buffered instead of stalling"
        );
    }

    /// The queue depth is what makes the loss of an abandoned stream visible,
    /// so it has to count what is actually in the channel.
    #[tokio::test]
    async fn abandoned_event_count_reports_the_queued_depth() {
        let (tx, _never_polled) = mpsc::channel::<firma_protobuf::v1::ExecutionEvent>(4);
        for id in ["evt-1", "evt-2", "evt-3"] {
            tx.send(execution_event_to_proto(sample_event(id)))
                .await
                .expect("slot is free");
        }
        let rpc_handle = tokio::spawn(async {
            Err::<tonic::Response<firma_protobuf::v1::StreamEventsResponse>, tonic::Status>(
                tonic::Status::unknown("test placeholder"),
            )
        });
        let state = (tx, rpc_handle);

        assert_eq!(GrpcAuditSink::abandoned_event_count(&state), 3);
    }

    #[test]
    fn execution_event_converts_to_proto() {
        let event = sample_event("evt-proto");
        let proto = execution_event_to_proto(event);

        assert_eq!(
            proto,
            firma_protobuf::v1::ExecutionEvent {
                event_id: "evt-proto".to_string(),
                session_id: "sess-1".to_string(),
                token_id: "ctok_01j0000000e008000000000001".to_string(),
                agent_id: "agt_01j0000000e008000000000001".to_string(),
                action: "http_get".to_string(),
                resource: "https://api.example.com/v1".to_string(),
                decision: 1,
                deny_reason: String::new(),
                enforcement_latency_us: 42,
                context_hash: "abc123".to_string(),
                bundle_version: "v1".to_string(),
                timestamp: Some(prost_types::Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0,
                }),
                signature: vec![0xDE, 0xAD],
                dispatch_status: 0,
                dispatch_latency_us: 0,
                response_size: 0,
                sandbox_id: String::new(),
                provenance: String::new(),
                thread_id: String::new(),
                parent_action_id: String::new(),
                run_evidence: None,
            }
        );
    }
}
