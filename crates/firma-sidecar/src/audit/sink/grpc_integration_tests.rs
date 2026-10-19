//! Integration tests for the durable gRPC audit sink.
//!
//! Spin up an in-process `AuditService` backed by tonic and drive
//! [`GrpcAuditSink`] against it to cover the behavior the unit tests cannot
//! reach without a server: reconnecting to a service that was down at
//! startup, replaying the buffer in order, and — the property that makes the
//! sink durable — keeping the buffer when a replay is not acknowledged.
//!
//! These live under `src/` rather than `tests/` because [`GrpcAuditSink`] is
//! `pub(crate)`, mirroring `authority_client::integration_tests`.

#![cfg(test)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use firma_protobuf::v1::audit_service_server::{AuditService, AuditServiceServer};
use firma_protobuf::v1::{ExecutionEvent as ProtoExecutionEvent, StreamEventsResponse};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use super::GrpcAuditSink;
use crate::audit::AuditSink as _;
use crate::audit::test_support::{buffered_ids, sample_event, wait_until};

/// How long a single enqueue may take before the sink counts as stalled.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on the events a test feeds an unreading collector before the
/// sink is expected to have fallen back to its buffer. The mock uses a small
/// stream window, so this leaves room for the stream channel to fill too.
const MAX_STALL_EVENTS: usize = 1_024;

/// The deliberately small HTTP/2 receive window for an unreading mock
/// collector. It makes the sink's stream channel fill promptly instead of
/// relying on the runtime's platform-dependent default window size.
const STALLED_COLLECTOR_STREAM_WINDOW: u32 = 4 * 1024;

/// How long a cancelled sink may take to return. Comfortably above the sink's
/// own bound on waiting for a close acknowledgment, so a test failure means
/// the wait was unbounded rather than merely slow.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// Mock AuditService
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockAuditState {
    /// Event IDs in the order the server received them.
    received: Mutex<Vec<String>>,
    /// When set, `StreamEvents` fails instead of acknowledging.
    reject: AtomicBool,
    /// How many times a client opened `StreamEvents`, rejected or not.
    stream_attempts: AtomicUsize,
    /// When set, the response acknowledges one fewer event than arrived,
    /// standing in for a collector that persists only part of a batch.
    acknowledge_short: AtomicBool,
    /// When set, the handler accepts the stream and never reads from it,
    /// standing in for a collector that is connected but not consuming.
    stall_reads: AtomicBool,
    /// When set, the handler reads the whole stream and never answers the
    /// half-close, standing in for a collector that goes quiet at shutdown.
    withhold_response: AtomicBool,
}

struct MockAudit {
    state: Arc<MockAuditState>,
    /// Released when the server is stopped, so handlers parked on purpose
    /// cannot outlive the test.
    stop: CancellationToken,
}

#[tonic::async_trait]
impl AuditService for MockAudit {
    async fn submit_event(
        &self,
        _request: Request<ProtoExecutionEvent>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        Err(Status::unimplemented("legacy collector"))
    }

    async fn stream_events(
        &self,
        request: Request<Streaming<ProtoExecutionEvent>>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        self.state.stream_attempts.fetch_add(1, Ordering::SeqCst);
        if self.state.reject.load(Ordering::SeqCst) {
            return Err(Status::unavailable("audit service rejecting streams"));
        }

        if self.state.stall_reads.load(Ordering::SeqCst) {
            self.stop.cancelled().await;
            return Err(Status::unavailable("audit service never read the stream"));
        }

        let mut stream = request.into_inner();
        let mut last_event_id = String::new();
        let mut events_received = 0i64;

        while let Some(event) = stream.message().await? {
            last_event_id.clone_from(&event.event_id);
            events_received += 1;
            self.state
                .received
                .lock()
                .expect("received lock")
                .push(event.event_id);
        }

        if self.state.withhold_response.load(Ordering::SeqCst) {
            self.stop.cancelled().await;
            return Err(Status::unavailable("audit service never acknowledged"));
        }

        if self.state.acknowledge_short.load(Ordering::SeqCst) {
            events_received = (events_received - 1).max(0);
        }

        Ok(Response::new(StreamEventsResponse {
            last_event_id,
            events_received,
            durably_persisted: false,
        }))
    }
}

struct MockAuditServer {
    state: Arc<MockAuditState>,
    shutdown: CancellationToken,
    join: JoinHandle<()>,
}

impl MockAuditServer {
    /// Returns the event IDs received so far, in arrival order.
    fn received(&self) -> Vec<String> {
        self.state.received.lock().expect("received lock").clone()
    }

    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.join.await;
    }
}

/// Reserves an ephemeral port without binding a server to it, so a sink can
/// be pointed at an endpoint that is not yet listening.
async fn reserve_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    format!("http://{addr}")
}

/// Starts a mock audit service on `url`'s address.
fn start_mock_audit(url: &str, state: Arc<MockAuditState>) -> MockAuditServer {
    let addr = url
        .trim_start_matches("http://")
        .parse()
        .expect("endpoint address");
    let shutdown = CancellationToken::new();
    let service = MockAudit {
        state: Arc::clone(&state),
        stop: shutdown.clone(),
    };
    let stalled_collector = state.stall_reads.load(Ordering::SeqCst);

    let shutdown_signal = shutdown.clone();
    let join = tokio::spawn(async move {
        let builder = Server::builder();
        let mut builder = if stalled_collector {
            builder.initial_stream_window_size(STALLED_COLLECTOR_STREAM_WINDOW)
        } else {
            builder
        };
        let _ = builder
            .add_service(AuditServiceServer::new(service))
            .serve_with_shutdown(addr, async move {
                shutdown_signal.cancelled().await;
            })
            .await;
    });

    MockAuditServer {
        state,
        shutdown,
        join,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn buffered_events_replay_in_order_once_the_service_appears() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("buffer.jsonl");
    let url = reserve_endpoint().await;

    // Start the sink against an endpoint nothing is listening on.
    let sink = GrpcAuditSink::new(url.clone(), &buffer_path, 10 * 1024 * 1024);
    let (tx, rx) = mpsc::channel(16);
    let exit = CancellationToken::new();
    let sink_exit = exit.clone();
    let sink_handle = tokio::spawn(async move { sink.run(rx, sink_exit).await });

    for id in ["evt-1", "evt-2", "evt-3"] {
        tx.send(sample_event(id)).await.expect("enqueue event");
    }

    let path_for_wait = buffer_path.clone();
    wait_until("events to reach the buffer", move || {
        buffered_ids(&path_for_wait).len() == 3
    })
    .await;

    // Bring the service up; the sink's reconnect arm should replay the batch.
    let server = start_mock_audit(&url, Arc::new(MockAuditState::default()));

    let received = Arc::clone(&server.state);
    wait_until("the buffered batch to be replayed", move || {
        received.received.lock().expect("received lock").len() == 3
    })
    .await;

    assert_eq!(
        server.received(),
        vec![
            "evt-1".to_string(),
            "evt-2".to_string(),
            "evt-3".to_string()
        ],
        "replay must preserve event order"
    );

    let path_for_wait = buffer_path.clone();
    wait_until("the acknowledged buffer to be cleared", move || {
        buffered_ids(&path_for_wait).is_empty()
    })
    .await;

    exit.cancel();
    drop(tx);
    let _ = sink_handle.await;
    server.stop().await;
}

#[tokio::test]
async fn an_unacknowledged_replay_keeps_the_buffer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("buffer.jsonl");
    let url = reserve_endpoint().await;

    // The service is reachable but refuses every stream, so replays connect
    // and then fail before any acknowledgment.
    let state = Arc::new(MockAuditState::default());
    state.reject.store(true, Ordering::SeqCst);
    let server = start_mock_audit(&url, Arc::clone(&state));

    let sink = GrpcAuditSink::new(url.clone(), &buffer_path, 10 * 1024 * 1024);
    let (tx, rx) = mpsc::channel(16);
    let exit = CancellationToken::new();
    let sink_exit = exit.clone();
    let sink_handle = tokio::spawn(async move { sink.run(rx, sink_exit).await });

    for id in ["evt-a", "evt-b"] {
        tx.send(sample_event(id)).await.expect("enqueue event");
    }

    let path_for_wait = buffer_path.clone();
    wait_until("events to reach the buffer", move || {
        buffered_ids(&path_for_wait).len() == 2
    })
    .await;

    // Wait for actual retries rather than a wall-clock guess: the assertion
    // below is only meaningful once the sink has been refused more than once.
    let attempts = Arc::clone(&state);
    wait_until("the sink to be refused repeatedly", move || {
        attempts.stream_attempts.load(Ordering::SeqCst) >= 3
    })
    .await;

    assert_eq!(
        buffered_ids(&buffer_path),
        vec!["evt-a".to_string(), "evt-b".to_string()],
        "a replay the server never acknowledged must not clear the buffer"
    );
    assert!(
        server.received().is_empty(),
        "the rejecting service must not have recorded events"
    );

    exit.cancel();
    drop(tx);
    let _ = sink_handle.await;
    server.stop().await;
}

#[tokio::test]
async fn a_restarted_sink_replays_the_buffer_left_by_its_predecessor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("buffer.jsonl");
    let url = reserve_endpoint().await;

    // First sink runs with nothing listening and leaves its events on disk.
    let sink = GrpcAuditSink::new(url.clone(), &buffer_path, 10 * 1024 * 1024);
    let (tx, rx) = mpsc::channel(16);
    let exit = CancellationToken::new();
    let sink_exit = exit.clone();
    let sink_handle = tokio::spawn(async move { sink.run(rx, sink_exit).await });

    for id in ["evt-before-restart-1", "evt-before-restart-2"] {
        tx.send(sample_event(id)).await.expect("enqueue event");
    }

    let path_for_wait = buffer_path.clone();
    wait_until("events to reach the buffer", move || {
        buffered_ids(&path_for_wait).len() == 2
    })
    .await;

    exit.cancel();
    drop(tx);
    let _ = sink_handle.await;

    // A fresh sink over the same buffer path, now with the service up.
    let server = start_mock_audit(&url, Arc::new(MockAuditState::default()));
    let sink = GrpcAuditSink::new(url.clone(), &buffer_path, 10 * 1024 * 1024);
    let (tx, rx) = mpsc::channel(16);
    let exit = CancellationToken::new();
    let sink_exit = exit.clone();
    let sink_handle = tokio::spawn(async move { sink.run(rx, sink_exit).await });

    let received = Arc::clone(&server.state);
    wait_until("the predecessor's buffer to be replayed", move || {
        received.received.lock().expect("received lock").len() == 2
    })
    .await;

    assert_eq!(
        server.received(),
        vec![
            "evt-before-restart-1".to_string(),
            "evt-before-restart-2".to_string()
        ],
        "events buffered before restart must survive it"
    );

    exit.cancel();
    drop(tx);
    let _ = sink_handle.await;
    server.stop().await;
}

/// A collector that takes the whole replay and then goes quiet is the case a
/// success status cannot distinguish from a collector that persisted nothing:
/// no response arrived, so the batch has to stay on disk.
#[tokio::test]
async fn a_replay_the_collector_never_answers_keeps_the_buffer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("buffer.jsonl");
    let url = reserve_endpoint().await;

    let state = Arc::new(MockAuditState::default());
    state.withhold_response.store(true, Ordering::SeqCst);

    let sink = GrpcAuditSink::new(url.clone(), &buffer_path, 10 * 1024 * 1024);
    let (tx, rx) = mpsc::channel(16);
    let exit = CancellationToken::new();
    let sink_exit = exit.clone();
    let sink_handle = tokio::spawn(async move { sink.run(rx, sink_exit).await });

    for id in ["evt-quiet-1", "evt-quiet-2"] {
        tx.send(sample_event(id)).await.expect("enqueue event");
    }

    let path_for_wait = buffer_path.clone();
    wait_until("events to reach the buffer", move || {
        buffered_ids(&path_for_wait).len() == 2
    })
    .await;

    let server = start_mock_audit(&url, Arc::clone(&state));

    let received = Arc::clone(&state);
    wait_until("the batch to reach the collector", move || {
        received.received.lock().expect("received lock").len() >= 2
    })
    .await;

    assert_eq!(
        buffered_ids(&buffer_path),
        vec!["evt-quiet-1".to_string(), "evt-quiet-2".to_string()],
        "a replay the collector never answered must stay on disk"
    );

    // The sink is parked in its acknowledgment wait. Cancelling has to come
    // out of that wait on its own, so this returns without the test having to
    // release the collector first.
    exit.cancel();
    drop(tx);
    let result = tokio::time::timeout(SHUTDOWN_TIMEOUT, sink_handle)
        .await
        .expect("cancelling must abandon the acknowledgment wait")
        .expect("sink task should not panic");
    assert!(
        result.is_ok(),
        "an abandoned replay is not a sink failure: {result:?}"
    );
    assert_eq!(
        buffered_ids(&buffer_path),
        vec!["evt-quiet-1".to_string(), "evt-quiet-2".to_string()],
        "an abandoned replay must leave the batch for the next process"
    );

    server.stop().await;
}

/// A collector that stays connected without reading is the worst case for the
/// enforcement path: the stream channel fills, and anything that waits for a
/// slot in it stalls the run loop, then the audit channel, then the handler
/// that writes to it. The sink must keep consuming and fall back to the
/// buffer instead.
#[tokio::test]
async fn a_collector_that_stops_reading_does_not_stall_the_sink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("buffer.jsonl");
    let url = reserve_endpoint().await;

    let state = Arc::new(MockAuditState::default());
    state.stall_reads.store(true, Ordering::SeqCst);
    let server = start_mock_audit(&url, Arc::clone(&state));

    let sink = GrpcAuditSink::new(url.clone(), &buffer_path, 10 * 1024 * 1024);
    let (tx, rx) = mpsc::channel(16);
    let exit = CancellationToken::new();
    let sink_exit = exit.clone();
    let sink_handle = tokio::spawn(async move { sink.run(rx, sink_exit).await });

    let attempts = Arc::clone(&state);
    wait_until("the sink to open a stream", move || {
        attempts.stream_attempts.load(Ordering::SeqCst) >= 1
    })
    .await;

    // Feed the sink until the stream channel and the HTTP/2 window behind it
    // are full and events start landing on disk instead. Every send is
    // bounded, so a sink that waits for stream capacity fails the test here
    // rather than hanging it.
    let mut buffered = Vec::new();
    for index in 0..MAX_STALL_EVENTS {
        let enqueue = tx.send(sample_event(&format!("evt-{index}")));
        let Ok(outcome) = tokio::time::timeout(SEND_TIMEOUT, enqueue).await else {
            // A send can also wait out the one pause the sink documents: once
            // the first events are on disk, the reconnect arm replays them on
            // the run loop, and nothing is consumed while that replay waits on
            // the same collector that is not reading. That pause is only
            // reachable after the fallback under test already happened, so what
            // separates it from a stall is whether the buffer holds anything.
            buffered = buffered_ids(&buffer_path);
            assert!(
                !buffered.is_empty(),
                "sink stopped consuming events at event {index} without buffering any"
            );
            break;
        };
        if let Err(err) = outcome {
            panic!("sink closed the audit channel at event {index}: {err}");
        }

        // Reading the buffer is far more expensive than a send, so check in
        // batches rather than after every event.
        if index % 256 == 0 {
            buffered = buffered_ids(&buffer_path);
            if !buffered.is_empty() {
                break;
            }
        }
    }

    assert!(
        !buffered.is_empty(),
        "a stream nobody reads must push events to the buffer within {MAX_STALL_EVENTS} events"
    );

    exit.cancel();
    drop(tx);
    let _ = sink_handle.await;
    server.stop().await;
}

/// The closing half-close is answered by the collector, so a collector that
/// goes quiet at exactly that moment must not be able to hold the sink — and
/// through it process exit — open.
#[tokio::test]
async fn shutdown_completes_when_the_collector_never_answers_the_close() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("buffer.jsonl");
    let url = reserve_endpoint().await;

    let state = Arc::new(MockAuditState::default());
    state.withhold_response.store(true, Ordering::SeqCst);
    let server = start_mock_audit(&url, Arc::clone(&state));

    let sink = GrpcAuditSink::new(url.clone(), &buffer_path, 10 * 1024 * 1024);
    let (tx, rx) = mpsc::channel(16);
    let exit = CancellationToken::new();
    let sink_exit = exit.clone();
    let sink_handle = tokio::spawn(async move { sink.run(rx, sink_exit).await });

    // Send only once the live stream is up: an event that lands in the buffer
    // first would be replayed instead, which is a different wait.
    let attempts = Arc::clone(&state);
    wait_until("the sink to open a stream", move || {
        attempts.stream_attempts.load(Ordering::SeqCst) >= 1
    })
    .await;

    tx.send(sample_event("evt-quiet-close"))
        .await
        .expect("enqueue event");

    let received = Arc::clone(&state);
    wait_until("the event to reach the collector", move || {
        received.received.lock().expect("received lock").len() == 1
    })
    .await;

    exit.cancel();
    drop(tx);

    let result = tokio::time::timeout(SHUTDOWN_TIMEOUT, sink_handle)
        .await
        .expect("the sink must not wait on a collector that never answers")
        .expect("sink task should not panic");
    assert!(
        result.is_ok(),
        "an unanswered close is a logging concern, not a sink failure: {result:?}"
    );

    server.stop().await;
}

/// A success status is not an acknowledgment of the whole batch: the response
/// carries the count, and a collector that persisted fewer events than were
/// sent must not cost the sink the rest.
#[tokio::test]
async fn a_partially_acknowledged_replay_keeps_the_buffer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let buffer_path = dir.path().join("buffer.jsonl");
    let url = reserve_endpoint().await;

    let state = Arc::new(MockAuditState::default());
    state.acknowledge_short.store(true, Ordering::SeqCst);

    let sink = GrpcAuditSink::new(url.clone(), &buffer_path, 10 * 1024 * 1024);
    let (tx, rx) = mpsc::channel(16);
    let exit = CancellationToken::new();
    let sink_exit = exit.clone();
    let sink_handle = tokio::spawn(async move { sink.run(rx, sink_exit).await });

    for id in ["evt-x", "evt-y"] {
        tx.send(sample_event(id)).await.expect("enqueue event");
    }

    let path_for_wait = buffer_path.clone();
    wait_until("events to reach the buffer", move || {
        buffered_ids(&path_for_wait).len() == 2
    })
    .await;

    let server = start_mock_audit(&url, Arc::clone(&state));

    let received = Arc::clone(&state);
    wait_until("the batch to be replayed", move || {
        received.received.lock().expect("received lock").len() >= 2
    })
    .await;

    assert_eq!(
        buffered_ids(&buffer_path),
        vec!["evt-x".to_string(), "evt-y".to_string()],
        "a batch the collector only partly acknowledged must stay on disk"
    );

    exit.cancel();
    drop(tx);
    let _ = sink_handle.await;
    server.stop().await;
}
