//! Serialized policy rewrite worker for Policy Control.
//!
//! Cedar policy files are rewritten as whole files. The queue keeps that work
//! on one background worker so two toggles cannot read the same old file and
//! overwrite each other. Requests are accepted from the TUI thread, processed
//! in FIFO order, and reported back as start/completion events.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, Sender, channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::control::{
    error::{ControlError, RewriteEventProbeError},
    state::{PolicyRewriteCompletion, PolicyRewriteRequest, PolicyRewriteStart},
    toggle,
};

/// Fn used by the worker to persist one rewrite request.
///
/// The default handler calls the Cedar rewrite layer. Tests replace it with a
/// controlled handler so they can pause active writes and check queue behavior
/// without depending on timing.
pub type PolicyRewriteHandler =
    Box<dyn Fn(&PolicyRewriteRequest) -> Result<(), ControlError> + Send + 'static>;

/// Notification emitted by the rewrite worker.
///
/// A request first reports that it has started, then reports completion with
/// either a structured error or a successful write result. The TUI still
/// refreshes policy state from disk after success instead of trusting the
/// requested state.
#[derive(Debug)]
pub enum PolicyRewriteEvent {
    /// The worker has started writing the batch.
    Started(PolicyRewriteStart),
    /// The worker has finished the batch.
    Completed(PolicyRewriteCompletion),
}

/// Coarse kind of rewrite event dispatched by the worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyRewriteEventKind {
    /// A started event was sent to the runner channel.
    Started,
    /// A completed event was sent to the runner channel.
    Completed,
}

/// Probe used by headless tests to observe rewrite event dispatch.
///
/// Rewrite handlers can signal that their own work has returned before the
/// queue worker has sent the corresponding runner event. This probe is tied to
/// the worker's event dispatch point, so tests can wait for the event that
/// `try_crank` will actually observe.
pub struct RewriteEventProbe {
    dispatched: Receiver<PolicyRewriteEventKind>,
}

impl RewriteEventProbe {
    /// Waits until the worker has dispatched a started event.
    ///
    /// # Errors
    ///
    /// Returns an error when the event is not observed before `timeout` or the
    /// worker-side probe channel is closed.
    pub fn wait_for_started(&self, timeout: Duration) -> Result<(), RewriteEventProbeError> {
        self.wait_for(PolicyRewriteEventKind::Started, timeout)
    }

    /// Waits until the worker has dispatched a completion event.
    ///
    /// # Errors
    ///
    /// Returns an error when the event is not observed before `timeout` or the
    /// worker-side probe channel is closed.
    pub fn wait_for_completed(&self, timeout: Duration) -> Result<(), RewriteEventProbeError> {
        self.wait_for(PolicyRewriteEventKind::Completed, timeout)
    }

    fn wait_for(
        &self,
        expected: PolicyRewriteEventKind,
        timeout: Duration,
    ) -> Result<(), RewriteEventProbeError> {
        let started = Instant::now();
        loop {
            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                return Err(RewriteEventProbeError::Timeout { timeout });
            };

            match self.dispatched.recv_timeout(remaining) {
                Ok(event_kind) if event_kind == expected => return Ok(()),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    return Err(RewriteEventProbeError::Timeout { timeout });
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(RewriteEventProbeError::Disconnected);
                }
            }
        }
    }
}

/// Background queue responsible for serializing Cedar rewrites.
///
/// The queue accepts file-level batch requests and owns one worker thread.
/// Pending requests can be sealed during shutdown; the active write is allowed
/// to finish, and queued-but-not-started requests are discarded.
pub struct PolicyRewriteQueue {
    request_tx: Option<Sender<PolicyRewriteRequest>>,
    event_rx: Receiver<PolicyRewriteEvent>,
    queued_requests: Arc<AtomicUsize>,
    shutdown_requested: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl PolicyRewriteQueue {
    /// Creates a queue backed by the normal Cedar rewrite handler.
    #[must_use]
    pub fn new() -> Self {
        Self::with_handler(Box::new(default_policy_rewrite_handler))
    }

    /// Creates a queue backed by a caller-supplied rewrite handler.
    ///
    /// Tests use this to observe the worker and hold a write open. Production
    /// code should normally use [`Self::new`].
    #[must_use]
    pub fn with_handler(handler: PolicyRewriteHandler) -> Self {
        Self::with_handler_and_dispatch_tx(handler, None)
    }

    /// Creates a queue with an injected rewrite handler and dispatch probe.
    ///
    /// The probe observes events only after they have been sent to the runner
    /// channel. This is mainly useful for deterministic tests around event
    /// priority.
    #[must_use]
    pub fn with_handler_and_probe(handler: PolicyRewriteHandler) -> (Self, RewriteEventProbe) {
        let (dispatched_tx, dispatched_rx) = channel();
        (
            Self::with_handler_and_dispatch_tx(handler, Some(dispatched_tx)),
            RewriteEventProbe {
                dispatched: dispatched_rx,
            },
        )
    }

    fn with_handler_and_dispatch_tx(
        handler: PolicyRewriteHandler,
        event_dispatch_tx: Option<Sender<PolicyRewriteEventKind>>,
    ) -> Self {
        let (request_tx, request_rx) = channel();
        let (event_tx, event_rx) = channel();
        let queued_requests = Arc::new(AtomicUsize::new(0));
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let worker_queued_requests = Arc::clone(&queued_requests);
        let worker_shutdown_requested = Arc::clone(&shutdown_requested);
        // NOTE: This is intentionally one global FIFO worker for now. It is
        // stricter than per-file serialization, but prevents concurrent
        // whole-file Cedar rewrites while keeping the API small enough to swap
        // in per-file workers later.
        let worker = thread::spawn(move || {
            worker_loop(
                &request_rx,
                &event_tx,
                &worker_queued_requests,
                &worker_shutdown_requested,
                &handler,
                event_dispatch_tx.as_ref(),
            );
        });

        Self {
            request_tx: Some(request_tx),
            event_rx,
            queued_requests,
            shutdown_requested,
            worker: Some(worker),
        }
    }

    /// Attempts to enqueue a rewrite request.
    ///
    /// Returns false once shutdown has started or when the worker channel is
    /// no longer available.
    pub fn enqueue(&self, request: PolicyRewriteRequest) -> bool {
        if self.is_shutting_down() {
            return false;
        }

        let Some(request_tx) = self.request_tx.as_ref() else {
            return false;
        };

        self.queued_requests.fetch_add(1, Ordering::SeqCst);
        if request_tx.send(request).is_ok() {
            true
        } else {
            self.queued_requests.fetch_sub(1, Ordering::SeqCst);
            false
        }
    }

    /// Returns the next worker event, if one is ready.
    ///
    /// This is non-blocking so the event pump can keep terminal input
    /// responsive while Cedar writes are running.
    pub fn try_recv(&self) -> Option<PolicyRewriteEvent> {
        self.event_rx.try_recv().ok()
    }

    /// Number of queued rewrite requests that have not started yet.
    pub fn len(&self) -> usize {
        self.queued_requests.load(Ordering::SeqCst)
    }

    /// Stops accepting new requests.
    ///
    /// The worker will not interrupt an active file write. Once the active
    /// request finishes, queued-but-not-started requests are drained without
    /// execution.
    pub fn shutdown(&mut self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.request_tx.take();
    }

    /// Returns true once shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }
}

impl Default for PolicyRewriteQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PolicyRewriteQueue {
    fn drop(&mut self) {
        self.shutdown();

        if let Some(worker) = self.worker.take() {
            let _panicked = worker.join().is_err();
        }
    }
}

fn worker_loop(
    request_rx: &Receiver<PolicyRewriteRequest>,
    event_tx: &Sender<PolicyRewriteEvent>,
    queued_requests: &AtomicUsize,
    shutdown_requested: &AtomicBool,
    policy_rewrite_handler: &PolicyRewriteHandler,
    event_dispatch_tx: Option<&Sender<PolicyRewriteEventKind>>,
) {
    while let Ok(request) = request_rx.recv() {
        queued_requests.fetch_sub(1, Ordering::SeqCst);
        if shutdown_requested.load(Ordering::SeqCst) {
            discard_pending_requests(request_rx, queued_requests);
            break;
        }

        if !send_rewrite_event(
            event_tx,
            event_dispatch_tx,
            PolicyRewriteEventKind::Started,
            PolicyRewriteEvent::Started(PolicyRewriteStart {
                file: request.file.clone(),
                ids: request.ids.clone(),
            }),
        ) {
            break;
        }

        let result = policy_rewrite_handler(&request);
        let PolicyRewriteRequest {
            file,
            ids,
            requested,
        } = request;

        if !send_rewrite_event(
            event_tx,
            event_dispatch_tx,
            PolicyRewriteEventKind::Completed,
            PolicyRewriteEvent::Completed(PolicyRewriteCompletion {
                file,
                ids,
                requested,
                result,
            }),
        ) {
            break;
        }

        if shutdown_requested.load(Ordering::SeqCst) {
            discard_pending_requests(request_rx, queued_requests);
            break;
        }
    }
}

fn send_rewrite_event(
    event_tx: &Sender<PolicyRewriteEvent>,
    event_dispatch_tx: Option<&Sender<PolicyRewriteEventKind>>,
    event_kind: PolicyRewriteEventKind,
    event: PolicyRewriteEvent,
) -> bool {
    if event_tx.send(event).is_err() {
        return false;
    }

    if let Some(event_dispatch_tx) = event_dispatch_tx {
        let _ = event_dispatch_tx.send(event_kind);
    }

    true
}

fn discard_pending_requests(
    request_rx: &Receiver<PolicyRewriteRequest>,
    queued_requests: &AtomicUsize,
) {
    while request_rx.try_recv().is_ok() {
        queued_requests.fetch_sub(1, Ordering::SeqCst);
    }
}

fn default_policy_rewrite_handler(request: &PolicyRewriteRequest) -> Result<(), ControlError> {
    toggle::set_policy_states(&request.file, &request.ids, request.requested)
        .map_err(|error| ControlError::policy_rewrite(&request.file, request.ids.clone(), error))
}
