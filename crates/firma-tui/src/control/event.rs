//! Input events for the control surface.

use std::sync::mpsc::Receiver;
use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind};

use crate::control::{
    app::App,
    command::ControlEffect,
    input,
    rewrite::{PolicyRewriteEvent, PolicyRewriteHandler, PolicyRewriteQueue, RewriteEventProbe},
    state::{AuditRow, PolicyRewriteRequest},
};

// Audit traffic can be much noisier than terminal input. Drain enough rows per
// pass to keep the table moving, but cap the batch so a busy sidecar cannot
// keep the runner inside audit processing while the operator is trying to move,
// filter, or quit.
const AUDIT_BATCH_LIMIT: usize = 64;

// Ready sources are checked before the runner waits for terminal input. Input
// goes first so keystrokes are consumed immediately; rewrite notifications come
// next because they unblock policy rows; audit rows come last because they are
// buffered and can safely lag by one pass.
const READY_EVENT_PRIORITY: &[ControlQueueKind] = &[
    ControlQueueKind::Input,
    ControlQueueKind::Rewrite,
    ControlQueueKind::Audit,
];

// After the blocking wait, terminal input has already had its chance to wake
// the loop. At that point pending rewrite completions still matter more than
// audit rows, and a tick is only produced when no real source is ready.
const POST_WAIT_EVENT_PRIORITY: &[ControlQueueKind] = &[
    ControlQueueKind::Rewrite,
    ControlQueueKind::Audit,
    ControlQueueKind::Tick,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlQueueKind {
    Input,
    Rewrite,
    Audit,
    Tick,
}

/// Event consumed by the Policy Control runner.
///
/// Terminal input, audit rows, rewrite notifications, and ticks all flow
/// through this single type so command handling can remain deterministic.
#[derive(Debug)]
pub enum Event {
    /// Batch of audit rows drained from the monitor-backed audit source.
    Audit(Vec<AuditRow>),
    /// Pressed terminal key.
    Key(KeyCode),
    /// Policy rewrite worker notification.
    PolicyRewrite(PolicyRewriteEvent),
    /// Terminal resize notification.
    Resize,
    /// Mouse input, currently ignored by command handling.
    Mouse,
    /// Redraw tick when no higher-priority event is ready.
    Tick,
}

/// Source of terminal input used by the event pump.
///
/// Tests provide a fake implementation so event priority can be checked
/// without entering raw mode.
pub trait TerminalEventSource {
    /// Checks whether a terminal event is ready before the timeout expires.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal source cannot be polled.
    fn poll(&self, timeout: Duration) -> anyhow::Result<bool>;

    /// Reads the next terminal event.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal source cannot read the next event.
    fn read(&self) -> anyhow::Result<Event>;
}

struct CrosstermTerminalSource;

impl TerminalEventSource for CrosstermTerminalSource {
    fn poll(&self, timeout: Duration) -> anyhow::Result<bool> {
        event::poll(timeout).map_err(Into::into)
    }

    fn read(&self) -> anyhow::Result<Event> {
        read_crossterm_event()
    }
}

/// External event sources consumed by the TUI.
///
/// Audit rows are borrowed from the CLI service. Policy rewrite events are
/// owned here so shutdown can stop accepting new rewrites before the runner
/// exits.
pub struct Sources<'a> {
    audit_rows: Option<&'a Receiver<AuditRow>>,
    policy_rewrites: PolicyRewriteQueue,
}

impl<'a> Sources<'a> {
    /// Creates sources with an optional audit receiver and a default rewrite
    /// queue.
    #[must_use]
    pub(crate) fn new(audit_rows: Option<&'a Receiver<AuditRow>>) -> Self {
        Self::with_policy_rewrite_queue(audit_rows, PolicyRewriteQueue::new())
    }

    /// Creates sources with an injected rewrite handler for tests.
    #[must_use]
    pub fn with_policy_rewrite_handler(
        audit_rows: Option<&'a Receiver<AuditRow>>,
        handler: PolicyRewriteHandler,
    ) -> Self {
        Self::with_policy_rewrite_queue(audit_rows, PolicyRewriteQueue::with_handler(handler))
    }

    /// Creates sources with an injected rewrite handler and dispatch probe.
    #[must_use]
    pub(crate) fn with_observed_policy_rewrite_handler(
        audit_rows: Option<&'a Receiver<AuditRow>>,
        handler: PolicyRewriteHandler,
    ) -> (Self, RewriteEventProbe) {
        let (policy_rewrites, rewrite_probe) = PolicyRewriteQueue::with_handler_and_probe(handler);
        (
            Self::with_policy_rewrite_queue(audit_rows, policy_rewrites),
            rewrite_probe,
        )
    }

    fn with_policy_rewrite_queue(
        audit_rows: Option<&'a Receiver<AuditRow>>,
        policy_rewrites: PolicyRewriteQueue,
    ) -> Self {
        Self {
            audit_rows,
            policy_rewrites,
        }
    }

    /// Enqueues a policy rewrite if the queue is still accepting work.
    #[must_use]
    pub fn enqueue_policy_rewrite(&self, request: PolicyRewriteRequest) -> bool {
        self.policy_rewrites.enqueue(request)
    }

    /// Number of rewrite requests waiting behind the active worker.
    #[must_use]
    pub fn rewrite_queue_len(&self) -> usize {
        self.policy_rewrites.len()
    }

    /// Returns true once rewrite shutdown has started.
    #[must_use]
    pub(crate) fn rewrite_queue_shutting_down(&self) -> bool {
        self.policy_rewrites.is_shutting_down()
    }

    /// Stops accepting rewrite requests and lets active work finish.
    pub(crate) fn shutdown_policy_rewrites(&mut self) {
        self.policy_rewrites.shutdown();
    }
}

/// Returns the next event from terminal and external sources.
///
/// Input and rewrite notifications are checked before audit rows. Audit rows
/// are drained in bounded batches so a noisy audit log cannot starve keyboard
/// input.
pub fn next(sources: &Sources<'_>, timeout: Duration) -> anyhow::Result<Event> {
    next_with_terminal(sources, &CrosstermTerminalSource, timeout)
}

/// Returns the next event using an injected terminal source.
///
/// # Errors
///
/// Returns an error when terminal polling or terminal event reading fails.
pub fn next_with_terminal(
    sources: &Sources<'_>,
    terminal: &impl TerminalEventSource,
    timeout: Duration,
) -> anyhow::Result<Event> {
    if let Some(event) = next_priority_event(sources, terminal, READY_EVENT_PRIORITY)? {
        return Ok(event);
    }

    if terminal.poll(timeout)? {
        return terminal.read();
    }

    if let Some(event) = next_priority_event(sources, terminal, POST_WAIT_EVENT_PRIORITY)? {
        return Ok(event);
    }

    Ok(Event::Tick)
}

fn next_priority_event(
    sources: &Sources<'_>,
    terminal: &impl TerminalEventSource,
    priorities: &[ControlQueueKind],
) -> anyhow::Result<Option<Event>> {
    for queue in priorities {
        if let Some(event) = next_event_from_queue(sources, terminal, *queue)? {
            return Ok(Some(event));
        }
    }

    Ok(None)
}

fn next_event_from_queue(
    sources: &Sources<'_>,
    terminal: &impl TerminalEventSource,
    queue: ControlQueueKind,
) -> anyhow::Result<Option<Event>> {
    match queue {
        ControlQueueKind::Input => next_input_event(terminal),
        ControlQueueKind::Rewrite => Ok(next_rewrite_event(sources)),
        ControlQueueKind::Audit => Ok(next_audit_event(sources)),
        ControlQueueKind::Tick => Ok(Some(Event::Tick)),
    }
}

fn next_input_event(terminal: &impl TerminalEventSource) -> anyhow::Result<Option<Event>> {
    if terminal.poll(Duration::ZERO)? {
        terminal.read().map(Some)
    } else {
        Ok(None)
    }
}

fn next_rewrite_event(sources: &Sources<'_>) -> Option<Event> {
    sources.policy_rewrites.try_recv().map(Event::PolicyRewrite)
}

fn next_audit_event(sources: &Sources<'_>) -> Option<Event> {
    let rows = drain_audit_rows(sources);
    (!rows.is_empty()).then_some(Event::Audit(rows))
}

fn drain_audit_rows(sources: &Sources<'_>) -> Vec<AuditRow> {
    let Some(audit_rows) = sources.audit_rows else {
        return Vec::new();
    };

    let mut rows = Vec::new();
    while rows.len() < AUDIT_BATCH_LIMIT {
        let Ok(row) = audit_rows.try_recv() else {
            break;
        };
        rows.push(row);
    }
    rows
}

fn read_crossterm_event() -> anyhow::Result<Event> {
    match event::read()? {
        CrosstermEvent::Key(key) if key.kind == KeyEventKind::Press => Ok(Event::Key(key.code)),
        CrosstermEvent::Resize(_, _) => Ok(Event::Resize),
        CrosstermEvent::Mouse(_) => Ok(Event::Mouse),
        _ => Ok(Event::Tick),
    }
}

/// Applies an event to application state and returns runner-owned effects.
pub fn handle(app: &mut App, event: Event) -> Vec<ControlEffect> {
    match event {
        Event::Audit(rows) => {
            app.push_audit_rows(rows);
            Vec::new()
        }
        Event::PolicyRewrite(event) => {
            handle_policy_rewrite_event(app, event);
            Vec::new()
        }
        Event::Key(key) => input::handle_key(app, key),
        Event::Mouse | Event::Resize | Event::Tick => Vec::new(),
    }
}

fn handle_policy_rewrite_event(app: &mut App, event: PolicyRewriteEvent) {
    match event {
        PolicyRewriteEvent::Started(policy) => app.start_policy_rewrite(&policy),
        PolicyRewriteEvent::Completed(completion) => app.finish_policy_rewrite(&completion),
    }
}
