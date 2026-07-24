//! Input events for the control surface.

use std::sync::mpsc::Receiver;
use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind};

use crate::control::{app::App, command::ControlEffect, input, state::AuditRow};

const EVENT_POLL_TIMEOUT: Duration = Duration::from_millis(100);
const AUDIT_BATCH_LIMIT: usize = 64;
const READY_EVENT_PRIORITY: &[ControlQueueKind] =
    &[ControlQueueKind::Input, ControlQueueKind::Audit];
const POST_WAIT_EVENT_PRIORITY: &[ControlQueueKind] =
    &[ControlQueueKind::Audit, ControlQueueKind::Tick];

/// Event queue checked by the event pump.
///
/// Input is checked before audit rows so keyboard handling remains responsive
/// even when the audit stream is busy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlQueueKind {
    Input,
    Audit,
    Tick,
}

/// Event consumed by the command layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    /// Batch of sidecar audit rows from the monitor audit source.
    Audit(Vec<AuditRow>),
    /// Pressed key.
    Key(KeyCode),
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
    /// Returns an error when the terminal event source cannot be polled.
    fn poll(&self, timeout: Duration) -> anyhow::Result<bool>;

    /// Reads the next terminal event.
    ///
    /// # Errors
    ///
    /// Returns an error when the next terminal event cannot be read.
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
pub struct Sources<'a> {
    audit_rows: Option<&'a Receiver<AuditRow>>,
}

impl<'a> Sources<'a> {
    /// Creates sources with an optional audit receiver.
    #[must_use]
    pub const fn new(audit_rows: Option<&'a Receiver<AuditRow>>) -> Self {
        Self { audit_rows }
    }
}

/// Returns the next event from terminal and external sources.
///
/// Input is checked before audit rows. Audit rows are drained in bounded
/// batches so a noisy audit log cannot starve keyboard input.
///
/// # Errors
///
/// Returns an error when terminal polling or terminal event reading fails.
pub fn next(sources: &Sources<'_>) -> anyhow::Result<Event> {
    next_with_terminal(sources, &CrosstermTerminalSource, EVENT_POLL_TIMEOUT)
}

/// Returns the next control event using an injected terminal source.
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

/// Applies one event to app state and returns runner side effects.
pub fn handle(app: &mut App, event: Event) -> Vec<ControlEffect> {
    match event {
        Event::Audit(rows) => {
            app.push_audit_rows(rows);
            Vec::new()
        }
        Event::Key(key) => input::handle_key(app, key),
        Event::Mouse | Event::Resize | Event::Tick => Vec::new(),
    }
}
