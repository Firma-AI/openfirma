//! Terminal input for Policy Control.

use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind};

use crate::control::{app::App, command::ControlEffect, input};

const EVENT_POLL_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Key(KeyCode),
    Resize,
    Mouse,
    Tick,
}

pub trait TerminalEventSource {
    /// Checks whether a terminal event is ready before the timeout expires.
    ///
    /// # Errors
    ///
    /// Fails if the terminal event source cannot be polled.
    fn poll(&self, timeout: Duration) -> anyhow::Result<bool>;

    /// Reads the next terminal event.
    ///
    /// # Errors
    ///
    /// Fails if the next terminal event cannot be read.
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

#[derive(Default)]
pub struct Sources;

impl Sources {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

pub fn next(sources: &Sources) -> anyhow::Result<Event> {
    next_with_terminal(sources, &CrosstermTerminalSource, EVENT_POLL_TIMEOUT)
}

/// Returns the next control event using an injected terminal source.
///
/// # Errors
///
/// Fails if terminal event polling fails.
pub fn next_with_terminal(
    _sources: &Sources,
    terminal: &impl TerminalEventSource,
    timeout: Duration,
) -> anyhow::Result<Event> {
    if terminal.poll(timeout)? {
        return terminal.read();
    }

    Ok(Event::Tick)
}

fn read_crossterm_event() -> anyhow::Result<Event> {
    match event::read()? {
        CrosstermEvent::Key(key) if key.kind == KeyEventKind::Press => Ok(Event::Key(key.code)),
        CrosstermEvent::Resize(_, _) => Ok(Event::Resize),
        CrosstermEvent::Mouse(_) => Ok(Event::Mouse),
        _ => Ok(Event::Tick),
    }
}

pub fn handle(app: &mut App, event: Event) -> Vec<ControlEffect> {
    match event {
        Event::Key(key) => input::handle_key(app, key),
        Event::Mouse | Event::Resize | Event::Tick => Vec::new(),
    }
}
