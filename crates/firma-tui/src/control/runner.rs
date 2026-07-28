//! Event pump for the Policy Control terminal UI.

use std::{collections::VecDeque, path::PathBuf, process::ExitCode, sync::mpsc::Receiver};

use crate::control::{
    ControlOptions,
    announcement::ControlAnnouncement,
    app::App,
    command::ControlEffect,
    event::{self, Event, Sources},
    terminal::Tui,
};

/// Runs the Policy Control event loop in a real terminal session.
///
/// The runner owns terminal drawing and side-effect execution. App state stays
/// focused on selections, audit rows, and lifecycle state.
///
/// # Errors
///
/// Returns an error when terminal setup, input polling, drawing, or shutdown
/// handling fails.
pub fn run(options: &ControlOptions) -> anyhow::Result<ExitCode> {
    Runner::enter(options)?.run()
}

/// Result of processing one headless runner step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCrankOutcome {
    /// No user or external event was ready.
    NoEvent,
    /// One non-tick event was processed.
    Processed(EventKind),
    /// Shutdown was requested.
    Quit,
}

/// Coarse event category used by runner tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Audit rows were consumed.
    Audit,
    /// Keyboard input was consumed.
    Input,
    /// Mouse input was consumed.
    Mouse,
    /// Terminal resize was consumed.
    Resize,
}

impl EventKind {
    const fn from_event(event: &Event) -> Option<Self> {
        match event {
            Event::Audit(_) => Some(Self::Audit),
            Event::Key(_) => Some(Self::Input),
            Event::Mouse => Some(Self::Mouse),
            Event::Resize => Some(Self::Resize),
            Event::Tick => None,
        }
    }
}

/// Runner variant used by non-terminal tests.
///
/// It uses the same app and event-source types as the real runner, but callers
/// provide a fake terminal input source and drive one step at a time.
pub struct HeadlessRunner<'a> {
    app: App,
    sources: Sources<'a>,
}

impl<'a> HeadlessRunner<'a> {
    /// Creates a headless runner without an audit source.
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>) -> Self {
        Self::with_audit_rows(policy_dir, None)
    }

    /// Creates a headless runner with an optional audit row receiver.
    #[must_use]
    pub fn with_audit_rows(
        policy_dir: Option<PathBuf>,
        audit_rows: Option<&'a Receiver<crate::control::AuditRow>>,
    ) -> Self {
        Self {
            app: App::new(policy_dir, audit_rows.is_some()),
            sources: Sources::new(audit_rows),
        }
    }

    /// Returns the current application state.
    #[must_use]
    pub const fn app(&self) -> &App {
        &self.app
    }

    /// Returns the event sources consumed by this runner.
    #[must_use]
    pub const fn sources(&self) -> &Sources<'a> {
        &self.sources
    }

    /// Processes at most one ready event.
    ///
    /// Tick events report [`ControlCrankOutcome::NoEvent`]. This lets tests
    /// assert event-priority behavior without sleeping or entering raw mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal source cannot be polled or read.
    pub fn try_crank(
        &mut self,
        terminal: &impl event::TerminalEventSource,
    ) -> anyhow::Result<ControlCrankOutcome> {
        if self.app.should_quit() {
            return Ok(ControlCrankOutcome::Quit);
        }

        self.sync_status();

        let event = event::next_with_terminal(&self.sources, terminal, std::time::Duration::ZERO)?;
        let Some(event_kind) = EventKind::from_event(&event) else {
            return Ok(ControlCrankOutcome::NoEvent);
        };

        let effects = event::handle(&mut self.app, event);
        self.execute_effects(effects);

        if self.app.should_quit() {
            Ok(ControlCrankOutcome::Quit)
        } else {
            Ok(ControlCrankOutcome::Processed(event_kind))
        }
    }

    /// Executes command side effects against the headless app.
    pub fn execute_effects(&mut self, effects: Vec<ControlEffect>) {
        execute_effects(&mut self.app, effects);
        self.sync_status();
    }

    fn sync_status(&mut self) {
        sync_status(&mut self.app, &self.sources);
    }
}

struct Runner<'a> {
    app: App,
    sources: Sources<'a>,
    tui: Tui,
}

impl<'a> Runner<'a> {
    fn enter(options: &'a ControlOptions) -> anyhow::Result<Self> {
        Ok(Self {
            app: App::new(options.policy_dir.clone(), options.audit_rows.is_some()),
            sources: Sources::new(options.audit_rows.as_ref()),
            tui: Tui::enter()?,
        })
    }

    fn run(mut self) -> anyhow::Result<ExitCode> {
        while !self.app.should_quit() {
            self.crank()?;
        }

        Ok(ExitCode::SUCCESS)
    }

    fn crank(&mut self) -> anyhow::Result<()> {
        self.draw()?;
        let event = event::next(&self.sources)?;
        let effects = event::handle(&mut self.app, event);
        execute_effects(&mut self.app, effects);
        Ok(())
    }

    fn draw(&mut self) -> anyhow::Result<()> {
        self.sync_status();
        self.tui.draw(&self.app)
    }

    fn sync_status(&mut self) {
        sync_status(&mut self.app, &self.sources);
    }
}

fn execute_effects(app: &mut App, effects: Vec<ControlEffect>) {
    let mut queue = VecDeque::from(effects);
    while let Some(effect) = queue.pop_front() {
        queue.extend(execute_effect(app, effect));
    }
}

fn execute_effect(app: &mut App, effect: ControlEffect) -> Vec<ControlEffect> {
    match effect {
        ControlEffect::Announce(announcement) => handle_control_announcement(app, announcement),
    }
}

fn handle_control_announcement(
    app: &mut App,
    announcement: ControlAnnouncement,
) -> Vec<ControlEffect> {
    match announcement {
        ControlAnnouncement::ShutdownRequested => app.request_quit(),
        ControlAnnouncement::FatalError(error) => {
            app.set_policy_error(error);
            app.request_quit();
        }
        ControlAnnouncement::QueueDumpRequested | ControlAnnouncement::PolicyReloadRequested => {}
    }

    Vec::new()
}

fn sync_status(app: &mut App, _sources: &Sources<'_>) {
    app.sync_rewrite_queue(0, false);
}
