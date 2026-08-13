//! Event pump for the Policy Control terminal UI.
//!
//! Commands mutate `App` and return effects, but the runner performs the
//! effects. That split keeps side effects in the layer that owns the terminal,
//! event sources, and rewrite queues. It also lets tests crank one event at a
//! time without starting an actual terminal session.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex, mpsc::Receiver},
    thread,
    time::{Duration, Instant},
};

use crate::control::{
    ControlOptions,
    announcement::ControlAnnouncement,
    app::App,
    command::ControlEffect,
    editor,
    error::{ControlError, EditorError},
    event::{self, Event, Sources},
    rewrite::{PolicyRewriteHandler, RewriteEventProbe},
    state::AuditRow,
    terminal::Tui,
};

// This is the idle wait, not the keyboard latency. The event pump checks ready
// input before waiting, then uses this short timeout to keep redraw ticks
// flowing when no source has produced work.
const EVENT_POLL_TIMEOUT: Duration = Duration::from_millis(100);

// Headless tests sometimes wait for work produced by background threads. When
// one crank finds no real event, give the worker a small scheduling window
// before checking again. Cranks that process an event continue immediately.
const HEADLESS_IDLE_WAIT: Duration = Duration::from_millis(1);

/// Runs Policy Control in a real terminal session.
///
/// Terminal setup and teardown are owned by the runner. Any failure from
/// terminal setup, event polling, drawing, or suspending around a blocking
/// editor is returned to the caller.
pub fn run(options: &ControlOptions) -> anyhow::Result<ExitCode> {
    Runner::enter(options)?.run()
}

/// Result of one headless runner crank.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCrankOutcome {
    /// No actionable event was ready.
    NoEvent,
    /// One event was processed.
    Processed(EventKind),
    /// The app requested shutdown.
    Quit,
}

/// Coarse category of event processed by the runner.
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
    /// A policy rewrite notification was consumed.
    Rewrite,
}

enum CrankUntilLoopOutcome {
    ConditionMet(ControlCrankOutcome),
    TimedOut { outcome: ControlCrankOutcome },
}

impl EventKind {
    fn from_event(event: &Event) -> Option<Self> {
        match event {
            Event::Audit(_) => Some(Self::Audit),
            Event::Key(_) => Some(Self::Input),
            Event::Mouse => Some(Self::Mouse),
            Event::Resize => Some(Self::Resize),
            Event::PolicyRewrite(_) => Some(Self::Rewrite),
            Event::Tick => None,
        }
    }
}

/// Probe used by headless tests to observe events processed by the runner.
///
/// The probe records events after the runner has dispatched them through the
/// normal app/effect path. Tests that care about ordering can then assert on
/// the same boundary an interactive session uses, instead of synchronizing on
/// helper channels owned by a particular event source.
#[derive(Clone, Debug, Default)]
pub struct ProcessedEventProbe {
    events: Arc<Mutex<Vec<EventKind>>>,
}

impl ProcessedEventProbe {
    /// Returns the event kinds observed so far.
    ///
    /// Tick events are intentionally absent. They do not dispatch commands and
    /// `try_crank` reports them as [`ControlCrankOutcome::NoEvent`].
    ///
    /// # Errors
    ///
    /// Returns an error if a previous panic poisoned the probe storage.
    pub fn observed_events(&self) -> anyhow::Result<Vec<EventKind>> {
        Ok(self
            .events
            .lock()
            .map_err(|error| anyhow::anyhow!("event dispatch probe mutex poisoned: {error}"))?
            .clone())
    }

    /// Returns true if any processed event satisfies the predicate.
    ///
    /// This is the small equivalent of Casper's condition-checking reactor
    /// hook: tests can ask about event behavior without exposing source-specific
    /// synchronization channels.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous panic poisoned the probe storage.
    pub fn observed_any(
        &self,
        mut predicate: impl FnMut(EventKind) -> bool,
    ) -> anyhow::Result<bool> {
        Ok(self.observed_events()?.into_iter().any(&mut predicate))
    }

    /// Counts processed events that satisfy the predicate.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous panic poisoned the probe storage.
    pub fn observed_count(
        &self,
        mut predicate: impl FnMut(EventKind) -> bool,
    ) -> anyhow::Result<usize> {
        Ok(self
            .observed_events()?
            .into_iter()
            .filter(|event_kind| predicate(*event_kind))
            .count())
    }

    fn record(&self, event_kind: EventKind) -> anyhow::Result<()> {
        self.events
            .lock()
            .map_err(|error| anyhow::anyhow!("event dispatch probe mutex poisoned: {error}"))?
            .push(event_kind);

        Ok(())
    }
}

/// Runner test harness that does not enter raw terminal mode.
///
/// Tests use this to process one event at a time while injecting fake terminal
/// input, audit rows, and policy rewrite handlers.
pub struct HeadlessRunner<'a> {
    app: App,
    event_probe: Option<ProcessedEventProbe>,
    sources: Sources<'a>,
}

impl<'a> HeadlessRunner<'a> {
    /// Creates a headless runner with the default policy rewrite queue.
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>, audit_rows: Option<&'a Receiver<AuditRow>>) -> Self {
        Self {
            app: App::new(policy_dir, audit_rows.is_some()),
            event_probe: None,
            sources: Sources::new(audit_rows),
        }
    }

    /// Creates a headless runner with an injected rewrite handler.
    #[must_use]
    pub fn with_policy_rewrite_handler(
        policy_dir: Option<PathBuf>,
        audit_rows: Option<&'a Receiver<AuditRow>>,
        handler: PolicyRewriteHandler,
    ) -> Self {
        Self {
            app: App::new(policy_dir, audit_rows.is_some()),
            event_probe: None,
            sources: Sources::with_policy_rewrite_handler(audit_rows, handler),
        }
    }

    /// Creates a headless runner with an injected rewrite handler and dispatch
    /// probe.
    ///
    /// The returned probe observes events only after they have been sent to the
    /// runner channel. Tests use it when they need to distinguish "the handler
    /// returned" from "the event pump can now see the completion".
    #[must_use]
    pub fn with_observed_policy_rewrite_handler(
        policy_dir: Option<PathBuf>,
        audit_rows: Option<&'a Receiver<AuditRow>>,
        handler: PolicyRewriteHandler,
    ) -> (Self, RewriteEventProbe) {
        let (sources, rewrite_probe) =
            Sources::with_observed_policy_rewrite_handler(audit_rows, handler);
        (
            Self {
                app: App::new(policy_dir, audit_rows.is_some()),
                event_probe: None,
                sources,
            },
            rewrite_probe,
        )
    }

    /// Starts recording the events processed by this runner.
    ///
    /// Calling this again replaces the existing recorder and returns a fresh
    /// probe. It is intended for tests that need to assert event-source
    /// priority without coupling themselves to an individual source's internal
    /// synchronization channel.
    #[must_use]
    pub fn observe_processed_events(&mut self) -> ProcessedEventProbe {
        let probe = ProcessedEventProbe::default();
        self.event_probe = Some(probe.clone());
        probe
    }

    /// Returns the current application state.
    #[must_use]
    pub fn app(&self) -> &App {
        &self.app
    }

    /// Returns the event sources consumed by this runner.
    #[must_use]
    pub fn sources(&self) -> &Sources<'a> {
        &self.sources
    }

    /// Processes at most one ready event.
    ///
    /// Tick events report [`ControlCrankOutcome::NoEvent`]. Editor failures
    /// that are part of the editor result are recorded in app state; failures
    /// while preparing the editor call are returned.
    ///
    /// # Errors
    ///
    /// Returns an error when event polling fails or when editor setup fails
    /// before the editor result can be handled.
    pub fn try_crank(
        &mut self,
        terminal: &impl event::TerminalEventSource,
        open_policy_source: impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>>,
    ) -> anyhow::Result<ControlCrankOutcome> {
        if self.app.should_quit() {
            return Ok(ControlCrankOutcome::Quit);
        }

        self.sync_status();

        let event = event::next_with_terminal(&self.sources, terminal, Duration::ZERO)?;
        let Some(event_kind) = EventKind::from_event(&event) else {
            return Ok(ControlCrankOutcome::NoEvent);
        };

        let effects = event::handle(&mut self.app, event);
        self.execute_effects_with_editor(effects, open_policy_source)?;
        self.record_event(event_kind)?;

        if self.app.should_quit() {
            Ok(ControlCrankOutcome::Quit)
        } else {
            Ok(ControlCrankOutcome::Processed(event_kind))
        }
    }

    /// Cranks until the application reaches a caller-defined condition.
    ///
    /// Tests use this when the observed behavior is a state transition, not a
    /// single known event. The loop stays on the runner path so status syncing,
    /// event priority, editor effects, and rewrite queue effects are exercised
    /// the same way as an interactive session.
    ///
    /// # Errors
    ///
    /// Returns an error from event processing, when the runner exits before
    /// the condition is met, or when the condition was not reached within the
    /// supplied time budget.
    pub fn crank_until(
        &mut self,
        terminal: &impl event::TerminalEventSource,
        mut open_policy_source: impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>>,
        mut condition: impl FnMut(&App) -> bool,
        timeout: Duration,
    ) -> anyhow::Result<ControlCrankOutcome> {
        if condition(&self.app) {
            return Ok(ControlCrankOutcome::NoEvent);
        }

        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| anyhow::anyhow!("crank timeout is too large: {timeout:?}"))?;

        match self.crank_and_check_until(
            terminal,
            &mut open_policy_source,
            &mut condition,
            deadline,
        )? {
            CrankUntilLoopOutcome::ConditionMet(outcome) => Ok(outcome),
            CrankUntilLoopOutcome::TimedOut { outcome } => {
                let last_outcome = format_last_crank_outcome(outcome);
                anyhow::bail!(
                    "condition was not met within {timeout:?}; last outcome: {last_outcome}"
                );
            }
        }
    }

    /// Cranks the headless runner until the deadline is reached.
    ///
    /// The public wrapper owns timeout construction and user-facing error
    /// text. This loop owns the runner progression: one event is processed per
    /// iteration, the app condition is checked after command effects have run,
    /// and background workers get a short scheduling window only when no event
    /// was ready.
    ///
    /// A quit outcome fails if it arrives before the requested state
    /// transition. If shutdown is the state a test is waiting for, the quit
    /// outcome is returned like any other condition-matching crank.
    fn crank_and_check_until(
        &mut self,
        terminal: &impl event::TerminalEventSource,
        open_policy_source: &mut impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>>,
        condition: &mut impl FnMut(&App) -> bool,
        deadline: Instant,
    ) -> anyhow::Result<CrankUntilLoopOutcome> {
        let mut outcome = ControlCrankOutcome::NoEvent;
        while Instant::now() < deadline {
            let crank_outcome = self.try_crank(terminal, &mut *open_policy_source)?;
            if condition(&self.app) {
                return Ok(CrankUntilLoopOutcome::ConditionMet(crank_outcome));
            }

            match crank_outcome {
                ControlCrankOutcome::NoEvent => thread::sleep(HEADLESS_IDLE_WAIT),
                ControlCrankOutcome::Processed(_) => {}
                ControlCrankOutcome::Quit => {
                    anyhow::bail!("runner quit before condition was met");
                }
            }

            outcome = crank_outcome;
        }

        Ok(CrankUntilLoopOutcome::TimedOut { outcome })
    }

    /// Executes command side effects with an injected editor callback.
    ///
    /// The runner executes effects in order and processes any follow-up
    /// effects they produce. This keeps chains such as "editor completed,
    /// reload policies" inside the runner instead of the command layer.
    ///
    /// # Errors
    ///
    /// Returns an error when a side effect cannot finish its runner-owned
    /// setup.
    pub fn execute_effects_with_editor(
        &mut self,
        effects: Vec<ControlEffect>,
        mut open_policy_source: impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>>,
    ) -> anyhow::Result<()> {
        execute_effects_with_editor(
            &mut self.app,
            &mut self.sources,
            effects,
            &mut open_policy_source,
        )?;

        self.sync_status();

        Ok(())
    }

    fn sync_status(&mut self) {
        sync_status(&mut self.app, &self.sources);
    }

    fn record_event(&self, event_kind: EventKind) -> anyhow::Result<()> {
        if let Some(event_probe) = &self.event_probe {
            event_probe.record(event_kind)?;
        }

        Ok(())
    }
}

fn format_last_crank_outcome(outcome: ControlCrankOutcome) -> String {
    format!("{outcome:?}")
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
        let event = self.next_event()?;
        self.dispatch(event)
    }

    fn draw(&mut self) -> anyhow::Result<()> {
        self.sync_status();
        self.tui.draw(&self.app)
    }

    fn next_event(&self) -> anyhow::Result<Event> {
        event::next(&self.sources, EVENT_POLL_TIMEOUT)
    }

    fn dispatch(&mut self, event: Event) -> anyhow::Result<()> {
        let effects = event::handle(&mut self.app, event);
        self.execute_effects(effects)
    }

    fn execute_effects(&mut self, effects: Vec<ControlEffect>) -> anyhow::Result<()> {
        let app = &mut self.app;
        let sources = &mut self.sources;
        let tui = &mut self.tui;
        execute_effects_with_editor(app, sources, effects, &mut |path| {
            tui.suspend(|| editor::open(path))
        })
    }

    fn sync_status(&mut self) {
        sync_status(&mut self.app, &self.sources);
    }
}

fn execute_effects_with_editor(
    app: &mut App,
    sources: &mut Sources<'_>,
    effects: Vec<ControlEffect>,
    open_policy_source: &mut impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>>,
) -> anyhow::Result<()> {
    let mut queue = VecDeque::from(effects);
    while let Some(effect) = queue.pop_front() {
        queue.extend(execute_effect_with_editor(
            app,
            sources,
            effect,
            open_policy_source,
        )?);
    }

    Ok(())
}

fn execute_effect_with_editor(
    app: &mut App,
    sources: &mut Sources<'_>,
    effect: ControlEffect,
    open_policy_source: &mut impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>>,
) -> anyhow::Result<Vec<ControlEffect>> {
    match effect {
        ControlEffect::Announce(announcement) => {
            Ok(handle_control_announcement(app, sources, announcement))
        }
        ControlEffect::EnqueuePolicyRewrite(request) => {
            let _queued = sources.enqueue_policy_rewrite(request);
            Ok(Vec::new())
        }
        ControlEffect::OpenPolicySource(path) => {
            // The editor runs outside the TUI and reports only whether the
            // process completed. Policy truth is still read from disk after a
            // successful edit, so the UI cannot drift from the Cedar files.
            let result = open_policy_source(&path)?;
            app.finish_policy_edit();
            Ok(policy_source_edit_effects(app, &path, result))
        }
    }
}

/// Converts an editor result into the next runner effects.
///
/// A successful edit requests a normal policy reload; it does not directly
/// mutate policy rows. A failed editor launch or unsuccessful editor exit is
/// recorded as an operator-visible policy error and reload is skipped.
fn policy_source_edit_effects(
    app: &mut App,
    path: &Path,
    result: Result<(), EditorError>,
) -> Vec<ControlEffect> {
    match result {
        Ok(()) => vec![ControlEffect::Announce(
            ControlAnnouncement::PolicyReloadRequested,
        )],
        Err(error) => {
            app.set_policy_error(ControlError::editor(path, error));
            Vec::new()
        }
    }
}

fn handle_control_announcement(
    app: &mut App,
    sources: &mut Sources<'_>,
    announcement: ControlAnnouncement,
) -> Vec<ControlEffect> {
    match announcement {
        ControlAnnouncement::ShutdownRequested => {
            sources.shutdown_policy_rewrites();
            sync_status(app, sources);
            app.request_quit();
        }
        ControlAnnouncement::FatalError(error) => {
            app.set_policy_error(error);
            sources.shutdown_policy_rewrites();
            sync_status(app, sources);
            app.request_quit();
        }
        ControlAnnouncement::PolicyReloadRequested => app.reload_policies(),
        ControlAnnouncement::QueueDumpRequested => {}
    }

    Vec::new()
}

fn sync_status(app: &mut App, sources: &Sources<'_>) {
    app.sync_rewrite_queue(
        sources.rewrite_queue_len(),
        sources.rewrite_queue_shutting_down(),
    );
}
