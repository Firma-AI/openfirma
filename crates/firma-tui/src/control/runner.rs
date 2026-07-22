//! Event pump for the Policy Control terminal UI.

use std::{collections::VecDeque, path::PathBuf, process::ExitCode};

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
/// # Errors
///
/// Fails if terminal setup, input polling, drawing, or shutdown handling fails.
pub fn run(options: &ControlOptions) -> anyhow::Result<ExitCode> {
    Runner::enter(options)?.run()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCrankOutcome {
    NoEvent,
    Processed(EventKind),
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Input,
    Mouse,
    Resize,
}

impl EventKind {
    const fn from_event(event: Event) -> Option<Self> {
        match event {
            Event::Key(_) => Some(Self::Input),
            Event::Mouse => Some(Self::Mouse),
            Event::Resize => Some(Self::Resize),
            Event::Tick => None,
        }
    }
}

pub struct HeadlessRunner {
    app: App,
    sources: Sources,
}

impl HeadlessRunner {
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>) -> Self {
        Self {
            app: App::new(policy_dir),
            sources: Sources::new(),
        }
    }

    #[must_use]
    pub const fn app(&self) -> &App {
        &self.app
    }

    #[must_use]
    pub const fn sources(&self) -> &Sources {
        &self.sources
    }

    /// Processes at most one ready event for tests.
    ///
    /// # Errors
    ///
    /// Fails if the event source cannot be polled.
    pub fn try_crank(
        &mut self,
        terminal: &impl event::TerminalEventSource,
    ) -> anyhow::Result<ControlCrankOutcome> {
        if self.app.should_quit() {
            return Ok(ControlCrankOutcome::Quit);
        }

        let event = event::next_with_terminal(&self.sources, terminal, std::time::Duration::ZERO)?;
        let Some(event_kind) = EventKind::from_event(event) else {
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

    pub fn execute_effects(&mut self, effects: Vec<ControlEffect>) {
        execute_effects(&mut self.app, effects);
    }
}

struct Runner {
    app: App,
    sources: Sources,
    tui: Tui,
}

impl Runner {
    fn enter(options: &ControlOptions) -> anyhow::Result<Self> {
        Ok(Self {
            app: App::new(options.policy_dir.clone()),
            sources: Sources::new(),
            tui: Tui::enter()?,
        })
    }

    fn run(mut self) -> anyhow::Result<ExitCode> {
        self.app.mark_running();
        while !self.app.should_quit() {
            self.crank()?;
        }

        Ok(ExitCode::SUCCESS)
    }

    fn crank(&mut self) -> anyhow::Result<()> {
        self.tui.draw(&self.app)?;
        let event = event::next(&self.sources)?;
        let effects = event::handle(&mut self.app, event);
        execute_effects(&mut self.app, effects);
        Ok(())
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
    }

    Vec::new()
}
