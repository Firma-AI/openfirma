//! Policy Control terminal UI.

mod announcement;
mod app;
mod bindings;
mod command;
mod error;
mod event;
mod input;
mod render;
mod runner;
mod state;
mod terminal;

use std::path::PathBuf;
use std::process::ExitCode;

pub use announcement::ControlAnnouncement;
pub use app::App;
pub use bindings::{BindingHint, footer_entries};
pub use command::{ControlCommand, ControlEffect};
pub use error::{ControlError, ErrorMessage, RuntimeError};
pub use event::{Event, Sources, TerminalEventSource, next_with_terminal};
pub use input::{command_for_key, handle_key};
pub use runner::{ControlCrankOutcome, EventKind, HeadlessRunner};
pub use state::{ControlRuntimeState, ControlStatus, Pane};

#[derive(Default)]
pub struct ControlOptions {
    policy_dir: Option<PathBuf>,
}

impl ControlOptions {
    #[must_use]
    pub fn with_policy_dir(mut self, policy_dir: PathBuf) -> Self {
        self.policy_dir = Some(policy_dir);
        self
    }
}

/// Runs the Policy Control event loop.
///
/// # Errors
///
/// Fails when terminal setup, input polling, or frame drawing fails.
pub fn run(options: &ControlOptions) -> anyhow::Result<ExitCode> {
    runner::run(options)
}
