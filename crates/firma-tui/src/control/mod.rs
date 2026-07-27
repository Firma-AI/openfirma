//! Policy Control terminal UI.

mod announcement;
mod app;
mod bindings;
mod command;
mod error;
mod event;
mod input;
mod policies;
mod render;
mod runner;
mod state;
mod terminal;
mod toggle;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::Receiver;

pub use announcement::ControlAnnouncement;
pub use app::App;
pub use bindings::{BindingHint, footer_entries};
pub use command::{ControlCommand, ControlEffect, SelectionMovement};
pub use error::{
    AuditSourceError, ControlError, EditorError, ErrorMessage, PolicyDiscoveryError,
    PolicyRewriteError, RuntimeError,
};
pub use event::{Event, Sources, TerminalEventSource, next_with_terminal};
pub use input::{command_for_key, handle_key};
pub use policies::PolicyStateReader;
pub use render::render;
pub use runner::{ControlCrankOutcome, EventKind, HeadlessRunner};
pub use state::{
    AuditDecision, AuditFilter, AuditRow, AuditViewportMode, ControlRuntimeState, ControlStatus,
    Pane, PolicyRow, PolicyRowStatus,
};
pub use toggle::PolicyState;

/// Options used to start Policy Control.
#[derive(Default)]
pub struct ControlOptions {
    audit_rows: Option<Receiver<AuditRow>>,
    policy_dir: Option<PathBuf>,
}

impl ControlOptions {
    /// Creates options backed by a live audit row receiver.
    #[must_use]
    pub fn with_audit_rows(audit_rows: Receiver<AuditRow>) -> Self {
        Self {
            audit_rows: Some(audit_rows),
            policy_dir: None,
        }
    }

    /// Records the Authority policy directory resolved by the CLI service.
    #[must_use]
    pub fn with_policy_dir(mut self, policy_dir: PathBuf) -> Self {
        self.policy_dir = Some(policy_dir);
        self
    }
}

/// Reads one policy state from a Cedar source file.
#[must_use]
pub fn read_policy_state(path: &std::path::Path, policy_id: &str) -> PolicyState {
    toggle::read_policy_state(path, policy_id)
}

/// Reads several policy states from one Cedar source file.
#[must_use]
pub fn read_policy_states(
    path: &std::path::Path,
    policy_ids: &[String],
) -> std::collections::HashMap<String, PolicyState> {
    toggle::read_policy_states(path, policy_ids)
}

/// Runs the Policy Control event loop.
///
/// Terminal setup, input polling, and drawing errors are returned to the
/// caller. Terminal cleanup is still attempted when setup partially succeeds.
///
/// # Errors
///
/// Returns an error when terminal setup, event polling, or drawing fails.
pub fn run(options: &ControlOptions) -> anyhow::Result<ExitCode> {
    runner::run(options)
}
