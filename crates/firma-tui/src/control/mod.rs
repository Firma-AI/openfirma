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
mod rewrite;
mod runner;
mod state;
mod terminal;
mod toggle;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::Receiver;

pub use announcement::ControlAnnouncement;
pub use app::App;
pub use bindings::{BindingHint, footer_entries};
pub use command::{ControlCommand, ControlEffect, SelectionMovement};
pub use error::{
    AuditSourceError, ControlError, EditorError, ErrorMessage, PolicyDiscoveryError,
    PolicyRewriteError, RewriteEventProbeError, RuntimeError,
};
pub use event::{Event, Sources, TerminalEventSource};
pub use input::{command_for_key, handle_key};
pub use policies::PolicyStateReader;
pub use render::render;
pub use rewrite::{PolicyRewriteEvent, PolicyRewriteHandler, RewriteEventProbe};
pub use runner::{ControlCrankOutcome, EventKind, HeadlessRunner};
pub use state::{
    AuditDecision, AuditFilter, AuditRow, AuditViewportMode, ControlRuntimeState, ControlStatus,
    Pane, PolicyRewriteCompletion, PolicyRewriteRequest, PolicyRewriteStart, PolicyRow,
    PolicyRowStatus,
};
pub use toggle::PolicyState;

/// Startup options for the Policy Control TUI.
///
/// The CLI service resolves real stack paths before constructing this value.
/// The TUI then consumes audit rows from the supplied receiver and displays the
/// resolved policy directory as its policy source.
#[derive(Default)]
pub struct ControlOptions {
    audit_rows: Option<Receiver<AuditRow>>,
    policy_dir: Option<PathBuf>,
}

impl ControlOptions {
    /// Creates options backed by an existing audit-row stream.
    #[must_use]
    pub fn with_audit_rows(audit_rows: Receiver<AuditRow>) -> Self {
        Self {
            audit_rows: Some(audit_rows),
            policy_dir: None,
        }
    }

    /// Sets the Authority policy directory shown and loaded by the TUI.
    #[must_use]
    pub fn with_policy_dir(mut self, policy_dir: PathBuf) -> Self {
        self.policy_dir = Some(policy_dir);
        self
    }
}

/// Reads one policy state from a Cedar source file.
#[must_use]
pub fn read_policy_state(path: &Path, policy_id: &str) -> PolicyState {
    toggle::read_policy_state(path, policy_id)
}

/// Reads several policy states from one Cedar source file.
#[must_use]
pub fn read_policy_states(
    path: &Path,
    policy_ids: &[String],
) -> std::collections::HashMap<String, PolicyState> {
    toggle::read_policy_states(path, policy_ids)
}

/// Sets one policy in a Cedar source file to the requested state.
///
/// # Errors
///
/// Fails when the Cedar file cannot be read, the policy id is missing or
/// malformed, the rewritten candidate does not parse, or the candidate cannot
/// be atomically persisted.
pub fn set_policy_state(
    path: &Path,
    policy_id: &str,
    requested: PolicyState,
) -> Result<(), PolicyRewriteError> {
    toggle::set_policy_state(path, policy_id, requested)
}

/// Sets multiple policies in one Cedar source file to the requested state.
///
/// # Errors
///
/// Fails when the Cedar file cannot be read, any policy id is missing or
/// malformed, the rewritten candidate does not parse, or the candidate cannot
/// be atomically persisted.
pub fn set_policy_states(
    path: &Path,
    policy_ids: &[String],
    requested: PolicyState,
) -> Result<(), PolicyRewriteError> {
    toggle::set_policy_states(path, policy_ids, requested)
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
