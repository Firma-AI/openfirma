//! Commands and side effects for Policy Control.

use crate::control::{
    announcement::ControlAnnouncement,
    app::App,
    state::{AuditFilter, PolicyRewriteRequest},
};

/// Selection movement requested by keyboard input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionMovement {
    /// Move one row toward the start of the focused pane.
    Up,
    /// Move one row toward the end of the focused pane.
    Down,
    /// Jump to the first row in the focused pane.
    First,
    /// Jump to the last row in the focused pane.
    Last,
}

/// User command after key bindings have been resolved.
///
/// Commands mutate [`App`] state and may return runner-owned side effects.
/// Keeping key parsing separate from command application lets the help text and
/// event loop use the same command vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCommand {
    /// Toggle the help overlay.
    ToggleHelp,
    /// Close the help overlay.
    CloseHelp,
    /// Toggle the selected policy row.
    ToggleSelectedPolicy,
    /// Toggle every policy row that needs to change.
    ToggleAllPolicies,
    /// Change the audit decision filter.
    SetAuditFilter(AuditFilter),
    /// Move selection in the focused pane.
    MoveSelection(SelectionMovement),
    /// Move focus to the next pane.
    SwitchPane,
    /// Request shutdown.
    Quit,
}

/// Side effect produced by a command.
///
/// Effects are executed by the runner after command application. This keeps
/// application state free of terminal and process ownership.
#[derive(Debug)]
pub enum ControlEffect {
    /// Runtime announcement to handle at the event-loop boundary.
    Announce(ControlAnnouncement),
    /// Policy rewrite request to enqueue on the serialized worker.
    EnqueuePolicyRewrite(PolicyRewriteRequest),
}

impl ControlCommand {
    /// Applies the command to app state and returns runner-owned effects.
    #[must_use]
    pub fn apply(self, app: &mut App) -> Vec<ControlEffect> {
        match self {
            Self::ToggleHelp => {
                app.toggle_help();
                Vec::new()
            }
            Self::CloseHelp => {
                app.close_help();
                Vec::new()
            }
            Self::ToggleSelectedPolicy => app
                .request_selected_policy_toggle()
                .map(ControlEffect::EnqueuePolicyRewrite)
                .into_iter()
                .collect(),
            Self::ToggleAllPolicies => app
                .request_all_policy_toggle()
                .into_iter()
                .map(ControlEffect::EnqueuePolicyRewrite)
                .collect(),
            Self::SetAuditFilter(audit_filter) => {
                app.set_audit_filter(audit_filter);
                Vec::new()
            }
            Self::MoveSelection(movement) => {
                apply_selection_movement(app, movement);
                Vec::new()
            }
            Self::SwitchPane => {
                app.switch_pane();
                Vec::new()
            }
            Self::Quit => vec![ControlEffect::Announce(
                ControlAnnouncement::ShutdownRequested,
            )],
        }
    }
}

fn apply_selection_movement(app: &mut App, movement: SelectionMovement) {
    match movement {
        SelectionMovement::Up => app.move_selection_up(),
        SelectionMovement::Down => app.move_selection_down(),
        SelectionMovement::First => app.move_selection_first(),
        SelectionMovement::Last => app.move_selection_last(),
    }
}
