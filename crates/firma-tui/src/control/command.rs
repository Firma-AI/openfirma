//! User commands for the control surface.

use std::path::PathBuf;

use crate::control::{
    announcement::ControlAnnouncement,
    app::App,
    state::{AuditFilter, PolicyRewriteRequest},
};

/// Row movement requested by keyboard navigation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionMovement {
    /// Move one row toward the start of the focused list.
    Up,
    /// Move one row toward the end of the focused list.
    Down,
    /// Move to the first row of the focused list.
    First,
    /// Move to the last row of the focused list.
    Last,
}

/// User command after key bindings and UI context have been resolved.
///
/// Commands update application state immediately when possible. Work that
/// needs the runner, such as queueing a rewrite or opening a source file, is
/// returned as a [`ControlEffect`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCommand {
    /// Toggle the about overlay.
    ToggleAbout,
    /// Close the about overlay.
    CloseAbout,
    /// Toggle the help overlay.
    ToggleHelp,
    /// Close the help overlay.
    CloseHelp,
    /// Close the audit row inspector.
    CloseAuditInspect,
    /// Request a rewrite for the selected policy.
    ToggleSelectedPolicy,
    /// Request rewrites for every policy that needs to change.
    ToggleAllPolicies,
    /// Change the audit decision filter.
    SetAuditFilter(AuditFilter),
    /// Open the selected policy source in an editor.
    OpenPolicySource,
    /// Open the selected audit row inspector.
    InspectAuditRow,
    /// Move selection in the focused pane.
    MoveSelection(SelectionMovement),
    /// Move focus between panes.
    SwitchPane,
    /// Request an orderly shutdown.
    Quit,
}

/// Side effect returned by command application.
///
/// Effects are executed by the runner so command handling can stay focused on
/// state transitions.
#[derive(Debug)]
pub enum ControlEffect {
    /// Emit a runtime announcement.
    Announce(ControlAnnouncement),
    /// Queue a policy rewrite request.
    EnqueuePolicyRewrite(PolicyRewriteRequest),
    /// Open a policy source path in the operator's editor.
    OpenPolicySource(PathBuf),
}

impl ControlCommand {
    /// Applies a command to application state and returns runner-owned work.
    ///
    /// Commands that cannot take effect in the current context return no
    /// effects. For example, opening policy source has no effect when no
    /// policy file is selected.
    #[must_use]
    pub(crate) fn apply(self, app: &mut App) -> Vec<ControlEffect> {
        match self {
            Self::ToggleAbout => {
                app.toggle_about();
                Vec::new()
            }
            Self::CloseAbout => {
                app.close_about();
                Vec::new()
            }
            Self::ToggleHelp => {
                app.toggle_help();
                Vec::new()
            }
            Self::CloseHelp => {
                app.close_help();
                Vec::new()
            }
            Self::CloseAuditInspect => {
                app.close_audit_inspect();
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
            Self::OpenPolicySource => open_policy_source_effect(app),
            Self::InspectAuditRow => {
                app.open_audit_inspect();
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

fn open_policy_source_effect(app: &mut App) -> Vec<ControlEffect> {
    if !app.request_policy_edit() {
        return Vec::new();
    }

    app.selected_policy_file()
        .map(std::path::Path::to_path_buf)
        .map_or_else(Vec::new, |path| vec![ControlEffect::OpenPolicySource(path)])
}

fn apply_selection_movement(app: &mut App, movement: SelectionMovement) {
    match movement {
        SelectionMovement::Up => app.move_selection_up(),
        SelectionMovement::Down => app.move_selection_down(),
        SelectionMovement::First => app.move_selection_first(),
        SelectionMovement::Last => app.move_selection_last(),
    }
}
