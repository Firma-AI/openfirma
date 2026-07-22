//! Runtime state for the Policy Control surface.

use std::path::{Path, PathBuf};

use crate::control::state::{
    AuditFilter, AuditRow, AuditState, AuditViewportMode, ControlRuntimeState, ControlStatus, Pane,
};

/// Mutable application state for Policy Control.
///
/// The runner owns side effects and feeds events into this type. `App` keeps
/// pane focus, help visibility, audit buffer state, and the runtime status
/// rendered in the terminal frame.
pub struct App {
    should_quit: bool,
    selected_pane: Pane,
    help_visible: bool,
    pending_key_prefix: Option<KeyPrefix>,
    status: ControlStatus,
    audit: AuditState,
}

impl App {
    /// Creates application state from the resolved policy directory and audit
    /// source state.
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>, audit_connected: bool) -> Self {
        let status = ControlStatus::new(policy_dir, audit_connected);
        Self {
            should_quit: false,
            selected_pane: Pane::Policies,
            help_visible: false,
            pending_key_prefix: None,
            status,
            audit: AuditState::default(),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new(None, false)
    }
}

impl App {
    /// Returns true once the runner should stop processing events.
    #[must_use]
    pub const fn should_quit(&self) -> bool {
        self.should_quit || self.status.runtime_state.is_shutting_down()
    }

    /// Marks the app as ready to exit.
    pub const fn quit(&mut self) {
        self.should_quit = true;
    }

    /// Requests a graceful shutdown.
    ///
    /// The runtime state is updated before setting the quit flag so the final
    /// status snapshot reflects that shutdown has started.
    pub fn request_quit(&mut self) {
        self.status.runtime_state = ControlRuntimeState::ShuttingDown;
        self.quit();
    }

    /// Marks the app as accepting input and external events.
    pub const fn mark_running(&mut self) {
        self.status.runtime_state = ControlRuntimeState::Running;
    }

    /// Toggles the help overlay.
    pub const fn toggle_help(&mut self) {
        self.help_visible = !self.help_visible;
    }

    /// Closes the help overlay.
    pub const fn close_help(&mut self) {
        self.help_visible = false;
    }

    /// Returns true when the help overlay is visible.
    #[must_use]
    pub const fn help_visible(&self) -> bool {
        self.help_visible
    }

    /// Pane currently receiving navigation commands.
    #[must_use]
    pub const fn selected_pane(&self) -> Pane {
        self.selected_pane
    }

    /// Moves focus to the next pane.
    ///
    /// Switching to the audit pane reconciles the selected audit row with the
    /// current filter before drawing.
    pub fn switch_pane(&mut self) {
        self.selected_pane = self.selected_pane.next();
        if self.selected_pane == Pane::Audit {
            self.audit.sync_selection_after_view_change();
        }
    }

    /// Moves selection up in the focused pane.
    pub fn move_selection_up(&mut self) {
        match self.selected_pane {
            Pane::Policies => {}
            Pane::Audit => self.audit.move_up(),
        }
    }

    /// Moves selection down in the focused pane.
    pub fn move_selection_down(&mut self) {
        match self.selected_pane {
            Pane::Policies => {}
            Pane::Audit => self.audit.move_down(),
        }
    }

    /// Moves selection to the first row in the focused pane.
    pub fn move_selection_first(&mut self) {
        match self.selected_pane {
            Pane::Policies => {}
            Pane::Audit => self.audit.move_first(),
        }
    }

    /// Moves selection to the last row in the focused pane.
    pub fn move_selection_last(&mut self) {
        match self.selected_pane {
            Pane::Policies => {}
            Pane::Audit => self.audit.move_last(),
        }
    }

    /// Current runtime status rendered by the frame.
    #[must_use]
    pub const fn status(&self) -> &ControlStatus {
        &self.status
    }

    /// Authority policy directory, when it was resolved from the stack config.
    #[must_use]
    pub fn policy_dir(&self) -> Option<&Path> {
        self.status.policy_dir.as_deref()
    }

    /// Changes the audit decision filter.
    ///
    /// Selection is clamped to the filtered row set and follows the tail again
    /// if the viewport is already in follow-tail mode.
    pub fn set_audit_filter(&mut self, audit_filter: AuditFilter) {
        self.audit.set_filter(audit_filter);
    }

    /// Current audit decision filter.
    #[must_use]
    pub const fn audit_filter(&self) -> AuditFilter {
        self.audit.filter()
    }

    /// Current audit viewport tracking mode.
    #[must_use]
    pub const fn audit_viewport_mode(&self) -> AuditViewportMode {
        self.audit.viewport_mode()
    }

    /// Index of the selected audit row in the filtered view.
    #[must_use]
    pub fn selected_audit_index(&self) -> usize {
        self.audit.selected_index()
    }

    /// Number of audit rows retained in the bounded buffer.
    #[must_use]
    pub fn audit_rows_len(&self) -> usize {
        self.audit.rows_len()
    }

    /// Iterates over audit rows visible under the current filter.
    pub fn visible_audit_rows(&self) -> impl Iterator<Item = &AuditRow> {
        self.audit.visible_rows()
    }

    /// Number of audit rows visible under the current filter.
    #[must_use]
    pub fn visible_audit_rows_len(&self) -> usize {
        self.audit.visible_rows_len()
    }

    /// Appends one audit row and updates audit selection.
    pub fn push_audit_row(&mut self, row: AuditRow) {
        self.audit.push_row(row);
        self.status.audit_rows = self.audit.rows_len();
    }

    /// Appends several audit rows in source order.
    pub fn push_audit_rows(&mut self, rows: impl IntoIterator<Item = AuditRow>) {
        for row in rows {
            self.push_audit_row(row);
        }
    }

    /// Starts a pending `g` prefix for `gg` navigation.
    pub fn start_g_prefix(&mut self) {
        self.pending_key_prefix = Some(KeyPrefix::G);
    }

    /// Consumes the pending `g` prefix and reports whether it was set.
    pub fn take_g_prefix(&mut self) -> bool {
        matches!(self.pending_key_prefix.take(), Some(KeyPrefix::G))
    }

    /// Clears any pending multi-key prefix.
    pub fn clear_g_prefix(&mut self) {
        self.pending_key_prefix = None;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyPrefix {
    G,
}
