//! UI state coordinator for the control surface.

use std::path::{Path, PathBuf};

use crate::control::{
    error::ControlError,
    policies::PolicyStateReader,
    state::{
        AuditFilter, AuditRow, AuditState, AuditViewportMode, ControlRuntimeState, ControlStatus,
        Pane, PoliciesState, PolicyRow,
    },
};

/// Mutable application state for Policy Control.
///
/// The runner owns side effects and feeds events into this type. `App` keeps
/// selection, help visibility, audit buffer state, policy row state, and the
/// runtime status that is rendered in the terminal frame.
#[derive(Debug)]
pub struct App {
    runtime_state: ControlRuntimeState,
    selected_pane: Pane,
    help_visible: bool,
    pending_key_prefix: Option<KeyPrefix>,
    audit_connected: bool,
    rewrite_queue_len: usize,
    audit: AuditState,
    policies: PoliciesState,
}

impl App {
    /// Creates application state from the resolved policy directory and audit
    /// source state.
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>, audit_connected: bool) -> Self {
        Self::with_policy_state_reader(policy_dir, audit_connected, &PolicyStateReader::default())
    }

    /// Creates application state with an injected policy-state reader.
    ///
    /// Tests use this to count or stub disk reads while keeping the same
    /// policy loading behavior as the interactive runner.
    #[must_use]
    pub fn with_policy_state_reader(
        policy_dir: Option<PathBuf>,
        audit_connected: bool,
        state_reader: &PolicyStateReader,
    ) -> Self {
        let policies = PoliciesState::with_state_reader(policy_dir, state_reader);
        let runtime_state = if policies.error().is_some() {
            ControlRuntimeState::Error
        } else {
            ControlRuntimeState::Running
        };

        Self {
            runtime_state,
            selected_pane: Pane::Policies,
            help_visible: false,
            pending_key_prefix: None,
            audit_connected,
            rewrite_queue_len: 0,
            audit: AuditState::default(),
            policies,
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
        self.runtime_state.is_shutting_down()
    }

    /// Requests a graceful shutdown.
    ///
    /// The runtime state is updated before setting the quit flag so the final
    /// status snapshot reflects that shutdown has started.
    pub fn request_quit(&mut self) {
        self.runtime_state = ControlRuntimeState::ShuttingDown;
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn runtime_state(&self) -> ControlRuntimeState {
        self.runtime_state
    }

    /// Updates status fields owned by runner-managed queues.
    ///
    /// A shutting-down queue moves the runtime into shutdown. Otherwise the
    /// runtime state is recalculated from the current app state.
    pub fn sync_rewrite_queue(&mut self, rewrite_queue_len: usize, shutting_down: bool) {
        self.rewrite_queue_len = rewrite_queue_len;
        if shutting_down {
            self.runtime_state = ControlRuntimeState::ShuttingDown;
        } else {
            self.refresh_runtime_state();
        }
    }

    /// Builds a point-in-time status snapshot for rendering and tests.
    #[must_use]
    pub fn status(&self) -> ControlStatus {
        ControlStatus {
            runtime_state: self.runtime_state,
            policy_dir: self.policies.dir().map(Path::to_path_buf),
            policy_count: self.policies.rows().len(),
            audit_connected: self.audit_connected,
            audit_rows: self.audit.rows_len(),
            rewrite_queue_len: self.rewrite_queue_len,
            pending_rewrites: self.policies.pending_rewrites(),
            last_policy_error: self.policies.last_error().cloned(),
        }
    }

    /// Records a policy error and marks the runtime as errored.
    pub fn set_policy_error(&mut self, error: ControlError) {
        self.policies.set_error(error);
        self.runtime_state = ControlRuntimeState::Error;
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
            Pane::Policies => self.policies.move_up(),
            Pane::Audit => self.audit.move_up(),
        }
    }

    /// Moves selection down in the focused pane.
    pub fn move_selection_down(&mut self) {
        match self.selected_pane {
            Pane::Policies => self.policies.move_down(),
            Pane::Audit => self.audit.move_down(),
        }
    }

    /// Moves selection to the first row in the focused pane.
    pub fn move_selection_first(&mut self) {
        match self.selected_pane {
            Pane::Policies => self.policies.move_first(),
            Pane::Audit => self.audit.move_first(),
        }
    }

    /// Moves selection to the last row in the focused pane.
    pub fn move_selection_last(&mut self) {
        match self.selected_pane {
            Pane::Policies => self.policies.move_last(),
            Pane::Audit => self.audit.move_last(),
        }
    }

    /// Authority policy directory, when it was resolved from the stack config.
    #[must_use]
    pub fn policy_dir(&self) -> Option<&Path> {
        self.policies.dir()
    }

    /// Index of the selected policy row.
    #[must_use]
    pub fn selected_policy_index(&self) -> usize {
        self.policies.selected_index()
    }

    /// Policy rows currently rendered by the policies pane.
    #[must_use]
    pub fn policies(&self) -> &[PolicyRow] {
        self.policies.rows()
    }

    /// Current policy load error.
    #[must_use]
    pub fn policy_error(&self) -> Option<&ControlError> {
        self.policies.error()
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

    fn refresh_runtime_state(&mut self) {
        if self.runtime_state == ControlRuntimeState::ShuttingDown {
            return;
        }

        self.runtime_state = if self.policies.error().is_some() {
            ControlRuntimeState::Error
        } else if self.policies.pending_rewrites() > 0 || self.rewrite_queue_len > 0 {
            ControlRuntimeState::Rewriting
        } else {
            ControlRuntimeState::Running
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyPrefix {
    G,
}
