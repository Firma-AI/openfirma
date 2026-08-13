//! UI state coordinator for the control surface.

use std::path::{Path, PathBuf};

use crate::control::{
    error::ControlError,
    policies::PolicyStateReader,
    state::{
        AuditFilter, AuditRow, AuditState, AuditViewportMode, ControlRuntimeState, ControlStatus,
        OverlayState, Pane, PoliciesState, PolicyRewriteCompletion, PolicyRewriteRequest,
        PolicyRewriteStart, PolicyRow,
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
    pending_key_prefix: Option<KeyPrefix>,
    audit_connected: bool,
    rewrite_queue_len: usize,
    audit: AuditState,
    overlays: OverlayState,
    policies: PoliciesState,
}

impl App {
    /// Creates application state from the resolved policy directory and audit
    /// source state.
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>, audit_connected: bool) -> Self {
        Self::with_policy_state_reader(policy_dir, audit_connected, PolicyStateReader::default())
    }

    /// Creates application state with an injected policy-state reader.
    ///
    /// Tests use this to count or stub disk reads while keeping the same
    /// policy loading behavior as the interactive runner.
    #[must_use]
    pub fn with_policy_state_reader(
        policy_dir: Option<PathBuf>,
        audit_connected: bool,
        state_reader: PolicyStateReader,
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
            pending_key_prefix: None,
            audit_connected,
            rewrite_queue_len: 0,
            audit: AuditState::default(),
            overlays: OverlayState::default(),
            policies,
        }
    }

    /// Updates the status fields that are owned by the rewrite queue.
    ///
    /// A shutting-down queue moves the runtime into shutdown. Otherwise the
    /// runtime state is recalculated from policy errors and pending rewrites.
    pub(crate) fn sync_rewrite_queue(&mut self, rewrite_queue_len: usize, shutting_down: bool) {
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
            policy_error: self.policies.error().cloned(),
        }
    }

    /// Requests shutdown.
    ///
    /// Once set, the runner will stop processing new events and exit the main
    /// loop.
    pub fn request_quit(&mut self) {
        self.runtime_state = ControlRuntimeState::ShuttingDown;
    }

    /// Returns true once shutdown has been requested.
    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.runtime_state.is_shutting_down()
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn runtime_state(&self) -> ControlRuntimeState {
        self.runtime_state
    }

    /// Toggles the help overlay.
    pub fn toggle_help(&mut self) {
        self.overlays.toggle_help();
    }

    /// Closes the help overlay.
    pub(crate) fn close_help(&mut self) {
        self.overlays.close_help();
    }

    /// Returns true when the help overlay is visible.
    #[must_use]
    pub fn help_visible(&self) -> bool {
        self.overlays.help_visible()
    }

    /// Toggles the about overlay.
    pub(crate) fn toggle_about(&mut self) {
        self.overlays.toggle_about();
    }

    /// Closes the about overlay.
    pub(crate) fn close_about(&mut self) {
        self.overlays.close_about();
    }

    /// Returns true when the about overlay is visible.
    #[must_use]
    pub(crate) fn about_visible(&self) -> bool {
        self.overlays.about_visible()
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
    /// Changes the audit decision filter.
    ///
    /// Selection is clamped to the filtered row set and follows the tail again
    /// if the viewport is already in follow-tail mode.
    pub fn set_audit_filter(&mut self, audit_filter: AuditFilter) {
        self.audit.set_filter(audit_filter);
    }

    /// Pane currently receiving navigation commands.
    #[must_use]
    pub fn selected_pane(&self) -> Pane {
        self.selected_pane
    }

    /// Index of the selected policy row.
    #[must_use]
    pub fn selected_policy_index(&self) -> usize {
        self.policies.selected_index()
    }

    /// Index of the selected audit row in the filtered view.
    #[must_use]
    pub fn selected_audit_index(&self) -> usize {
        self.audit.selected_index()
    }

    /// Current audit decision filter.
    #[must_use]
    pub fn audit_filter(&self) -> AuditFilter {
        self.audit.filter()
    }

    /// Current audit viewport tracking mode.
    #[must_use]
    pub fn audit_viewport_mode(&self) -> AuditViewportMode {
        self.audit.viewport_mode()
    }

    /// Policy rows currently rendered by the policies pane.
    #[must_use]
    pub fn policies(&self) -> &[PolicyRow] {
        self.policies.rows()
    }

    /// Selected audit row, if the filtered view contains one.
    #[must_use]
    pub(crate) fn selected_audit_row(&self) -> Option<&AuditRow> {
        self.audit.selected_row()
    }

    /// Current policy load or rewrite error.
    #[must_use]
    pub fn policy_error(&self) -> Option<&ControlError> {
        self.policies.error()
    }

    /// Records a policy error and marks the runtime as errored.
    pub(crate) fn set_policy_error(&mut self, error: ControlError) {
        self.policies.set_error(error);
        self.runtime_state = ControlRuntimeState::Error;
    }

    /// Source file for the selected policy row.
    #[must_use]
    pub(crate) fn selected_policy_file(&self) -> Option<&Path> {
        self.policies.selected_file()
    }

    /// Requests an edit session for the selected policy source.
    ///
    /// This has no effect outside the policy pane. If a policy rewrite is
    /// pending, the request is rejected and the policy state records an error.
    pub fn request_policy_edit(&mut self) -> bool {
        if self.selected_pane != Pane::Policies {
            return false;
        }

        let requested = self.policies.request_edit();
        if requested {
            self.runtime_state = ControlRuntimeState::EditingPolicy;
        } else {
            self.refresh_runtime_state();
        }

        requested
    }

    /// Reloads policies from disk.
    ///
    /// Existing audit rows are preserved. Policy selection is clamped if the
    /// reload changes the row count.
    pub fn reload_policies(&mut self) {
        self.policies.reload();
        self.refresh_runtime_state();
    }

    /// Marks the external policy editor session as finished.
    pub fn finish_policy_edit(&mut self) {
        self.refresh_runtime_state();
    }

    /// Opens the audit inspector for the selected audit row.
    ///
    /// This has no effect unless the audit pane is focused and a filtered row
    /// is selected.
    pub(crate) fn open_audit_inspect(&mut self) {
        if self.selected_pane == Pane::Audit && self.selected_audit_row().is_some() {
            self.overlays.open_audit_inspect();
        }
    }

    /// Closes the audit inspector.
    pub(crate) fn close_audit_inspect(&mut self) {
        self.overlays.close_audit_inspect();
    }

    /// Current audit viewport tracking mode.
    #[must_use]
    pub(crate) fn audit_inspect_visible(&self) -> bool {
        self.overlays.audit_inspect_visible()
    }

    /// Starts a pending `g` prefix for `gg` navigation.
    pub(crate) fn start_g_prefix(&mut self) {
        self.pending_key_prefix = Some(KeyPrefix::G);
    }

    /// Consumes the pending `g` prefix and reports whether it was set.
    pub(crate) fn take_g_prefix(&mut self) -> bool {
        matches!(self.pending_key_prefix.take(), Some(KeyPrefix::G))
    }

    /// Clears any pending multi-key prefix.
    pub(crate) fn clear_g_prefix(&mut self) {
        self.pending_key_prefix = None;
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
    pub(crate) fn push_audit_rows(&mut self, rows: impl IntoIterator<Item = AuditRow>) {
        for row in rows {
            self.push_audit_row(row);
        }
    }

    /// Queues a toggle request for the selected policy.
    ///
    /// This has no effect outside the policy pane or while the selected policy
    /// already has a pending rewrite.
    pub fn request_selected_policy_toggle(&mut self) -> Option<PolicyRewriteRequest> {
        if self.selected_pane != Pane::Policies {
            return None;
        }

        let request = self.policies.request_selected_toggle();
        self.refresh_runtime_state();
        request
    }

    /// Queues toggle requests for policies that need to change.
    ///
    /// If every policy is enabled, the requested state is disabled. Otherwise
    /// the requested state is enabled. Rows already matching the requested
    /// state are skipped.
    pub fn request_all_policy_toggle(&mut self) -> Vec<PolicyRewriteRequest> {
        let requests = self.policies.request_all_toggle();
        self.refresh_runtime_state();
        requests
    }

    /// Applies a completed policy rewrite and refreshes disk-derived state.
    pub fn finish_policy_rewrite(&mut self, completion: &PolicyRewriteCompletion) {
        self.policies.finish_rewrite(completion);
        self.refresh_runtime_state();
    }

    /// Marks rows from a started policy rewrite as writing.
    pub fn start_policy_rewrite(&mut self, policy: &PolicyRewriteStart) {
        self.policies.start_rewrite(policy);
        self.runtime_state = ControlRuntimeState::Rewriting;
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

impl Default for App {
    fn default() -> Self {
        Self::new(None, false)
    }
}
