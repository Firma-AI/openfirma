//! Audit buffer, filter, and viewport state.

use std::collections::VecDeque;

// The audit pane is a live view, not durable storage. Keeping the last thousand
// rows gives enough history for inspection while bounding redraw work and
// memory use during long-running demos or noisy local stacks.
const AUDIT_BUFFER_CAPACITY: usize = 1_000;

/// Decision filter applied to the audit pane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditFilter {
    /// Show every buffered audit row.
    All,
    /// Show only allow decisions.
    Allow,
    /// Show only deny decisions.
    Deny,
}

impl AuditFilter {
    /// Filters in the order rendered by the audit filter bar.
    pub(crate) const ALL: [Self; 3] = [Self::All, Self::Deny, Self::Allow];

    /// Short lowercase label rendered in the filter bar.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    const fn matches(self, decision: AuditDecision) -> bool {
        match self {
            Self::All => true,
            Self::Allow => matches!(decision, AuditDecision::Allow),
            Self::Deny => matches!(decision, AuditDecision::Deny),
        }
    }
}

/// Audit decision rendered by Policy Control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditDecision {
    /// The sidecar allowed the request.
    Allow,
    /// The sidecar denied the request.
    Deny,
}

impl AuditDecision {
    /// Short lowercase label rendered in the audit table.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// How the audit viewport should track incoming rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditViewportMode {
    /// Keep selection pinned to the newest visible event.
    FollowTail,
    /// Keep the operator-selected row stable while inspecting older events.
    Manual,
}

/// Normalized audit event displayed by the TUI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRow {
    /// Timestamp label already formatted for terminal display.
    pub time: String,
    /// Allow or deny decision.
    pub decision: AuditDecision,
    /// Normalized action class from the sidecar audit event.
    pub action_class: String,
    /// Resource label from the sidecar audit event.
    pub resource: String,
    /// Policy detail or deny reason associated with the decision.
    pub policy: String,
}

/// Bounded audit buffer with filter and selection state.
///
/// Incoming rows are retained up to the configured capacity. When the viewport
/// is following the tail, new matching rows advance selection automatically.
/// Once the operator moves to an older row, selection stays manual until the
/// operator returns to the latest row.
#[derive(Debug)]
pub struct AuditState {
    selected_index: usize,
    viewport_mode: AuditViewportMode,
    filter: AuditFilter,
    rows: VecDeque<AuditRow>,
}

impl AuditState {
    /// Creates an empty audit buffer in follow-tail mode.
    #[must_use]
    pub fn new() -> Self {
        Self {
            selected_index: 0,
            viewport_mode: AuditViewportMode::FollowTail,
            filter: AuditFilter::All,
            rows: VecDeque::with_capacity(AUDIT_BUFFER_CAPACITY),
        }
    }

    /// Moves selection one visible row up and enters manual mode.
    pub fn move_up(&mut self) {
        self.viewport_mode = AuditViewportMode::Manual;
        self.selected_index = self.selected_index.saturating_sub(1);
    }

    /// Moves selection one visible row down.
    ///
    /// Reaching the newest visible row resumes follow-tail mode.
    pub fn move_down(&mut self) {
        let max_index = self.visible_rows_len().saturating_sub(1);
        self.selected_index = self.selected_index.saturating_add(1).min(max_index);
        self.viewport_mode = if self.selected_index == max_index {
            AuditViewportMode::FollowTail
        } else {
            AuditViewportMode::Manual
        };
    }

    /// Moves selection to the first visible row and enters manual mode.
    pub fn move_first(&mut self) {
        self.viewport_mode = AuditViewportMode::Manual;
        self.selected_index = 0;
    }

    /// Moves selection to the newest visible row and follows the tail.
    pub fn move_last(&mut self) {
        self.viewport_mode = AuditViewportMode::FollowTail;
        self.select_latest_row();
    }

    /// Changes the decision filter and clamps selection to the new view.
    pub fn set_filter(&mut self, filter: AuditFilter) {
        self.filter = filter;
        self.sync_selection_after_view_change();
    }

    /// Index of the selected row in the filtered view.
    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected_index
    }

    /// Currently active decision filter.
    #[must_use]
    pub const fn filter(&self) -> AuditFilter {
        self.filter
    }

    /// Current viewport tracking mode.
    #[must_use]
    pub const fn viewport_mode(&self) -> AuditViewportMode {
        self.viewport_mode
    }

    /// Number of rows retained in the bounded buffer.
    #[must_use]
    pub fn rows_len(&self) -> usize {
        self.rows.len()
    }

    /// Iterates over rows visible under the active decision filter.
    pub fn visible_rows(&self) -> impl Iterator<Item = &AuditRow> {
        let filter = self.filter;
        self.rows
            .iter()
            .filter(move |row| filter.matches(row.decision))
    }

    /// Number of rows visible under the active decision filter.
    #[must_use]
    pub fn visible_rows_len(&self) -> usize {
        self.visible_rows().count()
    }

    /// Selected row in the filtered view, when one exists.
    #[must_use]
    pub fn selected_row(&self) -> Option<&AuditRow> {
        self.visible_rows().nth(self.selected_index)
    }

    /// Appends one audit row, dropping the oldest row at capacity.
    pub fn push_row(&mut self, row: AuditRow) {
        if self.rows.len() == AUDIT_BUFFER_CAPACITY {
            let _ = self.rows.pop_front();
            if self.viewport_mode == AuditViewportMode::Manual {
                self.selected_index = self.selected_index.saturating_sub(1);
            }
        }
        self.rows.push_back(row);
        self.sync_selection_after_view_change();
    }

    /// Reconciles selection after the visible row set changes.
    pub fn sync_selection_after_view_change(&mut self) {
        match self.viewport_mode {
            AuditViewportMode::FollowTail => self.select_latest_row(),
            AuditViewportMode::Manual => self.clamp_selected_index(),
        }
    }

    fn clamp_selected_index(&mut self) {
        let max_index = self.visible_rows_len().saturating_sub(1);
        self.selected_index = self.selected_index.min(max_index);
    }

    fn select_latest_row(&mut self) {
        self.selected_index = self.visible_rows_len().saturating_sub(1);
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self::new()
    }
}
