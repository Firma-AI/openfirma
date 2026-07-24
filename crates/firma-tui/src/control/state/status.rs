//! Runtime status for the control surface.

use std::path::PathBuf;

use crate::control::error::ControlError;

use super::ControlRuntimeState;

/// Snapshot of runtime information rendered by the UI.
///
/// The app refreshes this as audit rows arrive and lifecycle state changes, so
/// rendering can read one stable status value without querying event sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlStatus {
    /// Authority policy directory resolved from the active stack config.
    pub policy_dir: Option<PathBuf>,
    /// Current lifecycle state.
    pub runtime_state: ControlRuntimeState,
    /// Number of policy rows known to the TUI.
    pub policy_count: usize,
    /// Whether an audit source was connected when the TUI started.
    pub audit_connected: bool,
    /// Number of audit rows currently buffered.
    pub audit_rows: usize,
    /// Most recent runtime or source error.
    pub last_error: Option<ControlError>,
}

impl ControlStatus {
    /// Creates the initial status snapshot.
    #[must_use]
    pub const fn new(policy_dir: Option<PathBuf>, audit_connected: bool) -> Self {
        Self {
            policy_dir,
            runtime_state: ControlRuntimeState::Starting,
            policy_count: 0,
            audit_connected,
            audit_rows: 0,
            last_error: None,
        }
    }
}
