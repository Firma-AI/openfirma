//! Runtime status for the control surface.

use std::path::PathBuf;

use super::ControlRuntimeState;
use crate::control::error::ControlError;

/// Snapshot of runtime information rendered by the UI.
///
/// The runner refreshes this from app state before drawing so the frame can
/// show queue length, audit connectivity, and the current policy error
/// without querying event sources directly. Treat this as a display contract:
/// background sources update the app, the app produces one snapshot, and the
/// renderer stays a pure view over that snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlStatus {
    /// Current lifecycle state.
    pub runtime_state: ControlRuntimeState,
    /// Authority policy directory resolved from the active stack config.
    pub policy_dir: Option<PathBuf>,
    /// Number of policy rows known to the TUI.
    pub policy_count: usize,
    /// Whether an audit source was connected when the TUI started.
    pub audit_connected: bool,
    /// Number of audit rows currently buffered.
    pub audit_rows: usize,
    /// Number of policy rewrite requests waiting in the worker queue.
    pub rewrite_queue_len: usize,
    /// Number of policy rows that are queued or being written.
    pub pending_rewrites: usize,
    /// Current policy-side error.
    pub policy_error: Option<ControlError>,
}
