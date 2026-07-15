//! Runtime announcements for the control surface.

use crate::control::error::ControlError;

/// Runtime-level messages emitted by command handling and consumed by the
/// runner.
///
/// These are separated from key commands so shutdown, reloads, and fatal
/// errors can be handled at the event-loop boundary instead of inside view
/// state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlAnnouncement {
    /// Stop accepting new work and leave the event loop.
    ShutdownRequested,
    /// Record an unrecoverable error and shut the UI down.
    FatalError(ControlError),
    /// Request queue diagnostics.
    QueueDumpRequested,
    /// Reload policy rows from disk after an external edit.
    PolicyReloadRequested,
}
