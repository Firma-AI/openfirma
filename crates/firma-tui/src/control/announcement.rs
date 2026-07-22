//! Runtime announcements for the control surface.

/// Runtime-level messages emitted by command handling and consumed by the
/// runner.
///
/// These are separated from key commands so shutdown can be handled at the
/// event-loop boundary instead of inside view state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlAnnouncement {
    /// Stop accepting new work and leave the event loop.
    ShutdownRequested,
}
