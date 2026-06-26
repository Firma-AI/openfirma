//! Shared coarse-grained liveness state.

use serde::Serialize;

/// Reported state of a runtime component or per-run sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Pidfile present, process alive, listen endpoint accepting connections.
    Running,
    /// Pidfile present, process alive, but the listen endpoint is closed.
    Unhealthy,
    /// No pidfile, or the recorded pid no longer exists.
    Stopped,
    /// Pidfile present but liveness or endpoint probe could not be performed
    /// reliably (typically `EPERM` on Unix or access-denied on Windows).
    Unknown,
}
