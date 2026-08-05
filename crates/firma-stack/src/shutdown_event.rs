//! Cross-process graceful-shutdown signal contract.
//!
//! On Unix, [`crate::platform::TerminationTarget::signal_soft`] uses a kernel
//! signal that does not depend on a shared terminal. Windows has no equivalent
//! for Firma's console-less children, so each child creates a named event at
//! startup and the stop process signals that event. This module is the single
//! source of truth for the name used on both sides of that protocol.

/// Per-PID Windows named event used as the graceful-shutdown signal.
///
/// Always available, not gated on `cfg(windows)`, so callers on both sides
/// of the contract can import it without target gating.
#[must_use]
pub fn windows_shutdown_event_name(pid: u32) -> String {
    format!(r"Local\firma-shutdown-{pid}")
}
