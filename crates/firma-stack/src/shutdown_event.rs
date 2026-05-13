//! Cross-process graceful-shutdown signal contract.
//!
//! On Unix, `signal_soft` uses `SIGTERM` which the kernel delivers regardless
//! of session or tty. On Windows there is no equivalent: the natural
//! candidate, `GenerateConsoleCtrlEvent`, only reaches processes that share
//! the caller's console — and the stack's `stop` runs in a different console
//! than the children (which were spawned with `CREATE_NO_WINDOW`, so they
//! have no console at all). Instead, each child creates a named Windows
//! event at startup; `signal_soft` opens the event by name and signals it.
//! This module is the single source of truth for that name.

/// Per-PID Windows named event used as the graceful-shutdown signal.
///
/// Always available, not gated on `cfg(windows)`, so callers on both sides
/// of the contract can import it without target gating.
#[must_use]
pub fn windows_shutdown_event_name(pid: u32) -> String {
    format!(r"Local\firma-shutdown-{pid}")
}
