//! Unit coverage for the swappable foreground log sink ([`firma_run::log`]).
//!
//! `firma run` redirects its own compact log lines off the terminal into
//! `<dir>/run.log` while a wrapped agent's TUI owns it, then restores stderr
//! for teardown. These tests exercise that state machine directly — sink
//! swapping, the disabled (file mode) no-ops, the redirect failure path, and
//! the write dispatch — without needing a live sandbox or global subscriber.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use firma_run::log::ForegroundLog;

/// A fresh active handle targets stderr, not a file, and is not disabled.
#[test]
fn active_handle_starts_on_stderr() {
    let state = ForegroundLog::active().state();
    assert!(state.is_stderr());
    assert!(!state.is_disabled());
}

/// The file-mode (idle) handle is disabled and never claims stderr.
#[test]
fn idle_handle_is_disabled() {
    let state = ForegroundLog::idle().state();
    assert!(state.is_disabled());
    assert!(!state.is_stderr());
}

/// Redirecting an active handle creates `run.log`, moves the sink off stderr,
/// and routes subsequent writes into that file.
#[test]
fn redirect_writes_to_run_log() {
    let dir = tempfile::tempdir().unwrap();
    let handle = ForegroundLog::active();
    handle.redirect(dir.path());

    let state = handle.state();
    assert!(
        !state.is_stderr(),
        "sink should be off stderr once redirected"
    );
    assert!(!state.is_disabled());

    let n = state.write(b"hello run.log\n").unwrap();
    assert_eq!(n, "hello run.log\n".len());
    state.flush().unwrap();

    let log = std::fs::read_to_string(dir.path().join("run.log")).unwrap();
    assert_eq!(log, "hello run.log\n");
}

/// A redirect nested under a missing parent still lands `run.log`, since the
/// sink creates the directory tree on the way.
#[test]
fn redirect_creates_missing_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("run").join("sandbox-abc");
    let handle = ForegroundLog::active();
    handle.redirect(&nested);

    handle.state().write(b"x").unwrap();
    assert!(nested.join("run.log").is_file());
}

/// Restoring after a redirect returns the sink to stderr.
#[test]
fn restore_returns_to_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let handle = ForegroundLog::active();
    handle.redirect(dir.path());
    assert!(!handle.state().is_stderr());

    handle.restore();
    assert!(handle.state().is_stderr());
}

/// In file mode both redirect and restore are inert: no `run.log` is created
/// and the destination stays disabled.
#[test]
fn disabled_handle_ignores_redirect_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let handle = ForegroundLog::idle();

    handle.redirect(dir.path());
    assert!(handle.state().is_disabled());
    assert!(!dir.path().join("run.log").exists());

    handle.restore();
    assert!(handle.state().is_disabled());

    // The disabled sink swallows writes and flushes rather than touching
    // stderr or a file.
    let n = handle.state().write(b"swallowed").unwrap();
    assert_eq!(n, "swallowed".len());
    handle.state().flush().unwrap();
}

/// The default stderr sink accepts writes and flushes. An empty buffer keeps
/// the test output clean while still exercising the stderr write/flush arms.
#[test]
fn stderr_sink_write_and_flush_succeed() {
    let state = ForegroundLog::active().state();
    assert!(state.is_stderr());

    let n = state.write(b"").unwrap();
    assert_eq!(n, 0);
    state.flush().unwrap();
}

/// When the log file cannot be opened the sink stays on stderr and drops no
/// data silently into a broken handle. Here `run.log` already exists as a
/// directory, so the append-open fails.
#[test]
fn redirect_failure_leaves_stderr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("run.log")).unwrap();

    let handle = ForegroundLog::active();
    handle.redirect(dir.path());

    assert!(
        handle.state().is_stderr(),
        "failed redirect must leave the sink on stderr"
    );
}

/// A redirect after a prior redirect swaps to the newer file.
#[test]
fn redirect_reswaps_to_new_file() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let handle = ForegroundLog::active();

    handle.redirect(first.path());
    handle.state().write(b"one\n").unwrap();
    handle.redirect(second.path());
    handle.state().write(b"two\n").unwrap();
    handle.state().flush().unwrap();

    assert_eq!(
        std::fs::read_to_string(first.path().join("run.log")).unwrap(),
        "one\n"
    );
    assert_eq!(
        std::fs::read_to_string(second.path().join("run.log")).unwrap(),
        "two\n"
    );
}
