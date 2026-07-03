use std::process::Child;

use crate::backend::BackendKind;
use crate::error::RunError;

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;

/// Wait for the child while forwarding terminal signals to the sandbox.
///
/// Event-driven, no polling: SIGINT, SIGTERM, SIGWINCH, and SIGCHLD are blocked
/// on this thread and consumed synchronously with `sigwait(3)`. SIGCHLD wakes
/// the loop to reap the child; SIGWINCH (TUI resize) and termination signals
/// (SIGINT/SIGTERM) are forwarded into the sandboxed process group.
///
/// A second termination signal escalates to SIGKILL; the first forwards the
/// received signal so an interactive TUI can shut down cleanly.
///
/// The child is reaped with a non-blocking `try_wait` at the top of every
/// iteration. Because SIGCHLD is blocked before that first check, a child that
/// exits at any point leaves SIGCHLD pending, so the following `sigwait` never
/// blocks past the exit — no missed-wakeup race.
///
/// Relies on these signals being effectively blocked process-wide; `firma run`
/// waits from a single-threaded context, so no other thread competes for them.
///
/// # Errors
///
/// Returns an error when the signal mask cannot be installed or the child wait
/// operation fails.
#[cfg(unix)]
pub fn wait_with_signal_forwarding(
    mut child: Child,
    backend: BackendKind,
) -> Result<i32, RunError> {
    use nix::sys::signal::{SigSet, SigmaskHow};

    let child_pid = child.id();

    let mut wait_set: SigSet = SigSet::empty();
    wait_set.add(Signal::SIGINT);
    wait_set.add(Signal::SIGTERM);
    wait_set.add(Signal::SIGWINCH);
    wait_set.add(Signal::SIGCHLD);

    // Block the handled signals so they queue for sigwait instead of running
    // their default dispositions; keep the previous mask to restore on return.
    let previous_mask = wait_set
        .thread_swap_mask(SigmaskHow::SIG_BLOCK)
        .map_err(|error| RunError::Wait(format!("failed to block signals: {error}")))?;

    let mut termination_requested = false;
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(exit_code(status)),
            Ok(None) => {}
            Err(error) => break Err(RunError::Wait(error.to_string())),
        }

        match wait_set.wait() {
            Ok(Signal::SIGWINCH) => forward_signal(child_pid, backend, Signal::SIGWINCH),
            Ok(sig @ (Signal::SIGINT | Signal::SIGTERM)) => {
                let forwarded = if termination_requested {
                    Signal::SIGKILL
                } else {
                    termination_requested = true;
                    sig
                };
                forward_signal(child_pid, backend, forwarded);
            }
            // SIGCHLD (or any other blocked signal) just loops back to the
            // try_wait above, which is where the child is actually reaped.
            Ok(_) => {}
            Err(error) => break Err(RunError::Wait(format!("sigwait failed: {error}"))),
        }
    };

    let _ = previous_mask.thread_set_mask();
    result
}

/// Map an exit status to a process exit code.
///
/// Uses the wait-reported code when the child exited normally; otherwise, when
/// the child was terminated by a signal, follows the shell convention of
/// `128 + signum` so callers can distinguish signal deaths.
#[cfg(unix)]
fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;

    status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |signal| 128 + signal))
}

/// Wait for the child while forwarding Ctrl-C termination.
///
/// Windows retains a bounded poll loop: `std` offers no kill-by-pid, so the
/// thread-based waiter used on Unix cannot terminate the child from the signal
/// path. SIGWINCH forwarding is Unix-only and not relevant here.
///
/// # Errors
///
/// Returns an error when child wait operations fail or repeated termination
/// signals are received before process exit.
#[cfg(windows)]
pub fn wait_with_signal_forwarding(
    mut child: Child,
    _backend: BackendKind,
) -> Result<i32, RunError> {
    use std::sync::mpsc;
    use std::time::Duration;

    let (signal_tx, signal_rx) = mpsc::channel::<()>();

    if let Err(error) = ctrlc::set_handler(move || {
        let _ = signal_tx.send(());
    }) {
        tracing::warn!(
            "ctrl-c handler could not be installed (continuing without custom forwarding): {error}"
        );
    }

    let mut termination_requested = false;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| RunError::Wait(error.to_string()))?
        {
            return Ok(status.code().unwrap_or(1));
        }

        if signal_rx.recv_timeout(Duration::from_millis(100)).is_ok() {
            if termination_requested {
                return Err(RunError::Wait(
                    "received repeated termination signals while child did not exit".to_string(),
                ));
            }

            termination_requested = true;
            if let Err(error) = child.kill() {
                tracing::warn!("failed to terminate child process on signal: {error}");
            }
        }
    }
}

/// Forward a signal to the process running inside the sandbox.
///
/// bwrap's `--new-session` calls `setsid()` in the sandboxed child, creating a
/// new session (PGID = child PID) that never receives terminal signals. On
/// Linux we read the child PID from `/proc` and send to the whole process group
/// (`kill(-pgid)`) so every sandbox process (shell, proxy bridge, wrapped
/// command) gets the event. Falls back to a direct send to the outer child for
/// non-bwrap backends (vz, wsl2) where no session boundary exists.
#[cfg(unix)]
fn forward_signal(child_pid: u32, backend: BackendKind, signal: Signal) {
    // `backend` only selects the bwrap process-group path on Linux; elsewhere
    // every backend uses the direct fallback below.
    #[cfg(not(target_os = "linux"))]
    let _ = backend;

    // bwrap uses --new-session (setsid()), creating a new session where
    // PGID == sandbox child PID. Read the child from /proc and send to the
    // whole process group so every sandboxed process gets the signal.
    #[cfg(target_os = "linux")]
    if backend == BackendKind::Bwrap
        && let Some(sandbox_pid) = sandbox_child_pid(child_pid)
        && let Ok(pid) = i32::try_from(sandbox_pid)
    {
        let pgid = Pid::from_raw(-pid);
        if let Err(error) = kill(pgid, signal) {
            tracing::debug!("{signal} forward to sandbox pgroup {pgid}: {error}");
        }
        return;
    }

    // Fallback: direct send to the outer child (covers vz/wsl2/firecracker and
    // the bwrap case where /proc children are unavailable).
    let Ok(pid) = i32::try_from(child_pid) else {
        return;
    };
    let outer = Pid::from_raw(pid);
    if let Err(error) = kill(outer, signal) {
        tracing::debug!("{signal} forward to child {outer}: {error}");
    }
}

/// Read bwrap's immediate child PID from the Linux process filesystem.
///
/// Returns `None` when the file is absent (`CONFIG_PROC_CHILDREN` not compiled
/// in, or the child has not yet started). During bwrap startup the file may be
/// transiently empty; callers fall back to the outer child PID in that case, so
/// a signal during the brief startup window lands on bwrap itself rather than
/// the sandbox — harmless but silently dropped.
#[cfg(target_os = "linux")]
fn sandbox_child_pid(bwrap_pid: u32) -> Option<u32> {
    let path = format!("/proc/{bwrap_pid}/task/{bwrap_pid}/children");
    let content = std::fs::read_to_string(path).ok()?;
    parse_first_pid(&content)
}

/// Parse the first PID from the whitespace-separated `children` file contents.
///
/// The file lists a task's child PIDs separated by spaces. Returns `None` when
/// the content is empty/blank or the first token is not a valid PID.
#[cfg(target_os = "linux")]
fn parse_first_pid(content: &str) -> Option<u32> {
    content.split_whitespace().next()?.parse().ok()
}

#[cfg(all(test, unix))]
mod tests {
    use crate::backend::BackendKind;
    use crate::supervisor::wait_with_signal_forwarding;

    #[cfg(target_os = "linux")]
    use crate::supervisor::parse_first_pid;

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_first_pid_returns_first_token() {
        assert_eq!(parse_first_pid("123 456 789"), Some(123));
        assert_eq!(parse_first_pid("42\n"), Some(42));
        assert_eq!(parse_first_pid("  7  8 "), Some(7));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_first_pid_rejects_empty_or_nonnumeric() {
        assert_eq!(parse_first_pid(""), None);
        assert_eq!(parse_first_pid("   \n "), None);
        assert_eq!(parse_first_pid("abc"), None);
        assert_eq!(parse_first_pid("-1"), None);
    }

    #[test]
    fn propagates_child_exit_code() {
        let child = std::process::Command::new("sh")
            .args(["-c", "exit 7"])
            .spawn()
            .expect("spawn sh");
        let code = wait_with_signal_forwarding(child, BackendKind::Vz).expect("wait succeeds");
        assert_eq!(code, 7);
    }

    #[test]
    fn propagates_zero_exit_code() {
        let child = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn sh");
        let code = wait_with_signal_forwarding(child, BackendKind::Vz).expect("wait succeeds");
        assert_eq!(code, 0);
    }

    #[test]
    fn reports_signal_death_as_128_plus_signum() {
        // The child terminates itself with SIGTERM (15); the supervisor should
        // report 128 + 15 = 143 following the shell convention.
        let child = std::process::Command::new("sh")
            .args(["-c", "kill -TERM $$"])
            .spawn()
            .expect("spawn sh");
        let code = wait_with_signal_forwarding(child, BackendKind::Vz).expect("wait succeeds");
        assert_eq!(code, 143);
    }
}
