use std::process::Child;

use crate::backend::BackendKind;
use crate::error::RunError;

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;

/// How a supervised child ended.
#[derive(Debug)]
pub struct Supervised {
    /// The child's exit code, or why waiting for it failed.
    pub exit: Result<i32, RunError>,
    /// Whether a termination signal reached `firma` while it waited, counted
    /// only where the workload cannot send it itself.
    pub interrupted: bool,
    /// Whether the workload was stopped because the run's Sidecar exited.
    pub sidecar_stopped: bool,
}

/// Stops the workload once the run's Sidecar is gone: SIGTERM, then SIGKILL
/// after `grace`.
#[cfg_attr(
    windows,
    expect(dead_code, reason = "a managed run's Sidecar runs only on Unix")
)]
pub struct AgentStop<'a> {
    /// Polled while the workload runs; `true` once the Sidecar has exited.
    pub sidecar_exited: &'a mut dyn FnMut() -> bool,
    /// How long the workload may take to finish after SIGTERM.
    pub grace: std::time::Duration,
}

/// Terminal signals caught from before the workload starts until it is
/// reaped, so none of them kills `firma` in between.
///
/// A background thread receives SIGINT, SIGTERM, and SIGWINCH via
/// `signal_hook`'s self-pipe and forwards each into the sandbox. SIGWINCH (TUI
/// resize) is relayed as-is; the first SIGINT/SIGTERM is forwarded so an
/// interactive TUI can shut down cleanly, and a second termination signal
/// escalates to SIGKILL. A signal that arrives before [`Self::wait`] stays in
/// the pipe and is forwarded once the child is known.
///
/// The interruption is recorded by the signal handler and by the forwarder: a
/// terminal Ctrl-C also reaches the outer sandbox process, which may exit
/// before the forwarder drains the signal, and a signal between the two
/// registrations reaches only the forwarder.
#[cfg(unix)]
pub struct SignalForwarding {
    signals: signal_hook::iterator::Signals,
    interrupted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _flags: InterruptFlags,
}

/// The handlers that record an interruption, unregistered when dropped.
#[cfg(unix)]
struct InterruptFlags(Vec<signal_hook::SigId>);

#[cfg(unix)]
impl Drop for InterruptFlags {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

#[cfg(unix)]
impl SignalForwarding {
    /// Starts catching terminal signals.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Wait`] when the signal handlers cannot be
    /// installed.
    pub fn install() -> Result<Self, RunError> {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        use signal_hook::consts::{SIGINT, SIGTERM, SIGWINCH};

        let install_error = |error: std::io::Error| {
            RunError::Wait(format!("failed to install signal handlers: {error}"))
        };
        // The forwarding source first: a signal between the two
        // registrations is then forwarded, and the forwarder counts it.
        let signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGWINCH])
            .map_err(install_error)?;
        let interrupted = Arc::new(AtomicBool::new(false));
        let mut flags = InterruptFlags(Vec::new());
        for signal in [SIGINT, SIGTERM] {
            flags.0.push(
                signal_hook::flag::register(signal, Arc::clone(&interrupted))
                    .map_err(install_error)?,
            );
        }
        Ok(Self {
            signals,
            interrupted,
            _flags: flags,
        })
    }

    /// Waits for `child` while forwarding the caught signals to the sandbox.
    ///
    /// The child is reaped with a plain blocking `Child::wait` on this thread
    /// — no SIGCHLD handling — so reaping is correct regardless of how many
    /// threads the caller runs (a `sigwait`/`SIGCHLD` scheme only works when
    /// the signal is blocked process-wide, which does not hold under the
    /// multi-threaded test harness and hangs on some platforms). Once the
    /// child is reaped the signal source is closed, ending the forwarder
    /// thread.
    ///
    /// With `stop`, the child is polled instead, alongside the Sidecar, and
    /// stopped when the Sidecar exits.
    ///
    /// The exit is an error when the child wait operation fails.
    pub fn wait(
        self,
        mut child: Child,
        backend: BackendKind,
        stop: Option<AgentStop<'_>>,
    ) -> Supervised {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let Self {
            mut signals,
            interrupted,
            _flags,
        } = self;
        let child_pid = child.id();
        let handle = signals.handle();
        let counted = Arc::clone(&interrupted);

        let forwarder = std::thread::spawn(move || {
            let mut termination_requested = false;
            for raw in &mut signals {
                let Ok(signal) = Signal::try_from(raw) else {
                    continue;
                };
                match signal {
                    Signal::SIGWINCH => forward_signal(child_pid, backend, Signal::SIGWINCH),
                    Signal::SIGINT | Signal::SIGTERM => {
                        counted.store(true, Ordering::SeqCst);
                        let forwarded = if termination_requested {
                            Signal::SIGKILL
                        } else {
                            termination_requested = true;
                            signal
                        };
                        forward_signal(child_pid, backend, forwarded);
                    }
                    _ => {}
                }
            }
        });

        let (exit, sidecar_stopped) = match stop {
            None => (
                child
                    .wait()
                    .map(exit_code)
                    .map_err(|error| RunError::Wait(error.to_string())),
                false,
            ),
            Some(stop) => wait_or_stop(&mut child, backend, stop),
        };

        // Break the forwarder's blocking iterator and reclaim the thread.
        handle.close();
        let _ = forwarder.join();
        Supervised {
            exit,
            interrupted: interrupted.load(Ordering::SeqCst) && backend.isolates_workload(),
            sidecar_stopped,
        }
    }
}

/// Polls `child` until it exits, stopping it once the Sidecar has exited.
///
/// Each signal is sent only after `try_wait` on this thread found the child
/// still running, so none can reach a reused PID.
#[cfg(unix)]
fn wait_or_stop(
    child: &mut Child,
    backend: BackendKind,
    stop: AgentStop<'_>,
) -> (Result<i32, RunError>, bool) {
    use std::time::{Duration, Instant};

    const POLL_INTERVAL: Duration = Duration::from_millis(200);

    enum Phase {
        Watching,
        Terminating { kill_at: Instant },
        Killed,
    }

    let AgentStop {
        sidecar_exited,
        grace,
    } = stop;
    let mut phase = Phase::Watching;
    loop {
        let stopped = !matches!(phase, Phase::Watching);
        match child.try_wait() {
            // An agent can fail on its own as soon as its Sidecar is gone, so
            // the Sidecar is checked once more before the exit is reported.
            Ok(Some(status)) => return (Ok(exit_code(status)), stopped || sidecar_exited()),
            Ok(None) => {}
            Err(error) => return (Err(RunError::Wait(error.to_string())), stopped),
        }
        match phase {
            Phase::Watching if sidecar_exited() => {
                forward_signal(child.id(), backend, Signal::SIGTERM);
                phase = Phase::Terminating {
                    kill_at: Instant::now() + grace,
                };
            }
            Phase::Terminating { kill_at } if Instant::now() >= kill_at => {
                forward_signal(child.id(), backend, Signal::SIGKILL);
                phase = Phase::Killed;
            }
            _ => {}
        }
        std::thread::sleep(POLL_INTERVAL);
    }
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

/// Ctrl-C caught from before the workload starts until it exits.
///
/// Windows retains a bounded poll loop: `std` offers no kill-by-pid, so the
/// thread-based waiter used on Unix cannot terminate the child from the signal
/// path. SIGWINCH forwarding is Unix-only and not relevant here.
#[cfg(windows)]
pub struct SignalForwarding {
    signal_rx: std::sync::mpsc::Receiver<()>,
}

#[cfg(windows)]
impl SignalForwarding {
    /// Starts catching Ctrl-C.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Wait`] when the Ctrl-C handler cannot be
    /// installed.
    pub fn install() -> Result<Self, RunError> {
        let (signal_tx, signal_rx) = std::sync::mpsc::channel::<()>();
        ctrlc::set_handler(move || {
            let _ = signal_tx.send(());
        })
        .map_err(|error| {
            RunError::Wait(format!("failed to install the Ctrl-C handler: {error}"))
        })?;
        Ok(Self { signal_rx })
    }

    /// Waits for `child`, terminating it on the first Ctrl-C.
    ///
    /// The exit is an error when child wait operations fail or repeated
    /// termination signals are received before process exit.
    /// `stop` is ignored: a managed run's Sidecar runs only on Unix.
    pub fn wait(
        self,
        mut child: Child,
        _backend: BackendKind,
        _stop: Option<AgentStop<'_>>,
    ) -> Supervised {
        use std::time::Duration;

        let Self { signal_rx } = self;
        let mut termination_requested = false;
        loop {
            match child.try_wait() {
                // The console delivers Ctrl-C to the child too, which may exit
                // before the loop reads the channel: a pending send counts.
                Ok(Some(status)) => {
                    return Supervised {
                        exit: Ok(status.code().unwrap_or(1)),
                        interrupted: termination_requested || signal_rx.try_recv().is_ok(),
                        sidecar_stopped: false,
                    };
                }
                Ok(None) => {}
                Err(error) => {
                    return Supervised {
                        exit: Err(RunError::Wait(error.to_string())),
                        interrupted: termination_requested || signal_rx.try_recv().is_ok(),
                        sidecar_stopped: false,
                    };
                }
            }

            if signal_rx.recv_timeout(Duration::from_millis(100)).is_ok() {
                if termination_requested {
                    return Supervised {
                        exit: Err(RunError::Wait(
                            "received repeated termination signals while child did not exit"
                                .to_string(),
                        )),
                        interrupted: true,
                        sidecar_stopped: false,
                    };
                }

                termination_requested = true;
                if let Err(error) = child.kill() {
                    tracing::warn!("failed to terminate child process on signal: {error}");
                }
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
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    use crate::backend::BackendKind;
    use crate::error::RunError;
    use crate::supervisor::SignalForwarding;

    #[cfg(target_os = "linux")]
    use crate::supervisor::{forward_signal, parse_first_pid, sandbox_child_pid};

    /// The child's exit as supervised on a backend without isolation.
    fn supervise(child: std::process::Child) -> Result<i32, RunError> {
        SignalForwarding::install()
            .and_then(|signals| signals.wait(child, BackendKind::Vz, None).exit)
    }

    /// Send `signal` to this test process after `delay`.
    ///
    /// Each test runs in its own process under nextest, so signals raised here
    /// are caught by the handlers [`SignalForwarding::install`] registers
    /// and never leak into other tests.
    fn raise_self_after(delay: Duration, signal: Signal) {
        let Ok(pid) = i32::try_from(std::process::id()) else {
            return;
        };
        thread::spawn(move || {
            thread::sleep(delay);
            let _ = kill(Pid::from_raw(pid), signal);
        });
    }

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
        let code = supervise(child).expect("wait succeeds");
        assert_eq!(code, 7);
    }

    #[test]
    fn propagates_zero_exit_code() {
        let child = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn sh");
        let code = supervise(child).expect("wait succeeds");
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
        let code = supervise(child).expect("wait succeeds");
        assert_eq!(code, 143);
    }

    #[test]
    fn forwards_sigwinch_without_disturbing_exit() {
        // SIGWINCH (default disposition: ignore) must be relayed by the
        // forwarder thread while the child runs, and must not affect the
        // reported exit code once the child finishes on its own.
        let child = Command::new("sh")
            .args(["-c", "sleep 0.5; exit 0"])
            .spawn()
            .expect("spawn sh");
        raise_self_after(Duration::from_millis(150), Signal::SIGWINCH);
        let code = supervise(child).expect("wait succeeds");
        assert_eq!(code, 0);
    }

    #[test]
    fn first_sigterm_forwarded_terminates_child() {
        // A child with default SIGTERM disposition dies on the first forwarded
        // signal, reported as 128 + 15 = 143.
        let child = Command::new("sh")
            .args(["-c", "sleep 5"])
            .spawn()
            .expect("spawn sh");
        raise_self_after(Duration::from_millis(150), Signal::SIGTERM);
        let code = supervise(child).expect("wait succeeds");
        assert_eq!(code, 143);
    }

    #[test]
    fn second_termination_escalates_to_sigkill() {
        // The child ignores SIGTERM, so the first forwarded signal has no
        // effect. The second termination signal escalates to SIGKILL (9),
        // reported as 128 + 9 = 137.
        let child = Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 5"])
            .spawn()
            .expect("spawn sh");
        raise_self_after(Duration::from_millis(200), Signal::SIGTERM);
        raise_self_after(Duration::from_millis(700), Signal::SIGTERM);
        let code = supervise(child).expect("wait succeeds");
        assert_eq!(code, 137);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_child_pid_reads_proc_children() {
        // A shell that keeps a backgrounded child alive exposes that child in
        // its /proc children file; a shell with no children yields None.
        let mut with_child = Command::new("sh")
            .args(["-c", "sleep 5 & echo ready; wait"])
            .spawn()
            .expect("spawn sh");
        // Give the shell time to fork the backgrounded `sleep`.
        thread::sleep(Duration::from_millis(200));
        let discovered = sandbox_child_pid(with_child.id());
        // Exercise the bwrap process-group forwarding path; the resolved group
        // may not exist as a leader, so the send is best-effort.
        forward_signal(with_child.id(), BackendKind::Bwrap, Signal::SIGWINCH);
        let _ = with_child.kill();
        let _ = with_child.wait();
        // The children file requires CONFIG_PROC_CHILDREN, which is not
        // universal, so tolerate None; any discovered PID must be valid.
        if let Some(pid) = discovered {
            assert!(pid > 0);
            // Reap the backgrounded `sleep` so it is not orphaned past the test.
            if let Ok(raw) = i32::try_from(pid) {
                let _ = kill(Pid::from_raw(raw), Signal::SIGKILL);
            }
        }
    }
}
