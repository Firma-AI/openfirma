//! Swappable foreground log sink shared with the `firma` CLI.
//!
//! `firma run` writes its own compact log lines to stderr by default. Once the
//! wrapped agent's TUI takes over the terminal those lines would corrupt the
//! agent's interface, so the sink is redirected to `<dir>/run.log` for the
//! duration of the session and restored to stderr for teardown output.
//!
//! This module owns the pure, sink-swapping core — [`ForegroundLog`] and its
//! shared [`ForegroundState`] — with no dependency on `tracing`. The CLI wires
//! `ForegroundState` into a `tracing` layer: it resolves the active
//! destination on each write via [`ForegroundState::write`] and gates ANSI
//! color on [`ForegroundState::is_stderr`].
//!
//! In file mode (`--log-file`) no compact stderr layer is installed, so the
//! handle is [`ForegroundLog::idle`]: `redirect`/`restore` are no-ops and the
//! destination is never consulted.

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Name of the log file `firma run` redirects its foreground output to
/// while a wrapped agent's TUI owns the terminal.
const RUN_LOG_FILE: &str = "run.log";

/// Handle to the swappable foreground log surface.
///
/// `firma run` uses it to redirect its foreground output into a per-run
/// directory while the wrapped agent's TUI owns the terminal, then restore it
/// to stderr for teardown. In file mode (`--log-file`) the handle is inert:
/// stderr is never written, so [`ForegroundLog::redirect`] and
/// [`ForegroundLog::restore`] do nothing.
#[derive(Clone)]
pub struct ForegroundLog(Arc<ForegroundState>);

impl ForegroundLog {
    /// Handle over a live stderr surface whose sink can be swapped.
    #[must_use]
    pub fn active() -> Self {
        Self(Arc::new(ForegroundState::new()))
    }

    /// Inert handle for file mode, where there is no foreground surface.
    #[must_use]
    pub fn idle() -> Self {
        Self(Arc::new(ForegroundState::idle()))
    }

    /// Shared state, for wiring into a `tracing` layer's writer and formatter.
    #[must_use]
    pub fn state(&self) -> Arc<ForegroundState> {
        Arc::clone(&self.0)
    }

    /// Redirect the foreground log surface to `<dir>/run.log` so the wrapped
    /// agent's TUI is not corrupted by interleaved log lines, while the full
    /// record is still captured.
    pub fn redirect(&self, dir: &Path) {
        self.0.redirect_to(dir);
    }

    /// Restore the foreground log surface to stderr.
    pub fn restore(&self) {
        self.0.restore();
    }
}

/// Where the foreground compact log layer currently writes. Swapped at the
/// tty-handoff so `firma run` can move its own logs off the terminal the
/// wrapped agent's TUI has taken over.
enum Destination {
    /// File mode (`--log-file`): no compact stderr layer is installed, so the
    /// destination is never consulted and redirect/restore are inert.
    Disabled,
    /// Default: write to the real stderr.
    Stderr,
    /// Redirected: write to the run log file.
    RunLog(File),
}

/// Shared, runtime-swappable destination for the foreground compact layer.
pub struct ForegroundState {
    dest: RwLock<Destination>,
}

impl ForegroundState {
    /// Stderr mode: the compact layer is live and its sink can be swapped.
    fn new() -> Self {
        Self {
            dest: RwLock::new(Destination::Stderr),
        }
    }

    /// File mode: no compact layer exists; redirect/restore are no-ops.
    fn idle() -> Self {
        Self {
            dest: RwLock::new(Destination::Disabled),
        }
    }

    /// Redirect foreground output to `<runtime_dir>/run.log`. On failure the
    /// destination is left unchanged and a single warning is emitted. No-op in
    /// the disabled (file) mode.
    fn redirect_to(&self, runtime_dir: &Path) {
        if self.is_disabled() {
            return;
        }
        if let Err(e) = std::fs::create_dir_all(runtime_dir) {
            eprintln!(
                "[WARN] failed to create run log dir {}: {e}",
                runtime_dir.display()
            );
            return;
        }
        let path = runtime_dir.join(RUN_LOG_FILE);
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                if let Ok(mut dest) = self.dest.write() {
                    *dest = Destination::RunLog(file);
                }
            }
            Err(e) => {
                eprintln!(
                    "[WARN] failed to redirect run logs to {}: {e}",
                    path.display()
                );
            }
        }
    }

    /// Restore foreground output to stderr. No-op in the disabled (file) mode.
    fn restore(&self) {
        if self.is_disabled() {
            return;
        }
        if let Ok(mut dest) = self.dest.write() {
            *dest = Destination::Stderr;
        }
    }

    /// Whether the foreground currently targets stderr (used to gate ANSI
    /// color so redirected file output stays plain).
    #[must_use]
    pub fn is_stderr(&self) -> bool {
        self.dest
            .read()
            .map_or(true, |dest| matches!(&*dest, Destination::Stderr))
    }

    /// Whether the destination is disabled (file mode); redirect/restore do
    /// nothing.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.dest
            .read()
            .is_ok_and(|dest| matches!(&*dest, Destination::Disabled))
    }

    /// Write one buffer to the active destination, resolved lazily so a
    /// concurrent redirect/restore takes effect on the next event.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination lock is poisoned or the underlying
    /// sink write fails.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut dest = self
            .dest
            .write()
            .map_err(|_| io::Error::other("foreground log destination poisoned"))?;
        match &mut *dest {
            // Unreachable in practice: the disabled destination is only used in
            // file mode, where this writer is never installed. Swallow to stay
            // total.
            Destination::Disabled => Ok(buf.len()),
            Destination::Stderr => io::stderr().write(buf),
            Destination::RunLog(file) => file.write(buf),
        }
    }

    /// Flush the active destination.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination lock is poisoned or the underlying
    /// sink flush fails.
    pub fn flush(&self) -> io::Result<()> {
        let mut dest = self
            .dest
            .write()
            .map_err(|_| io::Error::other("foreground log destination poisoned"))?;
        match &mut *dest {
            Destination::Disabled => Ok(()),
            Destination::Stderr => io::stderr().flush(),
            Destination::RunLog(file) => file.flush(),
        }
    }
}
