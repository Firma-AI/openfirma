//! Per-run autostarted Mini Authority: spawn, scrape `ready`, tee logs,
//! kill on Drop. Mirrors `firma-run/src/sidecar/supervisor.rs` (FIR-102).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

#[cfg(unix)]
use tracing::debug;
use tracing::{info, warn};
use wait_timeout::ChildExt;

use crate::error::RunError;
use crate::identity::SandboxId;
use firma_core::AgentId;
use firma_runtime_state::UserProcessId;

/// Per-spec default ready-line wait. CLI flag overrides.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 10;

/// Grace period between `SIGTERM` and `SIGKILL` in [`Drop`].
const STOP_GRACE: Duration = Duration::from_secs(5);
/// Inputs to [`AuthoritySupervisor::spawn`].
#[doc(hidden)]
#[derive(Debug)]
pub struct SpawnRequest<'a> {
    pub sandbox_id: &'a SandboxId,
    pub agent_id: &'a AgentId,
    pub session_id: &'a str,
    pub marker_dir: PathBuf,
    pub profile_name: &'a str,
    pub firma_exe: PathBuf,
    pub startup_timeout: Duration,
    pub user_config_path: Option<PathBuf>,
}

/// Captured values from the ready sequence.
#[doc(hidden)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReadyCapture {
    pub listen_addr: String,
}

/// Outcome reported by the scraper thread to the main thread.
#[doc(hidden)]
#[derive(Debug)]
pub enum ScrapeResult {
    Ready(ReadyCapture),
    Eof,
    Error(String),
}

/// Owning handle for an autostarted per-run Mini Authority. Drop tears
/// the child down (`SIGTERM` then `SIGKILL`) and cleans the marker sub-dir.
#[doc(hidden)]
pub struct AuthoritySupervisor {
    listen_addr: String,
    marker_dir: PathBuf,
    pub_key_path: PathBuf,
    pid: UserProcessId,
    child: Option<Child>,
    tee_handle: Option<JoinHandle<()>>,
}

impl AuthoritySupervisor {
    /// Spawn the autostarted authority and wait for the ready line.
    ///
    /// # Errors
    ///
    /// - [`RunError::UnsupportedPlatform`] on non-Unix hosts.
    /// - [`RunError::AuthorityUnknownProfile`] when `profile_name` is not
    ///   registered.
    /// - [`RunError::AuthorityStartupFailed`] / [`RunError::AuthorityReadyTimeout`]
    ///   on spawn or scrape failure.
    /// - `Internal` for marker I/O failures.
    #[cfg(not(unix))]
    pub fn spawn(_req: SpawnRequest<'_>) -> Result<Self, RunError> {
        Err(RunError::UnsupportedPlatform {
            reason: "firma run authority autostart requires Unix; use --authority <url> on this \
                     platform"
                .into(),
        })
    }

    /// Spawn the autostarted authority and wait for the ready line.
    ///
    /// # Errors
    ///
    /// See the platform-stub variant of this method for the full list.
    #[cfg(unix)]
    #[expect(
        clippy::too_many_lines,
        reason = "linear handoff from preparation through guarded startup is easier to audit"
    )]
    pub fn spawn(req: SpawnRequest<'_>) -> Result<Self, RunError> {
        use firma_runtime_state::ChildExt as _;

        let startup_timeout = req.startup_timeout;
        let mut prepared =
            crate::authority::prepare::prepare(crate::authority::prepare::PrepareRequest {
                sandbox_id: req.sandbox_id,
                agent_id: req.agent_id,
                session_id: req.session_id,
                marker_dir: req.marker_dir,
                profile_name: req.profile_name,
                firma_exe: req.firma_exe,
                user_config_path: req.user_config_path,
            })?;
        debug!(
            expected_endpoint = %prepared.expected_endpoint,
            "authority launch prepared"
        );
        let child =
            prepared
                .take_command()?
                .spawn()
                .map_err(|error| RunError::AuthorityStartupFailed {
                    reason: format!("spawn firma authority: {error}"),
                    log_path: prepared.log_path.clone(),
                })?;
        let pid = child.process_id();
        // Arm ownership immediately: every error after spawn synchronously kills
        // and reaps the child, and joins the scraper once one exists.
        let mut startup = StartupOwner::new(child);
        let stderr =
            startup
                .child_mut()
                .stderr
                .take()
                .ok_or_else(|| RunError::AuthorityStartupFailed {
                    reason: "stderr pipe missing".into(),
                    log_path: prepared.log_path.clone(),
                })?;
        let log_file = std::fs::File::create(&prepared.log_path).map_err(|error| {
            RunError::AuthorityStartupFailed {
                reason: format!("create log {}: {error}", prepared.log_path.display()),
                log_path: prepared.log_path.clone(),
            }
        })?;
        let (tx, rx) = mpsc::sync_channel::<ScrapeResult>(1);
        let mirror_child_logs = child_log_mirroring_enabled();
        let tee_handle = std::thread::Builder::new()
            .name("firma-authority-tee".into())
            .spawn(move || {
                run_scraper(
                    std::io::BufReader::new(stderr),
                    log_file,
                    std::io::stderr(),
                    mirror_child_logs,
                    tx,
                );
            })
            .map_err(|error| RunError::AuthorityStartupFailed {
                reason: format!("spawn scraper thread: {error}"),
                log_path: prepared.log_path.clone(),
            })?;
        startup.tee_handle = Some(tee_handle);
        let capture = match rx.recv_timeout(startup_timeout) {
            Ok(ScrapeResult::Ready(capture)) => capture,
            Ok(ScrapeResult::Eof) => {
                return Err(RunError::AuthorityStartupFailed {
                    reason: "authority stderr closed before 'ready'".into(),
                    log_path: prepared.log_path,
                });
            }
            Ok(ScrapeResult::Error(reason)) => {
                return Err(RunError::AuthorityStartupFailed {
                    reason,
                    log_path: prepared.log_path,
                });
            }
            Err(_) => {
                return Err(RunError::AuthorityReadyTimeout {
                    timeout_secs: startup_timeout.as_secs(),
                    log_path: prepared.log_path,
                });
            }
        };
        firma_runtime_state::pidfile::write(&prepared.pid_path, pid)
            .map_err(|error| RunError::Internal(format!("write authority.pid: {error}")))?;
        crate::authority::metadata::write(
            &prepared.metadata_path,
            &crate::authority::metadata::Metadata {
                sandbox_id: prepared.sandbox_id,
                agent_id: prepared.agent_id,
                session_id: prepared.session_id,
                profile: prepared.profile_name,
                listen_addr: capture.listen_addr.clone(),
                pid,
                started_at: chrono::Utc::now().to_rfc3339(),
            },
        )?;
        info!(sandbox_id = %prepared.sandbox_id, pid = %pid,
            listen_addr = %capture.listen_addr, "authority started");
        let (child, tee_handle) = startup.disarm();
        Ok(Self {
            listen_addr: capture.listen_addr,
            marker_dir: prepared.marker_dir,
            pub_key_path: prepared.pub_key_path,
            pid,
            child: Some(child),
            tee_handle,
        })
    }

    /// The URL the spawned Authority is reachable at.
    #[must_use]
    #[doc(hidden)]
    pub fn url(&self) -> String {
        format!("http://{}", self.listen_addr)
    }

    #[doc(hidden)]
    #[must_use]
    pub fn pid(&self) -> UserProcessId {
        self.pid
    }

    #[doc(hidden)]
    #[must_use]
    pub fn marker_dir(&self) -> &Path {
        &self.marker_dir
    }

    /// Path to the Ed25519 public key for this run's authority instance.
    #[must_use]
    #[expect(
        dead_code,
        reason = "legacy supervisor remains available for direct integration tests"
    )]
    fn pub_key_path(&self) -> PathBuf {
        self.pub_key_path.clone()
    }
}

#[cfg(unix)]
struct StartupOwner {
    child: Option<Child>,
    tee_handle: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl StartupOwner {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            tee_handle: None,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        // Constructed with a child and only emptied by disarm immediately
        // before returning the completed supervisor.
        self.child.as_mut().unwrap_or_else(|| unreachable!())
    }

    fn disarm(mut self) -> (Child, Option<JoinHandle<()>>) {
        let child = self.child.take().unwrap_or_else(|| unreachable!());
        (child, self.tee_handle.take())
    }
}

#[cfg(unix)]
impl Drop for StartupOwner {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Startup failure must be prompt; do not use the normal five-second
            // graceful shutdown intended for a successfully started service.
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(handle) = self.tee_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for AuthoritySupervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Err(error) = self.pid.send_sigterm_signal() {
                warn!(%error, pid = %self.pid, "SIGTERM to authority failed");
            }
            match child.wait_timeout(STOP_GRACE) {
                Ok(Some(_)) => {
                    info!(pid = %self.pid, "authority stopped");
                }
                Ok(None) => {
                    warn!(pid = %self.pid, "authority SIGKILL after grace");
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(e) => {
                    warn!(error = %e, "authority wait failed");
                    let _ = child.kill();
                }
            }
        }
        if let Some(h) = self.tee_handle.take() {
            let _ = h.join();
        }
        let keep_markers = std::env::var("FIRMA_RUN_KEEP_MARKERS")
            .ok()
            .is_some_and(|v| {
                matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
            });
        if !keep_markers {
            let _ = std::fs::remove_dir_all(&self.marker_dir);
        }
    }
}

const LISTENING_TOKEN: &str = "listening";

#[doc(hidden)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "tx is moved into the spawned thread"
)]
pub fn run_scraper<R, W, M>(
    mut reader: R,
    mut log: W,
    mut mirror: M,
    mirror_enabled: bool,
    tx: mpsc::SyncSender<ScrapeResult>,
) where
    R: BufRead,
    W: Write,
    M: Write,
{
    let mut capture = ReadyCapture::default();
    let mut signalled = false;
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) => {
                if !signalled {
                    let _ = tx.send(ScrapeResult::Eof);
                }
                return;
            }
            Ok(_) => {
                let _ = log.write_all(buf.as_bytes());
                if mirror_enabled {
                    let _ = mirror.write_all(buf.as_bytes());
                }
                if !signalled {
                    let plain = strip_ansi(&buf);
                    if plain.contains(LISTENING_TOKEN)
                        && let Some(addr) = extract_kv(&plain, "addr")
                    {
                        capture.listen_addr = addr;
                    } else if line_marks_ready(&plain) {
                        signalled = true;
                        let _ = tx.send(ScrapeResult::Ready(capture.clone()));
                    }
                }
            }
            Err(e) => {
                if !signalled {
                    let _ = tx.send(ScrapeResult::Error(format!("read stderr: {e}")));
                }
                return;
            }
        }
    }
}

#[cfg(unix)]
fn child_log_mirroring_enabled() -> bool {
    std::env::var("FIRMA_LOG_FILTER")
        .or_else(|_| std::env::var("RUST_LOG"))
        .is_ok_and(|filter| log_filter_requests_child_mirroring(&filter))
}

#[cfg(unix)]
fn log_filter_requests_child_mirroring(filter: &str) -> bool {
    filter
        .split(',')
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .any(|directive| {
            directive == "debug"
                || directive == "trace"
                || directive.ends_with("=debug")
                || directive.ends_with("=trace")
        })
}

#[cfg(all(test, unix))]
mod log_filter_tests {
    #[test]
    fn debug_and_trace_filters_request_child_log_mirroring() {
        for filter in [
            "debug",
            "trace",
            "firma_authority=debug",
            "openfirma=trace",
            " info , firma_run=debug ",
        ] {
            assert!(
                super::log_filter_requests_child_mirroring(filter),
                "{filter} should mirror child logs"
            );
        }
    }

    #[test]
    fn less_verbose_filters_do_not_request_child_log_mirroring() {
        for filter in ["", "info", "warn,firma=info", "firma_authority=warn"] {
            assert!(
                !super::log_filter_requests_child_mirroring(filter),
                "{filter} should not mirror child logs"
            );
        }
    }
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut copy_from = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            if copy_from < i {
                out.push_str(&input[copy_from..i]);
            }
            i += 2;
            while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                i += 1;
            }
            i = i.saturating_add(1);
            copy_from = i;
            continue;
        }
        i += 1;
    }
    if copy_from < bytes.len() {
        out.push_str(&input[copy_from..]);
    }
    out
}

fn line_marks_ready(line: &str) -> bool {
    line.trim_end().ends_with("authority ready")
}

fn extract_kv(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let idx = line.find(&needle)?;
    let rest = &line[idx + needle.len()..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        return Some(stripped[..end].to_string());
    }
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[doc(hidden)]
pub mod testing {
    pub use super::{ReadyCapture, ScrapeResult, run_scraper};
}
