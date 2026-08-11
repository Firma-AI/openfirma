//! Per-run autostarted sidecar: spawn, scrape `ready`, tee logs, kill on Drop.
//!
//! Constructed inside [`crate::routing::prepare_network_runtime`] when the
//! configured sidecar endpoint is unreachable and autostart is enabled.
//! The supervisor wraps a [`std::process::Child`] whose stderr is piped.
//! A scraper thread reads lines, captures values from the seven-line ready
//! log contract, and signals the main thread on the final `ready` line.
//! The same thread keeps draining stderr into `<marker_dir>/sidecar.log`
//! until the child exits. [`Drop`] sends `SIGTERM`, waits up to
//! `STOP_GRACE`, then `SIGKILL`, and joins the tee thread.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use tracing::{info, warn};
use wait_timeout::ChildExt;

use crate::config::SidecarEndpoint;
use crate::error::RunError;
use crate::identity::SandboxId;
use firma_config_loader::AgentProfile;
use firma_core::AgentId;
use firma_runtime_state::UserProcessId;
use firma_sidecar::authority_credentials::SidecarCredentialsConfig;

/// Per-spec default ready-line wait. CLI flag overrides this value.
pub(crate) const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 10;

/// Grace period between `SIGTERM` and `SIGKILL` in [`Drop`].
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Inputs to [`SidecarSupervisor::spawn`].
#[doc(hidden)]
#[derive(Debug)]
pub struct SpawnRequest<'a> {
    pub sandbox_id: &'a SandboxId,
    pub agent_id: &'a AgentId,
    pub execution_profile: AgentProfile,
    pub session_id: &'a str,
    pub marker_dir: PathBuf,
    pub template_path: Option<&'a Path>,
    pub env_template: Option<PathBuf>,
    pub cwd_template: Option<PathBuf>,
    pub firma_exe: PathBuf,
    pub startup_timeout: Duration,
    /// Effective Authority URL injected into
    /// `[sidecar.authority].url` of the synthesized sidecar config.
    /// `None` leaves the section untouched.
    pub authority_url: Option<&'a str>,
    /// CA cert path injected into `[sidecar.authority].ca_cert_path`.
    /// `None` leaves existing value.
    pub authority_ca_cert: Option<PathBuf>,
    /// Authority public key path injected into
    /// `[sidecar.authority].public_key_path` so the sidecar can verify the
    /// per-session capability seed. `None` leaves existing.
    pub authority_pub_key: Option<PathBuf>,
    /// Sidecar credentials injected into `[sidecar.authority.credentials]`.
    /// `None` leaves existing.
    pub authority_credentials: Option<SidecarCredentialsConfig>,
    /// Path of the per-session capability seed minted by `firma run`, threaded
    /// into `[sidecar.capability_seed].paths` during synthesis. `None` when no
    /// seed was minted (e.g. `--capability-file` was passed).
    pub capability_seed_path: Option<PathBuf>,
    /// When `true`, synthesize an `http_proxy` interceptor instead of a
    /// Unix-domain socket. Set from [`ResolvedProfile::use_http_proxy_sidecar`].
    pub use_http_proxy_interceptor: bool,
    /// Default audit log path (`<state_dir>/audit.jsonl`) injected as a `file`
    /// sink when the template configures none, so `firma monitor` can tail the
    /// per-run sidecar's decisions. `None` leaves the audit sink untouched.
    pub audit_fallback_path: Option<PathBuf>,
    /// When `true`, override `[sidecar].mode = "monitor"` in the synthesized
    /// config regardless of the operator template value. Passed through from
    /// `--monitor` on the `firma run` CLI.
    pub monitor_mode: bool,
}

/// Captured values from the seven-line ready sequence.
#[doc(hidden)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReadyCapture {
    pub policy_bundle_version: String,
    pub authority_url: String,
    pub interceptor_addr: String,
}

/// Outcome reported by the scraper thread to the main thread.
#[doc(hidden)]
#[derive(Debug)]
pub enum ScrapeResult {
    /// Final `ready` line observed. Tee thread continues draining stderr.
    Ready(ReadyCapture),
    /// Child stderr closed before the `ready` line was seen.
    Eof,
    /// I/O or spawn error before reaching `ready`.
    Error(String),
}

/// Owning handle for an autostarted per-run sidecar. Drop tears the child
/// down (`SIGTERM` then `SIGKILL`) and cleans the marker directory.
#[doc(hidden)]
pub struct SidecarSupervisor {
    endpoint: SidecarEndpoint,
    marker_dir: PathBuf,
    pid: UserProcessId,
    child: Option<Child>,
    tee_handle: Option<JoinHandle<()>>,
}

impl SidecarSupervisor {
    /// Spawn the autostarted sidecar and wait for the ready line.
    ///
    /// # Errors
    ///
    /// Returns:
    ///
    /// - [`RunError::UnsupportedPlatform`] on non-Unix hosts (autostart
    ///   currently requires a UDS interceptor).
    /// - [`RunError::SidecarStartupFailed`] when the child fails to spawn,
    ///   stderr cannot be piped, or stderr closes before `ready`.
    /// - [`RunError::SidecarReadyTimeout`] when the seven-line contract
    ///   does not complete within `req.startup_timeout`.
    /// - Internal errors when marker files cannot be written.
    #[cfg(not(unix))]
    pub fn spawn(_req: SpawnRequest<'_>) -> Result<Self, RunError> {
        Err(RunError::UnsupportedPlatform {
            reason: "firma run sidecar autostart requires Unix; use --sidecar <url> on this \
                     platform"
                .into(),
        })
    }

    #[cfg(unix)]
    #[expect(
        clippy::too_many_lines,
        reason = "linear guarded startup is easier to audit"
    )]
    pub fn spawn(req: SpawnRequest<'_>) -> Result<Self, RunError> {
        use firma_runtime_state::ChildExt as _;

        let startup_timeout = req.startup_timeout;
        let mut prepared =
            crate::sidecar::prepare::prepare(crate::sidecar::prepare::PrepareRequest {
                sandbox_id: req.sandbox_id,
                agent_id: req.agent_id,
                execution_profile: req.execution_profile,
                session_id: req.session_id,
                marker_dir: req.marker_dir,
                template_path: req.template_path,
                env_template: req.env_template.clone(),
                cwd_template: req.cwd_template.clone(),
                firma_exe: req.firma_exe,
                authority_url: req.authority_url,
                authority_ca_cert: req.authority_ca_cert,
                authority_pub_key: req.authority_pub_key,
                authority_credentials: req.authority_credentials,
                capability_seed_path: req.capability_seed_path,
                use_http_proxy_interceptor: req.use_http_proxy_interceptor,
                audit_fallback_path: req.audit_fallback_path,
                monitor_mode: req.monitor_mode,
            })?;
        let mut command = prepared.take_command()?;
        let child = command
            .spawn()
            .map_err(|error| RunError::SidecarStartupFailed {
                reason: format!("spawn firma sidecar: {error}"),
                log_path: prepared.log_path.clone(),
            })?;
        let pid = child.process_id();
        let mut startup = StartupOwner::new(child);
        let stderr =
            startup
                .child_mut()
                .stderr
                .take()
                .ok_or_else(|| RunError::SidecarStartupFailed {
                    reason: "stderr pipe missing".into(),
                    log_path: prepared.log_path.clone(),
                })?;
        let log_file = std::fs::File::create(&prepared.log_path).map_err(|error| {
            RunError::SidecarStartupFailed {
                reason: format!("create log {}: {error}", prepared.log_path.display()),
                log_path: prepared.log_path.clone(),
            }
        })?;
        let (tx, rx) = mpsc::sync_channel::<ScrapeResult>(1);
        let mirror_child_logs = child_log_mirroring_enabled();
        let tee_handle = std::thread::Builder::new()
            .name("firma-sidecar-tee".into())
            .spawn(move || {
                run_scraper_with_mirror(
                    std::io::BufReader::new(stderr),
                    log_file,
                    std::io::stderr(),
                    mirror_child_logs,
                    tx,
                );
            })
            .map_err(|error| RunError::SidecarStartupFailed {
                reason: format!("spawn scraper thread: {error}"),
                log_path: prepared.log_path.clone(),
            })?;
        startup.tee_handle = Some(tee_handle);
        let capture = match rx.recv_timeout(startup_timeout) {
            Ok(ScrapeResult::Ready(capture)) => capture,
            Ok(ScrapeResult::Eof) => {
                return Err(RunError::SidecarStartupFailed {
                    reason: "sidecar stderr closed before 'ready'".into(),
                    log_path: prepared.log_path.clone(),
                });
            }
            Ok(ScrapeResult::Error(reason)) => {
                return Err(RunError::SidecarStartupFailed {
                    reason,
                    log_path: prepared.log_path.clone(),
                });
            }
            Err(_) => {
                return Err(RunError::SidecarReadyTimeout {
                    timeout_secs: startup_timeout.as_secs(),
                    log_path: prepared.log_path.clone(),
                });
            }
        };
        let endpoint =
            validate_captured_endpoint(&prepared.expected_endpoint, &capture.interceptor_addr)
                .map_err(|reason| RunError::SidecarStartupFailed {
                    reason,
                    log_path: prepared.log_path.clone(),
                })?;
        crate::sidecar::prepare::publish_metadata(
            &prepared,
            &endpoint,
            pid,
            Some((&capture.authority_url, &capture.policy_bundle_version)),
        )?;

        info!(
            sandbox_id = %prepared.sandbox_id,
            pid = %pid,
            endpoint = %capture.interceptor_addr,
            "sidecar started"
        );
        let (child, tee_handle) = startup.disarm();
        Ok(Self {
            endpoint,
            marker_dir: prepared.marker_dir,
            pid,
            child: Some(child),
            tee_handle,
        })
    }

    /// The UDS endpoint the spawned sidecar is listening on.
    #[must_use]
    pub(crate) fn endpoint(&self) -> SidecarEndpoint {
        self.endpoint.clone()
    }

    /// Pid of the spawned sidecar. Useful for integration tests that
    /// need to assert kill-on-Drop semantics.
    #[doc(hidden)]
    #[must_use]
    pub fn pid(&self) -> UserProcessId {
        self.pid
    }

    /// Marker directory path. Useful for integration tests that inspect
    /// `metadata.toml` and friends.
    #[doc(hidden)]
    #[must_use]
    pub fn marker_dir(&self) -> &Path {
        &self.marker_dir
    }
}

impl Drop for SidecarSupervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Err(error) = self.pid.send_sigterm_signal() {
                warn!(%error, pid = %self.pid, "SIGTERM to sidecar failed");
            }
            match child.wait_timeout(STOP_GRACE) {
                Ok(Some(_)) => {
                    info!(pid = %self.pid, "sidecar stopped");
                }
                Ok(None) => {
                    warn!(pid = %self.pid, "sidecar SIGKILL after grace");
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(error) => {
                    warn!(%error, "sidecar wait failed");
                    let _ = child.kill();
                }
            }
        }
        if let Some(handle) = self.tee_handle.take() {
            let _ = handle.join();
        }
        // Best-effort marker cleanup. FIR-103 also GCs stale dirs.
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

#[cfg(unix)]
fn validate_captured_endpoint(
    expected: &SidecarEndpoint,
    captured: &str,
) -> Result<SidecarEndpoint, String> {
    match expected {
        SidecarEndpoint::Tcp { addr: expected } => {
            let actual = captured.parse::<std::net::SocketAddr>().map_err(|error| {
                format!("invalid captured TCP interceptor endpoint '{captured}': {error}")
            })?;
            if actual.port() == 0 {
                return Err("captured TCP interceptor endpoint has port 0 after bind".into());
            }
            if actual.ip() != expected.ip()
                || (expected.port() != 0 && actual.port() != expected.port())
            {
                return Err(format!(
                    "captured interceptor endpoint {actual} does not match expected {expected}"
                ));
            }
            Ok(SidecarEndpoint::Tcp { addr: actual })
        }
        SidecarEndpoint::Unix { path } if captured == path.to_string_lossy() => {
            Ok(SidecarEndpoint::Unix { path: path.clone() })
        }
        SidecarEndpoint::Unix { path } => Err(format!(
            "captured interceptor endpoint '{captured}' does not match expected {}",
            path.display()
        )),
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
        self.child.as_mut().unwrap_or_else(|| unreachable!())
    }
    fn disarm(mut self) -> (Child, Option<JoinHandle<()>>) {
        (
            self.child.take().unwrap_or_else(|| unreachable!()),
            self.tee_handle.take(),
        )
    }
}

#[cfg(unix)]
impl Drop for StartupOwner {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(handle) = self.tee_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Substring matched on the third info line in the ready contract.
const POLICY_TOKEN: &str = "policy bundle loaded";
/// Substring matched on the fourth info line in the ready contract.
const AUTHORITY_TOKEN: &str = "authority stream connected";
/// Substring matched on the sixth info line in the ready contract.
const INTERCEPTOR_TOKEN: &str = "interceptor listening";

/// Loop body for the scraper / tee thread. Reads stderr line by line,
/// captures version / authority values, signals readiness on the seventh
/// line, then continues to drain stderr into `log` until EOF.
///
/// ANSI escape sequences are stripped from the inspected copy before
/// matching, in case the spawned sidecar emits colored output (e.g. when
/// `tracing-subscriber` decides to enable ANSI even though stderr is
/// piped). The raw bytes are written to the log file unmodified so a
/// human `cat`ting the log still sees the colors the subscriber chose.
#[doc(hidden)]
pub fn run_scraper<R, W>(mut reader: R, mut log: W, tx: mpsc::SyncSender<ScrapeResult>)
where
    R: BufRead,
    W: Write,
{
    run_scraper_with_mirror(&mut reader, &mut log, std::io::sink(), false, tx);
}

#[doc(hidden)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "tx is moved into the spawned thread and owns the sender for the thread lifetime"
)]
pub fn run_scraper_with_mirror<R, W, M>(
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
                    if plain.contains(POLICY_TOKEN)
                        && let Some(version) = extract_kv(&plain, "version")
                    {
                        capture.policy_bundle_version = version;
                    } else if plain.contains(AUTHORITY_TOKEN)
                        && let Some(endpoint) = extract_kv(&plain, "endpoint")
                    {
                        capture.authority_url = if endpoint == "(disabled)" {
                            String::new()
                        } else {
                            endpoint
                        };
                    } else if plain.contains(INTERCEPTOR_TOKEN)
                        && let Some(addr) = extract_kv(&plain, "addr")
                    {
                        capture.interceptor_addr = addr;
                    } else if line_marks_ready(&plain) {
                        signalled = true;
                        if tx.send(ScrapeResult::Ready(capture.clone())).is_err() {
                            // Receiver gone — main thread bailed; just drain.
                        }
                    }
                }
            }
            Err(error) => {
                if !signalled {
                    let _ = tx.send(ScrapeResult::Error(format!("read stderr: {error}")));
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
            "firma_sidecar=debug",
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
        for filter in ["", "info", "warn,firma=info", "firma_sidecar=warn"] {
            assert!(
                !super::log_filter_requests_child_mirroring(filter),
                "{filter} should not mirror child logs"
            );
        }
    }
}

/// Strip CSI escape sequences (`ESC '[' ... final_byte`) used by ANSI
/// colour. Conservative implementation: only handles the common
/// `\x1b[...m` form `tracing-subscriber` emits. ESC and the terminator
/// bytes are ASCII so byte-level skipping is UTF-8 safe; non-escape
/// payload is copied unchanged.
fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut copy_from = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            // Flush everything since the last escape.
            if copy_from < i {
                out.push_str(&input[copy_from..i]);
            }
            // Skip `ESC [` then everything until a CSI terminator (0x40..=0x7e).
            i += 2;
            while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                i += 1;
            }
            i = i.saturating_add(1); // skip the terminator
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
    line.trim_end().ends_with("sidecar ready")
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
    pub use super::{ReadyCapture, ScrapeResult, run_scraper, run_scraper_with_mirror};
}
