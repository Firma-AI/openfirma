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
#[cfg(unix)]
use std::net::SocketAddr;
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

/// Per-spec default ready-line wait. CLI flag overrides this value.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 10;

/// Grace period between `SIGTERM` and `SIGKILL` in [`Drop`].
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Inputs to [`SidecarSupervisor::spawn`].
#[doc(hidden)]
#[derive(Debug)]
pub struct SpawnRequest<'a> {
    pub sandbox_id: &'a SandboxId,
    pub agent_id: &'a str,
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
    /// `[sidecar.authority].public_key_path` and
    /// `[sidecar.preflight].authority_pub_key_path`. `None` leaves existing.
    pub authority_pub_key: Option<PathBuf>,
    /// When `true`, synthesize an `http_proxy` interceptor instead of a
    /// Unix-domain socket. Set from [`ResolvedProfile::use_http_proxy_sidecar`].
    pub use_http_proxy_interceptor: bool,
    /// Default audit log path (`<state_dir>/audit.jsonl`) injected as a `file`
    /// sink when the template configures none, so `firma monitor` can tail the
    /// per-run sidecar's decisions. `None` leaves the audit sink untouched.
    pub audit_fallback_path: Option<PathBuf>,
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
    pid: u32,
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
    #[allow(
        clippy::too_many_lines,
        reason = "single linear spawn-then-scrape sequence reads more clearly inline than split"
    )]
    pub fn spawn(req: SpawnRequest<'_>) -> Result<Self, RunError> {
        std::fs::create_dir_all(&req.marker_dir).map_err(|error| {
            RunError::Internal(format!("mkdir {}: {error}", req.marker_dir.display()))
        })?;

        let sock_path = req.marker_dir.join("sidecar.sock");
        let use_http_proxy_interceptor = req.use_http_proxy_interceptor;
        let max_attempts = if use_http_proxy_interceptor { 3 } else { 1 };
        let cfg_path = req.marker_dir.join("sidecar.toml");
        let log_path = req.marker_dir.join("sidecar.log");
        let pid_path = req.marker_dir.join("sidecar.pid");
        let metadata_path = req.marker_dir.join("metadata.toml");

        // Pre-clean any leftover socket file from a crashed run.
        let _ = std::fs::remove_file(&sock_path);
        let mut last_error: Option<RunError> = None;
        let mut ready: Option<(Child, JoinHandle<()>, u32, ReadyCapture)> = None;
        for attempt in 0..max_attempts {
            let proxy_listen_addr = if use_http_proxy_interceptor {
                Some(select_loopback_port())
            } else {
                None
            };
            crate::sidecar::config::synthesize(crate::sidecar::config::SynthesizeRequest {
                agent_id: req.agent_id,
                session_id: req.session_id,
                explicit_template: req.template_path,
                env_template: req.env_template.clone(),
                cwd_template: req.cwd_template.clone(),
                socket_path: &sock_path,
                listen_addr: proxy_listen_addr,
                out_path: &cfg_path,
                authority_url: req.authority_url,
                authority_ca_cert: req.authority_ca_cert.as_deref(),
                authority_pub_key: req.authority_pub_key.as_deref(),
                audit_fallback_path: req.audit_fallback_path.as_deref(),
            })?;

            let mut child = std::process::Command::new(&req.firma_exe)
                .args(["sidecar", "--config"])
                .arg(&cfg_path)
                .env_remove("FIRMA_LOG_FILE")
                // Avoid cross-run collisions when multiple autostarted sidecars
                // run concurrently on the same host.
                .env("FIRMA_SIDECAR_HEALTH_BIND_ADDR", "127.0.0.1:0")
                // Per-run identity stamped on every audit ExecutionEvent
                // (FIR-185). Matches the marker directory name.
                .env("FIRMA_RUN_SANDBOX_ID", req.sandbox_id)
                .env("NO_COLOR", "1")
                .env("CLICOLOR", "0")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|error| RunError::SidecarStartupFailed {
                    reason: format!("spawn firma sidecar: {error}"),
                    log_path: log_path.clone(),
                })?;
            let pid = child.id();

            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| RunError::SidecarStartupFailed {
                    reason: "stderr pipe missing".into(),
                    log_path: log_path.clone(),
                })?;

            let log_file = std::fs::File::create(&log_path).map_err(|error| {
                RunError::SidecarStartupFailed {
                    reason: format!("create log {}: {error}", log_path.display()),
                    log_path: log_path.clone(),
                }
            })?;

            let reader = std::io::BufReader::new(stderr);
            let (tx, rx) = mpsc::sync_channel::<ScrapeResult>(1);
            let tee_handle = std::thread::Builder::new()
                .name("firma-sidecar-tee".into())
                .spawn(move || run_scraper(reader, log_file, tx))
                .map_err(|error| RunError::SidecarStartupFailed {
                    reason: format!("spawn scraper thread: {error}"),
                    log_path: log_path.clone(),
                })?;

            match rx.recv_timeout(req.startup_timeout) {
                Ok(ScrapeResult::Ready(capture)) => {
                    ready = Some((child, tee_handle, pid, capture));
                    break;
                }
                Ok(ScrapeResult::Eof) => {
                    let _ = child.wait();
                    let _ = tee_handle.join();
                    last_error = Some(RunError::SidecarStartupFailed {
                        reason: "sidecar stderr closed before 'ready'".into(),
                        log_path: log_path.clone(),
                    });
                }
                Ok(ScrapeResult::Error(reason)) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = tee_handle.join();
                    last_error = Some(RunError::SidecarStartupFailed {
                        reason,
                        log_path: log_path.clone(),
                    });
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = tee_handle.join();
                    last_error = Some(RunError::SidecarReadyTimeout {
                        timeout_secs: req.startup_timeout.as_secs(),
                        log_path: log_path.clone(),
                    });
                }
            }
            if attempt + 1 < max_attempts {
                std::thread::sleep(Duration::from_millis(120));
            }
        }
        let Some((child, tee_handle, pid, capture)) = ready else {
            return Err(
                last_error.unwrap_or_else(|| RunError::SidecarStartupFailed {
                    reason: "sidecar autostart failed".into(),
                    log_path: log_path.clone(),
                }),
            );
        };

        firma_stack::pidfile::write(&pid_path, pid)
            .map_err(|error| RunError::Internal(format!("write sidecar.pid: {error}")))?;
        crate::sidecar::metadata::write(
            &metadata_path,
            &crate::sidecar::metadata::Metadata {
                sandbox_id: req.sandbox_id.to_string(),
                agent_id: req.agent_id.to_string(),
                session_id: req.session_id.to_string(),
                authority_url: capture.authority_url,
                policy_bundle_version: capture.policy_bundle_version,
                pid,
                started_at: chrono::Utc::now().to_rfc3339(),
                // Persist the real interceptor endpoint so `firma sidecar
                // status` probes the correct transport (FIR-195): a TCP port
                // for `http_proxy`, the UDS path otherwise.
                listen: capture.interceptor_addr.clone(),
            },
        )?;

        info!(
            sandbox_id = req.sandbox_id.compact(),
            pid,
            endpoint = %capture.interceptor_addr,
            "sidecar started"
        );

        let endpoint = capture.interceptor_addr.parse::<SocketAddr>().map_or_else(
            |_| SidecarEndpoint::Unix {
                path: sock_path.clone(),
            },
            |addr| SidecarEndpoint::Tcp { addr },
        );

        Ok(Self {
            endpoint,
            marker_dir: req.marker_dir,
            pid,
            child: Some(child),
            tee_handle: Some(tee_handle),
        })
    }

    /// The UDS endpoint the spawned sidecar is listening on.
    #[must_use]
    pub fn endpoint(&self) -> SidecarEndpoint {
        self.endpoint.clone()
    }

    /// Pid of the spawned sidecar. Useful for integration tests that
    /// need to assert kill-on-Drop semantics.
    #[doc(hidden)]
    #[must_use]
    pub fn pid(&self) -> u32 {
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
            send_sigterm(self.pid);
            match child.wait_timeout(STOP_GRACE) {
                Ok(Some(_)) => {
                    info!(pid = self.pid, "sidecar stopped");
                }
                Ok(None) => {
                    warn!(pid = self.pid, "sidecar SIGKILL after grace");
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
fn send_sigterm(pid: u32) {
    let Ok(raw) = i32::try_from(pid) else {
        warn!(pid, "pid does not fit in i32; skipping SIGTERM");
        return;
    };
    let target = nix::unistd::Pid::from_raw(raw);
    if let Err(error) = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGTERM) {
        warn!(%error, pid, "SIGTERM to sidecar failed");
    }
}

#[cfg(not(unix))]
fn send_sigterm(_pid: u32) {}

#[cfg(unix)]
fn select_loopback_port() -> SocketAddr {
    // Ask kernel for an ephemeral loopback port. Sidecar startup now logs
    // the actual bound address from the active listener, so run-side scraping
    // can consume the real endpoint without fixed/random port guessing.
    SocketAddr::from(([127, 0, 0, 1], 0))
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
#[allow(
    clippy::needless_pass_by_value,
    reason = "tx is moved into the spawned thread and owns the sender for the thread lifetime"
)]
pub fn run_scraper<R, W>(mut reader: R, mut log: W, tx: mpsc::SyncSender<ScrapeResult>)
where
    R: BufRead,
    W: Write,
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
    let trimmed = line.trim_end();
    // tracing default: `<ts> <LEVEL> <target>: ready`
    // CompactFormatter (no --log-file): `[INFO] ready`
    trimmed.ends_with(": ready") || trimmed == "ready" || trimmed.ends_with("] ready")
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
