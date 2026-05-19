//! Per-run autostarted Mini Authority: spawn, scrape `ready`, tee logs,
//! kill on Drop. Mirrors `firma-run/src/sidecar/supervisor.rs` (FIR-102).

use std::io::{BufRead, Write};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::error::RunError;

/// Per-spec default ready-line wait. CLI flag overrides.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 10;

/// Grace period between `SIGTERM` and `SIGKILL` in [`Drop`].
const STOP_GRACE: Duration = Duration::from_secs(5);
const MAX_BIND_ATTEMPTS: usize = 8;
const AUTOSTART_LOCAL_DEVELOPER_POLICY: &str = r#"// Local autostart profile for `firma run`.
//
// Keeps default operation strict while allowing outbound communication flows
// that are further constrained by sidecar mapping, capability scope, and
// session-bound issued tokens.
permit(
    principal,
    action == Firma::Action::"communication.external.send",
    resource
);
"#;

/// Inputs to [`AuthoritySupervisor::spawn`].
#[doc(hidden)]
#[derive(Debug)]
pub struct SpawnRequest<'a> {
    pub sandbox_id: &'a str,
    pub agent_id: &'a str,
    pub session_id: &'a str,
    /// Sub-marker dir (the `authority/` directory inside the sandbox marker).
    pub marker_dir: PathBuf,
    pub profile_name: &'a str,
    pub firma_exe: PathBuf,
    pub startup_timeout: Duration,
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
    pid: u32,
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
    #[allow(
        clippy::too_many_lines,
        reason = "single linear spawn-then-scrape sequence reads more clearly inline"
    )]
    pub fn spawn(req: SpawnRequest<'_>) -> Result<Self, RunError> {
        firma_authority::cedar_for(req.profile_name).map_err(|_| {
            RunError::AuthorityUnknownProfile {
                name: req.profile_name.to_string(),
            }
        })?;

        std::fs::create_dir_all(&req.marker_dir)
            .map_err(|e| RunError::Internal(format!("mkdir {}: {e}", req.marker_dir.display())))?;

        let policy_dir = req.marker_dir.join("policy_dir");
        let keys_dir = req.marker_dir.join("keys");
        let cedar_path = policy_dir.join(format!("{}.cedar", req.profile_name));
        let key_path = keys_dir.join("authority.key");
        let revocation_path = req.marker_dir.join("revocations.txt");
        let authority_toml = req.marker_dir.join("authority.toml");
        let log_path = req.marker_dir.join("authority.log");
        let pid_path = req.marker_dir.join("authority.pid");
        let metadata_path = req.marker_dir.join("metadata.toml");

        std::fs::create_dir_all(&policy_dir)
            .map_err(|e| RunError::Internal(format!("mkdir {}: {e}", policy_dir.display())))?;
        std::fs::create_dir_all(&keys_dir)
            .map_err(|e| RunError::Internal(format!("mkdir {}: {e}", keys_dir.display())))?;

        let cedar_text = if req.profile_name == firma_authority::DEFAULT_PROFILE {
            AUTOSTART_LOCAL_DEVELOPER_POLICY
        } else {
            firma_authority::cedar_for(req.profile_name).map_err(|_| {
                RunError::AuthorityUnknownProfile {
                    name: req.profile_name.to_string(),
                }
            })?
        };
        std::fs::write(&cedar_path, cedar_text)
            .map_err(|e| RunError::Internal(format!("write {}: {e}", cedar_path.display())))?;

        std::fs::write(&revocation_path, b"")
            .map_err(|e| RunError::Internal(format!("write {}: {e}", revocation_path.display())))?;

        let key_status = std::process::Command::new(&req.firma_exe)
            .args(["authority", "generate-key", "--output"])
            .arg(&key_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| RunError::AuthorityStartupFailed {
                reason: format!("spawn firma authority generate-key: {e}"),
                log_path: log_path.clone(),
            })?;
        if !key_status.success() {
            return Err(RunError::AuthorityStartupFailed {
                reason: format!("generate-key exited with status {key_status}"),
                log_path,
            });
        }

        let mut capture: Option<ReadyCapture> = None;
        let mut child: Option<Child> = None;
        let mut pid: u32 = 0;
        let mut tee_handle: Option<JoinHandle<()>> = None;
        let mut last_error: Option<RunError> = None;
        for attempt in 0..MAX_BIND_ATTEMPTS {
            let listen_addr = select_loopback_v6_port()?;
            let authority_cfg = format!(
                "[authority]\n\
                 listen_addr = \"{listen_addr}\"\n\
                 policy_dir = \"{policy}\"\n\
                 issuance_policy_dir = \"{policy}\"\n\
                 revocation_file = \"{rev}\"\n\
                 max_ttl_seconds = 3600\n\
                 key_file = \"{key}\"\n\
                 log_level = \"info\"\n\
                 bundle_ttl_seconds = 30\n",
                policy = policy_dir.display(),
                rev = revocation_path.display(),
                key = key_path.display(),
            );
            std::fs::write(&authority_toml, authority_cfg).map_err(|e| {
                RunError::Internal(format!("write {}: {e}", authority_toml.display()))
            })?;

            let mut try_child = std::process::Command::new(&req.firma_exe)
                .args(["authority", "--config"])
                .arg(&authority_toml)
                .env_remove("FIRMA_LOG_FILE")
                .env("NO_COLOR", "1")
                .env("CLICOLOR", "0")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| RunError::AuthorityStartupFailed {
                    reason: format!("spawn firma authority: {e}"),
                    log_path: log_path.clone(),
                })?;
            let try_pid = try_child.id();
            let stderr =
                try_child
                    .stderr
                    .take()
                    .ok_or_else(|| RunError::AuthorityStartupFailed {
                        reason: "stderr pipe missing".into(),
                        log_path: log_path.clone(),
                    })?;
            let log_file =
                std::fs::File::create(&log_path).map_err(|e| RunError::AuthorityStartupFailed {
                    reason: format!("create log {}: {e}", log_path.display()),
                    log_path: log_path.clone(),
                })?;
            let reader = std::io::BufReader::new(stderr);
            let (tx, rx) = mpsc::sync_channel::<ScrapeResult>(1);
            let try_tee_handle = thread::Builder::new()
                .name("firma-authority-tee".into())
                .spawn(move || run_scraper(reader, log_file, tx))
                .map_err(|e| RunError::AuthorityStartupFailed {
                    reason: format!("spawn scraper thread: {e}"),
                    log_path: log_path.clone(),
                })?;

            match rx.recv_timeout(req.startup_timeout) {
                Ok(ScrapeResult::Ready(c)) => {
                    capture = Some(c);
                    child = Some(try_child);
                    pid = try_pid;
                    tee_handle = Some(try_tee_handle);
                    break;
                }
                Ok(ScrapeResult::Eof) => {
                    let _ = try_child.wait();
                    let _ = try_tee_handle.join();
                    last_error = Some(RunError::AuthorityStartupFailed {
                        reason: "authority stderr closed before 'ready'".into(),
                        log_path: log_path.clone(),
                    });
                }
                Ok(ScrapeResult::Error(reason)) => {
                    let _ = try_child.kill();
                    let _ = try_child.wait();
                    let _ = try_tee_handle.join();
                    last_error = Some(RunError::AuthorityStartupFailed {
                        reason,
                        log_path: log_path.clone(),
                    });
                }
                Err(_) => {
                    let _ = try_child.kill();
                    let _ = try_child.wait();
                    let _ = try_tee_handle.join();
                    last_error = Some(RunError::AuthorityReadyTimeout {
                        timeout_secs: req.startup_timeout.as_secs(),
                        log_path: log_path.clone(),
                    });
                }
            }
            if attempt + 1 < MAX_BIND_ATTEMPTS {
                thread::sleep(Duration::from_millis(120));
            }
        }
        let capture = capture.ok_or_else(|| {
            last_error.unwrap_or_else(|| RunError::AuthorityStartupFailed {
                reason: "authority autostart failed".into(),
                log_path: log_path.clone(),
            })
        })?;
        let child = child.ok_or_else(|| RunError::AuthorityStartupFailed {
            reason: "authority child missing after startup".into(),
            log_path: log_path.clone(),
        })?;
        let tee_handle = tee_handle.ok_or_else(|| RunError::AuthorityStartupFailed {
            reason: "authority tee thread missing after startup".into(),
            log_path: log_path.clone(),
        })?;

        firma_stack::pidfile::write(&pid_path, pid)
            .map_err(|e| RunError::Internal(format!("write authority.pid: {e}")))?;
        crate::authority::metadata::write(
            &metadata_path,
            &crate::authority::metadata::Metadata {
                sandbox_id: req.sandbox_id.to_string(),
                agent_id: req.agent_id.to_string(),
                session_id: req.session_id.to_string(),
                profile: req.profile_name.to_string(),
                listen_addr: capture.listen_addr.clone(),
                pid,
                started_at: chrono::Utc::now().to_rfc3339(),
            },
        )?;

        tracing::info!(
            sandbox_id = req.sandbox_id,
            pid,
            listen_addr = %capture.listen_addr,
            "autostarted authority ready"
        );

        Ok(Self {
            listen_addr: capture.listen_addr,
            marker_dir: req.marker_dir,
            pid,
            child: Some(child),
            tee_handle: Some(tee_handle),
        })
    }

    /// The URL the spawned Authority is reachable at.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.listen_addr)
    }

    #[doc(hidden)]
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[doc(hidden)]
    #[must_use]
    pub fn marker_dir(&self) -> &Path {
        &self.marker_dir
    }
}

impl Drop for AuthoritySupervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            debug!(pid = self.pid, "stopping autostarted authority");
            send_sigterm(self.pid);
            let deadline = Instant::now() + STOP_GRACE;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() >= deadline => {
                        warn!(pid = self.pid, "authority SIGKILL after grace");
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(100)),
                    Err(e) => {
                        warn!(error = %e, "authority wait failed");
                        let _ = child.kill();
                        break;
                    }
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

#[cfg(unix)]
fn send_sigterm(pid: u32) {
    let Ok(raw) = i32::try_from(pid) else {
        warn!(pid, "pid does not fit in i32; skipping SIGTERM");
        return;
    };
    let target = nix::unistd::Pid::from_raw(raw);
    if let Err(e) = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGTERM) {
        warn!(error = %e, pid, "SIGTERM to authority failed");
    }
}

#[cfg(unix)]
fn select_loopback_v6_port() -> Result<SocketAddr, RunError> {
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));
    let listener =
        TcpListener::bind(addr).map_err(|e| RunError::Internal(format!("bind [::1]:0: {e}")))?;
    let selected = listener
        .local_addr()
        .map_err(|e| RunError::Internal(format!("read local addr for authority port: {e}")))?;
    Ok(selected)
}

#[cfg(not(unix))]
fn send_sigterm(_pid: u32) {}

const LISTENING_TOKEN: &str = "listening";

#[doc(hidden)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "tx is moved into the spawned thread"
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
    let trimmed = line.trim_end();
    trimmed.ends_with(": ready") || trimmed == "ready"
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
