//! Per-run autostarted Mini Authority: spawn, scrape `ready`, tee logs,
//! kill on Drop. Mirrors `firma-run/src/sidecar/supervisor.rs` (FIR-102).

use std::io::{BufRead, Write};
#[cfg(unix)]
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

#[cfg(unix)]
use firma_authority::{AuthorityConfig, AuthorityTlsConfig};
use tracing::{info, warn};
use wait_timeout::ChildExt;

use crate::error::RunError;
use crate::identity::SandboxId;
use firma_runtime_state::UserProcessId;

/// Per-spec default ready-line wait. CLI flag overrides.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 10;

/// Grace period between `SIGTERM` and `SIGKILL` in [`Drop`].
const STOP_GRACE: Duration = Duration::from_secs(5);
#[cfg(unix)]
const MAX_BIND_ATTEMPTS: usize = 8;
#[cfg(unix)]
const AUTOSTART_LOCAL_DEVELOPER_POLICY: &str = r"// Local autostart profile for `firma run`.
//
// Governs token *issuance* only. Runtime enforcement is handled by the
// sidecar's Cedar policy bundle (dev.cedar). All registered action classes
// are permitted here so the sidecar can classify and enforce without the
// Authority becoming the bottleneck for local dev.
permit(principal, action, resource);
";

/// Inputs to [`AuthoritySupervisor::spawn`].
#[doc(hidden)]
#[derive(Debug)]
pub struct SpawnRequest<'a> {
    pub sandbox_id: &'a SandboxId,
    pub agent_id: &'a str,
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
        reason = "single linear spawn-then-scrape sequence reads more clearly inline"
    )]
    pub fn spawn(req: SpawnRequest<'_>) -> Result<Self, RunError> {
        use firma_runtime_state::ChildExt as _;

        firma_authority::cedar_for(req.profile_name).map_err(|_| {
            RunError::AuthorityUnknownProfile {
                name: req.profile_name.to_string(),
            }
        })?;

        firma_runtime_state::fs::create_private_dir_all(&req.marker_dir)
            .map_err(|e| RunError::Internal(e.to_string()))?;

        let authority_toml = req.marker_dir.join("authority.toml");
        let log_path = req.marker_dir.join("authority.log");
        let pid_path = req.marker_dir.join("authority.pid");
        let metadata_path = req.marker_dir.join("metadata.toml");

        // Resolve the key, policy dirs, and revocation file to use.
        //
        // Persisted path: `user_config_path` is set — use the key and policy
        // dirs from the user's `[authority]` config so tokens survive authority
        // restarts and the real Cedar posture is enforced. The key is generated
        // on demand if the configured path has none yet.
        //
        // Ephemeral path: no user config — generate a fresh key and write a
        // permissive issuance policy into a per-run temp dir.
        let mut authority_config = if let Some(ref user_config) = req.user_config_path {
            persisted_authority_config(user_config)?
        } else {
            ephemeral_authority_config(&req, &log_path)?
        };

        let supervisor_pub_key_path = authority_config.key_file.with_extension("pub");

        let mut capture: Option<ReadyCapture> = None;
        let mut child: Option<Child> = None;
        let mut pid: Option<UserProcessId> = None;
        let mut tee_handle: Option<JoinHandle<()>> = None;
        let mut last_error: Option<RunError> = None;
        for attempt in 0..MAX_BIND_ATTEMPTS {
            let inner = toml::to_string_pretty(&authority_config).map_err(|err| {
                RunError::Internal(format!("invalid synthetic authority config: {err}"))
            })?;
            let authority_conf_str = format!("[authority]\n{inner}");
            std::fs::write(&authority_toml, &authority_conf_str).map_err(|e| {
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
            let try_pid = try_child.process_id();
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
            let mirror_child_logs = child_log_mirroring_enabled();
            let try_tee_handle = std::thread::Builder::new()
                .name("firma-authority-tee".into())
                .spawn(move || {
                    run_scraper_with_mirror(
                        reader,
                        log_file,
                        std::io::stderr(),
                        mirror_child_logs,
                        tx,
                    );
                })
                .map_err(|e| RunError::AuthorityStartupFailed {
                    reason: format!("spawn scraper thread: {e}"),
                    log_path: log_path.clone(),
                })?;

            match rx.recv_timeout(req.startup_timeout) {
                Ok(ScrapeResult::Ready(c)) => {
                    capture = Some(c);
                    child = Some(try_child);
                    pid = Some(try_pid);
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
                std::thread::sleep(Duration::from_millis(120));
            }
            let listen_addr = select_loopback_v6_port()?;
            authority_config.listen_addr = listen_addr.to_string();
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
        let pid = pid.ok_or_else(|| RunError::AuthorityStartupFailed {
            reason: "authority pid missing after startup".into(),
            log_path: log_path.clone(),
        })?;

        firma_runtime_state::pidfile::write(&pid_path, pid)
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

        info!(
            sandbox_id = req.sandbox_id.compact(),
            pid = %pid,
            listen_addr = %capture.listen_addr,
            "authority started"
        );

        Ok(Self {
            listen_addr: capture.listen_addr,
            marker_dir: req.marker_dir,
            pub_key_path: supervisor_pub_key_path,
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
    pub fn pub_key_path(&self) -> PathBuf {
        self.pub_key_path.clone()
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

/// Resolve key, policy, and revocation paths from the user's `firma.toml`.
///
/// Called when `user_config_path` is set. `firma config` has already generated
/// the key and populated the policy dirs, so the persisted key and policies are
/// reused — tokens survive authority restarts and the real Cedar posture is
/// enforced. The authority is spawned with an ephemeral port + no TLS
/// (plaintext loopback).
#[cfg(unix)]
fn persisted_authority_config(user_config: &std::path::Path) -> Result<AuthorityConfig, RunError> {
    let config_dir = user_config
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();

    let body = firma_config_loader::load_section(user_config, "authority").map_err(|e| {
        RunError::Internal(format!(
            "load [authority] from {}: {e}",
            user_config.display()
        ))
    })?;

    let mut cfg = toml::from_str::<firma_authority::AuthorityConfig>(&body)
        .map_err(|e| RunError::Internal(format!("parse authority config: {e}")))?;
    cfg.rebase_defaults(&config_dir);

    // Per-run authority always runs plaintext on loopback — strip any TLS and
    // override any configured listen_addr with an ephemeral loopback port.
    // Honoring the user's listen_addr could bind wide (e.g. 0.0.0.0) with no
    // TLS, or collide with another run on a fixed port.
    cfg.tls = firma_authority::AuthorityTlsConfig::default();
    cfg.listen_addr = select_loopback_v6_port()?.to_string();

    // Regenerate the signing key on demand when the configured path has none.
    // `firma config` writes the key once, but the configured `key_file` often
    // lives in a volatile location (e.g. `$XDG_RUNTIME_DIR`, a tmpfs cleared on
    // logout): the persisted config keeps pointing at it after a reboot even
    // though the file is gone. Without this, the spawned authority fails closed
    // with "failed to read key file … No such file or directory".
    ensure_authority_key(&cfg.key_file)?;

    Ok(cfg)
}

/// Ensure an Ed25519 authority keypair exists at `key_path`, generating one
/// only when the secret is missing. Idempotent: an existing key is preserved so
/// issued tokens survive authority restarts. Unlike [`generate_authority_key`],
/// this tolerates — and reuses — a pre-existing key.
#[cfg(unix)]
fn ensure_authority_key(key_path: &std::path::Path) -> Result<(), RunError> {
    if key_path.is_file() {
        return Ok(());
    }
    if let Some(parent) = key_path.parent() {
        firma_runtime_state::fs::create_private_dir_all(parent)
            .map_err(|e| RunError::Internal(e.to_string()))?;
    }
    firma_authority::write_keypair(key_path).map_err(|e| {
        RunError::Internal(format!(
            "generate authority key at {}: {e}",
            key_path.display()
        ))
    })?;
    Ok(())
}

/// Generate an Ed25519 authority keypair at `key_path` and its `.pub` sibling.
///
/// Calls [`firma_authority::write_keypair`] in-process so the on-disk key
/// format stays identical to `firma authority generate-key`. Fails if a key is
/// already present — callers that may race a concurrent writer should use
/// [`ensure_authority_key`] instead.
#[cfg(unix)]
fn generate_authority_key(
    key_path: &std::path::Path,
    log_path: &std::path::Path,
) -> Result<(), RunError> {
    firma_authority::write_keypair(key_path).map_err(|e| RunError::AuthorityStartupFailed {
        reason: format!("generate authority key: {e}"),
        log_path: log_path.to_path_buf(),
    })?;
    Ok(())
}

/// Set up ephemeral key, policy dir, and revocation file in `marker_dir`.
///
/// Called when no `user_config_path` is set. Generates a fresh signing key
/// and writes a permissive issuance Cedar policy so any action class can be
/// granted during local development.
#[cfg(unix)]
fn ephemeral_authority_config(
    req: &SpawnRequest<'_>,
    log_path: &std::path::Path,
) -> Result<AuthorityConfig, RunError> {
    let policy_dir = req.marker_dir.join("policy_dir");
    let keys_dir = req.marker_dir.join("keys");
    let cedar_path = policy_dir.join(format!("{}.cedar", req.profile_name));
    let key_path = keys_dir.join("authority.key");
    let revocation_file = req.marker_dir.join("revocations.txt");

    firma_runtime_state::fs::create_private_dir_all(&policy_dir)
        .map_err(|e| RunError::Internal(e.to_string()))?;
    firma_runtime_state::fs::create_private_dir_all(&keys_dir)
        .map_err(|e| RunError::Internal(e.to_string()))?;

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

    std::fs::write(&revocation_file, b"")
        .map_err(|e| RunError::Internal(format!("write {}: {e}", revocation_file.display())))?;

    generate_authority_key(&key_path, log_path)?;

    Ok(AuthorityConfig {
        listen_addr: select_loopback_v6_port()?.to_string(),
        policy_dir: policy_dir.clone(),
        issuance_policy_dir: policy_dir,
        schema_path: None,
        revocation_file,
        max_ttl_seconds: 3600,
        key_file: key_path,
        log_level: "info".to_string(),
        bundle_ttl_seconds: 30,
        tls: AuthorityTlsConfig::default(),
    })
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

const LISTENING_TOKEN: &str = "listening";

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
    reason = "tx is moved into the spawned thread"
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
    pub use super::{ReadyCapture, ScrapeResult, run_scraper, run_scraper_with_mirror};
}

#[cfg(all(test, unix))]
mod persisted_key_tests {
    use super::persisted_authority_config;

    /// The configured `key_file` path is resolved and left untouched.
    #[test]
    fn resolves_configured_key_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("authority.key");
        fs_err::write(&key, b"existing").expect("write key");
        let config = dir.path().join("firma.toml");
        fs_err::write(
            &config,
            format!(
                "[authority]\nlisten_addr = \"[::1]:0\"\nkey_file = \"{}\"\n",
                key.display()
            ),
        )
        .expect("write firma.toml");

        let cfg = persisted_authority_config(&config).expect("resolve persisted");

        assert_eq!(cfg.key_file, key);
        assert_eq!(fs_err::read(&cfg.key_file).expect("read key"), b"existing");
    }

    /// A configured `key_file` that no longer exists (e.g. its `$XDG_RUNTIME_DIR`
    /// tmpfs was wiped on reboot) is regenerated on demand rather than failing
    /// closed at authority startup. Regression test for #174.
    #[test]
    fn regenerates_missing_key_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Point at a key inside a not-yet-created subdir to also cover parent
        // directory creation, mirroring a wiped runtime dir.
        let key = dir.path().join("wiped-runtime").join("authority.key");
        let config = dir.path().join("firma.toml");
        fs_err::write(
            &config,
            format!(
                "[authority]\nlisten_addr = \"[::1]:0\"\nkey_file = \"{}\"\n",
                key.display()
            ),
        )
        .expect("write firma.toml");

        assert!(!key.exists(), "precondition: key absent");

        let cfg = persisted_authority_config(&config).expect("resolve persisted");

        assert_eq!(cfg.key_file, key);
        assert!(cfg.key_file.is_file(), "secret key generated on demand");
        assert!(
            cfg.key_file.with_extension("pub").is_file(),
            "public key generated alongside the secret"
        );
    }
}
