//! Persistence and observation of per-run sidecar markers.

use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io::{ErrorKind, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::process_id::UserProcessId;
use crate::runtime_paths::{RunEntryLayout, RuntimeLayout};
use firma_identifiers::SandboxId;

/// Connect timeout for the TCP liveness probe of an `http_proxy` interceptor.
const TCP_PROBE_TIMEOUT: Duration = Duration::from_millis(200);

/// On-disk schema of `<runtime>/run/<sandbox_id>/metadata.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetadataFile {
    /// Sandbox identifier for this run.
    pub sandbox_id: SandboxId,
    /// Agent identifier for this run.
    pub agent_id: String,
    /// Session identifier for this run.
    pub session_id: String,
    /// URL of the authority that issued the capability tokens for this run.
    pub authority_url: String,
    /// Policy bundle version digest string, as written by firma-run at startup.
    pub policy_bundle_version: String,
    /// PID of the sidecar process.
    pub pid: UserProcessId,
    /// RFC 3339 UTC timestamp of when the sidecar process started.
    pub started_at: String,
    /// Interceptor listen endpoint to health-probe: a `host:port` pair for an
    /// `http_proxy` interceptor, or a filesystem path for a Unix-domain-socket
    /// interceptor. Empty (the `serde` default) for legacy markers written
    /// before FIR-195, in which case the probe falls back to
    /// `<marker_dir>/sidecar.sock`.
    #[serde(default)]
    pub listen: String,
}

/// Observed state of one persisted per-run sidecar marker.
#[derive(Debug, Clone, Serialize)]
pub struct SidecarEntry {
    /// Sandbox identifier for this run.
    pub sandbox_id: String,
    /// Agent identifier for this run.
    pub agent_id: String,
    /// Session identifier for this run.
    pub session_id: String,
    /// URL of the authority that issued the capability tokens for this run.
    pub authority_url: String,
    /// Policy bundle version digest string.
    pub policy_bundle_version: String,
    /// PID of the sidecar process, when known.
    pub pid: Option<UserProcessId>,
    /// RFC 3339 UTC timestamp of when the sidecar process started.
    pub started_at: String,
    /// Coarse-grained liveness state derived from pid + socket probes.
    pub state: crate::status::State,
    /// Interceptor listen endpoint: a TCP `host:port` value or Unix-domain socket path.
    pub listen: PathBuf,
    /// Seconds since `sidecar.pid` was written in the marker directory, used as a proxy for sidecar start time. `None` if the file is absent or its mtime is in the future.
    pub uptime_secs: Option<u64>,
}

/// Atomically publish a sidecar's PID and metadata in `marker_dir`.
///
/// The PID file is written first and `metadata.toml` acts as the publication
/// point. Readers therefore never observe metadata before its associated PID
/// file exists. Both files are flushed and renamed from temporary files in the
/// marker directory.
///
/// # Errors
///
/// Returns serialization or filesystem errors. A failure may leave a PID file
/// without metadata, which readers treat as an incomplete marker.
pub fn publish(marker_dir: &Path, metadata: &MetadataFile) -> crate::error::Result<()> {
    fs::create_dir_all(marker_dir)?;
    let layout = RunEntryLayout::from_root(marker_dir);
    crate::pidfile::write(&layout.sidecar_pid(), metadata.pid)?;

    let text = toml::to_string_pretty(metadata)?;
    let mut temp = tempfile::NamedTempFile::new_in(marker_dir)?;
    temp.write_all(text.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist(layout.sidecar_metadata())
        .map_err(|error| error.error)?;
    #[cfg(unix)]
    File::open(marker_dir)?.sync_all()?;
    Ok(())
}

/// UDS reachability: a successful `connect` means the sidecar is
/// accepting connections. Deterministic, no protocol handshake.
#[cfg(unix)]
fn socket_responds(sock: &Path) -> bool {
    use std::os::unix::net::UnixStream;
    UnixStream::connect(sock).is_ok()
}

#[cfg(not(unix))]
fn socket_responds(_sock: &Path) -> bool {
    false
}

/// Reachability probe for a per-run sidecar's interceptor endpoint.
fn endpoint_responds(listen_str: &str, listen_path: &Path) -> bool {
    listen_str.parse::<SocketAddr>().map_or_else(
        |_| socket_responds(listen_path),
        |addr| TcpStream::connect_timeout(&addr, TCP_PROBE_TIMEOUT).is_ok(),
    )
}

fn marker_uptime_secs(marker_dir: &Path) -> Option<u64> {
    let mtime = fs::metadata(RunEntryLayout::from_root(marker_dir).sidecar_pid())
        .and_then(|m| m.modified())
        .ok()?;
    SystemTime::now()
        .duration_since(mtime)
        .ok()
        .map(|d| d.as_secs())
}

/// Returns `true` only when the marker's metadata parses and its recorded pid
/// is no longer alive. An unreadable or unparseable marker is treated as NOT
/// stale: we never delete a directory we cannot understand, since it may belong
/// to a live sidecar (deleting it would orphan its socket).
fn is_stale(marker_dir: &Path) -> bool {
    match read(marker_dir) {
        Ok(meta) => matches!(meta.pid.process_exists(), Ok(false)),
        Err(_) => false,
    }
}

/// Remove every stale marker dir under `<runtime>/run`. Returns the
/// sandbox ids removed, sorted. Missing `run/` is not an error.
///
/// # Errors
///
/// Returns [`crate::error::RuntimeStateError::Io`] if the `run/` dir exists but
/// cannot be enumerated.
pub fn gc_stale(runtime_dir: &Path) -> crate::error::Result<Vec<String>> {
    use crate::error::RuntimeStateError;

    let run_dir = RuntimeLayout::from_root(runtime_dir).run_dir();
    let read = match fs::read_dir(&run_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RuntimeStateError::Io(e)),
    };
    let mut removed = Vec::new();
    for entry in read {
        let entry = entry.map_err(RuntimeStateError::Io)?;
        let path = entry.path();
        if path.is_dir()
            && is_stale(&path)
            && fs::remove_dir_all(&path).is_ok()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            removed.push(name.to_string());
        }
    }
    removed.sort();
    Ok(removed)
}

/// List all readable per-run sidecars under `<runtime>/run`, sorted by
/// `sandbox_id`.
///
/// Corrupt or transiently-missing markers (race away between readdir and
/// open, or with an unparseable `metadata.toml`) are skipped so that one
/// bad marker does not break the full listing. Use [`get`] when you need
/// an error surfaced for a specific sandbox id. This operation is
/// observational; callers that want to delete stale markers must invoke
/// [`gc_stale`] explicitly.
///
/// # Errors
///
/// Returns [`crate::error::RuntimeStateError::Io`] if `run/` exists but cannot be
/// enumerated, or any I/O error other than `NotFound` from [`probe_entry`].
pub fn list(runtime_dir: &Path) -> crate::error::Result<Vec<SidecarEntry>> {
    use crate::error::RuntimeStateError;

    let run_dir = RuntimeLayout::from_root(runtime_dir).run_dir();
    let read = match fs::read_dir(&run_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RuntimeStateError::Io(e)),
    };
    let mut entries = Vec::new();
    for dir_entry in read {
        let dir_entry = dir_entry.map_err(RuntimeStateError::Io)?;
        let path = dir_entry.path();
        if !path.is_dir() {
            continue;
        }
        match probe_entry(&path) {
            Ok(entry) => entries.push(entry),
            Err(
                RuntimeStateError::MarkerParse { .. }
                | RuntimeStateError::MarkerIdentityMismatch { .. },
            ) => {}
            Err(RuntimeStateError::Io(e)) if e.kind() == ErrorKind::NotFound => {}
            Err(other) => return Err(other),
        }
    }
    entries.sort_by(|a, b| a.sandbox_id.cmp(&b.sandbox_id));
    Ok(entries)
}

/// Probe a single sidecar by `sandbox_id`. Returns `Ok(None)` when no such
/// marker dir exists.
///
/// # Errors
///
/// Returns a parse or I/O error from [`probe_entry`] when the marker exists
/// but is malformed.
pub fn get(
    runtime_dir: &Path,
    sandbox_id: &SandboxId,
) -> crate::error::Result<Option<SidecarEntry>> {
    let marker_dir = RuntimeLayout::from_root(runtime_dir)
        .run_entry_layout(sandbox_id)
        .into_root();
    if !marker_dir.is_dir() {
        return Ok(None);
    }
    Ok(Some(probe_entry(&marker_dir)?))
}

/// Read + probe a single marker directory.
///
/// This is the lower-level single-marker primitive used by [`list`] and
/// [`get`]. It is `pub` for module-level integration tests but is not
/// re-exported at the crate root.
///
/// # Errors
///
/// Returns [`crate::error::RuntimeStateError::Io`] when `metadata.toml` cannot be
/// read and [`crate::error::RuntimeStateError::MarkerParse`] on parse failure
/// (fail-closed: an unreadable marker is surfaced, never silently treated as
/// healthy).
pub fn probe_entry(marker_dir: &Path) -> crate::error::Result<SidecarEntry> {
    use crate::status::State;

    let meta = read(marker_dir)?;

    // Legacy markers (pre-FIR-195) record no `listen`; fall back to the
    // conventional UDS path so their probe behavior is unchanged.
    let listen = if meta.listen.is_empty() {
        RunEntryLayout::from_root(marker_dir).sidecar_socket()
    } else {
        PathBuf::from(&meta.listen)
    };
    let state = match meta.pid.process_exists() {
        Ok(false) => State::Stopped,
        Ok(true) if endpoint_responds(&meta.listen, &listen) => State::Running,
        Ok(true) => State::Unhealthy,
        Err(_) => State::Unknown,
    };

    Ok(SidecarEntry {
        sandbox_id: meta.sandbox_id.to_string(),
        agent_id: meta.agent_id,
        session_id: meta.session_id,
        authority_url: meta.authority_url,
        policy_bundle_version: meta.policy_bundle_version,
        pid: Some(meta.pid),
        started_at: meta.started_at,
        state,
        listen,
        uptime_secs: marker_uptime_secs(marker_dir),
    })
}

/// Read and validate `metadata.toml` from one marker directory.
///
/// # Errors
///
/// Returns an I/O or parse error, or an identity-mismatch error when the
/// metadata's sandbox ID differs from the marker directory name.
pub fn read(marker_dir: &Path) -> crate::error::Result<MetadataFile> {
    use crate::error::RuntimeStateError;

    let meta_path = RunEntryLayout::from_root(marker_dir).sidecar_metadata();
    let text = fs::read_to_string(&meta_path)?;
    let meta: MetadataFile =
        toml::from_str(&text).map_err(|source| RuntimeStateError::MarkerParse {
            path: meta_path,
            source: Box::new(source),
        })?;
    let directory = marker_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if directory != meta.sandbox_id.to_string() {
        return Err(RuntimeStateError::MarkerIdentityMismatch {
            path: marker_dir.to_path_buf(),
            directory: directory.to_string(),
            metadata: meta.sandbox_id.to_string(),
        });
    }
    Ok(meta)
}
