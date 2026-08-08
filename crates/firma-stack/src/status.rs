//! Observational stack status from runtime state and bounded probes.
//!
//! [`probe`] classifies a component as [`State::Running`] only when its
//! persisted [`TerminationTarget`] is live and its recorded TCP endpoint
//! accepts a connection. A live target without a reachable endpoint is
//! [`State::Unhealthy`]; missing or stale target state is [`State::Stopped`].
//! Listen-address and uptime metadata are best-effort and never grant lifecycle
//! authority.

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub use firma_runtime_state::State;
use firma_runtime_state::UserProcessId;
use serde::Serialize;
use tracing::{debug, trace};

use crate::error::Result;
use crate::platform::TerminationTarget;
use firma_runtime_state::pidfile;

/// Snapshot of one component's runtime state.
#[derive(Debug, Clone, Serialize)]
pub struct ComponentStatus {
    /// Logical component name (`authority` / `sidecar`).
    pub name: String,
    /// PID read from `<state_dir>/<name>.pid`, when present.
    pub pid: Option<UserProcessId>,
    /// Coarse-grained state. See [`State`].
    pub state: State,
    /// Listen address read from `<state_dir>/<name>.listen` (written at spawn
    /// time), if the file exists and parses as a [`SocketAddr`].
    pub listen: Option<SocketAddr>,
    /// Seconds since the pidfile was written, used as a proxy for process
    /// uptime. Absent when the pidfile is missing or its mtime is in the future
    /// relative to system time.
    pub uptime_secs: Option<u64>,
}

/// Aggregate stack snapshot returned by [`status`].
#[derive(Debug, Clone, Serialize)]
pub struct StackStatus {
    /// One entry per known component (authority first, then sidecar).
    pub components: Vec<ComponentStatus>,
}

/// Return current stack status.
///
/// # Errors
///
/// Returns errors propagated by [`probe`].
pub fn status(state_dir: &Path) -> Result<StackStatus> {
    status_components(state_dir, crate::plan::component_names())
}

/// Probe each named component in order without acquiring process ownership.
///
/// The component names are firma-specific data supplied by the caller; this
/// loop is agnostic to which components the stack contains.
///
/// # Errors
///
/// Returns errors propagated by [`probe`].
fn status_components(state_dir: &Path, names: &[&str]) -> Result<StackStatus> {
    debug!(state_dir = %state_dir.display(), "probing stack status");
    let components = names
        .iter()
        .map(|name| probe(state_dir, name))
        .collect::<Result<Vec<_>>>()?;
    for component in &components {
        trace!(
            name = %component.name,
            pid = ?component.pid,
            state = ?component.state,
            "component probe result"
        );
    }
    Ok(StackStatus { components })
}

/// Classify one component without acquiring process ownership.
///
/// Failures from [`pidfile::read`] and [`TerminationTarget::exists`] are
/// returned because malformed lifecycle evidence or unknown liveness cannot
/// safely be classified as [`State::Stopped`]. A missing pidfile remains
/// legitimate absence. Endpoint and timestamp failures degrade only their
/// corresponding metadata.
fn probe(state_dir: &Path, name: &str) -> Result<ComponentStatus> {
    let pidfile_path: PathBuf = state_dir.join(format!("{name}.pid"));
    let pid = pidfile::read(&pidfile_path)?;
    let Some(pid) = pid else {
        return Ok(ComponentStatus {
            name: name.into(),
            pid: None,
            state: State::Stopped,
            listen: None,
            uptime_secs: None,
        });
    };

    if !TerminationTarget::from_stored_id(pid).exists()? {
        return Ok(ComponentStatus {
            name: name.into(),
            pid: Some(pid),
            state: State::Stopped,
            listen: None,
            uptime_secs: pidfile_uptime(&pidfile_path),
        });
    }

    let listen = listen_addr_for(state_dir, name);
    let port_open = listen
        .as_ref()
        .is_some_and(|addr| TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok());
    Ok(ComponentStatus {
        name: name.into(),
        pid: Some(pid),
        state: if port_open {
            State::Running
        } else {
            State::Unhealthy
        },
        listen,
        uptime_secs: pidfile_uptime(&pidfile_path),
    })
}

/// Read the recorded endpoint as optional status metadata.
fn listen_addr_for(state_dir: &Path, name: &str) -> Option<SocketAddr> {
    let text = std::fs::read_to_string(state_dir.join(format!("{name}.listen"))).ok()?;
    text.trim().parse().ok()
}

/// Approximate uptime from pidfile age rather than process creation time.
fn pidfile_uptime(path: &Path) -> Option<u64> {
    let mtime = pidfile::mtime(path).ok().flatten()?;
    SystemTime::now()
        .duration_since(mtime)
        .ok()
        .map(|duration| duration.as_secs())
}
