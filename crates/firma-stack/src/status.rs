//! Stack status: pid liveness, port probe, and uptime.

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub use firma_runtime_state::State;
use firma_runtime_state::UserProcessId;
use serde::Serialize;
use tracing::{debug, trace};

use crate::error::Result;
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
    /// Listen address read from `<state_dir>/<name>.listen` (written at
    /// spawn time), if the file exists and parses as `SocketAddr`.
    pub listen: Option<SocketAddr>,
    /// Seconds since the pidfile was written, used as a proxy for process
    /// uptime. `None` when the pidfile is missing or its mtime is in the
    /// future relative to system time.
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
/// Currently returns no error, but keeps a fallible API for future probes.
pub fn status(state_dir: &Path) -> Result<StackStatus> {
    debug!(state_dir = %state_dir.display(), "probing stack status");
    let components = vec![probe(state_dir, "authority"), probe(state_dir, "sidecar")];
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

fn probe(state_dir: &Path, name: &str) -> ComponentStatus {
    let pidfile_path: PathBuf = state_dir.join(format!("{name}.pid"));
    let pid = pidfile::read(&pidfile_path).ok().flatten();
    let Some(pid) = pid else {
        return ComponentStatus {
            name: name.into(),
            pid: None,
            state: State::Stopped,
            listen: None,
            uptime_secs: None,
        };
    };

    if pid.reap_if_exited() || !pid.process_exists() {
        return ComponentStatus {
            name: name.into(),
            pid: Some(pid),
            state: State::Stopped,
            listen: None,
            uptime_secs: pidfile_uptime(&pidfile_path),
        };
    }

    let listen = listen_addr_for(state_dir, name);
    let port_open = listen
        .as_ref()
        .is_some_and(|addr| TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok());
    ComponentStatus {
        name: name.into(),
        pid: Some(pid),
        state: if port_open {
            State::Running
        } else {
            State::Unhealthy
        },
        listen,
        uptime_secs: pidfile_uptime(&pidfile_path),
    }
}

fn listen_addr_for(state_dir: &Path, name: &str) -> Option<SocketAddr> {
    let text = std::fs::read_to_string(state_dir.join(format!("{name}.listen"))).ok()?;
    text.trim().parse().ok()
}

fn pidfile_uptime(path: &Path) -> Option<u64> {
    let mtime = pidfile::mtime(path).ok().flatten()?;
    SystemTime::now()
        .duration_since(mtime)
        .ok()
        .map(|duration| duration.as_secs())
}
