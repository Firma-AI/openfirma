//! Observational stack status from runtime state and bounded probes.
//!
//! [`probe`] classifies a component as [`State::Running`] only when its
//! persisted [`TerminationTarget`] is live and its recorded endpoint
//! accepts a connection. A live target without a reachable endpoint is
//! [`State::Unhealthy`]; missing or stale target state is [`State::Stopped`].
//! Listen-address and uptime metadata are best-effort and never grant lifecycle
//! authority.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub use firma_runtime_state::State;
use firma_runtime_state::UserProcessId;
use serde::Serialize;
use tracing::{debug, trace};

use crate::error::OrchestratorError;
use crate::platform::TerminationTarget;
use crate::{ComponentEndpoint, StackTopology};
use firma_runtime_state::pidfile;

const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(200);

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
    /// time), if the file exists and parses as a [`ComponentEndpoint`].
    pub listen: Option<ComponentEndpoint>,
    /// Seconds since the pidfile was written, used as a proxy for process
    /// uptime. Absent when the pidfile is missing or its mtime is in the future
    /// relative to system time.
    pub uptime_secs: Option<u64>,
}

/// Aggregate stack snapshot returned by [`status_components`].
#[derive(Debug, Clone, Serialize)]
pub struct StackStatus {
    /// One entry per known component (authority first, then sidecar).
    pub components: Vec<ComponentStatus>,
}

/// Probe each named component in order without acquiring process ownership.
///
/// The component names are caller-supplied data supplied in startup order; this
/// loop is agnostic to which components the stack contains.
///
/// # Errors
///
/// Returns errors propagated by [`probe`].
pub fn status_components(
    state_dir: &Path,
    topology: &StackTopology,
) -> Result<StackStatus, OrchestratorError> {
    debug!(state_dir = %state_dir.display(), "probing stack status");
    let components = topology
        .names()
        .map(|name| probe(state_dir, name))
        .collect::<Result<Vec<_>, OrchestratorError>>()?;
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
fn probe(state_dir: &Path, name: &str) -> Result<ComponentStatus, OrchestratorError> {
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
    let endpoint_open = listen.as_ref().is_some_and(endpoint_is_connectable);
    Ok(ComponentStatus {
        name: name.into(),
        pid: Some(pid),
        state: if endpoint_open {
            State::Running
        } else {
            State::Unhealthy
        },
        listen,
        uptime_secs: pidfile_uptime(&pidfile_path),
    })
}

/// Read the recorded endpoint as optional status metadata.
fn listen_addr_for(state_dir: &Path, name: &str) -> Option<ComponentEndpoint> {
    let mut text = std::fs::read_to_string(state_dir.join(format!("{name}.listen"))).ok()?;
    if !text.ends_with('\n') {
        return None;
    }
    text.pop();
    let endpoint = text.parse::<ComponentEndpoint>().ok()?;
    (endpoint.to_string() == text).then_some(endpoint)
}

fn endpoint_is_connectable(endpoint: &ComponentEndpoint) -> bool {
    match endpoint {
        ComponentEndpoint::Tcp(addr) => {
            std::net::TcpStream::connect_timeout(addr, CONNECT_ATTEMPT_TIMEOUT).is_ok()
        }
        #[cfg(unix)]
        ComponentEndpoint::Unix(path) => crate::unix_connect::connect_with_timeout(
            path.as_path().as_std_path(),
            CONNECT_ATTEMPT_TIMEOUT,
        ),
    }
}

/// Approximate uptime from pidfile age rather than process creation time.
fn pidfile_uptime(path: &Path) -> Option<u64> {
    let mtime = pidfile::mtime(path).ok().flatten()?;
    SystemTime::now()
        .duration_since(mtime)
        .ok()
        .map(|duration| duration.as_secs())
}
