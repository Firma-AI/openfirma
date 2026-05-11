//! Tear down a running stack.

use std::path::Path;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::error::Result;
use crate::pidfile;
use crate::platform::{Platform, SystemPlatform};

/// Result of a [`stop`] call.
#[derive(Debug, Clone)]
pub struct StopOutcome {
    /// `true` if at least one component required a hard kill
    /// (`SIGKILL` / `TerminateProcess`) because the soft-signal grace
    /// window expired; `false` when every child exited cleanly within the
    /// configured timeout.
    pub forced: bool,
}

/// Stop a running stack.
///
/// # Errors
///
/// Returns pidfile or cleanup errors.
pub fn stop(state_dir: &Path, timeout: Duration) -> Result<StopOutcome> {
    info!(state_dir = %state_dir.display(), timeout_secs = timeout.as_secs(), "stopping firma stack");
    let stack_pid = pidfile::read(&state_dir.join("stack.pid"))?;
    let authority_pid = pidfile::read(&state_dir.join("authority.pid"))?;
    let sidecar_pid = pidfile::read(&state_dir.join("sidecar.pid"))?;
    debug!(?stack_pid, ?authority_pid, ?sidecar_pid, "loaded pidfiles");

    // Signal everything we know about. Sidecar first so that its outbound
    // gRPC streams to the authority close cleanly; that lets the authority's
    // tonic graceful shutdown finish instead of blocking on long-lived
    // server-streaming RPCs.
    for pid in [sidecar_pid, stack_pid, authority_pid]
        .into_iter()
        .flatten()
    {
        if SystemPlatform::is_alive(pid) {
            debug!(pid, "sending soft signal");
            if let Err(e) = SystemPlatform::signal_soft(pid) {
                // Not fatal: hard-kill will still run after the grace window.
                // Common when a child crashed before installing its shutdown
                // listener; log so the failure isn't silent.
                debug!(pid, error = %e, "soft signal failed");
            }
        }
    }

    // Wait the whole timeout for them to exit on their own.
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let authority_dead = authority_pid.is_none_or(|pid| !SystemPlatform::is_alive(pid));
        let sidecar_dead = sidecar_pid.is_none_or(|pid| !SystemPlatform::is_alive(pid));
        if authority_dead && sidecar_dead {
            info!("all children exited cleanly");
            cleanup(state_dir)?;
            return Ok(StopOutcome { forced: false });
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Hard-kill survivors. This is the expected path for components that
    // hang in their own graceful-shutdown logic; not an error.
    let mut forced = false;
    for pid in [stack_pid, authority_pid, sidecar_pid]
        .into_iter()
        .flatten()
    {
        if SystemPlatform::is_alive(pid) {
            info!(pid, "soft-signal grace exceeded; hard-killing");
            let _ = SystemPlatform::signal_hard(pid);
            forced = true;
        }
    }
    cleanup(state_dir)?;
    info!(forced, "stop complete");
    Ok(StopOutcome { forced })
}

fn cleanup(state_dir: &Path) -> Result<()> {
    for name in [
        "authority.pid",
        "authority.listen",
        "sidecar.pid",
        "sidecar.listen",
        "stack.pid",
        "stack.lock",
    ] {
        pidfile::remove(&state_dir.join(name))?;
    }
    Ok(())
}
