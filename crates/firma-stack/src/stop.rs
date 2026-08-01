//! Tear down a running stack.

use std::path::Path;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::error::Result;
use crate::platform::TerminationTarget;
use firma_runtime_state::pidfile;

/// Result of a [`stop`] call.
#[derive(Debug, Clone)]
pub struct StopOutcome {
    /// `true` if at least one component still had a platform termination
    /// target after the soft-signal grace window and a hard termination
    /// (`SIGKILL` / `TerminateProcess`) was requested; `false` when every
    /// target disappeared within the configured timeout.
    ///
    /// On Unix, the kernel can report a process group containing only
    /// unreaped zombies as present, resulting in a conservative hard-kill
    /// request even though no process in the group is still executing.
    pub forced: bool,
}

/// Stop a running stack.
///
/// # Errors
///
/// Returns pidfile or cleanup errors.
pub fn stop(state_dir: &Path, timeout: Duration) -> Result<StopOutcome> {
    info!(state_dir = %state_dir.display(), timeout_secs = timeout.as_secs(), "stopping firma stack");
    let stack_target = read_target(state_dir, "stack.pid")?;
    let authority_target = read_target(state_dir, "authority.pid")?;
    let sidecar_target = read_target(state_dir, "sidecar.pid")?;
    debug!(
        ?stack_target,
        ?authority_target,
        ?sidecar_target,
        "loaded termination targets"
    );

    // Signal everything we know about. Sidecar first so that its outbound
    // gRPC streams to the authority close cleanly; that lets the authority's
    // tonic graceful shutdown finish instead of blocking on long-lived
    // server-streaming RPCs.
    for target in [sidecar_target, stack_target, authority_target]
        .into_iter()
        .flatten()
    {
        if target.exists()? {
            debug!(id = %target.stored_id(), "sending soft signal");
            if let Err(e) = target.signal_soft() {
                // Not fatal: hard-kill will still run after the grace window.
                // Common when a child crashed before installing its shutdown
                // listener; log so the failure isn't silent.
                debug!(id = %target.stored_id(), error = %e, "soft signal failed");
            }
        }
    }

    // Wait the whole timeout for them to exit on their own.
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let authority_dead = match authority_target {
            Some(target) => !target.exists()?,
            None => true,
        };
        let sidecar_dead = match sidecar_target {
            Some(target) => !target.exists()?,
            None => true,
        };
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
    for target in [stack_target, authority_target, sidecar_target]
        .into_iter()
        .flatten()
    {
        if target.exists()? {
            info!(id = %target.stored_id(), "soft-signal grace exceeded; hard-killing");
            let _ = target.signal_hard();
            forced = true;
        }
    }
    cleanup(state_dir)?;
    info!(forced, "stop complete");
    Ok(StopOutcome { forced })
}

fn read_target(state_dir: &Path, name: &str) -> Result<Option<TerminationTarget>> {
    Ok(pidfile::read(&state_dir.join(name))?.map(TerminationTarget::from_stored_id))
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
