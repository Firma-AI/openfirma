//! Foreground ownership and detached observation loops.
//!
//! Owned supervision uses [`SpawnedComponent`] child handles to detect and
//! collect leader exits. Observed supervision has only persisted
//! [`UserProcessId`] values and can establish liveness but cannot collect those
//! processes. Both loops return when a stop request or either component exit
//! makes coordinated teardown necessary; returning successfully does not itself
//! stop the remaining component. That responsibility stays with their caller.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::Result;
use crate::spawn::SpawnedComponent;
use firma_runtime_state::UserProcessId;

/// Persisted component identities available to a detached observer.
///
/// This value grants no child-collection or process-termination authority.
#[derive(Clone, Copy)]
pub struct ObservedChildren {
    pub authority_pid: UserProcessId,
    pub sidecar_pid: UserProcessId,
}

/// Wait until owned foreground supervision should begin coordinated teardown.
///
/// A direct-child exit is collected through [`SpawnedComponent::child`]. Stop
/// requests and exits both return [`Ok`]; process probing or collection failures
/// are returned while component teardown remains the caller's responsibility.
pub fn block_until_owned_exit(
    authority: &mut SpawnedComponent,
    sidecar: &mut SpawnedComponent,
) -> Result<()> {
    let stop = install_stop_handler();
    debug!(
        authority_pid = %authority.leader_pid,
        sidecar_pid = %sidecar.leader_pid,
        "foreground supervisor watching owned children"
    );

    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Ctrl-C received; caller will tear stack down");
            return Ok(());
        }
        if authority.child.try_wait()?.is_some() {
            warn!(pid = %authority.leader_pid, "authority exited unexpectedly");
            return Ok(());
        }
        if sidecar.child.try_wait()?.is_some() {
            warn!(pid = %sidecar.leader_pid, "sidecar exited unexpectedly");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait until observed detached supervision should begin coordinated teardown.
///
/// Unlike [`block_until_owned_exit`], this function can only probe persisted
/// identities in [`ObservedChildren`]. It cannot collect a child or infer the
/// full platform termination scope from those identities.
pub fn block_until_observed_exit(children: ObservedChildren) -> Result<()> {
    let stop = install_stop_handler();
    debug!(
        authority_pid = %children.authority_pid,
        sidecar_pid = %children.sidecar_pid,
        "detached supervisor observing children"
    );

    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Ctrl-C received; caller will tear stack down");
            return Ok(());
        }
        if !children.authority_pid.process_exists()? {
            warn!(
                pid = %children.authority_pid,
                "authority exited unexpectedly"
            );
            return Ok(());
        }
        if !children.sidecar_pid.process_exists()? {
            warn!(pid = %children.sidecar_pid, "sidecar exited unexpectedly");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Install a process-local request flag for both supervision loops.
///
/// The handler only requests loop termination; it never signals components.
/// Handler installation is best-effort because another crate may already own
/// the process-wide handler.
fn install_stop_handler() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    });
    stop
}

/// Transfer direct-child collection to an unjoined background thread.
///
/// This function prevents eventual leader exits from becoming zombies after a
/// [`crate::start::RunningStack`] relinquishes synchronous ownership. It does
/// not supervise health or terminate the peer when one child exits; detached
/// process governance belongs to [`crate::start::supervise`].
pub fn collect_in_background(
    mut authority: std::process::Child,
    mut sidecar: std::process::Child,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut authority_collected = false;
        let mut sidecar_collected = false;
        while !authority_collected || !sidecar_collected {
            if !authority_collected {
                authority_collected = !matches!(authority.try_wait(), Ok(None));
            }
            if !sidecar_collected {
                sidecar_collected = !matches!(sidecar.try_wait(), Ok(None));
            }
            if !authority_collected || !sidecar_collected {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    })
}
