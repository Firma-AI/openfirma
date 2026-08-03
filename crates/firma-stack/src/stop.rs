//! Tear down a running stack.

use std::path::Path;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::error::{Result, StackError};
use crate::platform::TerminationTarget;
use crate::spawn::SpawnedComponent;
use firma_runtime_state::pidfile;

const HARD_TERMINATION_SETTLEMENT: Duration = Duration::from_secs(2);

/// Result of a [`stop`] call.
#[derive(Debug, Clone)]
pub struct StopOutcome {
    /// `true` if at least one component still had a platform termination
    /// target after the soft-signal grace window and a hard termination
    /// (`SIGKILL` / `TerminateProcess`) was requested successfully; `false` when every
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
/// Returns pidfile, process-probe, termination, or cleanup errors. Runtime
/// state is retained when probing or hard termination fails so cleanup can be
/// retried.
pub fn stop(state_dir: &Path, timeout: Duration) -> Result<StopOutcome> {
    let supervisor = read_target(state_dir, "stack.pid")?;
    let authority = read_target(state_dir, "authority.pid")?;
    let sidecar = read_target(state_dir, "sidecar.pid")?;
    stop_inner(
        state_dir,
        timeout,
        supervisor,
        authority,
        sidecar,
        || Ok(()),
    )
}

pub(crate) fn stop_owned(
    state_dir: &Path,
    timeout: Duration,
    authority: &mut SpawnedComponent,
    sidecar: &mut SpawnedComponent,
) -> Result<StopOutcome> {
    stop_inner(
        state_dir,
        timeout,
        None,
        Some(authority.termination_target),
        Some(sidecar.termination_target),
        || {
            let _ = sidecar.child.try_wait()?;
            let _ = authority.child.try_wait()?;
            Ok(())
        },
    )
}

pub(crate) fn stop_observed_components(state_dir: &Path, timeout: Duration) -> Result<StopOutcome> {
    let authority = read_target(state_dir, "authority.pid")?;
    let sidecar = read_target(state_dir, "sidecar.pid")?;
    stop_inner(state_dir, timeout, None, authority, sidecar, || Ok(()))
}

fn stop_inner(
    state_dir: &Path,
    timeout: Duration,
    stack_target: Option<TerminationTarget>,
    authority_target: Option<TerminationTarget>,
    sidecar_target: Option<TerminationTarget>,
    mut collect_owned: impl FnMut() -> Result<()>,
) -> Result<StopOutcome> {
    info!(state_dir = %state_dir.display(), timeout_secs = timeout.as_secs(), "stopping firma stack");
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
    let mut teardown_error = collect_owned().err();
    for target in [sidecar_target, stack_target, authority_target]
        .into_iter()
        .flatten()
    {
        if target_may_exist(target, &mut teardown_error) {
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
    while teardown_error.is_none() && Instant::now() < deadline {
        if let Err(error) = collect_owned() {
            teardown_error = Some(error);
            break;
        }
        if targets_absent(
            [sidecar_target, stack_target, authority_target],
            &mut teardown_error,
        ) {
            info!("all termination targets exited cleanly");
            cleanup(state_dir)?;
            return Ok(StopOutcome { forced: false });
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Hard-kill survivors. This is the expected path for components that
    // hang in their own graceful-shutdown logic; not an error.
    if let Err(error) = collect_owned()
        && teardown_error.is_none()
    {
        teardown_error = Some(error);
    }
    let mut forced = false;
    let mut hard_termination_error = None;
    for target in [stack_target, authority_target, sidecar_target]
        .into_iter()
        .flatten()
    {
        if target_may_exist(target, &mut teardown_error) {
            info!(id = %target.stored_id(), "soft-signal grace exceeded; hard-killing");
            match target.signal_hard() {
                Ok(()) => forced = true,
                Err(error) => {
                    if let Err(collect_error) = collect_owned()
                        && teardown_error.is_none()
                    {
                        teardown_error = Some(collect_error);
                    }
                    if !matches!(target.exists(), Ok(false)) {
                        info!(id = %target.stored_id(), %error, "hard termination failed; retaining runtime state");
                        if hard_termination_error.is_none() {
                            hard_termination_error = Some(error);
                        }
                    }
                }
            }
        }
    }
    let settlement_deadline = Instant::now() + HARD_TERMINATION_SETTLEMENT;
    let targets_disappeared = loop {
        if let Err(error) = collect_owned()
            && teardown_error.is_none()
        {
            teardown_error = Some(error);
        }
        if targets_absent(
            [sidecar_target, stack_target, authority_target],
            &mut teardown_error,
        ) {
            break true;
        }
        if Instant::now() >= settlement_deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if !targets_disappeared && teardown_error.is_none() {
        teardown_error = hard_termination_error.or(Some(StackError::TerminationTimeout {
            timeout_secs: HARD_TERMINATION_SETTLEMENT.as_secs(),
        }));
    }
    if let Some(error) = teardown_error {
        info!(%error, "teardown incomplete; retaining runtime state");
        return Err(error);
    }
    cleanup(state_dir)?;
    info!(forced, "stop complete");
    Ok(StopOutcome { forced })
}

fn targets_absent<const N: usize>(
    targets: [Option<TerminationTarget>; N],
    teardown_error: &mut Option<StackError>,
) -> bool {
    let mut all_absent = true;
    for target in targets.into_iter().flatten() {
        if target_may_exist(target, teardown_error) {
            all_absent = false;
        }
    }
    all_absent
}

fn target_may_exist(target: TerminationTarget, teardown_error: &mut Option<StackError>) -> bool {
    match target.exists() {
        Ok(exists) => exists,
        Err(error) => {
            info!(id = %target.stored_id(), %error, "termination-target probe failed; signalling conservatively");
            if teardown_error.is_none() {
                *teardown_error = Some(error);
            }
            true
        }
    }
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
        "stack.ready",
        "stack.lock",
    ] {
        pidfile::remove(&state_dir.join(name))?;
    }
    Ok(())
}
