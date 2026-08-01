//! Fail-closed teardown of a running stack.
//!
//! [`stop`] snapshots persisted [`TerminationTarget`] values and delegates to
//! [`stop_inner`]. Runtime state is removed by [`cleanup`] only after every
//! target is proven absent. [`target_may_exist`] treats probe uncertainty as
//! presence, preserving both signalling effort and retry evidence.

use std::path::Path;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::component::OwnedComponent;
use crate::error::{Result, StackError};
use crate::platform::TerminationTarget;
use firma_runtime_state::pidfile;

/// Maximum interval for proving target absence after forced termination.
///
/// This settlement interval is distinct from the graceful timeout supplied to
/// [`stop`]. Its expiration retains runtime state rather than claiming cleanup
/// succeeded.
const HARD_TERMINATION_SETTLEMENT: Duration = Duration::from_secs(2);

/// Result of a [`stop`] call.
#[derive(Debug, Clone)]
pub struct StopOutcome {
    /// Whether at least one recorded [`TerminationTarget`] survived the
    /// graceful interval and accepted [`TerminationTarget::signal_hard`].
    /// A positive result reports that a forced request was made; it does not by
    /// itself prove that the target had disappeared at that instant.
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
        None,
        || Ok(()),
    )
}

/// Run [`stop_inner`] while retaining direct-child collection authority.
///
/// No supervisor target is included because the current process owns both
/// [`OwnedComponent`] values and performs their collection during teardown.
pub(crate) fn stop_owned(
    state_dir: &Path,
    timeout: Duration,
    authority: &mut OwnedComponent,
    sidecar: &mut OwnedComponent,
    state_owner: Option<firma_runtime_state::UserProcessId>,
) -> Result<StopOutcome> {
    stop_inner(
        state_dir,
        timeout,
        None,
        Some(authority.termination_target()),
        Some(sidecar.termination_target()),
        state_owner,
        || {
            let _ = sidecar.try_wait()?;
            let _ = authority.try_wait()?;
            Ok(())
        },
    )
}

/// Apply the common graceful-to-forced teardown state machine.
///
/// The Sidecar receives [`TerminationTarget::signal_soft`] before the Authority
/// so its long-lived RPC streams can close before Authority shutdown. Soft
/// signalling failure does not prevent a later forced request. Probe or child
/// collection errors retain the first failure while teardown continues
/// conservatively. A forced request is a normal timeout outcome, but
/// [`cleanup`] remains forbidden until [`targets_absent`] proves every component
/// target gone within [`HARD_TERMINATION_SETTLEMENT`]. A recorded supervisor is
/// signalled as part of coordination, while component absence remains the
/// cleanup gate.
fn stop_inner(
    state_dir: &Path,
    timeout: Duration,
    stack_target: Option<TerminationTarget>,
    authority_target: Option<TerminationTarget>,
    sidecar_target: Option<TerminationTarget>,
    state_owner: Option<firma_runtime_state::UserProcessId>,
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
        if targets_absent([sidecar_target, authority_target], &mut teardown_error) {
            info!("all component targets exited cleanly");
            cleanup(state_dir, state_owner)?;
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
        if targets_absent([sidecar_target, authority_target], &mut teardown_error) {
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
    cleanup(state_dir, state_owner)?;
    info!(forced, "stop complete");
    Ok(StopOutcome { forced })
}

/// Prove that every component target is absent under [`target_may_exist`] policy.
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

/// Conservatively classify target presence for teardown decisions.
///
/// Failure of [`TerminationTarget::exists`] records the first teardown error
/// and returns possible presence, ensuring the caller still attempts signals
/// and cannot authorize [`cleanup`].
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

/// Reconstruct a [`TerminationTarget`] without reinterpreting its stored ID.
fn read_target(state_dir: &Path, name: &str) -> Result<Option<TerminationTarget>> {
    Ok(pidfile::read(&state_dir.join(name))?.map(TerminationTarget::from_stored_id))
}

/// Commit successful teardown by removing state owned by this stop attempt.
///
/// Callers may invoke this function only after [`targets_absent`] proves that
/// no component target remains. When an expected supervisor identity is
/// supplied, a mismatch preserves the replacement owner's state and returns
/// successfully because process teardown has already completed. Matching
/// readiness is removed through [`crate::start::supervisor_ready_path`].
fn cleanup(
    state_dir: &Path,
    state_owner: Option<firma_runtime_state::UserProcessId>,
) -> Result<()> {
    let current_owner = pidfile::read(&state_dir.join("stack.pid"))?;
    if let Some(expected_owner) = state_owner
        && current_owner != Some(expected_owner)
    {
        info!(%expected_owner, ?current_owner, "runtime state now belongs to another supervisor; skipping cleanup");
        return Ok(());
    }
    if let Some(current_owner) = current_owner {
        pidfile::remove(&crate::start::supervisor_ready_path(
            state_dir,
            current_owner,
        ))?;
    }
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
