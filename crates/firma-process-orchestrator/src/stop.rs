//! Fail-closed teardown of a running stack.
//!
//! [`stop_components`] takes a process-target snapshot under [`StateTransaction`], then
//! delegates to [`stop_inner`]. Runtime state is removed by [`cleanup`] only
//! after every target is proven absent and [`cleanup_generation`] confirms the
//! original [`StateLease`] still owns the directory. [`target_may_exist`] treats
//! probe uncertainty as presence, preserving signalling effort and retry
//! evidence. See the [lifecycle and ownership model](mod@crate::start) for the
//! process and runtime-state capabilities required by teardown.

use std::path::Path;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::StackTopology;
use crate::component::OwnedComponent;
use crate::error::OrchestratorError;
use crate::platform::TerminationTarget;
use crate::state_lease::{StackGeneration, StateLease, StateTransaction};
use firma_runtime_state::pidfile;

/// Maximum interval for proving target absence after forced termination.
///
/// This settlement interval is distinct from the graceful timeout supplied to
/// `stop`. Its expiration retains runtime state rather than claiming cleanup
/// succeeded.
const HARD_TERMINATION_SETTLEMENT: Duration = Duration::from_secs(2);
const TARGET_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// First-error-wins accumulator for teardown: the earliest recorded error is
/// retained and later ones are dropped, matching fail-closed precedence.
#[derive(Default)]
struct FirstError(Option<OrchestratorError>);

impl FirstError {
    fn record(&mut self, error: OrchestratorError) {
        if self.0.is_none() {
            self.0 = Some(error);
        }
    }

    fn is_set(&self) -> bool {
        self.0.is_some()
    }

    fn into_inner(self) -> Option<OrchestratorError> {
        self.0
    }
}

/// Resolve the final teardown error by precedence:
/// recorded teardown error > (only if targets remain) hard-termination error > timeout.
/// Confirmed absence of all targets suppresses the hard-termination error.
fn resolve(
    first_teardown: Option<OrchestratorError>,
    first_hard: Option<OrchestratorError>,
    targets_disappeared: bool,
    timeout: impl FnOnce() -> OrchestratorError,
) -> Option<OrchestratorError> {
    if let Some(error) = first_teardown {
        return Some(error);
    }
    if targets_disappeared {
        return None;
    }
    Some(first_hard.unwrap_or_else(timeout))
}

/// Policy for acquiring state serialization after process termination.
///
/// Process termination must not be postponed by state contention. This value
/// therefore distinguishes an external stop that already holds a transaction,
/// an owned supervisor that may only attempt cleanup after teardown, and
/// malformed state that must be retained after its targets are stopped.
enum CleanupLock<'a> {
    /// Reuse a [`StateTransaction`] held across an external `stop` call.
    Held(&'a StateTransaction),
    /// Use [`StateTransaction::try_acquire`] after owned process termination.
    Try,
    /// Terminate snapshotted targets but never remove malformed generation state.
    ///
    /// This permits operator-requested teardown without letting an unparseable
    /// generation accidentally authorize deletion.
    Retain {
        /// Keep [`StateTransaction`] serialization held through target termination.
        _transaction: &'a StateTransaction,
        /// Report the [`OrchestratorError::InvalidStackGeneration`] after teardown.
        error: OrchestratorError,
    },
}

/// Borrowed [`TerminationTarget`] snapshot for one teardown attempt.
///
/// Keeping the targets in one value preserves a consistent signal, probe, and
/// cleanup-gating set throughout [`stop_inner`]. `components` is held in
/// **startup order**; [`Self::teardown_order`] yields the reverse plus the
/// optional supervisor.
struct StopTargets<'a> {
    /// Optional detached supervisor target, torn down last.
    supervisor: Option<&'a TerminationTarget>,
    /// Component process-scope targets, in startup order.
    components: Vec<&'a TerminationTarget>,
}

impl<'a> StopTargets<'a> {
    /// Yield targets in the single uniform teardown order used by every phase.
    ///
    /// The order is the reverse of startup: components in reverse of their
    /// startup order, then the supervisor last. Dependents are torn down before
    /// their dependencies (the sidecar client drains before the authority
    /// server it talks to), and the supervisor that manages the components is
    /// stopped last. The same iterator drives the soft-signal loop, the
    /// hard-kill loop, and both target-absence checks so no phase can diverge.
    fn teardown_order(&self) -> impl Iterator<Item = &'a TerminationTarget> {
        self.components.iter().rev().copied().chain(self.supervisor)
    }
}

/// Result of a `stop` call.
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

/// Stop a running stack made of the named components.
///
/// The component names are caller-supplied data (in startup order); this
/// function is agnostic to which components the stack contains.
///
/// # Errors
///
/// Returns pidfile, process-probe, termination, or cleanup errors. Runtime
/// state is retained when probing or hard termination fails, or when the
/// generation is malformed, so cleanup can be retried. Malformed generation
/// state does not prevent process teardown; its
/// [`OrchestratorError::InvalidStackGeneration`] is returned afterward.
pub fn stop_components(
    state_dir: &Path,
    timeout: Duration,
    topology: &StackTopology,
) -> Result<StopOutcome, OrchestratorError> {
    stop_expected_generation(state_dir, timeout, topology, None)
}

/// Stop only the processes belonging to one launcher-assigned generation.
///
/// A generation mismatch is a successful no-op, preventing delayed detached
/// rollback from terminating a replacement stack. A malformed generation fails
/// before process teardown because the launcher cannot attribute those targets.
pub(crate) fn stop_generation(
    state_dir: &Path,
    timeout: Duration,
    topology: &StackTopology,
    generation: StackGeneration,
) -> Result<StopOutcome, OrchestratorError> {
    stop_expected_generation(state_dir, timeout, topology, Some(generation))
}

/// Snapshot and stop state under the expected [`StackGeneration`] policy.
///
/// Explicit `stop` records malformed-generation failure in
/// [`CleanupLock::Retain`] and still tears down known targets. Generation-bound
/// rollback instead fails before signalling because ownership cannot be proven.
fn stop_expected_generation(
    state_dir: &Path,
    timeout: Duration,
    topology: &StackTopology,
    expected_generation: Option<StackGeneration>,
) -> Result<StopOutcome, OrchestratorError> {
    if !state_dir.exists() {
        return Ok(StopOutcome { forced: false });
    }
    let transaction = StateTransaction::acquire(state_dir)?;
    let (state_lease, cleanup_lock) = match StateLease::load(state_dir) {
        Ok(state_lease) => (state_lease, CleanupLock::Held(&transaction)),
        Err(error @ OrchestratorError::InvalidStackGeneration { .. })
            if expected_generation.is_none() =>
        {
            (
                None,
                CleanupLock::Retain {
                    _transaction: &transaction,
                    error,
                },
            )
        }
        Err(error) => return Err(error),
    };
    if let Some(expected_generation) = expected_generation
        && !state_lease.is_some_and(|lease| lease.belongs_to(expected_generation))
    {
        info!(%expected_generation, ?state_lease, "stack generation changed; skipping stale stop");
        return Ok(StopOutcome { forced: false });
    }
    let supervisor = read_target(state_dir, "stack.pid")?;
    // Read the caller-supplied component pidfiles in startup order. The set of
    // component names is firma-specific data supplied by the caller.
    let component_targets = topology
        .names()
        .map(|name| read_target(state_dir, &format!("{name}.pid")))
        .collect::<Result<Vec<_>, OrchestratorError>>()?;
    let components = component_targets.iter().flatten().collect();
    stop_inner(
        state_dir,
        timeout,
        topology,
        &StopTargets {
            supervisor: supervisor.as_ref(),
            components,
        },
        state_lease,
        cleanup_lock,
        || Ok(()),
    )
}

/// Run [`stop_inner`] while retaining direct-child collection authority.
///
/// The current process owns every [`OwnedComponent`], so no supervisor target
/// is needed. [`CleanupLock::Try`] ensures transaction contention cannot delay
/// process termination; cleanup failure leaves state for a later `stop`.
///
/// `components` is in startup order. Each [`OwnedComponent::child_and_target`]
/// yields a disjoint `&mut Child` and `&TerminationTarget` that share the
/// component's lifetime; splitting the collected pairs lets `stop_inner` probe
/// the targets while `collect_owned` reaps every child, all without `unsafe`.
pub(crate) fn stop_owned(
    state_dir: &Path,
    timeout: Duration,
    topology: &StackTopology,
    components: &mut [OwnedComponent],
    state_lease: StateLease,
) -> Result<StopOutcome, OrchestratorError> {
    let (mut children, targets): (Vec<&mut std::process::Child>, Vec<&TerminationTarget>) =
        components
            .iter_mut()
            .map(OwnedComponent::child_and_target)
            .unzip();
    stop_inner(
        state_dir,
        timeout,
        topology,
        &StopTargets {
            supervisor: None,
            components: targets,
        },
        Some(state_lease),
        CleanupLock::Try,
        || {
            for child in &mut children {
                let _ = child.try_wait()?;
            }
            Ok(())
        },
    )
}

/// Apply the common graceful-to-forced teardown state machine.
///
/// Components receive [`TerminationTarget::signal_soft`] in reverse startup
/// order so dependents can close before their dependencies. Soft signalling
/// failure does not prevent a later forced request. Probe or child
/// collection errors retain the first failure while teardown continues
/// conservatively. A forced request is a normal timeout outcome, but [`cleanup`]
/// remains forbidden until [`targets_absent`] proves every recorded target gone
/// within [`HARD_TERMINATION_SETTLEMENT`].
fn stop_inner(
    state_dir: &Path,
    timeout: Duration,
    topology: &StackTopology,
    targets: &StopTargets<'_>,
    state_lease: Option<StateLease>,
    cleanup_lock: CleanupLock<'_>,
    mut collect_owned: impl FnMut() -> Result<(), OrchestratorError>,
) -> Result<StopOutcome, OrchestratorError> {
    info!(state_dir = %state_dir.display(), timeout_secs = timeout.as_secs(), "stopping stack");
    debug!(
        supervisor_target = ?targets.supervisor,
        component_targets = ?targets.components,
        "loaded termination targets"
    );

    // Signal everything we know about in the uniform teardown order (reverse of
    // startup, supervisor last; see `StopTargets::teardown_order`).
    let mut teardown_error = FirstError::default();
    if let Err(error) = collect_owned() {
        teardown_error.record(error);
    }
    for target in targets.teardown_order() {
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
    while !teardown_error.is_set() && Instant::now() < deadline {
        if let Err(error) = collect_owned() {
            teardown_error.record(error);
            break;
        }
        if targets_absent(targets.teardown_order(), &mut teardown_error) {
            info!("all component targets exited cleanly");
            cleanup(state_dir, topology, state_lease, cleanup_lock)?;
            return Ok(StopOutcome { forced: false });
        }
        std::thread::sleep(TARGET_POLL_INTERVAL);
    }

    // Hard-kill survivors. This is the expected path for components that
    // hang in their own graceful-shutdown logic; not an error.
    if let Err(error) = collect_owned() {
        teardown_error.record(error);
    }
    let mut forced = false;
    let mut hard_termination_error = FirstError::default();
    for target in targets.teardown_order() {
        if target_may_exist(target, &mut teardown_error) {
            info!(id = %target.stored_id(), "soft-signal grace exceeded; hard-killing");
            match target.signal_hard() {
                Ok(()) => forced = true,
                Err(error) => {
                    if let Err(collect_error) = collect_owned() {
                        teardown_error.record(collect_error);
                    }
                    if !matches!(target.exists(), Ok(false)) {
                        info!(id = %target.stored_id(), %error, "hard termination failed; retaining runtime state");
                        hard_termination_error.record(error);
                    }
                }
            }
        }
    }
    let settlement_deadline = Instant::now() + HARD_TERMINATION_SETTLEMENT;
    let targets_disappeared = loop {
        if let Err(error) = collect_owned() {
            teardown_error.record(error);
        }
        if targets_absent(targets.teardown_order(), &mut teardown_error) {
            break true;
        }
        if Instant::now() >= settlement_deadline {
            break false;
        }
        std::thread::sleep(TARGET_POLL_INTERVAL);
    };
    let final_error = resolve(
        teardown_error.into_inner(),
        hard_termination_error.into_inner(),
        targets_disappeared,
        || OrchestratorError::TerminationTimeout {
            timeout_secs: HARD_TERMINATION_SETTLEMENT.as_secs(),
        },
    );
    if let Some(error) = final_error {
        info!(%error, "teardown incomplete; retaining runtime state");
        return Err(error);
    }
    cleanup(state_dir, topology, state_lease, cleanup_lock)?;
    info!(forced, "stop complete");
    Ok(StopOutcome { forced })
}

/// Prove that every recorded target is absent under [`target_may_exist`] policy.
fn targets_absent<'a>(
    targets: impl Iterator<Item = &'a TerminationTarget>,
    teardown_error: &mut FirstError,
) -> bool {
    let mut all_absent = true;
    for target in targets {
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
fn target_may_exist(target: &TerminationTarget, teardown_error: &mut FirstError) -> bool {
    match target.exists() {
        Ok(exists) => exists,
        Err(error) => {
            info!(id = %target.stored_id(), %error, "termination-target probe failed; signalling conservatively");
            teardown_error.record(error);
            true
        }
    }
}

/// Reconstruct a [`TerminationTarget`] without reinterpreting its stored identity.
fn read_target(
    state_dir: &Path,
    name: &str,
) -> Result<Option<TerminationTarget>, OrchestratorError> {
    Ok(pidfile::read(&state_dir.join(name))?.map(TerminationTarget::from_stored_id))
}

/// Remove runtime state only while the supplied generation still owns it.
///
/// The [`StateTransaction`] proves that no startup or concurrent `stop` can
/// mutate the directory between [`StateLease::is_current`] and final state
/// removal. Legacy state without a lease remains removable only while
/// [`StateLease::load`] confirms no generation has replaced it.
///
/// # Errors
///
/// Returns runtime-state read or removal errors. A generation mismatch safely
/// skips cleanup and returns success.
pub(crate) fn cleanup_generation(
    state_dir: &Path,
    topology: &StackTopology,
    state_lease: Option<StateLease>,
    _transaction: &StateTransaction,
) -> Result<(), OrchestratorError> {
    let lease_is_current = match state_lease {
        Some(state_lease) => state_lease.is_current(state_dir)?,
        None => StateLease::load(state_dir)?.is_none(),
    };
    if !lease_is_current {
        info!(
            ?state_lease,
            "runtime state now belongs to another generation; skipping cleanup"
        );
        return Ok(());
    }
    let mut cleanup_error = FirstError::default();
    let stack_pid_readable = match pidfile::read(&state_dir.join("stack.pid")) {
        Ok(Some(current_owner)) => {
            record_cleanup(
                &mut cleanup_error,
                pidfile::remove(&crate::start::supervisor_ready_path(
                    state_dir,
                    current_owner,
                ))
                .map_err(OrchestratorError::from),
            );
            record_cleanup(
                &mut cleanup_error,
                pidfile::remove(&crate::start::supervisor_attached_path(
                    state_dir,
                    current_owner,
                ))
                .map_err(OrchestratorError::from),
            );
            true
        }
        Ok(None) => true,
        Err(error) => {
            cleanup_error.record(error.into());
            false
        }
    };
    // Derive each component's runtime-state files from its caller-supplied name
    // (startup order), then remove the supervisor's files.
    for component in topology.names() {
        record_cleanup(
            &mut cleanup_error,
            pidfile::remove(&state_dir.join(format!("{component}.pid")))
                .map_err(OrchestratorError::from),
        );
        record_cleanup(
            &mut cleanup_error,
            pidfile::remove(&state_dir.join(format!("{component}.listen")))
                .map_err(OrchestratorError::from),
        );
    }
    if let Some(state_lease) = state_lease {
        record_cleanup(
            &mut cleanup_error,
            crate::start::remove_startup_report_dir(&crate::start::startup_report_dir(
                state_dir,
                state_lease.generation(),
            )),
        );
    }
    if stack_pid_readable {
        record_cleanup(
            &mut cleanup_error,
            pidfile::remove(&state_dir.join("stack.pid")).map_err(OrchestratorError::from),
        );
    }
    if let Some(error) = cleanup_error.into_inner() {
        return Err(error);
    }
    // The generation lock is the commit marker for cleanup. Retain it whenever
    // any prior artifact could not be removed, preventing a replacement startup
    // from observing partially cleaned state as available.
    pidfile::remove(&state_dir.join("stack.lock"))?;
    Ok(())
}

/// Attempt every generation artifact while retaining the first cleanup error.
fn record_cleanup(cleanup_error: &mut FirstError, result: Result<(), OrchestratorError>) {
    if let Err(error) = result {
        cleanup_error.record(error);
    }
}

/// Apply the cleanup policy selected before process teardown.
///
/// [`CleanupLock::Try`] reports contention instead of waiting. The
/// [`CleanupLock::Retain`] path returns its saved generation error only after
/// target absence is proven and deliberately leaves all state intact.
fn cleanup(
    state_dir: &Path,
    topology: &StackTopology,
    state_lease: Option<StateLease>,
    cleanup_lock: CleanupLock<'_>,
) -> Result<(), OrchestratorError> {
    match cleanup_lock {
        CleanupLock::Held(transaction) => {
            cleanup_generation(state_dir, topology, state_lease, transaction)
        }
        CleanupLock::Try => {
            let transaction = StateTransaction::try_acquire(state_dir)?.ok_or_else(|| {
                OrchestratorError::RuntimeStateBusy {
                    path: state_dir.to_path_buf(),
                }
            })?;
            cleanup_generation(state_dir, topology, state_lease, &transaction)
        }
        CleanupLock::Retain {
            _transaction: _,
            error,
        } => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeout() -> OrchestratorError {
        OrchestratorError::TerminationTimeout { timeout_secs: 2 }
    }

    #[test]
    fn recorded_teardown_error_wins_over_hard_and_timeout() {
        for targets_disappeared in [true, false] {
            let resolved = resolve(
                Some(OrchestratorError::Platform("teardown".into())),
                Some(OrchestratorError::Platform("hard".into())),
                targets_disappeared,
                timeout,
            );
            assert!(matches!(
                resolved,
                Some(OrchestratorError::Platform(message)) if message == "teardown"
            ));
        }
    }

    #[test]
    fn disappeared_targets_suppress_hard_error() {
        let resolved = resolve(
            None,
            Some(OrchestratorError::Platform("hard".into())),
            true,
            timeout,
        );
        assert!(resolved.is_none());
    }

    #[test]
    fn surviving_targets_surface_hard_error() {
        let resolved = resolve(
            None,
            Some(OrchestratorError::Platform("hard".into())),
            false,
            timeout,
        );
        assert!(matches!(
            resolved,
            Some(OrchestratorError::Platform(message)) if message == "hard"
        ));
    }

    #[test]
    fn surviving_targets_without_hard_error_time_out() {
        let resolved = resolve(None, None, false, timeout);
        assert!(matches!(
            resolved,
            Some(OrchestratorError::TerminationTimeout { timeout_secs: 2 })
        ));
    }
}
