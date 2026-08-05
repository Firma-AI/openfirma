//! Fail-closed teardown of a running stack.
//!
//! [`stop`] takes a process-target snapshot under [`StateTransaction`], then
//! delegates to [`stop_inner`]. Runtime state is removed by [`cleanup`] only
//! after every target is proven absent and [`cleanup_generation`] confirms the
//! original [`StateLease`] still owns the directory. [`target_may_exist`] treats
//! probe uncertainty as presence, preserving signalling effort and retry
//! evidence.

use std::path::Path;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::component::OwnedComponent;
use crate::error::{Result, StackError};
use crate::platform::TerminationTarget;
use crate::state_lease::{StackGeneration, StateLease, StateTransaction};
use firma_runtime_state::pidfile;

/// Maximum interval for proving target absence after forced termination.
///
/// This settlement interval is distinct from the graceful timeout supplied to
/// [`stop`]. Its expiration retains runtime state rather than claiming cleanup
/// succeeded.
const HARD_TERMINATION_SETTLEMENT: Duration = Duration::from_secs(2);

/// Policy for acquiring state serialization after process termination.
///
/// Process termination must not be postponed by state contention. This value
/// therefore distinguishes an external stop that already holds a transaction,
/// an owned supervisor that may only attempt cleanup after teardown, and
/// malformed state that must be retained after its targets are stopped.
enum CleanupLock<'a> {
    /// Reuse a [`StateTransaction`] held across an external [`stop`] call.
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
        /// Report the [`StackError::InvalidStackGeneration`] after teardown.
        error: StackError,
    },
}

/// Borrowed [`TerminationTarget`] snapshot for one teardown attempt.
///
/// Keeping the targets in one value preserves a consistent signal, probe, and
/// cleanup-gating set throughout [`stop_inner`].
#[derive(Clone, Copy)]
struct StopTargets<'a> {
    /// Optional detached supervisor target.
    stack: Option<&'a TerminationTarget>,
    /// Authority process-scope target.
    authority: Option<&'a TerminationTarget>,
    /// Sidecar process-scope target.
    sidecar: Option<&'a TerminationTarget>,
}

/// Sans-I/O policy for one graceful-to-forced teardown attempt.
///
/// [`TeardownPolicy`] receives normalized observations from [`stop_inner`] and
/// retains only the decisions that must remain stable across operating systems:
/// probe uncertainty is possible presence, the first teardown error wins, and
/// cleanup is authorized only after every target is proven absent. Process
/// collection, signalling, deadlines, and state removal remain with the caller.
pub(crate) struct TeardownPolicy<E> {
    first_teardown_error: Option<E>,
    first_hard_error: Option<E>,
    forced: bool,
}

/// Normalized result of probing one teardown target.
pub(crate) enum Presence<E> {
    /// The target is proven absent.
    Absent,
    /// The target remains present.
    Present,
    /// Presence is unknown and teardown must fail closed with the supplied error.
    Unknown(E),
}

/// Result of requesting forced termination from one target.
pub(crate) enum HardObservation<E> {
    /// The target accepted the forced request.
    Accepted,
    /// Delivery failed and the follow-up probe either did or did not prove absence.
    Failed {
        error: E,
        confirmed_absent_afterward: bool,
    },
}

/// Next action after a graceful-phase observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraceDecision {
    /// Every target is absent, so teardown may proceed to cleanup.
    Complete,
    /// Continue collecting and probing until the graceful deadline.
    Poll,
    /// Enter forced teardown because the deadline elapsed or an observation failed.
    Escalate,
}

/// Next action after a forced-settlement observation.
pub(crate) enum SettlementDecision<E> {
    /// Continue collecting and probing until the settlement deadline.
    Poll,
    /// Every target is absent and cleanup is authorized.
    Complete { forced: bool },
    /// Teardown could not prove safe cleanup.
    Fail(E),
}

impl<E> TeardownPolicy<E> {
    /// Begin teardown without any observations or accepted forced requests.
    pub(crate) const fn new() -> Self {
        Self {
            first_teardown_error: None,
            first_hard_error: None,
            forced: false,
        }
    }

    /// Retain the first direct-child collection failure.
    pub(crate) fn observe_collection(&mut self, result: std::result::Result<(), E>) {
        if let Err(error) = result
            && self.first_teardown_error.is_none()
        {
            self.first_teardown_error = Some(error);
        }
    }

    /// Classify whether a target may remain and retain probe uncertainty.
    pub(crate) fn target_may_exist(&mut self, presence: Presence<E>) -> bool {
        match presence {
            Presence::Absent => false,
            Presence::Present => true,
            Presence::Unknown(error) => {
                if self.first_teardown_error.is_none() {
                    self.first_teardown_error = Some(error);
                }
                true
            }
        }
    }

    /// Decide whether graceful teardown may complete or must escalate.
    pub(crate) fn decide_grace(&self, all_absent: bool, deadline_elapsed: bool) -> GraceDecision {
        if self.first_teardown_error.is_some() || deadline_elapsed {
            GraceDecision::Escalate
        } else if all_absent {
            GraceDecision::Complete
        } else {
            GraceDecision::Poll
        }
    }

    /// Retain accepted forced termination and unsuppressed delivery failures.
    pub(crate) fn observe_hard(&mut self, observation: HardObservation<E>) {
        match observation {
            HardObservation::Accepted => self.forced = true,
            HardObservation::Failed {
                error,
                confirmed_absent_afterward,
            } => {
                if !confirmed_absent_afterward && self.first_hard_error.is_none() {
                    self.first_hard_error = Some(error);
                }
            }
        }
    }

    /// Decide whether forced teardown may complete, must keep polling, or failed.
    pub(crate) fn decide_settlement(
        &mut self,
        all_absent: bool,
        deadline_elapsed: bool,
        timeout_error: impl FnOnce() -> E,
    ) -> SettlementDecision<E> {
        if all_absent {
            return match self.first_teardown_error.take() {
                Some(error) => SettlementDecision::Fail(error),
                None => SettlementDecision::Complete {
                    forced: self.forced,
                },
            };
        }
        if !deadline_elapsed {
            return SettlementDecision::Poll;
        }
        if let Some(error) = self.first_teardown_error.take() {
            return SettlementDecision::Fail(error);
        }
        if let Some(error) = self.first_hard_error.take() {
            return SettlementDecision::Fail(error);
        }
        SettlementDecision::Fail(timeout_error())
    }
}

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
/// state is retained when probing or hard termination fails, or when the
/// generation is malformed, so cleanup can be retried. Malformed generation
/// state does not prevent process teardown; its
/// [`StackError::InvalidStackGeneration`] is returned afterward.
pub fn stop(state_dir: &Path, timeout: Duration) -> Result<StopOutcome> {
    stop_expected_generation(state_dir, timeout, None)
}

/// Stop only the processes belonging to one launcher-assigned generation.
///
/// A generation mismatch is a successful no-op, preventing delayed detached
/// rollback from terminating a replacement stack. A malformed generation fails
/// before process teardown because the launcher cannot attribute those targets.
pub(crate) fn stop_generation(
    state_dir: &Path,
    timeout: Duration,
    generation: StackGeneration,
) -> Result<StopOutcome> {
    stop_expected_generation(state_dir, timeout, Some(generation))
}

/// Snapshot and stop state under the expected [`StackGeneration`] policy.
///
/// Explicit [`stop`] records malformed-generation failure in
/// [`CleanupLock::Retain`] and still tears down known targets. Generation-bound
/// rollback instead fails before signalling because ownership cannot be proven.
fn stop_expected_generation(
    state_dir: &Path,
    timeout: Duration,
    expected_generation: Option<StackGeneration>,
) -> Result<StopOutcome> {
    if !state_dir.exists() {
        return Ok(StopOutcome { forced: false });
    }
    let transaction = StateTransaction::acquire(state_dir)?;
    let (state_lease, cleanup_lock) = match StateLease::load(state_dir) {
        Ok(state_lease) => (state_lease, CleanupLock::Held(&transaction)),
        Err(error @ StackError::InvalidStackGeneration { .. }) if expected_generation.is_none() => {
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
    let authority = read_target(state_dir, "authority.pid")?;
    let sidecar = read_target(state_dir, "sidecar.pid")?;
    stop_inner(
        state_dir,
        timeout,
        StopTargets {
            stack: supervisor.as_ref(),
            authority: authority.as_ref(),
            sidecar: sidecar.as_ref(),
        },
        state_lease,
        cleanup_lock,
        || Ok(()),
    )
}

/// Run [`stop_inner`] while retaining direct-child collection authority.
///
/// The current process owns both [`OwnedComponent`] values, so no supervisor
/// target is needed. [`CleanupLock::Try`] ensures transaction contention cannot
/// delay process termination; cleanup failure leaves state for a later [`stop`].
pub(crate) fn stop_owned(
    state_dir: &Path,
    timeout: Duration,
    authority: &mut OwnedComponent,
    sidecar: &mut OwnedComponent,
    state_lease: StateLease,
) -> Result<StopOutcome> {
    let (authority_child, authority_target) = authority.child_and_target();
    let (sidecar_child, sidecar_target) = sidecar.child_and_target();
    stop_inner(
        state_dir,
        timeout,
        StopTargets {
            stack: None,
            authority: Some(authority_target),
            sidecar: Some(sidecar_target),
        },
        Some(state_lease),
        CleanupLock::Try,
        || {
            let _ = sidecar_child.try_wait()?;
            let _ = authority_child.try_wait()?;
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
/// conservatively. A forced request is a normal timeout outcome, but [`cleanup`]
/// remains forbidden until [`targets_absent`] proves every recorded target gone
/// within [`HARD_TERMINATION_SETTLEMENT`].
fn stop_inner(
    state_dir: &Path,
    timeout: Duration,
    targets: StopTargets<'_>,
    state_lease: Option<StateLease>,
    cleanup_lock: CleanupLock<'_>,
    mut collect_owned: impl FnMut() -> Result<()>,
) -> Result<StopOutcome> {
    info!(state_dir = %state_dir.display(), timeout_secs = timeout.as_secs(), "stopping firma stack");
    debug!(
        stack_target = ?targets.stack,
        authority_target = ?targets.authority,
        sidecar_target = ?targets.sidecar,
        "loaded termination targets"
    );

    // Signal everything we know about. Sidecar first so that its outbound
    // gRPC streams to the authority close cleanly; that lets the authority's
    // tonic graceful shutdown finish instead of blocking on long-lived
    // server-streaming RPCs.
    let mut policy = TeardownPolicy::new();
    policy.observe_collection(collect_owned());
    for target in [targets.sidecar, targets.stack, targets.authority]
        .into_iter()
        .flatten()
    {
        if target_may_exist(target, &mut policy) {
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
    loop {
        if policy.decide_grace(false, Instant::now() >= deadline) == GraceDecision::Escalate {
            break;
        }
        policy.observe_collection(collect_owned());
        if policy.decide_grace(false, false) == GraceDecision::Escalate {
            break;
        }
        let all_absent = targets_absent(
            [targets.sidecar, targets.stack, targets.authority],
            &mut policy,
        );
        match policy.decide_grace(all_absent, false) {
            GraceDecision::Complete => {
                info!("all component targets exited cleanly");
                cleanup(state_dir, state_lease, cleanup_lock)?;
                return Ok(StopOutcome { forced: false });
            }
            GraceDecision::Poll => std::thread::sleep(Duration::from_millis(50)),
            GraceDecision::Escalate => {
                // Preserve the final grace interval after probe uncertainty.
                std::thread::sleep(Duration::from_millis(50));
                break;
            }
        }
    }

    // Hard-kill survivors. This is the expected path for components that
    // hang in their own graceful-shutdown logic; not an error.
    policy.observe_collection(collect_owned());
    for target in [targets.stack, targets.authority, targets.sidecar]
        .into_iter()
        .flatten()
    {
        if target_may_exist(target, &mut policy) {
            info!(id = %target.stored_id(), "soft-signal grace exceeded; hard-killing");
            match target.signal_hard() {
                Ok(()) => policy.observe_hard(HardObservation::Accepted),
                Err(error) => {
                    policy.observe_collection(collect_owned());
                    let confirmed_absent_afterward = matches!(target.exists(), Ok(false));
                    if !confirmed_absent_afterward {
                        info!(id = %target.stored_id(), %error, "hard termination failed; retaining runtime state");
                    }
                    policy.observe_hard(HardObservation::Failed {
                        error,
                        confirmed_absent_afterward,
                    });
                }
            }
        }
    }
    let settlement_deadline = Instant::now() + HARD_TERMINATION_SETTLEMENT;
    loop {
        policy.observe_collection(collect_owned());
        let all_absent = targets_absent(
            [targets.sidecar, targets.stack, targets.authority],
            &mut policy,
        );
        match policy.decide_settlement(all_absent, Instant::now() >= settlement_deadline, || {
            StackError::TerminationTimeout {
                timeout_secs: HARD_TERMINATION_SETTLEMENT.as_secs(),
            }
        }) {
            SettlementDecision::Poll => std::thread::sleep(Duration::from_millis(50)),
            SettlementDecision::Complete { forced } => {
                cleanup(state_dir, state_lease, cleanup_lock)?;
                info!(forced, "stop complete");
                return Ok(StopOutcome { forced });
            }
            SettlementDecision::Fail(error) => {
                info!(%error, "teardown incomplete; retaining runtime state");
                return Err(error);
            }
        }
    }
}

/// Prove that every recorded target is absent under [`target_may_exist`] policy.
fn targets_absent<const N: usize>(
    targets: [Option<&TerminationTarget>; N],
    policy: &mut TeardownPolicy<StackError>,
) -> bool {
    let mut all_absent = true;
    for target in targets.into_iter().flatten() {
        if target_may_exist(target, policy) {
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
fn target_may_exist(target: &TerminationTarget, policy: &mut TeardownPolicy<StackError>) -> bool {
    let presence = match target.exists() {
        Ok(false) => Presence::Absent,
        Ok(true) => Presence::Present,
        Err(error) => {
            info!(id = %target.stored_id(), %error, "termination-target probe failed; signalling conservatively");
            Presence::Unknown(error)
        }
    };
    policy.target_may_exist(presence)
}

/// Reconstruct a [`TerminationTarget`] without reinterpreting its stored identity.
fn read_target(state_dir: &Path, name: &str) -> Result<Option<TerminationTarget>> {
    Ok(pidfile::read(&state_dir.join(name))?.map(TerminationTarget::from_stored_id))
}

/// Remove runtime state only while the supplied generation still owns it.
///
/// The [`StateTransaction`] proves that no startup or concurrent [`stop`] can
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
    state_lease: Option<StateLease>,
    _transaction: &StateTransaction,
) -> Result<()> {
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
    let current_owner = pidfile::read(&state_dir.join("stack.pid"))?;
    if let Some(current_owner) = current_owner {
        pidfile::remove(&crate::start::supervisor_ready_path(
            state_dir,
            current_owner,
        ))?;
        pidfile::remove(&crate::start::supervisor_attached_path(
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

/// Apply the cleanup policy selected before process teardown.
///
/// [`CleanupLock::Try`] reports contention instead of waiting. The
/// [`CleanupLock::Retain`] path returns its saved generation error only after
/// target absence is proven and deliberately leaves all state intact.
fn cleanup(
    state_dir: &Path,
    state_lease: Option<StateLease>,
    cleanup_lock: CleanupLock<'_>,
) -> Result<()> {
    match cleanup_lock {
        CleanupLock::Held(transaction) => cleanup_generation(state_dir, state_lease, transaction),
        CleanupLock::Try => {
            let transaction = StateTransaction::try_acquire(state_dir)?.ok_or_else(|| {
                StackError::RuntimeStateBusy {
                    path: state_dir.to_path_buf(),
                }
            })?;
            cleanup_generation(state_dir, state_lease, &transaction)
        }
        CleanupLock::Retain {
            _transaction: _,
            error,
        } => Err(error),
    }
}
