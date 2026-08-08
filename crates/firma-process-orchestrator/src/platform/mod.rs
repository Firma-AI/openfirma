//! Operating-system authority over managed process scopes.
//!
//! [`Platform::spawn_in_group`] returns both a direct child handle and a
//! durable [`TerminationTarget`]. The child handle owns leader collection;
//! the target owns liveness probes and signals for the platform scope that must
//! be torn down. Callers must not treat [`TerminationTarget::stored_id`] as an
//! ordinary process ID: it identifies a process group on Unix and a component
//! process on Windows. [`Group`] is setup-time grouping authority and is not a
//! substitute for the target persisted by [`crate::spawn::spawn_component`].

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::path::Path;
use std::process::{Child, Command};

use crate::error::Result;
use firma_runtime_state::UserProcessId;

/// Setup-time platform resource used to attach managed children to one scope.
///
/// On Windows, [`Platform::arm_group_termination`] makes owner loss terminate
/// that scope. Each resulting [`TerminationTarget`] retains the Job Object, so
/// dropping this setup handle after startup does not abandon the group.
pub struct Group {
    /// Unix process-group identity established before the first spawn.
    #[cfg(unix)]
    pub pgid: i32,
    /// Owned Windows Job Object used to establish component membership.
    #[cfg(windows)]
    pub job: *mut std::ffi::c_void,
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "the Windows Group wraps an owned Job Object handle that is safe to move across threads"
)]
unsafe impl Send for Group {}
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "shared references rely on Windows Job Object handle semantics rather than Rust auto-derivation"
)]
unsafe impl Sync for Group {}

#[cfg(windows)]
impl Drop for Group {
    fn drop(&mut self) {
        self::windows::close_job_object(self.job);
    }
}

/// Result of attaching a new direct child to a managed platform scope.
///
/// [`child`](Self::child) and
/// [`termination_target`](Self::termination_target) represent distinct
/// collection and termination responsibilities, even when
/// [`leader_pid`](Self::leader_pid) and [`TerminationTarget::stored_id`] have
/// the same numeric identity.
pub struct SpawnedChild {
    /// Direct-child collection capability.
    pub child: Child,
    /// Stable leader identity used for status and diagnostics.
    pub leader_pid: UserProcessId,
    /// Authority over the complete platform termination scope.
    pub termination_target: TerminationTarget,
}

/// Authority to probe and signal the full process scope Firma must govern.
///
/// On Unix, the stored identity names the process group and is sufficient to
/// reconstruct equivalent authority. An in-process Windows target retains a
/// Job Object handle covering descendants; dropping the last owned handle
/// triggers the owner-loss policy armed by [`Platform::arm_group_termination`].
/// Persisted Windows state can record only the leader process identity, so a
/// target reconstructed by [`Self::from_stored_id`] is necessarily leader-only.
/// This asymmetry is why the capability is not copyable and why
/// [`crate::component::OwnedComponent`] keeps it attached to child collection.
#[derive(Debug)]
pub struct TerminationTarget {
    id: UserProcessId,
    #[cfg(windows)]
    job: Option<*mut std::ffi::c_void>,
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "an owned Windows Job Object handle may be transferred to the collector thread"
)]
unsafe impl Send for TerminationTarget {}

#[cfg(windows)]
impl Drop for TerminationTarget {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            self::windows::close_job_object(job);
        }
    }
}

impl TerminationTarget {
    /// Derive a leader-only target from a newly spawned process.
    ///
    /// Platform spawn paths should return their complete scope through
    /// [`SpawnedChild::termination_target`] instead.
    pub fn for_leader(leader_pid: UserProcessId) -> Self {
        Self {
            id: leader_pid,
            #[cfg(windows)]
            job: None,
        }
    }

    /// Reconstruct the strongest authority available from persisted identity.
    ///
    /// See [`TerminationTarget`] for the platform asymmetry this entails.
    pub fn from_stored_id(id: UserProcessId) -> Self {
        Self {
            id,
            #[cfg(windows)]
            job: None,
        }
    }

    #[cfg(windows)]
    /// Construct an owned target retaining a component's Windows Job Object.
    pub(crate) fn for_job(leader_pid: UserProcessId, job: *mut std::ffi::c_void) -> Self {
        Self {
            id: leader_pid,
            job: Some(job),
        }
    }

    #[cfg(windows)]
    /// Return the retained Job Object handle when this target owns one.
    pub(crate) const fn job(&self) -> Option<*mut std::ffi::c_void> {
        self.job
    }

    /// Return the identity suitable for runtime-state persistence.
    ///
    /// This value identifies the [`TerminationTarget`]; callers must not infer
    /// that it is always an ordinary process ID or preserves Windows Job
    /// Object authority across processes.
    pub const fn stored_id(&self) -> UserProcessId {
        self.id
    }

    /// Determine whether any process remains in this target's available scope.
    ///
    /// # Errors
    ///
    /// Returns a platform error when absence cannot be established. Lifecycle
    /// callers must treat that uncertainty as possible presence.
    pub fn exists(&self) -> Result<bool> {
        SystemPlatform::termination_target_exists(self)
    }

    /// Request graceful shutdown for this target's platform scope.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the request cannot be delivered.
    pub fn signal_soft(&self) -> Result<()> {
        SystemPlatform::signal_soft(self)
    }

    /// Request forced termination for this target's platform scope.
    ///
    /// A signalling error is ignored only when [`Self::exists`] subsequently
    /// proves the target absent. Probe uncertainty preserves the original error
    /// so callers cannot mistake an ungoverned target for successful teardown.
    ///
    /// # Errors
    ///
    /// Returns the platform signalling error while target presence or absence
    /// remains unconfirmed.
    pub fn signal_hard(&self) -> Result<()> {
        match SystemPlatform::signal_hard(self) {
            Ok(()) => Ok(()),
            Err(signal_error) => match self.exists() {
                Ok(false) => Ok(()),
                Ok(true) | Err(_) => Err(signal_error),
            },
        }
    }
}

/// Platform-specific operations for creating and governing process scopes.
///
/// Implementations must attach the child before returning from
/// [`Platform::spawn_in_group`] and return a [`TerminationTarget`] whose scope
/// matches the descendants Firma is responsible for. Lifecycle callers use
/// that target rather than assuming a stored identity has process-ID semantics.
pub trait Platform {
    /// Create a new setup-time [`Group`].
    ///
    /// # Errors
    ///
    /// Returns a platform error if the OS cannot allocate the group.
    fn new_group() -> Result<Group>;

    /// Arm owner-loss termination for a production [`Group`].
    ///
    /// Unix process groups need no retained kernel handle. Windows configures
    /// its Job Object before assigning the first production component.
    ///
    /// # Errors
    ///
    /// Returns a platform error when owner-loss termination cannot be enabled.
    fn arm_group_termination(group: &Group) -> Result<()>;

    /// Return whether a [`TerminationTarget`] remains present.
    ///
    /// Unix targets probe the process group, which can remain addressable when
    /// it contains only zombies. Owned Windows targets query their retained Job
    /// Object; targets reconstructed by [`TerminationTarget::from_stored_id`]
    /// probe the recorded leader.
    ///
    /// # Errors
    ///
    /// Returns a platform error when target presence cannot be determined.
    fn termination_target_exists(target: &TerminationTarget) -> Result<bool>;

    /// Spawn a command as a member of a [`Group`].
    ///
    /// The returned [`SpawnedChild`] must not execute outside the intended
    /// termination scope after this function succeeds. Implementations must
    /// therefore establish membership before component code can escape.
    ///
    /// # Errors
    ///
    /// Returns spawn, log, or group-assignment errors.
    fn spawn_in_group(group: &Group, cmd: &mut Command, log_path: &Path) -> Result<SpawnedChild>;

    /// Deliver a graceful shutdown request to a [`TerminationTarget`].
    ///
    /// # Errors
    ///
    /// Returns a platform error if the signal cannot be delivered.
    fn signal_soft(target: &TerminationTarget) -> Result<()>;

    /// Forcefully terminate a [`TerminationTarget`].
    ///
    /// # Errors
    ///
    /// Returns a platform error if termination cannot be requested.
    fn signal_hard(target: &TerminationTarget) -> Result<()>;

    /// Return whether a child-collection error means another wait already
    /// reaped the child.
    ///
    /// Unix reports this condition through `ECHILD`; Windows child handles
    /// never surface it, so collection callers can treat the child as gone on
    /// Unix and retry elsewhere.
    fn child_already_reaped(error: &std::io::Error) -> bool;

    /// Spawn a command detached from the launcher's controlling terminal or
    /// job so it survives the launcher.
    ///
    /// Unix uses `setsid` to leave the launcher's session; Windows uses
    /// detached and breakaway creation flags so the child escapes the
    /// launcher's console and Job Object.
    ///
    /// # Errors
    ///
    /// Returns a spawn error when the detached child cannot be created.
    fn spawn_detached(cmd: &mut Command) -> Result<Child>;
}

#[cfg(unix)]
pub type SystemPlatform = self::unix::UnixPlatform;
#[cfg(windows)]
pub type SystemPlatform = self::windows::WindowsPlatform;
