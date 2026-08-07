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

/// Setup-time platform resource used to attach managed children to a group.
///
/// Dropping this value releases only grouping resources. Durable probing and
/// signalling authority is represented by each [`TerminationTarget`].
pub struct Group {
    #[cfg(unix)]
    pub pgid: i32,
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
    pub child: Child,
    pub leader_pid: UserProcessId,
    pub termination_target: TerminationTarget,
}

/// Persistable handle for the full scope that must be terminated.
///
/// The stored identifier names a process group on Unix and the component
/// process on Windows. It initially has the same numeric value as the leader
/// PID, but callers must choose the type that matches the intended operation.
#[derive(Debug, Clone, Copy)]
pub struct TerminationTarget {
    id: UserProcessId,
}

impl TerminationTarget {
    /// Derive a fresh platform target from a newly spawned leader.
    pub fn for_leader(leader_pid: UserProcessId) -> Self {
        Self { id: leader_pid }
    }

    /// Reconstruct platform termination authority from persisted identity.
    pub fn from_stored_id(id: UserProcessId) -> Self {
        Self { id }
    }

    /// Return the identity suitable for runtime-state persistence.
    ///
    /// This value identifies the [`TerminationTarget`]; callers must not infer
    /// that it is always an ordinary process ID.
    pub fn stored_id(self) -> UserProcessId {
        self.id
    }

    /// Determine whether any process remains in this target's platform scope.
    ///
    /// # Errors
    ///
    /// Returns a platform error when absence cannot be established. Lifecycle
    /// callers must treat that uncertainty as possible presence.
    pub fn exists(self) -> Result<bool> {
        SystemPlatform::termination_target_exists(self)
    }

    /// Request graceful shutdown for this target's platform scope.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the request cannot be delivered.
    pub fn signal_soft(self) -> Result<()> {
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
    pub fn signal_hard(self) -> Result<()> {
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

    /// Return whether the platform termination target remains present.
    ///
    /// Unix targets probe the process group, which can remain addressable when
    /// it contains only zombies. Windows targets probe the recorded process
    /// because the Job Object handle does not survive detached startup.
    ///
    /// # Errors
    ///
    /// Returns a platform error when target presence cannot be determined.
    fn termination_target_exists(target: TerminationTarget) -> Result<bool>;

    /// Spawn a command as a member of a [`Group`].
    ///
    /// The returned [`SpawnedChild`] must not execute outside the intended
    /// termination scope after this function succeeds.
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
    fn signal_soft(target: TerminationTarget) -> Result<()>;

    /// Forcefully terminate a [`TerminationTarget`].
    ///
    /// # Errors
    ///
    /// Returns a platform error if termination cannot be requested.
    fn signal_hard(target: TerminationTarget) -> Result<()>;
}

#[cfg(unix)]
pub type SystemPlatform = self::unix::UnixPlatform;
#[cfg(windows)]
pub type SystemPlatform = self::windows::WindowsPlatform;
