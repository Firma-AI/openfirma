//! Operating-system abstraction for process groups.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::path::Path;
use std::process::{Child, Command};

use crate::error::Result;
use firma_runtime_state::UserProcessId;

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

pub struct SpawnedChild {
    pub child: Child,
    pub leader_pid: UserProcessId,
    pub termination_target: TerminationTarget,
}

/// Persistable handle for the full scope that must be terminated.
///
/// The stored identifier names a process group on Unix and the component
/// process on Windows. An in-process Windows target additionally owns a Job
/// Object handle that covers descendants; reconstructed persisted targets are
/// necessarily leader-only.
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
    pub fn for_leader(leader_pid: UserProcessId) -> Self {
        Self {
            id: leader_pid,
            #[cfg(windows)]
            job: None,
        }
    }

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
    /// Return the retained Job Object handle when this is an owned target.
    pub(crate) const fn job(&self) -> Option<*mut std::ffi::c_void> {
        self.job
    }

    pub const fn stored_id(&self) -> UserProcessId {
        self.id
    }

    pub fn exists(&self) -> Result<bool> {
        SystemPlatform::termination_target_exists(self)
    }

    pub fn signal_soft(&self) -> Result<()> {
        SystemPlatform::signal_soft(self)
    }

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

/// Platform-specific operations for managing process groups.
pub trait Platform {
    /// Create a new process group.
    ///
    /// # Errors
    ///
    /// Returns a platform error if the OS cannot allocate the group.
    fn new_group() -> Result<Group>;

    /// Arm owner-loss termination for a production process group.
    ///
    /// Unix process groups need no retained kernel handle. Windows enables
    /// `KILL_ON_JOB_CLOSE` before assigning the first production component.
    ///
    /// # Errors
    ///
    /// Returns a platform error when owner-loss termination cannot be enabled.
    fn arm_group_termination(group: &Group) -> Result<()>;

    /// Return whether the platform termination target remains present.
    ///
    /// Unix targets probe the process group, which can remain addressable when
    /// it contains only zombies. Owned Windows targets query their retained Job
    /// Object; reconstructed persisted targets probe the recorded leader.
    ///
    /// # Errors
    ///
    /// Returns a platform error when target presence cannot be determined.
    fn termination_target_exists(target: &TerminationTarget) -> Result<bool>;

    /// Spawn `cmd` as a member of `group`, redirecting stdout/stderr to `log_path`.
    ///
    /// The implementation must prevent component code from executing before
    /// membership is established. Unix does this during `fork`/`exec`; Windows
    /// creates the process suspended, assigns its Job, then resumes it.
    ///
    /// # Errors
    ///
    /// Returns spawn, log, or group-assignment errors.
    fn spawn_in_group(group: &Group, cmd: &mut Command, log_path: &Path) -> Result<SpawnedChild>;

    /// Deliver a graceful shutdown signal to the process group.
    ///
    /// # Errors
    ///
    /// Returns a platform error if the signal cannot be delivered.
    fn signal_soft(target: &TerminationTarget) -> Result<()>;

    /// Forcefully terminate the process group.
    ///
    /// # Errors
    ///
    /// Returns a platform error if termination cannot be requested.
    fn signal_hard(target: &TerminationTarget) -> Result<()>;
}

#[cfg(unix)]
pub type SystemPlatform = self::unix::UnixPlatform;
#[cfg(windows)]
pub type SystemPlatform = self::windows::WindowsPlatform;
