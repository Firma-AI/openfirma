//! Operating-system abstraction for process groups.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::path::Path;
use std::process::Command;

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
    pub fn for_leader(leader_pid: UserProcessId) -> Self {
        Self { id: leader_pid }
    }

    pub fn from_stored_id(id: UserProcessId) -> Self {
        Self { id }
    }

    pub fn stored_id(self) -> UserProcessId {
        self.id
    }

    pub fn exists(self) -> Result<bool> {
        SystemPlatform::termination_target_exists(self)
    }

    pub fn signal_soft(self) -> Result<()> {
        SystemPlatform::signal_soft(self)
    }

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

/// Platform-specific operations for managing process groups.
pub trait Platform {
    /// Create a new process group.
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

    /// Spawn `cmd` as a member of `group`, redirecting stdout/stderr to `log_path`.
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
    fn signal_soft(target: TerminationTarget) -> Result<()>;

    /// Forcefully terminate the process group.
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
