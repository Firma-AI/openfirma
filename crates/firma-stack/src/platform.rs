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
    pub pid: UserProcessId,
}

/// Platform-specific operations for managing process groups.
pub trait Platform {
    /// Create a new process group.
    ///
    /// # Errors
    ///
    /// Returns a platform error if the OS cannot allocate the group.
    fn new_group() -> Result<Group>;

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
    fn signal_soft(group_pid: UserProcessId) -> Result<()>;

    /// Forcefully terminate the process group.
    ///
    /// # Errors
    ///
    /// Returns a platform error if termination cannot be requested.
    fn signal_hard(group_pid: UserProcessId) -> Result<()>;

    /// Report whether `pid` is currently a live process.
    fn is_alive(pid: UserProcessId) -> bool;
}

#[cfg(unix)]
pub type SystemPlatform = self::unix::UnixPlatform;
#[cfg(windows)]
pub type SystemPlatform = self::windows::WindowsPlatform;
