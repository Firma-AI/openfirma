//! Operating-system abstraction for process groups.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::path::Path;
use std::process::Command;

use crate::error::Result;

pub(crate) struct Group {
    #[cfg(unix)]
    pub(crate) pgid: i32,
    #[cfg(windows)]
    pub(crate) job: *mut std::ffi::c_void,
}

#[cfg(windows)]
#[allow(unsafe_code)]
unsafe impl Send for Group {}
#[cfg(windows)]
#[allow(unsafe_code)]
unsafe impl Sync for Group {}

#[cfg(windows)]
impl Drop for Group {
    fn drop(&mut self) {
        self::windows::close_job_object(self.job);
    }
}

pub(crate) struct SpawnedChild {
    pub(crate) pid: u32,
}

/// Platform-specific operations for managing process groups.
pub(crate) trait Platform {
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
    fn signal_soft(group_pid: u32) -> Result<()>;

    /// Forcefully terminate the process group.
    ///
    /// # Errors
    ///
    /// Returns a platform error if termination cannot be requested.
    fn signal_hard(group_pid: u32) -> Result<()>;

    /// Report whether `pid` is currently a live process.
    fn is_alive(pid: u32) -> bool;
}

#[cfg(unix)]
pub(crate) type SystemPlatform = self::unix::UnixPlatform;
#[cfg(windows)]
pub(crate) type SystemPlatform = self::windows::WindowsPlatform;
