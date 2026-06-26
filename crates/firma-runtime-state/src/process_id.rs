//! Process identifier types used by runtime state files.

use std::fmt;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

/// Operating-system process identifier for spawned user processes.
///
/// OS PID `0` can have platform-specific meaning, but `OpenFirma` pidfiles and
/// markers only record spawned user processes. Use `Option<UserProcessId>`
/// when a runtime-state record may not have a process ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserProcessId(NonZeroU32);

impl UserProcessId {
    /// Construct a process ID from its raw integer representation.
    #[must_use]
    pub fn new(raw: u32) -> Option<Self> {
        NonZeroU32::new(raw).map(Self)
    }

    /// Return the raw integer representation.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

#[cfg(unix)]
impl UserProcessId {
    /// Return whether this process ID appears to identify a live process.
    ///
    /// On Unix, this reaps exited child zombies before falling back to
    /// `kill(pid, 0)` for non-child processes. It is intended for local
    /// runtime-state observation, not for process ownership or signaling.
    #[must_use]
    pub fn is_alive(self) -> bool {
        let Ok(raw) = i32::try_from(self.get()) else {
            return false;
        };
        let pid = nix::unistd::Pid::from_raw(raw);
        // If the process is our child and has exited, reap the zombie here.
        // Otherwise `kill(pid, 0)` still reports a zombie as present.
        match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(
                nix::sys::wait::WaitStatus::Exited(_, _)
                | nix::sys::wait::WaitStatus::Signaled(_, _, _),
            ) => false,
            Ok(_) => true,
            Err(nix::errno::Errno::ECHILD) => matches!(
                nix::sys::signal::kill(pid, None),
                Ok(()) | Err(nix::errno::Errno::EPERM)
            ),
            Err(_) => false,
        }
    }
}

#[cfg(windows)]
#[cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "Windows process liveness uses raw Win32 process handles"
    )
)]
impl UserProcessId {
    /// Return whether this process ID appears to identify a live process.
    ///
    /// This is intended for local runtime-state observation, not for process
    /// ownership or signaling.
    #[must_use]
    pub fn is_alive(self) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, self.get()) };
        if handle.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &raw mut code) };
        unsafe { CloseHandle(handle) };
        ok != 0 && code == STILL_ACTIVE as u32
    }
}

impl TryFrom<u32> for UserProcessId {
    type Error = UserProcessIdError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(UserProcessIdError)
    }
}

impl From<UserProcessId> for u32 {
    fn from(value: UserProcessId) -> Self {
        value.get()
    }
}

impl fmt::Display for UserProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Error returned when converting a raw integer into [`UserProcessId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("process id must be non-zero")]
#[non_exhaustive]
pub struct UserProcessIdError;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "unit tests use expect to make fixture failures explicit"
    )]

    use super::*;

    #[test]
    fn rejects_zero() {
        assert_eq!(UserProcessId::new(0), None);
        assert_eq!(UserProcessId::try_from(0), Err(UserProcessIdError));
    }

    #[test]
    fn exposes_raw_value() {
        let pid = UserProcessId::try_from(42).expect("non-zero pid");

        assert_eq!(pid.get(), 42);
        assert_eq!(u32::from(pid), 42);
        assert_eq!(pid.to_string(), "42");
    }

    #[test]
    fn serializes_as_integer() {
        let pid = UserProcessId::try_from(42).expect("non-zero pid");

        let value = toml::Value::try_from(pid).expect("serialize pid");

        assert_eq!(value.as_integer(), Some(42));
    }

    #[test]
    fn deserializes_from_integer() {
        let value = toml::Value::Integer(42);

        let pid: UserProcessId = value.try_into().expect("deserialize pid");

        assert_eq!(pid.get(), 42);
    }

    #[test]
    fn deserialize_rejects_zero() {
        let value = toml::Value::Integer(0);

        let error = value.try_into::<UserProcessId>().expect_err("zero pid");

        assert!(error.to_string().contains("nonzero"));
    }
}
