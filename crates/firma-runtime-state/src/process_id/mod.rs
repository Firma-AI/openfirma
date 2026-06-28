//! Process identifier types used by runtime state files.

use std::fmt;
use std::num::NonZeroU32;

pub use child_ext::ChildExt;
use serde::{Deserialize, Serialize};

mod child_ext;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Operating-system process identifier for spawned user processes.
///
/// OS PID `0` can have platform-specific meaning, but `OpenFirma` pidfiles and
/// markers only record spawned user processes. Use `Option<UserProcessId>`
/// when a runtime-state record may not have a process ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(windows, expect(clippy::unsafe_derive_deserialize))]
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

/// Error returned when signaling a process ID fails.
#[derive(Debug, thiserror::Error)]
pub enum SignalProcessError {
    /// The process ID does not fit the platform `pid_t` type.
    #[error("process id {0} does not fit platform pid_t")]
    PidOutOfRange(UserProcessId),
    /// The operating system rejected the signal operation.
    #[cfg(unix)]
    #[error("SIGTERM to process id {pid} failed: {source}")]
    Signal {
        /// Process ID targeted by the signal.
        pid: UserProcessId,
        /// OS error returned by `kill`.
        source: nix::errno::Errno,
    },
}
