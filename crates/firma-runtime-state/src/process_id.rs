//! Process identifier types used by runtime state files.

use std::fmt;
use std::num::NonZeroU32;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Operating-system process identifier for spawned user processes.
///
/// OS PID `0` can have platform-specific meaning, but `OpenFirma` pidfiles and
/// markers only record spawned user processes. Use `Option<UserProcessId>`
/// when a runtime-state record may not have a process ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        Self::new(value).ok_or(UserProcessIdError::Zero)
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

impl Serialize for UserProcessId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.get())
    }
}

impl<'de> Deserialize<'de> for UserProcessId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = u32::deserialize(deserializer)?;
        Self::new(raw).ok_or_else(|| serde::de::Error::custom("process id must be non-zero"))
    }
}

/// Error returned when converting a raw integer into [`UserProcessId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UserProcessIdError {
    /// `OpenFirma` runtime-state process IDs cannot be zero.
    #[error("process id must be non-zero")]
    Zero,
}

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
        assert_eq!(UserProcessId::try_from(0), Err(UserProcessIdError::Zero));
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

        assert!(error.to_string().contains("process id must be non-zero"));
    }
}
