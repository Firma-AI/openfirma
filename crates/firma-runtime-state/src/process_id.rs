//! Process identifier types used by runtime state files.

use std::fmt;
use std::num::NonZeroU32;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Non-zero operating-system process identifier used in `OpenFirma` runtime state.
///
/// OS PID `0` can have platform-specific meaning, but `OpenFirma` pidfiles and
/// markers only record spawned user processes. Use `Option<NonZeroProcessId>`
/// when a runtime-state record may not have a process ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonZeroProcessId(NonZeroU32);

impl NonZeroProcessId {
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

impl TryFrom<u32> for NonZeroProcessId {
    type Error = ProcessIdError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(ProcessIdError::Zero)
    }
}

impl From<NonZeroProcessId> for u32 {
    fn from(value: NonZeroProcessId) -> Self {
        value.get()
    }
}

impl fmt::Display for NonZeroProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for NonZeroProcessId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.get())
    }
}

impl<'de> Deserialize<'de> for NonZeroProcessId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = u32::deserialize(deserializer)?;
        Self::new(raw).ok_or_else(|| serde::de::Error::custom("process id must be non-zero"))
    }
}

/// Error returned when converting a raw integer into [`NonZeroProcessId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProcessIdError {
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
        assert_eq!(NonZeroProcessId::new(0), None);
        assert_eq!(NonZeroProcessId::try_from(0), Err(ProcessIdError::Zero));
    }

    #[test]
    fn exposes_raw_value() {
        let pid = NonZeroProcessId::try_from(42).expect("non-zero pid");

        assert_eq!(pid.get(), 42);
        assert_eq!(u32::from(pid), 42);
        assert_eq!(pid.to_string(), "42");
    }

    #[test]
    fn serializes_as_integer() {
        let pid = NonZeroProcessId::try_from(42).expect("non-zero pid");

        let value = toml::Value::try_from(pid).expect("serialize pid");

        assert_eq!(value.as_integer(), Some(42));
    }

    #[test]
    fn deserializes_from_integer() {
        let value = toml::Value::Integer(42);

        let pid: NonZeroProcessId = value.try_into().expect("deserialize pid");

        assert_eq!(pid.get(), 42);
    }

    #[test]
    fn deserialize_rejects_zero() {
        let value = toml::Value::Integer(0);

        let error = value.try_into::<NonZeroProcessId>().expect_err("zero pid");

        assert!(error.to_string().contains("process id must be non-zero"));
    }
}
