//! Reusable value types and Serde helpers for configuration fields.

pub(crate) mod byte_size {
    use bytesize::ByteSize;
    use serde::{Deserialize as _, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ByteSize, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.parse::<u64>().is_ok() {
            return Err(serde::de::Error::custom("byte size must include a unit"));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}

use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A strictly non-zero duration.
///
/// `NonZeroDuration` owns the intrinsic non-zero invariant for configuration values
/// that bound an operation, wait, retry, backoff, or session lifetime. Cross-field
/// and runtime-specific validation remains with the consuming component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonZeroDuration(Duration);

impl NonZeroDuration {
    /// Constructs a value from a non-zero duration.
    ///
    /// # Errors
    ///
    /// Returns [`ZeroDurationError`] when `duration` is [`Duration::ZERO`].
    pub const fn new(duration: Duration) -> Result<Self, ZeroDurationError> {
        if duration.is_zero() {
            Err(ZeroDurationError)
        } else {
            Ok(Self::from_static(duration))
        }
    }

    /// Returns the wrapped duration.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.0
    }

    /// Constructs a fixed schema default inside a compile-evaluated constant.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `duration` is zero.
    pub(crate) const fn from_static(duration: Duration) -> Self {
        assert!(
            !duration.is_zero(),
            "static duration must be greater than zero"
        );
        Self(duration)
    }
}

impl TryFrom<Duration> for NonZeroDuration {
    type Error = ZeroDurationError;

    fn try_from(duration: Duration) -> Result<Self, Self::Error> {
        Self::new(duration)
    }
}

impl From<NonZeroDuration> for Duration {
    fn from(duration: NonZeroDuration) -> Self {
        duration.0
    }
}

impl From<NonZeroU64> for NonZeroDuration {
    fn from(seconds: NonZeroU64) -> Self {
        Self(Duration::from_secs(seconds.get()))
    }
}

impl AsRef<Duration> for NonZeroDuration {
    fn as_ref(&self) -> &Duration {
        &self.0
    }
}

impl Serialize for NonZeroDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        jiff::fmt::serde::unsigned_duration::friendly::compact::required::serialize(
            &self.0, serializer,
        )
    }
}

impl<'de> Deserialize<'de> for NonZeroDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let duration =
            jiff::fmt::serde::unsigned_duration::friendly::compact::required::deserialize(
                deserializer,
            )?;
        Self::try_from(duration).map_err(serde::de::Error::custom)
    }
}

/// Error returned when constructing a [`NonZeroDuration`] from a zero duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroDurationError;

impl fmt::Display for ZeroDurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("duration must be greater than zero")
    }
}

impl std::error::Error for ZeroDurationError {}
