//! Reusable value types for Firma configuration.

use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

use bytesize::ByteSize;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod byte_size;
pub mod http;

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

    /// Constructs a fixed configuration default inside a compile-evaluated constant.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `duration` is zero.
    #[must_use]
    pub const fn from_static(duration: Duration) -> Self {
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

/// A strictly non-zero byte size.
///
/// `NonZeroByteSize` owns the intrinsic non-zero invariant for configuration
/// values that bound a buffer, body, or file. It uses the same unit-bearing
/// representation as [`byte_size`], and cross-field or platform-specific
/// validation remains with the consuming component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonZeroByteSize(NonZeroU64);

impl NonZeroByteSize {
    /// Constructs a value from a non-zero byte size.
    ///
    /// # Errors
    ///
    /// Returns [`ZeroByteSizeError`] when `size` is zero bytes.
    pub const fn new(size: ByteSize) -> Result<Self, ZeroByteSizeError> {
        match NonZeroU64::new(size.as_u64()) {
            Some(bytes) => Ok(Self(bytes)),
            None => Err(ZeroByteSizeError),
        }
    }

    /// Returns the size in bytes.
    #[must_use]
    pub const fn bytes(&self) -> NonZeroU64 {
        self.0
    }

    /// Constructs a fixed configuration default inside a compile-evaluated constant.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `size` is zero bytes.
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "a zero static default is rejected during constant evaluation"
    )]
    pub const fn from_static(size: ByteSize) -> Self {
        match Self::new(size) {
            Ok(size) => size,
            Err(ZeroByteSizeError) => panic!("static byte size must be greater than zero"),
        }
    }
}

impl TryFrom<ByteSize> for NonZeroByteSize {
    type Error = ZeroByteSizeError;

    fn try_from(size: ByteSize) -> Result<Self, Self::Error> {
        Self::new(size)
    }
}

impl From<NonZeroByteSize> for ByteSize {
    fn from(size: NonZeroByteSize) -> Self {
        Self::b(size.0.get())
    }
}

impl Serialize for NonZeroByteSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        byte_size::serialize(&ByteSize::from(*self), serializer)
    }
}

impl<'de> Deserialize<'de> for NonZeroByteSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let size = byte_size::deserialize(deserializer)?;
        Self::try_from(size).map_err(serde::de::Error::custom)
    }
}

/// Error returned when constructing a [`NonZeroByteSize`] from zero bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroByteSizeError;

impl fmt::Display for ZeroByteSizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("byte size must be greater than zero")
    }
}

impl std::error::Error for ZeroByteSizeError {}
