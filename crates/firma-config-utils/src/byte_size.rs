//! Serde helpers for unit-bearing [`ByteSize`] fields.
//!
//! A bare number is rejected so that a size is never read in an unintended
//! unit; values serialize as an exact byte count such as `"4194304 B"`.

use bytesize::ByteSize;
use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

/// Deserializes a unit-bearing byte size such as `"4 MiB"`.
///
/// # Errors
///
/// Returns an error when the value is not a string, is a bare number, or is
/// not a valid byte size.
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

/// Serializes a byte size as an exact byte count such as `"4194304 B"`.
///
/// # Errors
///
/// Returns the serializer's error.
pub fn serialize<S>(value: &ByteSize, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    format!("{} B", value.as_u64()).serialize(serializer)
}
