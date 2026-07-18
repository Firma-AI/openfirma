//! Validated identity for a single `firma run` sandbox.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::{Uuid, Variant, Version};

/// A Firma-generated UUID v7 identifying one sandbox execution.
///
/// The inner UUID is private so values can only enter the type through
/// generation or validated parsing. In particular, this type deliberately
/// does not implement `AsRef<Path>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxId(Uuid);

/// Error returned when text is not a valid sandbox identifier.
#[derive(Debug, thiserror::Error)]
pub enum SandboxIdParseError {
    /// The input is not a UUID.
    #[error("sandbox id must be a UUID v7: {0}")]
    Malformed(#[source] uuid::Error),
    /// The input is a UUID, but not version 7.
    #[error("sandbox id must be a UUID v7")]
    NotVersion7,
    /// The UUID does not use the RFC 9562 variant.
    #[error("sandbox id must use the RFC 9562 UUID variant")]
    NotRfc9562,
}

impl SandboxId {
    /// Generate a new time-ordered UUID v7 sandbox identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::now_v7())
    }

    /// Return the first eight hexadecimal digits for compact log fields.
    #[must_use]
    pub fn compact(&self) -> String {
        self.0.to_string()[..8].to_string()
    }
}

impl FromStr for SandboxId {
    type Err = SandboxIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(value).map_err(SandboxIdParseError::Malformed)?;
        if uuid.get_variant() != Variant::RFC4122 {
            return Err(SandboxIdParseError::NotRfc9562);
        }
        if uuid.get_version() != Some(Version::SortRand) {
            return Err(SandboxIdParseError::NotVersion7);
        }
        Ok(Self(uuid))
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for SandboxId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SandboxId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}
