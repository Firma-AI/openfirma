//! Validated identity for a single `firma run` sandbox.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use type_safe_id::{StaticType, TypeSafeId};
use uuid::{Variant, Version};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SandboxIdType;

impl StaticType for SandboxIdType {
    const TYPE: &'static str = "sbx";
}

/// A Firma-generated, time-ordered identifier for one sandbox execution.
///
/// Its canonical representation is a `sbx` `TypeID` backed by an RFC 9562 UUID
/// v7. The inner value is private so IDs can only enter through generation or
/// validated parsing. This type deliberately does not implement `AsRef<Path>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxId(TypeSafeId<SandboxIdType>);

/// Error returned when text is not a valid sandbox identifier.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SandboxIdParseError(SandboxIdParseErrorKind);

#[derive(Debug, thiserror::Error)]
enum SandboxIdParseErrorKind {
    #[error("sandbox id must start with `sbx` as prefix: `{0}` does not")]
    IncorrectPrefix(String),
    #[error("sandbox id must be a valid TypeID: `{0}` has an invalid suffix")]
    InvalidSuffix(String),
    #[error("sandbox id must be a valid TypeID: `{value}` is malformed: {source}")]
    Malformed {
        value: String,
        #[source]
        source: type_safe_id::Error,
    },
    #[error("sandbox id must be backed by a UUID v7: `{value}` is backed by a UUID v{actual}")]
    NotVersion7 { value: String, actual: usize },
    #[error(
        "sandbox id must be backed by an RFC 9562 UUID: `{value}` is backed by a UUID with the {actual:?} variant"
    )]
    NotRfc9562 { value: String, actual: Variant },
}

impl SandboxId {
    /// Generate a new time-ordered `sbx` sandbox identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(TypeSafeId::new())
    }
}

impl FromStr for SandboxId {
    type Err = SandboxIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let id = value
            .parse::<TypeSafeId<SandboxIdType>>()
            .map_err(|error| {
                let kind = if matches!(&error, type_safe_id::Error::IncorrectType { .. }) {
                    SandboxIdParseErrorKind::IncorrectPrefix(value.to_string())
                } else if matches!(&error, type_safe_id::Error::InvalidData) {
                    SandboxIdParseErrorKind::InvalidSuffix(value.to_string())
                } else {
                    SandboxIdParseErrorKind::Malformed {
                        value: value.to_string(),
                        source: error,
                    }
                };
                SandboxIdParseError(kind)
            })?;
        let uuid = id.uuid();
        let variant = uuid.get_variant();
        if variant != Variant::RFC4122 {
            return Err(SandboxIdParseError(SandboxIdParseErrorKind::NotRfc9562 {
                value: value.to_string(),
                actual: variant,
            }));
        }
        if uuid.get_version() != Some(Version::SortRand) {
            return Err(SandboxIdParseError(SandboxIdParseErrorKind::NotVersion7 {
                value: value.to_string(),
                actual: uuid.get_version_num(),
            }));
        }
        Ok(Self(id))
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
        serializer.collect_str(self)
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
