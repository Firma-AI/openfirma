//! Validated identities for Authority-registered agents.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use type_safe_id::{StaticType, TypeSafeId};
use uuid::{Variant, Version};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AgentIdType;

impl StaticType for AgentIdType {
    const TYPE: &'static str = "agt";
}

/// A Firma-generated, time-ordered identifier for one registered agent.
///
/// Its canonical representation is an `agt` `TypeID` backed by an RFC 9562 UUID
/// v7. The inner value is private so IDs can only enter through generation or
/// validated parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentId(TypeSafeId<AgentIdType>);

/// Error returned when text is not a valid agent identifier.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AgentIdParseError(AgentIdParseErrorKind);

#[derive(Debug, thiserror::Error)]
enum AgentIdParseErrorKind {
    #[error("agent id must start with `agt` as prefix: `{0}` does not")]
    IncorrectPrefix(String),
    #[error("agent id must be a valid TypeID: `{0}` has an invalid suffix")]
    InvalidSuffix(String),
    #[error("agent id must be a valid TypeID: `{value}` is malformed: {source}")]
    Malformed {
        value: String,
        #[source]
        source: type_safe_id::Error,
    },
    #[error("agent id must be backed by a UUID v7: `{value}` is backed by a UUID v{actual}")]
    NotVersion7 { value: String, actual: usize },
    #[error(
        "agent id must be backed by an RFC 9562 UUID: `{value}` is backed by a UUID with the {actual:?} variant"
    )]
    NotRfc9562 { value: String, actual: Variant },
}

impl AgentId {
    /// Generate a new time-ordered `agt` agent identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(TypeSafeId::new())
    }
}

impl FromStr for AgentId {
    type Err = AgentIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let id = value.parse::<TypeSafeId<AgentIdType>>().map_err(|error| {
            let kind = if matches!(&error, type_safe_id::Error::IncorrectType { .. }) {
                AgentIdParseErrorKind::IncorrectPrefix(value.to_string())
            } else if matches!(&error, type_safe_id::Error::InvalidData) {
                AgentIdParseErrorKind::InvalidSuffix(value.to_string())
            } else {
                AgentIdParseErrorKind::Malformed {
                    value: value.to_string(),
                    source: error,
                }
            };
            AgentIdParseError(kind)
        })?;
        let uuid = id.uuid();
        let variant = uuid.get_variant();
        if variant != Variant::RFC4122 {
            return Err(AgentIdParseError(AgentIdParseErrorKind::NotRfc9562 {
                value: value.to_string(),
                actual: variant,
            }));
        }
        if uuid.get_version() != Some(Version::SortRand) {
            return Err(AgentIdParseError(AgentIdParseErrorKind::NotVersion7 {
                value: value.to_string(),
                actual: uuid.get_version_num(),
            }));
        }
        Ok(Self(id))
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for AgentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AgentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}
