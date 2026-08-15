//! Validated identifiers used across `OpenFirma`'s external interfaces.
//!
//! Firma-generated identifiers use `TypeID`s backed by RFC 9562 UUID v7 values.
//! [`SessionId`] also accepts caller-provided values because sessions can be
//! correlated with external runtimes.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use type_safe_id::{StaticType, TypeSafeId};
use uuid::{Variant, Version};

#[derive(Debug, thiserror::Error)]
enum TypeIdParseError {
    #[error("{label} must start with `{prefix}` as prefix: `{value}` does not")]
    IncorrectPrefix {
        label: &'static str,
        prefix: &'static str,
        value: String,
    },
    #[error("{label} must be a valid TypeID: `{value}` has an invalid suffix")]
    InvalidSuffix { label: &'static str, value: String },
    #[error("{label} must be a valid TypeID: `{value}` is malformed: {source}")]
    Malformed {
        label: &'static str,
        value: String,
        #[source]
        source: type_safe_id::Error,
    },
    #[error("{label} must be backed by a UUID v7: `{value}` is backed by a UUID v{actual}")]
    NotVersion7 {
        label: &'static str,
        value: String,
        actual: usize,
    },
    #[error(
        "{label} must be backed by an RFC 9562 UUID: `{value}` is backed by a UUID with the {actual:?} variant"
    )]
    NotRfc9562 {
        label: &'static str,
        value: String,
        actual: Variant,
    },
}

fn parse_type_id<T: StaticType>(
    value: &str,
    label: &'static str,
) -> Result<TypeSafeId<T>, TypeIdParseError> {
    let id = value
        .parse::<TypeSafeId<T>>()
        .map_err(|error| match error {
            type_safe_id::Error::IncorrectType { .. } => TypeIdParseError::IncorrectPrefix {
                label,
                prefix: T::TYPE,
                value: value.to_string(),
            },
            type_safe_id::Error::InvalidData => TypeIdParseError::InvalidSuffix {
                label,
                value: value.to_string(),
            },
            source => TypeIdParseError::Malformed {
                label,
                value: value.to_string(),
                source,
            },
        })?;
    let uuid = id.uuid();
    let variant = uuid.get_variant();
    if variant != Variant::RFC4122 {
        return Err(TypeIdParseError::NotRfc9562 {
            label,
            value: value.to_string(),
            actual: variant,
        });
    }
    if uuid.get_version() != Some(Version::SortRand) {
        return Err(TypeIdParseError::NotVersion7 {
            label,
            value: value.to_string(),
            actual: uuid.get_version_num(),
        });
    }
    Ok(id)
}

macro_rules! firma_type_id {
    ($(#[$type_attr:meta])* $type:ident, $marker:ident, $error:ident, $prefix:literal, $label:literal) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        struct $marker;

        impl StaticType for $marker {
            const TYPE: &'static str = $prefix;
        }

        $(#[$type_attr])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $type(TypeSafeId<$marker>);

        #[doc = concat!("Error returned when text is not a valid `", stringify!($type), "`.")]
        #[derive(Debug, thiserror::Error)]
        #[error(transparent)]
        pub struct $error(TypeIdParseError);

        impl $type {
            #[doc = concat!("Generate a new time-ordered `", $prefix, "` identifier.")]
            #[must_use]
            pub fn generate() -> Self {
                Self(TypeSafeId::new())
            }
        }

        impl FromStr for $type {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_type_id(value, $label).map(Self).map_err($error)
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

firma_type_id!(
    /// A Firma-generated identifier for one Authority-registered agent.
    ///
    /// Its canonical representation is an `agt` `TypeID` backed by an RFC 9562
    /// UUID v7.
    AgentId,
    AgentIdType,
    AgentIdParseError,
    "agt",
    "agent id"
);

firma_type_id!(
    /// A Firma-generated identifier for one sandbox execution.
    ///
    /// A sandbox ID is not a credential. Parsing proves only that the value is
    /// a canonical `sbx` `TypeID` backed by an RFC 9562 UUID v7.
    SandboxId,
    SandboxIdType,
    SandboxIdParseError,
    "sbx",
    "sandbox id"
);

firma_type_id!(
    /// A Firma-generated identifier for one capability token.
    ///
    /// Its canonical representation is a `ctok` `TypeID` backed by an RFC 9562
    /// UUID v7.
    TokenId,
    TokenIdType,
    TokenIdParseError,
    "ctok",
    "capability token id"
);

#[derive(Debug, thiserror::Error)]
enum UuidIdParseError {
    #[error("{label} must be a valid UUID: `{value}` is malformed: {source}")]
    Malformed {
        label: &'static str,
        value: String,
        #[source]
        source: uuid::Error,
    },
    #[error("{label} must be a UUID v{expected}: `{value}` is a UUID v{actual}")]
    IncorrectVersion {
        label: &'static str,
        value: String,
        expected: usize,
        actual: usize,
    },
    #[error("{label} must be an RFC 9562 UUID: `{value}` is a UUID with the {actual:?} variant")]
    NotRfc9562 {
        label: &'static str,
        value: String,
        actual: Variant,
    },
}

fn parse_uuid_id(
    value: &str,
    label: &'static str,
    version: Version,
) -> Result<uuid::Uuid, UuidIdParseError> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|source| UuidIdParseError::Malformed {
        label,
        value: value.to_string(),
        source,
    })?;
    let variant = uuid.get_variant();
    if variant != Variant::RFC4122 {
        return Err(UuidIdParseError::NotRfc9562 {
            label,
            value: value.to_string(),
            actual: variant,
        });
    }
    if uuid.get_version() != Some(version) {
        return Err(UuidIdParseError::IncorrectVersion {
            label,
            value: value.to_string(),
            expected: version as usize,
            actual: uuid.get_version_num(),
        });
    }
    Ok(uuid)
}

macro_rules! firma_uuid_id {
    ($(#[$type_attr:meta])* $type:ident, $error:ident, $generator:ident, $version:ident, $label:literal) => {
        $(#[$type_attr])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $type(uuid::Uuid);

        #[doc = concat!("Error returned when text is not a valid `", stringify!($type), "`.")]
        #[derive(Debug, thiserror::Error)]
        #[error(transparent)]
        pub struct $error(UuidIdParseError);

        impl $type {
            #[doc = concat!("Generate a new `", stringify!($type), "`.")]
            #[must_use]
            pub fn generate() -> Self {
                Self(uuid::Uuid::$generator())
            }
        }

        impl FromStr for $type {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_uuid_id(value, $label, uuid::Version::$version)
                    .map(Self)
                    .map_err($error)
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

firma_uuid_id!(
    /// The time-ordered UUID v7 assigned to one emitted audit event.
    AuditEventId,
    AuditEventIdParseError,
    now_v7,
    SortRand,
    "audit event id"
);

firma_uuid_id!(
    /// The opaque UUID v4 assigned to one human-approval request.
    ApprovalTokenId,
    ApprovalTokenIdParseError,
    new_v4,
    Random,
    "approval token id"
);

/// Error returned when a [`SessionId`] string fails validation.
#[derive(Debug, thiserror::Error)]
pub enum InvalidSessionIdError {
    #[error("session id must not be empty")]
    Empty,
    #[error("session id must be 1–128 characters: letters, digits, hyphens, or underscores")]
    InvalidFormat,
}

/// An identifier used to correlate activity within a session.
///
/// Session IDs accept `[a-zA-Z0-9_-]{1,128}` so callers can supply an existing
/// runtime identifier while remaining safe for use as a Cedar entity UID.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SessionId(String);

impl SessionId {
    /// Generate a new session identifier backed by an RFC 9562 UUID v7.
    #[must_use]
    pub fn generate() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<String> for SessionId {
    type Error = InvalidSessionIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(InvalidSessionIdError::Empty);
        }
        if value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(InvalidSessionIdError::InvalidFormat);
        }
        Ok(Self(value))
    }
}

impl FromStr for SessionId {
    type Err = InvalidSessionIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_string())
    }
}
