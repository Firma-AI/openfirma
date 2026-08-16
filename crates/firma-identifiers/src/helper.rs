use type_safe_id::{StaticType, TypeSafeId};
use uuid::{Variant, Version};

#[derive(Debug, thiserror::Error)]
pub enum TypeIdParseError {
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

pub fn parse_type_id<T: StaticType>(
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

        impl type_safe_id::StaticType for $marker {
            const TYPE: &'static str = $prefix;
        }

        $(#[$type_attr])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $type(type_safe_id::TypeSafeId<$marker>);

        #[doc = concat!("Error returned when text is not a valid `", stringify!($type), "`.")]
        #[derive(Debug, thiserror::Error)]
        #[error(transparent)]
        pub struct $error(crate::helper::TypeIdParseError);

        impl $type {
            #[doc = concat!("Generate a new time-ordered `", $prefix, "` identifier.")]
            #[must_use]
            pub fn generate() -> Self {
                Self(type_safe_id::TypeSafeId::new())
            }
        }

        impl std::str::FromStr for $type {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                crate::helper::parse_type_id(value, $label)
                    .map(Self)
                    .map_err($error)
            }
        }

        impl std::fmt::Display for $type {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize>::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

#[derive(Debug, thiserror::Error)]
pub enum UuidIdParseError {
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

pub fn parse_uuid_id(
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
        pub struct $error(crate::helper::UuidIdParseError);

        impl $type {
            #[doc = concat!("Generate a new `", stringify!($type), "`.")]
            #[must_use]
            pub fn generate() -> Self {
                Self(uuid::Uuid::$generator())
            }
        }

        impl std::str::FromStr for $type {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                crate::helper::parse_uuid_id(value, $label, uuid::Version::$version)
                    .map(Self)
                    .map_err($error)
            }
        }

        impl std::fmt::Display for $type {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize>::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}
