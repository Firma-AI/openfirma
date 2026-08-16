use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

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
