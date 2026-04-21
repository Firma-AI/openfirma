//! Session identity types.

use serde::{Deserialize, Serialize};

/// Error returned when a [`SessionId`] string fails validation.
#[derive(Debug, thiserror::Error)]
#[error("invalid session id: {0}")]
pub struct InvalidSessionIdError(&'static str);

impl InvalidSessionIdError {
    #[inline]
    #[must_use]
    pub fn empty_string() -> Self {
        Self("must not be empty")
    }
}

/// Unique identifier for a session.
///
/// Non-empty string, serialises and deserialises as a plain string.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SessionId(String);

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<String> for SessionId {
    type Error = InvalidSessionIdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(InvalidSessionIdError::empty_string());
        }
        Ok(Self(s))
    }
}

impl std::str::FromStr for SessionId {
    type Err = InvalidSessionIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_parse() {
        assert!("".parse::<SessionId>().is_err());
    }

    #[test]
    fn rejects_empty_deserialize() {
        assert!(serde_json::from_str::<SessionId>(r#""""#).is_err());
    }

    #[test]
    fn roundtrip() {
        let id: SessionId = "sess-xyz".parse().unwrap();
        assert_eq!(id.to_string(), "sess-xyz");
        assert_eq!(id.as_ref(), "sess-xyz");
    }
}
