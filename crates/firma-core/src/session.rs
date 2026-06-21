//! Session identity types.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

const SESSION_ID_PATTERN: &str = "^[a-zA-Z0-9_-]{1,128}$";

#[expect(
    clippy::expect_used,
    reason = "compiles a fixed SessionId regex literal that is only invalid if edited"
)]
static SESSION_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(SESSION_ID_PATTERN).expect("compile-time literal pattern"));

/// Error returned when a [`SessionId`] string fails validation.
#[derive(Debug, thiserror::Error)]
pub enum InvalidSessionIdError {
    #[error("session id must not be empty")]
    Empty,
    #[error("session id must be 1–128 characters: letters, digits, hyphens, or underscores")]
    InvalidFormat,
}

/// Unique identifier for a session.
///
/// Accepts only `[a-zA-Z0-9_-]{1,128}`. Validated at construction so any
/// code holding a typed value is guaranteed safe for Cedar entity UID use.
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
            return Err(InvalidSessionIdError::Empty);
        }
        if !SESSION_ID_RE.is_match(&s) {
            return Err(InvalidSessionIdError::InvalidFormat);
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

    #[test]
    fn rejects_injection_payload() {
        assert!(r#"evil"; permit(principal, action, resource); //"#.parse::<SessionId>().is_err());
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(r#"sess"id"#.parse::<SessionId>().is_err());
        assert!("sess\\id".parse::<SessionId>().is_err());
        assert!("sess;id".parse::<SessionId>().is_err());
        assert!("sess\nid".parse::<SessionId>().is_err());
        assert!("sess\u{1F916}id".parse::<SessionId>().is_err());
    }

    #[test]
    fn rejects_too_long() {
        assert!("s".repeat(129).parse::<SessionId>().is_err());
    }

    #[test]
    fn accepts_boundary_length() {
        assert!("s".repeat(128).parse::<SessionId>().is_ok());
        assert!("s".parse::<SessionId>().is_ok());
    }
}
