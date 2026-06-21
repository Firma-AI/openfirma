//! Agent identity types.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

const AGENT_ID_PATTERN: &str = "^[a-zA-Z0-9_-]{1,128}$";

#[expect(
    clippy::expect_used,
    reason = "compiles a fixed AgentId regex literal that is only invalid if edited"
)]
static AGENT_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(AGENT_ID_PATTERN).expect("compile-time literal pattern"));

/// Error returned when an [`AgentId`] string fails validation.
#[derive(Debug, thiserror::Error)]
pub enum InvalidAgentIdError {
    #[error("agent id must not be empty")]
    Empty,
    #[error("agent id must be 1–128 characters: letters, digits, hyphens, or underscores")]
    InvalidFormat,
}

/// Unique identifier for an agent.
///
/// Accepts only `[a-zA-Z0-9_-]{1,128}`. Validated at construction so any
/// code holding a typed value is guaranteed safe for Cedar entity UID use.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct AgentId(String);

impl AsRef<str> for AgentId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<String> for AgentId {
    type Error = InvalidAgentIdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(InvalidAgentIdError::Empty);
        }
        if !AGENT_ID_RE.is_match(&s) {
            return Err(InvalidAgentIdError::InvalidFormat);
        }
        Ok(Self(s))
    }
}

impl std::str::FromStr for AgentId {
    type Err = InvalidAgentIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_parse() {
        assert!("".parse::<AgentId>().is_err());
    }

    #[test]
    fn rejects_empty_deserialize() {
        assert!(serde_json::from_str::<AgentId>(r#""""#).is_err());
    }

    #[test]
    fn roundtrip() {
        let id: AgentId = "agent-abc".parse().unwrap();
        assert_eq!(id.to_string(), "agent-abc");
        assert_eq!(id.as_ref(), "agent-abc");
    }

    #[test]
    fn rejects_injection_payload() {
        assert!(r#"evil"; permit(principal, action, resource); //"#.parse::<AgentId>().is_err());
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(r#"agent"id"#.parse::<AgentId>().is_err());
        assert!("agent\\id".parse::<AgentId>().is_err());
        assert!("agent;id".parse::<AgentId>().is_err());
        assert!("agent\nid".parse::<AgentId>().is_err());
        assert!("agent\u{1F916}id".parse::<AgentId>().is_err());
    }

    #[test]
    fn rejects_too_long() {
        assert!("a".repeat(129).parse::<AgentId>().is_err());
    }

    #[test]
    fn accepts_boundary_length() {
        assert!("a".repeat(128).parse::<AgentId>().is_ok());
        assert!("a".parse::<AgentId>().is_ok());
    }
}
