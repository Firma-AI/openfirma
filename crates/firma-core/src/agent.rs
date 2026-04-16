//! Agent identity types.

use serde::{Deserialize, Serialize};

/// Error returned when an [`AgentId`] string fails validation.
#[derive(Debug, thiserror::Error)]
#[error("invalid agent id: {0}")]
pub struct InvalidAgentIdError(&'static str);

impl InvalidAgentIdError {
    #[inline]
    #[must_use]
    pub fn empty_string() -> Self {
        Self("must not be empty")
    }
}

/// Unique identifier for an agent.
///
/// Non-empty string, serialises and deserialises as a plain string.
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
            return Err(InvalidAgentIdError::empty_string());
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
#[allow(clippy::unwrap_used)]
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
}
