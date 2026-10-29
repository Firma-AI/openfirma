//! Workspace-relative Agent handles shared by the Authority and its clients.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Error returned when a string is not a canonical [`AgentHandle`].
#[derive(Debug, thiserror::Error)]
#[error("agent handle must be 1-63 lowercase ASCII letters, digits, or single inner hyphens")]
#[non_exhaustive]
pub struct AgentHandleParseError;

/// The Workspace-relative address of one Authority-registered agent.
///
/// A handle is 1 to [`AgentHandle::MAX_LEN`] bytes of lowercase ASCII letters,
/// digits, and hyphens, neither starting nor ending with a hyphen and never
/// holding two in a row, so it is safe as a URL path segment, a DNS label, and
/// a command argument.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct AgentHandle(String);

impl AgentHandle {
    /// The longest handle, in bytes: one DNS label.
    pub const MAX_LEN: usize = 63;

    /// Validates a canonical handle.
    ///
    /// # Errors
    ///
    /// Returns [`AgentHandleParseError`] for any noncanonical input.
    pub fn new(value: String) -> Result<Self, AgentHandleParseError> {
        if !(1..=Self::MAX_LEN).contains(&value.len())
            || value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AgentHandleParseError);
        }
        Ok(Self(value))
    }

    /// Returns the canonical handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AgentHandle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<String> for AgentHandle {
    type Error = AgentHandleParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl FromStr for AgentHandle {
    type Err = AgentHandleParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value.to_owned())
    }
}
