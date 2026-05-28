use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Sandbox identifier — either explicitly provided by the operator or
/// auto-generated for this execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxId {
    /// User-supplied value (via `FIRMA_RUN_SANDBOX_ID` or deserialization).
    Custom(String),
    /// Auto-generated UUID v7, stored as formatted string.
    Generated(String),
}

impl Default for SandboxId {
    fn default() -> Self {
        Self::Generated(Uuid::now_v7().to_string())
    }
}

impl SandboxId {
    fn as_str(&self) -> &str {
        match self {
            Self::Custom(s) | Self::Generated(s) => s.as_str(),
        }
    }

    /// Shortened form for log fields: first 8 hex chars + `…` for generated
    /// IDs, full value for custom ones.
    #[must_use]
    pub fn compact(&self) -> String {
        match self {
            Self::Custom(s) => s.clone(),
            Self::Generated(s) => format!("{}…", &s[..8]),
        }
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for SandboxId {
    fn from(s: String) -> Self {
        Self::Custom(s)
    }
}

impl From<&str> for SandboxId {
    fn from(s: &str) -> Self {
        Self::Custom(s.to_string())
    }
}

impl AsRef<str> for SandboxId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<OsStr> for SandboxId {
    fn as_ref(&self) -> &OsStr {
        OsStr::new(self.as_str())
    }
}

impl AsRef<Path> for SandboxId {
    fn as_ref(&self) -> &Path {
        Path::new(self.as_str())
    }
}

impl Serialize for SandboxId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SandboxId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::Custom(String::deserialize(deserializer)?))
    }
}

/// Deterministic identity tuple associated with a `firma run` execution.
///
/// Values are generated once per execution and then reused everywhere in the
/// runtime to keep attribution stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIdentity {
    pub sandbox_id: SandboxId,
    pub session_id: String,
    pub profile: String,
}

impl RunIdentity {
    /// Create a new run identity for a profile.
    #[must_use]
    pub fn new(profile: impl Into<String>) -> Self {
        Self {
            sandbox_id: read_identity_override("FIRMA_RUN_SANDBOX_ID")
                .map(SandboxId::Custom)
                .unwrap_or_default(),
            session_id: read_identity_override("FIRMA_RUN_SESSION_ID")
                .unwrap_or_else(|| Uuid::now_v7().to_string()),
            profile: profile.into(),
        }
    }

    /// Environment variables injected into the wrapped process for
    /// attribution.
    #[must_use]
    pub fn env_pairs(&self) -> BTreeMap<String, String> {
        let mut pairs = BTreeMap::new();
        pairs.insert(
            "FIRMA_RUN_SANDBOX_ID".to_string(),
            self.sandbox_id.to_string(),
        );
        pairs.insert("FIRMA_RUN_SESSION_ID".to_string(), self.session_id.clone());
        pairs.insert("FIRMA_RUN_PROFILE".to_string(), self.profile.clone());
        pairs
    }

    /// Header-style attribution keys suitable for transport bridges.
    #[must_use]
    pub fn attribution_headers(&self) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert(
            "x-firma-sandbox-id".to_string(),
            self.sandbox_id.to_string(),
        );
        headers.insert("x-firma-session-id".to_string(), self.session_id.clone());
        headers.insert("x-firma-profile".to_string(), self.profile.clone());
        headers
    }
}

fn read_identity_override(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::RunIdentity;

    #[test]
    fn identity_env_contains_required_fields() {
        let identity = RunIdentity::new("generic");
        let env = identity.env_pairs();

        assert!(env.contains_key("FIRMA_RUN_SANDBOX_ID"));
        assert!(env.contains_key("FIRMA_RUN_SESSION_ID"));
        assert_eq!(env.get("FIRMA_RUN_PROFILE"), Some(&"generic".to_string()));
    }
}
