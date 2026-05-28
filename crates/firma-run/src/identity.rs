use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Deterministic identity tuple associated with a `firma run` execution.
///
/// Values are generated once per execution and then reused everywhere in the
/// runtime to keep attribution stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIdentity {
    pub sandbox_id: String,
    pub session_id: String,
    pub profile: String,
}

impl RunIdentity {
    /// Create a new run identity for a profile.
    #[must_use]
    pub fn new(profile: impl Into<String>) -> Self {
        Self {
            sandbox_id: read_identity_override("FIRMA_RUN_SANDBOX_ID")
                .unwrap_or_else(|| Uuid::now_v7().to_string()),
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
        pairs.insert("FIRMA_RUN_SANDBOX_ID".to_string(), self.sandbox_id.clone());
        pairs.insert("FIRMA_RUN_SESSION_ID".to_string(), self.session_id.clone());
        pairs.insert("FIRMA_RUN_PROFILE".to_string(), self.profile.clone());
        pairs
    }

    /// Header-style attribution keys suitable for transport bridges.
    #[must_use]
    pub fn attribution_headers(&self) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert("x-firma-sandbox-id".to_string(), self.sandbox_id.clone());
        headers.insert("x-firma-session-id".to_string(), self.session_id.clone());
        headers.insert("x-firma-profile".to_string(), self.profile.clone());
        headers
    }

    /// Full set of attribution headers including agent and host-user identity.
    ///
    /// Used by the host-side proxy bridge (non-structural / macOS path) and by
    /// `FIRMA_RUN_ATTR_HEADERS_JSON` (structural / bwrap path) to stamp every
    /// outbound request with consistent attribution.  Mirrors what the sandboxed
    /// `firma __proxy-bridge` subprocess injects when `FIRMA_RUN_ATTR_HEADERS_JSON`
    /// is set in its environment.
    #[must_use]
    pub fn full_attribution_headers(&self) -> BTreeMap<String, String> {
        let mut headers = self.attribution_headers();
        let user = std::env::var("USER")
            .ok()
            .or_else(|| std::env::var("USERNAME").ok())
            .or_else(|| std::env::var("LOGNAME").ok())
            .unwrap_or_else(|| "unknown".to_string());
        // `profile` equals the resolved `ResolvedProfile::id` (set at construction).
        headers.insert("x-firma-agent".to_string(), self.profile.clone());
        headers.insert("x-firma-user".to_string(), user);
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
