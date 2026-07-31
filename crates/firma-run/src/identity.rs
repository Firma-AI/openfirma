use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use firma_core::AgentId;
pub use firma_runtime_state::SandboxId;

/// Stable identity tuple associated with a `firma run` execution.
///
/// Values are generated once per execution and then reused everywhere in the
/// runtime to keep attribution stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIdentity {
    pub sandbox_id: SandboxId,
    pub(crate) session_id: String,
    pub(crate) agent_id: AgentId,
    pub(crate) execution_profile: String,
}

impl RunIdentity {
    /// Create a new run identity for a registered agent and execution profile.
    #[must_use]
    pub fn new(agent_id: AgentId, execution_profile: impl Into<String>) -> Self {
        Self {
            sandbox_id: SandboxId::generate(),
            session_id: read_identity_override("FIRMA_RUN_SESSION_ID")
                .unwrap_or_else(|| Uuid::now_v7().to_string()),
            agent_id,
            execution_profile: execution_profile.into(),
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
        pairs.insert("FIRMA_AGENT_ID".to_string(), self.agent_id.to_string());
        pairs.insert(
            "FIRMA_RUN_PROFILE".to_string(),
            self.execution_profile.clone(),
        );
        pairs
    }

    /// Header-style attribution keys suitable for transport bridges.
    #[must_use]
    fn attribution_headers(&self) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert(
            "x-firma-sandbox-id".to_string(),
            self.sandbox_id.to_string(),
        );
        headers.insert("x-firma-session-id".to_string(), self.session_id.clone());
        headers.insert(
            "x-firma-profile".to_string(),
            self.execution_profile.clone(),
        );
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
        let user = std::env::var("LOGNAME")
            .ok()
            .or_else(|| std::env::var("USER").ok())
            .or_else(|| std::env::var("USERNAME").ok())
            .unwrap_or_else(|| "unknown".to_string());
        headers.insert("x-firma-agent".to_string(), self.agent_id.to_string());
        headers.insert("x-firma-user".to_string(), user);
        headers
    }
}

/// Reject an operator-provided sandbox identity before `firma run` performs
/// configuration or filesystem work.
///
/// # Errors
///
/// Returns [`crate::error::RunError::ReservedSandboxIdEnvironment`] whenever
/// `FIRMA_RUN_SANDBOX_ID` is present, including with an empty value.
pub fn reject_reserved_sandbox_id_environment() -> Result<(), crate::error::RunError> {
    if std::env::var_os("FIRMA_RUN_SANDBOX_ID").is_some() {
        return Err(crate::error::RunError::ReservedSandboxIdEnvironment);
    }
    Ok(())
}

/// Read and validate the registered agent `TypeID` from `firma.toml`.
///
/// # Errors
///
/// Returns a typed missing, legacy-profile, malformed `TypeID`, or config parse
/// error. The returned [`AgentId`] always contains the canonical `agt` `TypeID`.
pub fn read_configured_agent_id(path: &std::path::Path) -> Result<AgentId, crate::error::RunError> {
    let text =
        std::fs::read_to_string(path).map_err(|error| crate::error::RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let value: toml::Value =
        toml::from_str(&text).map_err(|error| crate::error::RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let raw = value
        .get("sidecar")
        .and_then(|sidecar| sidecar.get("authority"))
        .and_then(|authority| authority.get("agent_id"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| crate::error::RunError::MissingAgentId {
            path: path.to_path_buf(),
        })?;
    if firma_config_loader::AgentProfile::from_name(raw).is_some() {
        return Err(crate::error::RunError::LegacyProfileAgentId {
            path: path.to_path_buf(),
            value: raw.to_string(),
        });
    }
    raw.parse()
        .map_err(|_| crate::error::RunError::InvalidAgentId {
            path: path.to_path_buf(),
            value: raw.to_string(),
        })
}

fn read_identity_override(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
pub(crate) fn test_agent_id() -> AgentId {
    "agt_01j0000000e008000000000001"
        .parse()
        .expect("valid test agent ID")
}

#[cfg(test)]
mod tests {
    use super::RunIdentity;

    #[test]
    fn identity_env_contains_required_fields() {
        let identity = RunIdentity::new(super::test_agent_id(), "generic");
        let env = identity.env_pairs();

        assert!(env.contains_key("FIRMA_RUN_SANDBOX_ID"));
        assert!(env.contains_key("FIRMA_RUN_SESSION_ID"));
        assert_eq!(env.get("FIRMA_RUN_PROFILE"), Some(&"generic".to_string()));
    }

    #[test]
    fn full_headers_include_agent_user_and_session() {
        let identity = RunIdentity::new(super::test_agent_id(), "generic");
        let headers = identity.full_attribution_headers();

        assert_eq!(
            headers.get("x-firma-agent"),
            Some(&super::test_agent_id().to_string())
        );
        assert!(headers.contains_key("x-firma-session-id"));
        assert!(headers.contains_key("x-firma-user"));
        assert!(!headers["x-firma-user"].trim().is_empty());
    }
}
