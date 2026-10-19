//! Enforcement engine configuration.

#![allow(
    dead_code,
    reason = "Authority-wired capability manifest support is defined now but not consumed yet"
)]

use std::num::NonZeroUsize;
use std::path::PathBuf;

use firma_config_schema::sidecar::enforcement::{self as schema, SessionStateBackend};
use firma_core::HttpMethod;
use firma_http::Method;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

// ---------------------------------------------------------------------------
// Enforcement configuration
// ---------------------------------------------------------------------------

/// Validated enforcement engine configuration.
///
/// Configurable constraint enforcement (Stage 2).
#[derive(Debug, Clone, Default)]
pub struct EnforcementConfig {
    /// Constraint enforcement settings.
    pub constraint_enforcement: ConstraintEnforcementConfig,
}

/// Error validating an [`EnforcementConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnforcementConfigError {
    /// `sidecar.constraint_enforcement.session_state_capacity` was zero.
    #[error("constraint_enforcement.session_state_capacity must be at least 1")]
    ZeroSessionStateCapacity,
}

impl TryFrom<schema::EnforcementConfig> for EnforcementConfig {
    type Error = EnforcementConfigError;

    fn try_from(s: schema::EnforcementConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            constraint_enforcement: s.constraint_enforcement.try_into()?,
        })
    }
}

/// Validated constraint enforcement configuration.
#[derive(Debug, Clone)]
pub struct ConstraintEnforcementConfig {
    /// Maximum number of active sessions tracked in the session-state cache.
    pub capacity: NonZeroUsize,
    /// Session-state storage backend.
    pub backend: SessionStateBackend,
    /// Optional path for the persistent session-state JSONL file.
    pub path: Option<PathBuf>,
}

impl Default for ConstraintEnforcementConfig {
    fn default() -> Self {
        Self {
            capacity: default_session_state_capacity(),
            backend: SessionStateBackend::default(),
            path: None,
        }
    }
}

impl TryFrom<schema::ConstraintEnforcementConfig> for ConstraintEnforcementConfig {
    type Error = EnforcementConfigError;

    fn try_from(s: schema::ConstraintEnforcementConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            capacity: NonZeroUsize::new(s.session_state_capacity)
                .ok_or(EnforcementConfigError::ZeroSessionStateCapacity)?,
            backend: s.session_state_backend,
            path: s.session_state_path,
        })
    }
}

// ---------------------------------------------------------------------------
// Mapping rules file
// ---------------------------------------------------------------------------

/// A single mapping rule as deserialized from the rules TOML file.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MappingRuleConfig {
    /// HTTP method to match (`None` = any method).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<Method>,
    /// Host pattern to match (supports `*` wildcard).
    pub host: String,
    /// Path pattern to match (supports `*` wildcard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Canonical action class this rule maps to.
    pub action_class: String,
}

impl MappingRuleConfig {
    /// Validate a single mapping rule.
    ///
    /// # Errors
    ///
    /// Returns a message describing the first invalid field.
    pub fn validate(&self) -> Result<(), String> {
        firma_core::mapping::validate_authored_mapping_host(&self.host)?;
        if self.action_class.trim().is_empty() {
            return Err("action_class must not be empty".into());
        }
        if let Some(ref method) = self.method
            && method.as_str().parse::<HttpMethod>().is_err()
        {
            return Err(format!(
                "invalid HTTP method '{}'; expected one of: {}",
                method,
                HttpMethod::iter()
                    .map(HttpMethod::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Ok(())
    }
}

/// Top-level structure of the mapping rules TOML file.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MappingRulesFile {
    /// Individual mapping rules.
    #[serde(rename = "rules", default)]
    pub rules: Vec<MappingRuleConfig>,
}

impl MappingRulesFile {
    /// Total number of mapping rules in this file.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Validate all rules in the file.
    ///
    /// # Errors
    ///
    /// Returns a message identifying the first invalid rule (by
    /// index).
    pub fn validate(&self) -> Result<(), String> {
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate().map_err(|e| format!("rule {i}: {e}"))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Capability manifest
// ---------------------------------------------------------------------------

/// Capability manifest entry for token provisioning.
#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityManifestEntry {
    /// Agent identifier.
    pub agent_id: String,
    /// Set of action classes the agent may perform.
    pub action_set: Vec<String>,
    /// Resource scope expression.
    pub resource_scope: String,
}

impl CapabilityManifestEntry {
    /// Validate a single capability manifest entry.
    ///
    /// # Errors
    ///
    /// Returns a message describing the first invalid field.
    pub fn validate(&self) -> Result<(), String> {
        if self.agent_id.trim().is_empty() {
            return Err("agent_id must not be empty".into());
        }
        if self.action_set.is_empty() {
            return Err("action_set must not be empty".into());
        }
        if self.resource_scope.trim().is_empty() {
            return Err("resource_scope must not be empty".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const fn default_session_state_capacity() -> NonZeroUsize {
    const { NonZeroUsize::new(8192).unwrap() }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    // -- MappingRuleConfig --------------------------------------------------

    #[test]
    fn test_valid_mapping_rule() {
        let rule = MappingRuleConfig {
            method: Some(Method::POST),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_valid_connect_mapping_rule() {
        let rule = MappingRuleConfig {
            method: Some(Method::CONNECT),
            host: "api.openai.com:443".to_string(),
            path: Some("/".to_string()),
            action_class: "communication.external.send".to_string(),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_empty_host_rejected() {
        let rule = MappingRuleConfig {
            method: None,
            host: String::new(),
            path: None,
            action_class: "communication.external.send".to_string(),
        };
        let err = rule.validate().unwrap_err();
        assert!(err.contains("host"), "error should mention host: {err}");
    }

    #[test]
    fn test_empty_action_class_rejected() {
        let rule = MappingRuleConfig {
            method: None,
            host: "*.example.com".to_string(),
            path: None,
            action_class: "  ".to_string(),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.contains("action_class"),
            "error should mention action_class: {err}"
        );
    }

    #[test]
    fn test_invalid_http_method_rejected() {
        let rule = MappingRuleConfig {
            method: Some(Method(http::Method::from_str("YEET").unwrap())),
            host: "api.example.com".to_string(),
            path: None,
            action_class: "filesystem.read".to_string(),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.contains("YEET"),
            "error should mention invalid method: {err}"
        );
    }

    // -- MappingRulesFile ---------------------------------------------------

    #[test]
    fn test_rules_file_cascading_validation() {
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: None,
                host: String::new(),
                path: None,
                action_class: "communication.external.send".to_string(),
            }],
        };
        let err = file.validate().unwrap_err();
        assert!(
            err.starts_with("rule 0:"),
            "error should identify rule index: {err}"
        );
    }

    // -- CapabilityManifestEntry --------------------------------------------

    #[test]
    fn test_valid_capability_manifest_entry() {
        let entry = CapabilityManifestEntry {
            agent_id: "agent_1".to_string(),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_empty_agent_id_rejected() {
        let entry = CapabilityManifestEntry {
            agent_id: String::new(),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
        };
        let err = entry.validate().unwrap_err();
        assert!(
            err.contains("agent_id"),
            "error should mention agent_id: {err}"
        );
    }

    #[test]
    fn test_empty_action_set_rejected() {
        let entry = CapabilityManifestEntry {
            agent_id: "agent_1".to_string(),
            action_set: vec![],
            resource_scope: "*".to_string(),
        };
        let err = entry.validate().unwrap_err();
        assert!(
            err.contains("action_set"),
            "error should mention action_set: {err}"
        );
    }

    #[test]
    fn test_empty_resource_scope_rejected() {
        let entry = CapabilityManifestEntry {
            agent_id: "agent_1".to_string(),
            action_set: vec!["*".to_string()],
            resource_scope: "  ".to_string(),
        };
        let err = entry.validate().unwrap_err();
        assert!(
            err.contains("resource_scope"),
            "error should mention resource_scope: {err}"
        );
    }

    // -- EnforcementConfig --------------------------------------------------

    use firma_config_schema::sidecar::enforcement::{
        ConstraintEnforcementConfig as SchemaConstraint, EnforcementConfig as SchemaEnforcement,
    };

    #[test]
    fn defaults_valid() {
        assert!(EnforcementConfig::try_from(SchemaEnforcement::default()).is_ok());
    }

    // -- SessionStateBackend / capacity (AARM R2 G4) -----------------------

    #[test]
    fn session_state_defaults_to_lru_and_8192() {
        let ce = ConstraintEnforcementConfig::default();
        assert_eq!(ce.capacity.get(), 8192);
        assert_eq!(ce.backend, SessionStateBackend::Lru);
        assert!(ce.path.is_none());
    }

    #[test]
    fn session_state_backend_parses_persistent_lowercase() {
        let schema: SchemaConstraint = toml::from_str(
            r#"
            session_state_capacity = 4096
            session_state_backend = "persistent"
            session_state_path = "/var/lib/firma/sessions.jsonl"
            "#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let cfg = ConstraintEnforcementConfig::try_from(schema).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cfg.capacity.get(), 4096);
        assert_eq!(cfg.backend, SessionStateBackend::Persistent);
        assert_eq!(
            cfg.path.as_deref(),
            Some(std::path::Path::new("/var/lib/firma/sessions.jsonl"))
        );
    }

    #[test]
    fn session_state_zero_capacity_rejected() {
        let mut schema = SchemaEnforcement::default();
        schema.constraint_enforcement.session_state_capacity = 0;
        assert!(matches!(
            EnforcementConfig::try_from(schema),
            Err(EnforcementConfigError::ZeroSessionStateCapacity)
        ));
    }

    #[test]
    fn session_state_unknown_backend_rejected() {
        let result: Result<SchemaConstraint, _> = toml::from_str(
            r#"
            session_state_backend = "redis"
            "#,
        );
        let err = result.unwrap_err();
        assert!(err.to_string().contains("redis"));
    }
}
