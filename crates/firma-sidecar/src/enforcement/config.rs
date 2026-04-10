//! Enforcement configuration types.
//!
//! Deserialized from TOML at startup. Contains configuration for all
//! enforcement sub-systems: mapping rules (intent normalization),
//! Stage 1 (clock skew tolerance), and Stage 2 (policy bundle TTL).
//!
//! Validated eagerly at startup via [`EnforcementConfig::validate`] to
//! surface misconfigurations before the first request arrives.

use serde::Deserialize;

const VALID_HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// Top-level enforcement configuration (deserialized from TOML).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnforcementConfig {
    #[serde(default)]
    pub mapping: MappingConfig,
    #[serde(default)]
    pub stage1: Stage1Config,
    #[serde(default)]
    pub stage2: Stage2Config,
}

impl EnforcementConfig {
    /// Validate the entire config tree. Call immediately after deserialization
    /// to surface misconfigurations at startup rather than at request time.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message identifying the invalid field.
    pub fn validate(&self) -> Result<(), String> {
        if self.mapping.rules_path.trim().is_empty() {
            return Err("mapping.rules_path must not be empty".to_string());
        }
        Ok(())
    }
}

/// Mapping rules configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MappingConfig {
    /// Path to the mapping rules TOML file.
    #[serde(default = "default_mapping_path")]
    pub rules_path: String,
    /// Whether unlisted hosts are protected by default.
    #[serde(default = "default_true")]
    pub default_protected: bool,
}

/// Stage 1 (token validation) configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Stage1Config {
    /// Clock skew tolerance for expiry checks (seconds). Default: 0 (strict).
    #[serde(default)]
    pub clock_skew_tolerance_seconds: u64,
}

/// Stage 2 (Cedar evaluation) configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Stage2Config {
    /// Policy bundle TTL in seconds. Default: 30.
    #[serde(default = "default_bundle_ttl")]
    pub bundle_ttl_seconds: u64,
}

/// A single mapping rule as deserialized from the rules TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct MappingRuleConfig {
    /// HTTP method to match (None = any method).
    pub method: Option<String>,
    /// Host pattern to match (supports `*` wildcard).
    pub host: String,
    /// Path pattern to match (supports `*` wildcard).
    #[serde(default)]
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
        if self.host.trim().is_empty() {
            return Err("host must not be empty".to_string());
        }
        if self.action_class.trim().is_empty() {
            return Err("action_class must not be empty".to_string());
        }
        if let Some(ref method) = self.method
            && !VALID_HTTP_METHODS.contains(&method.to_uppercase().as_str())
        {
            return Err(format!(
                "invalid HTTP method '{}'; expected one of: {}",
                method,
                VALID_HTTP_METHODS.join(", ")
            ));
        }
        Ok(())
    }
}

/// Top-level structure of the mapping rules TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct MappingRulesFile {
    #[serde(rename = "rules", default)]
    pub rules: Vec<MappingRuleConfig>,
}

impl MappingRulesFile {
    /// Validate all rules in the file.
    ///
    /// # Errors
    ///
    /// Returns a message identifying the first invalid rule (by index).
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.is_empty() {
            return Err("mapping rules file contains no rules".to_string());
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate().map_err(|e| format!("rule {i}: {e}"))?;
        }
        Ok(())
    }
}

/// Capability manifest entry for token provisioning.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct CapabilityManifestEntry {
    pub agent_id: String,
    pub action_set: Vec<String>,
    pub resource_scope: String,
}

impl CapabilityManifestEntry {
    /// Validate a single capability manifest entry.
    ///
    /// # Errors
    ///
    /// Returns a message describing the first invalid field.
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), String> {
        if self.agent_id.trim().is_empty() {
            return Err("agent_id must not be empty".to_string());
        }
        if self.action_set.is_empty() {
            return Err("action_set must not be empty".to_string());
        }
        if self.resource_scope.trim().is_empty() {
            return Err("resource_scope must not be empty".to_string());
        }
        Ok(())
    }
}

fn default_mapping_path() -> String {
    "mapping-rules.toml".to_string()
}

const fn default_true() -> bool {
    true
}

const fn default_bundle_ttl() -> u64 {
    30
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            rules_path: default_mapping_path(),
            default_protected: true,
        }
    }
}

impl Default for Stage2Config {
    fn default() -> Self {
        Self {
            bundle_ttl_seconds: default_bundle_ttl(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_mapping_rule() {
        let rule = MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_empty_host_rejected() {
        let rule = MappingRuleConfig {
            method: None,
            host: "".to_string(),
            path: None,
            action_class: "llm.inference".to_string(),
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
            method: Some("YEET".to_string()),
            host: "api.example.com".to_string(),
            path: None,
            action_class: "http.get".to_string(),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.contains("YEET"),
            "error should mention invalid method: {err}"
        );
    }

    #[test]
    fn test_empty_rules_file_rejected() {
        let file = MappingRulesFile { rules: vec![] };
        let err = file.validate().unwrap_err();
        assert!(
            err.contains("no rules"),
            "error should mention no rules: {err}"
        );
    }

    #[test]
    fn test_rules_file_cascading_validation() {
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: None,
                host: "".to_string(),
                path: None,
                action_class: "llm.inference".to_string(),
            }],
        };
        let err = file.validate().unwrap_err();
        assert!(
            err.starts_with("rule 0:"),
            "error should identify rule index: {err}"
        );
    }

    #[test]
    fn test_valid_capability_manifest_entry() {
        let entry = CapabilityManifestEntry {
            agent_id: "agent_1".to_string(),
            action_set: vec!["llm.inference".to_string()],
            resource_scope: "*".to_string(),
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_empty_agent_id_rejected() {
        let entry = CapabilityManifestEntry {
            agent_id: "".to_string(),
            action_set: vec!["llm.inference".to_string()],
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
}
