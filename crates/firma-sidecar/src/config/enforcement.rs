//! Enforcement engine configuration.

#![allow(
    dead_code,
    reason = "Authority-wired capability manifest support is defined now but not consumed yet"
)]

use serde::{Deserialize, Serialize};

const VALID_HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT",
];

// ---------------------------------------------------------------------------
// Enforcement configuration
// ---------------------------------------------------------------------------

/// Enforcement engine configuration.
///
/// Groups the three enforcement sub-systems: intent-mapping rules,
/// capability validation (Stage 1), and constraint enforcement
/// (Stage 2).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnforcementConfig {
    /// Intent normalization / mapping rules.
    #[serde(default)]
    pub mapping: MappingConfig,
    /// Capability validation settings.
    #[serde(default)]
    pub capability_validation: CapabilityValidationConfig,
    /// Constraint enforcement settings.
    #[serde(default)]
    pub constraint_enforcement: ConstraintEnforcementConfig,
}

impl EnforcementConfig {
    /// Validate the enforcement configuration tree.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message identifying the invalid field.
    pub fn validate(&self) -> Result<(), String> {
        if self.mapping.rules_path.trim().is_empty() {
            return Err("mapping.rules_path must not be empty".into());
        }
        for (i, p) in self.mapping.rules_paths.iter().enumerate() {
            if p.trim().is_empty() {
                return Err(format!("mapping.rules_paths[{i}] must not be empty"));
            }
        }
        Ok(())
    }

    /// Re-base every relative mapping path (`rules_path` and each entry
    /// of `rules_paths`) against `config_dir`; absolute paths untouched.
    /// No default-name sentinel check — relative consistently means
    /// "relative to the config file's directory".
    pub fn rebase_defaults(&mut self, config_dir: &std::path::Path) {
        let rebase = |p: &mut String| {
            // Empty is left for the validator to reject.
            if !p.is_empty() && std::path::Path::new(p.as_str()).is_relative() {
                *p = config_dir.join(p.as_str()).to_string_lossy().into_owned();
            }
        };
        rebase(&mut self.mapping.rules_path);
        for p in &mut self.mapping.rules_paths {
            rebase(p);
        }
    }
}

/// Mapping rules configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MappingConfig {
    /// Path to the primary mapping rules TOML file.
    #[serde(default = "default_mapping_path")]
    pub rules_path: String,
    /// Additional mapping rule files merged on top of `rules_path`.
    /// Rule lists are concatenated; duplicate `(method, host, path)`
    /// tuples across merged files fail at startup (fail-closed).
    #[serde(default)]
    pub rules_paths: Vec<String>,
    /// Whether unlisted hosts are protected by default.
    #[serde(default = "default_true")]
    pub default_protected: bool,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            rules_path: default_mapping_path(),
            rules_paths: Vec::new(),
            default_protected: true,
        }
    }
}

/// Capability validation configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CapabilityValidationConfig {
    /// Clock skew tolerance for expiry checks (seconds).
    /// Default: 0 (strict).
    #[serde(default)]
    pub clock_skew_tolerance_seconds: u64,
}

/// Constraint enforcement configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ConstraintEnforcementConfig {
    /// Policy bundle TTL in seconds. Default: 30.
    #[serde(default = "default_bundle_ttl")]
    pub bundle_ttl_seconds: u64,
    /// Optional Stage 2 evaluation timeout in milliseconds.
    /// Any timeout must fail closed with `DenyReason::EnforcementTimeout`.
    #[serde(default = "default_stage2_timeout_ms")]
    pub enforcement_timeout_ms: u64,
}

impl Default for ConstraintEnforcementConfig {
    fn default() -> Self {
        Self {
            bundle_ttl_seconds: default_bundle_ttl(),
            enforcement_timeout_ms: default_stage2_timeout_ms(),
        }
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
    pub method: Option<String>,
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
        if self.host.trim().is_empty() {
            return Err("host must not be empty".into());
        }
        if self.action_class.trim().is_empty() {
            return Err("action_class must not be empty".into());
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
        if self.rules.is_empty() {
            return Err("mapping rules file contains no rules".into());
        }
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

/// Sentinel: unset `mapping.rules_path`.
pub const DEFAULT_MAPPING_PATH: &str = "mapping-rules.toml";

fn default_mapping_path() -> String {
    DEFAULT_MAPPING_PATH.to_string()
}

const fn default_true() -> bool {
    true
}

const fn default_bundle_ttl() -> u64 {
    30
}

const fn default_stage2_timeout_ms() -> u64 {
    50
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- MappingRuleConfig --------------------------------------------------

    #[test]
    fn test_valid_mapping_rule() {
        let rule = MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_valid_connect_mapping_rule() {
        let rule = MappingRuleConfig {
            method: Some("CONNECT".to_string()),
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
            method: Some("YEET".to_string()),
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

    #[test]
    fn test_enforcement_config_defaults_valid() {
        let config = EnforcementConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn mapping_config_rules_paths_defaults_empty() {
        let cfg: EnforcementConfig = toml::from_str(
            r#"
            [mapping]
            rules_path = "config/mappings/default.toml"
            "#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(cfg.mapping.rules_paths.is_empty());
    }

    #[test]
    fn mapping_config_rules_paths_parses_vec() {
        let cfg: EnforcementConfig = toml::from_str(
            r#"
            [mapping]
            rules_path = "a.toml"
            rules_paths = ["b.toml", "c.toml"]
            "#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cfg.mapping.rules_paths, vec!["b.toml", "c.toml"]);
    }

    #[test]
    fn mapping_config_empty_rules_path_entry_rejected() {
        let cfg: EnforcementConfig = toml::from_str(
            r#"
            [mapping]
            rules_path = "a.toml"
            rules_paths = ["b.toml", ""]
            "#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("rules_paths[1]"), "err: {err}");
    }

    #[test]
    fn test_enforcement_config_empty_rules_path_rejected() {
        let config = EnforcementConfig {
            mapping: MappingConfig {
                rules_path: String::new(),
                ..MappingConfig::default()
            },
            ..EnforcementConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("rules_path"),
            "error should mention rules_path: {err}"
        );
    }
}
