//! Mapping table for intent normalization.
//!
//! Loaded from TOML configuration at startup. Each rule maps an HTTP
//! method + host + path pattern to a canonical action class from the
//! Canonical Action Class Registry v0.1. Rules are sorted by descending
//! specificity so that the first match wins.
//!
//! The `intent.action_class` field produced by the normalizer MUST be one of
//! the configured registry identifiers. Unknown protected actions that cannot
//! be deterministically mapped to a registry entry fail closed with
//! `DENY: UNCLASSIFIED_INTENT` (FEP \[I-N1\]).

use crate::config::MappingRulesFile;
use crate::enforcement::registry::ActionClassRegistry;

/// A validated mapping rule ready for matching.
#[derive(Debug, Clone)]
pub struct MappingRule {
    pub method: Option<String>,
    pub host_pattern: String,
    pub path_pattern: Option<String>,
    pub action_class: String,
    specificity: u32,
}

/// Collection of validated, specificity-ordered mapping rules.
///
/// Loaded from TOML configuration at startup. Immutable after initialization.
#[derive(Debug, Clone)]
pub struct MappingTable {
    rules: Vec<MappingRule>,
    default_protected: bool,
}

/// The result of matching a request against the mapping table.
#[derive(Debug)]
pub enum MatchResult<'a> {
    /// Matched a rule — use this action class.
    Matched(&'a MappingRule),
    /// No rule matched and the host is protected — deny as unclassified.
    UnclassifiedProtected,
    /// No rule matched and the host is not protected — passthrough.
    NotProtected,
}

impl MappingRule {
    fn compute_specificity(method: Option<&String>, host: &str, path: Option<&String>) -> u32 {
        let mut score = 0u32;

        // Exact host > wildcard host
        if !host.contains('*') {
            score += 100;
        }

        // Specific method > any method
        if method.is_some() {
            score += 10;
        }

        // Path presence and specificity
        if let Some(p) = path {
            score += 5;
            // Longer path = more specific
            #[allow(clippy::cast_possible_truncation)] // path segments will never exceed u32
            let segments = p.split('/').filter(|s| !s.is_empty()).count() as u32;
            score += segments;
            // No wildcards in path = more specific
            if !p.contains('*') {
                score += 10;
            }
        }

        score
    }
}

impl MappingTable {
    /// Load and validate mapping rules from a parsed config.
    ///
    /// # Errors
    /// Returns an error if any rule references an unknown action class.
    pub fn from_config(
        file: &MappingRulesFile,
        registry: &ActionClassRegistry,
        default_protected: bool,
    ) -> Result<Self, String> {
        file.validate()?;

        let mut rules = Vec::with_capacity(file.rules.len());

        for (i, rule_cfg) in file.rules.iter().enumerate() {
            if !registry.contains(&rule_cfg.action_class) {
                return Err(format!(
                    "rule {i}: action class '{}' not in registry",
                    rule_cfg.action_class
                ));
            }

            let specificity = MappingRule::compute_specificity(
                rule_cfg.method.as_ref(),
                &rule_cfg.host,
                rule_cfg.path.as_ref(),
            );

            rules.push(MappingRule {
                method: rule_cfg.method.clone(),
                host_pattern: rule_cfg.host.clone(),
                path_pattern: rule_cfg.path.clone(),
                action_class: rule_cfg.action_class.clone(),
                specificity,
            });
        }

        // Sort by descending specificity (most specific first)
        rules.sort_by(|a, b| b.specificity.cmp(&a.specificity));

        Ok(Self {
            rules,
            default_protected,
        })
    }

    /// Find the first (most specific) matching rule for a request.
    #[must_use]
    pub fn find_match<'a>(&'a self, method: &str, host: &str, path: &str) -> MatchResult<'a> {
        for rule in &self.rules {
            if Self::rule_matches(rule, method, host, path) {
                return MatchResult::Matched(rule);
            }
        }

        if self.default_protected {
            MatchResult::UnclassifiedProtected
        } else {
            MatchResult::NotProtected
        }
    }

    fn rule_matches(rule: &MappingRule, method: &str, host: &str, path: &str) -> bool {
        // Check method (None = any method)
        if let Some(ref rule_method) = rule.method
            && !rule_method.eq_ignore_ascii_case(method)
        {
            return false;
        }

        // Check host pattern
        if !glob_match(&rule.host_pattern, host) {
            return false;
        }

        // Check path pattern (None = any path)
        if let Some(ref pattern) = rule.path_pattern
            && !glob_match(pattern, path)
        {
            return false;
        }

        true
    }
}

/// Simple glob matching supporting `*` as a single-segment wildcard.
///
/// - `*` matches any sequence of non-separator characters
/// - `*.example.com` matches `api.example.com` but not `deep.api.example.com`
/// - `/v1/*/completions` matches `/v1/chat/completions`
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Split into segments by the `*` wildcard
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No wildcard — exact match
        return pattern == value;
    }

    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match value[pos..].find(part) {
            Some(found) => {
                // First part must match at the start
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }

    // Last part must match at the end
    if let Some(last) = parts.last()
        && !last.is_empty()
    {
        return value.ends_with(last);
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MappingRuleConfig;

    fn test_registry() -> ActionClassRegistry {
        ActionClassRegistry::v0_1()
    }

    fn test_rules_file() -> MappingRulesFile {
        MappingRulesFile {
            rules: vec![
                MappingRuleConfig {
                    method: Some("POST".to_string()),
                    host: "api.openai.com".to_string(),
                    path: Some("/v1/chat/completions".to_string()),
                    action_class: "llm.inference".to_string(),
                },
                MappingRuleConfig {
                    method: Some("POST".to_string()),
                    host: "api.anthropic.com".to_string(),
                    path: Some("/v1/messages".to_string()),
                    action_class: "llm.inference".to_string(),
                },
                MappingRuleConfig {
                    method: Some("GET".to_string()),
                    host: "*".to_string(),
                    path: None,
                    action_class: "http.get".to_string(),
                },
                MappingRuleConfig {
                    method: Some("POST".to_string()),
                    host: "*".to_string(),
                    path: None,
                    action_class: "http.post".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_from_config_validates_action_classes() {
        let registry = test_registry();
        let bad_file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: None,
                host: "*".to_string(),
                path: None,
                action_class: "nonexistent.action".to_string(),
            }],
        };
        let result = MappingTable::from_config(&bad_file, &registry, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_specific_rule_matches_first() {
        let registry = test_registry();
        let table = MappingTable::from_config(&test_rules_file(), &registry, true)
            .unwrap_or_else(|e| panic!("{e}"));

        match table.find_match("POST", "api.openai.com", "/v1/chat/completions") {
            MatchResult::Matched(rule) => assert_eq!(rule.action_class, "llm.inference"),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn test_wildcard_rule_matches_unknown_host() {
        let registry = test_registry();
        let table = MappingTable::from_config(&test_rules_file(), &registry, true)
            .unwrap_or_else(|e| panic!("{e}"));

        match table.find_match("GET", "api.weather.com", "/forecast") {
            MatchResult::Matched(rule) => assert_eq!(rule.action_class, "http.get"),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn test_no_match_protected_returns_unclassified() {
        let registry = test_registry();
        // Table with only specific rules, no wildcard
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "llm.inference".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        assert!(matches!(
            table.find_match("GET", "unknown.host", "/"),
            MatchResult::UnclassifiedProtected
        ));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("api.openai.com", "api.openai.com"));
        assert!(!glob_match("api.openai.com", "api.anthropic.com"));
    }

    #[test]
    fn test_glob_match_wildcard_prefix() {
        assert!(glob_match("*.openai.com", "api.openai.com"));
        assert!(!glob_match("*.openai.com", "api.anthropic.com"));
    }

    #[test]
    fn test_glob_match_star_matches_all() {
        assert!(glob_match("*", "anything.at.all"));
    }

    #[test]
    fn test_glob_match_path_wildcard() {
        assert!(glob_match("/v1/*/completions", "/v1/chat/completions"));
        assert!(!glob_match("/v1/*/completions", "/v2/chat/completions"));
    }
}
