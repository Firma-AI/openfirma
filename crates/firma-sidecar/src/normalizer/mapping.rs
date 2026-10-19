//! Mapping table for intent normalization.
//!
//! Compiled from each accepted Authority snapshot. Each rule maps an HTTP
//! method + host + path pattern to a canonical action class from the
//! Canonical Action Class Registry v0.1. Rules are sorted by descending
//! specificity so that the first match wins.
//!
//! The `intent.action_class` field produced by the normalizer MUST be one of
//! the configured registry identifiers. Unknown protected actions that cannot
//! be deterministically mapped to a registry entry fail closed with
//! `DENY: UNCLASSIFIED_INTENT` (FEP \[I-N1\]).

use firma_http::{Authority, Method};

use crate::config::{MappingRuleConfig, MappingRulesFile};
use crate::enforcement::registry::ActionClassRegistry;

/// Errors that can occur while building a [`MappingTable`] from configuration.
#[derive(Debug, thiserror::Error)]
pub enum MappingTableError {
    /// The mapping rules file itself failed validation (malformed host,
    /// malformed rule, invalid HTTP method, etc).
    #[error("invalid mapping rules file: {0}")]
    InvalidRulesFile(String),

    /// Two rules share the same `(method, host, path)` tuple, which
    /// makes classification ambiguous.
    #[error(
        "rule {index}: duplicate mapping tuple method={:?} host={:?} path={:?}",
        rule.method.as_ref().map(|method| method.as_str()).unwrap_or_default(),
        rule.host,
        rule.path.as_deref().unwrap_or_default()
    )]
    DuplicateRule {
        index: usize,
        rule: MappingRuleConfig,
    },

    /// A rule references an action class outside the built-in FEP
    /// registry.
    #[error(
        "rule {index}: action class '{}' is not in the built-in FEP action class registry.\n\
         Note: schema_path in [authority] only affects Cedar policy validation in the \
         Authority — it does not extend this registry, which is fixed when the Sidecar \
         loads.\nTo use this action class in a mapping rule, add it to the registry first.\n\
         See: https://firma-ai.github.io/openfirma/guides/extend-mapping/",
        rule.action_class
    )]
    NonExistingActionClass {
        index: usize,
        rule: MappingRuleConfig,
    },
}

/// A validated mapping rule ready for matching.
#[derive(Debug, Clone)]
pub struct MappingRule {
    pub method: Option<Method>,
    pub host_pattern: String,
    pub path_pattern: Option<String>,
    pub action_class: String,
    specificity: usize,
}

/// Collection of validated, specificity-ordered mapping rules.
///
/// Compiled once per accepted snapshot and immutable afterwards.
#[derive(Debug, Clone)]
pub struct MappingTable {
    rules: Vec<MappingRule>,
}

/// The result of matching a request against the mapping table.
#[derive(Debug)]
pub enum MatchResult<'a> {
    /// Matched a rule — use this action class.
    Matched(&'a MappingRule),
    /// No rule matched and the host is protected — deny as unclassified.
    UnclassifiedProtected,
}

impl MappingRule {
    fn compute_specificity(method: Option<&Method>, host: &str, path: Option<&String>) -> usize {
        firma_core::mapping_specificity(method.is_some(), host, path.map(String::as_str))
    }
}

impl MappingTable {
    /// An explicit managed snapshot with no rules still protects all traffic.
    pub(crate) fn empty_protected() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load and validate mapping rules from a parsed config.
    ///
    /// Host patterns are normalized like runtime request hosts (lowercased,
    /// trailing dot stripped): request hosts arrive in that form, so an
    /// unnormalized pattern such as `API.GitHub.COM.` could never match
    /// anything and would sit in the table as a dead rule.
    ///
    /// # Errors
    /// Returns an error if the rules are structurally invalid or
    /// ambiguous. Empty rules are protected deny-all.
    pub fn from_config(
        file: &MappingRulesFile,
        registry: &ActionClassRegistry,
    ) -> Result<Self, MappingTableError> {
        file.validate()
            .map_err(MappingTableError::InvalidRulesFile)?;

        Self::compile(file, registry)
    }

    /// Compile a complete managed rule list, including a protected empty list.
    ///
    /// Managed snapshots must arrive normalized: hosts are already lowercased
    /// without trailing dots or default ports, and paths are already checked
    /// for NUL and length. A non-canonical spelling is a producer bug and
    /// fails closed here instead of being silently normalized like local
    /// files, which remain forgiving for operator-authored configuration.
    ///
    /// # Errors
    /// Rejects malformed rules, unknown action classes, and duplicate matchers.
    pub fn from_managed_rules(rules: Vec<MappingRuleConfig>) -> Result<Self, MappingTableError> {
        let file = MappingRulesFile { rules };
        for (index, rule) in file.rules.iter().enumerate() {
            firma_core::mapping::validate_managed_rule(
                rule.method.as_ref().map(|method| method.as_str()),
                &rule.host,
                rule.path.as_deref(),
                &rule.action_class,
            )
            .map_err(|error| {
                MappingTableError::InvalidRulesFile(format!("rule {index}: {error}"))
            })?;
        }
        Self::compile(&file, &ActionClassRegistry::v0_1())
    }

    fn compile(
        file: &MappingRulesFile,
        registry: &ActionClassRegistry,
    ) -> Result<Self, MappingTableError> {
        // Duplicate (method, host, path) tuple detection. Two rules
        // with the same triple across merged mapping files produces
        // ambiguous classification — fail-closed at startup. Hosts are
        // compared in normalized form so case or trailing-dot variants of
        // the same rule cannot slip past the check.
        let mut seen: std::collections::HashSet<(Option<Method>, String, String)> =
            std::collections::HashSet::new();
        for (i, rule_cfg) in file.rules.iter().enumerate() {
            let key = (
                rule_cfg.method.clone(),
                normalize_host_pattern(&rule_cfg.host),
                rule_cfg.path.clone().unwrap_or_default(),
            );
            if !seen.insert(key) {
                return Err(MappingTableError::DuplicateRule {
                    index: i,
                    rule: rule_cfg.clone(),
                });
            }
        }

        let mut rules = Vec::with_capacity(file.rules.len());

        for (i, rule_cfg) in file.rules.iter().enumerate() {
            if !registry.contains(&rule_cfg.action_class) {
                return Err(MappingTableError::NonExistingActionClass {
                    index: i,
                    rule: rule_cfg.clone(),
                });
            }

            let host_pattern = normalize_host_pattern(&rule_cfg.host);
            let specificity = MappingRule::compute_specificity(
                rule_cfg.method.as_ref(),
                &host_pattern,
                rule_cfg.path.as_ref(),
            );

            rules.push(MappingRule {
                method: rule_cfg.method.clone(),
                host_pattern,
                path_pattern: rule_cfg.path.clone(),
                action_class: rule_cfg.action_class.clone(),
                specificity,
            });
        }

        // Sort by descending specificity (most specific first)
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.specificity));

        Ok(Self { rules })
    }

    /// Find the first (most specific) matching rule for a request.
    #[must_use]
    pub fn find_match<'a>(
        &'a self,
        method: &Method,
        host: &Authority,
        path: &str,
    ) -> MatchResult<'a> {
        for rule in &self.rules {
            if Self::rule_matches(rule, method, host, path) {
                return MatchResult::Matched(rule);
            }
        }

        MatchResult::UnclassifiedProtected
    }

    fn rule_matches(rule: &MappingRule, method: &Method, host: &Authority, path: &str) -> bool {
        // Check method (None = any method)
        if rule
            .method
            .as_ref()
            .is_some_and(|rule_method| rule_method != method)
        {
            return false;
        }

        // Check host pattern
        if !glob_match(&rule.host_pattern, host.as_str()) {
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

/// Normalize a host or rule host pattern into its canonical matching form.
///
/// This is [`firma_core::normalize_mapping_host`], re-exported so runtime
/// request hosts, rule host patterns, and config validation can never
/// disagree on what a spelling means.
pub use firma_core::normalize_mapping_host as normalize_host_pattern;

/// Normalize a request host into the authority used for outbound dispatch.
///
/// Splits the authority with [`firma_core::split_mapping_authority`], but drops
/// the port only when it is the default for the request's *actual* scheme
/// (`443` for HTTPS, `80` for HTTP) rather than either default. An explicit
/// port that names the opposite scheme's default — `:443` on a plain HTTP
/// request, or `:80` on HTTPS — is not this request's default port and must
/// be preserved, since the connector dispatches to exactly the authority
/// stored in the normalized envelope's resource host.
pub fn normalize_dispatch_host(host: &str, is_https: bool) -> String {
    let (name, port) = firma_core::split_mapping_authority(host);
    let default_port = if is_https { "443" } else { "80" };
    match port.as_deref() {
        Some(port) if port != default_port => format!("{name}:{port}"),
        _ => name,
    }
}

/// Simple glob matching where `*` matches any sequence of characters.
///
/// Shared with `firma-secret-provider`'s `HttpIntegrationSpec` host/path
/// matching (a distinct crate this one already depends on) rather than
/// reimplemented here, so the two never silently diverge.
pub use firma_core::glob_match;

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use pretty_assertions::assert_matches;

    use super::*;
    use crate::config::MappingRuleConfig;

    #[test]
    fn mapping_rules_rejects_nonexisting_action_class() {
        let bad_file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: None,
                host: "*".to_string(),
                path: None,
                action_class: "nonexistent.action".to_string(),
            }],
        };
        let err = MappingTable::from_config(&bad_file, &ActionClassRegistry::v0_1()).unwrap_err();
        assert_matches!(
            err,
            MappingTableError::NonExistingActionClass { index: 0, ref rule }
                if rule.action_class == "nonexistent.action"
        );
        assert_snapshot!(err.to_string(), @"
        rule 0: action class 'nonexistent.action' is not in the built-in FEP action class registry.
        Note: schema_path in [authority] only affects Cedar policy validation in the Authority — it does not extend this registry, which is fixed when the Sidecar loads.
        To use this action class in a mapping rule, add it to the registry first.
        See: https://firma-ai.github.io/openfirma/guides/extend-mapping/
        ");
    }

    #[test]
    fn duplicated_mapping_rule_is_rejected() {
        let file = MappingRulesFile {
            rules: vec![
                MappingRuleConfig {
                    method: Some(Method::GET),
                    host: "api.github.com".to_string(),
                    path: Some("/repos/*/*".to_string()),
                    action_class: "code.read".to_string(),
                },
                MappingRuleConfig {
                    method: Some(Method::GET),
                    host: "api.github.com".to_string(),
                    path: Some("/repos/*/*".to_string()),
                    action_class: "code.review.read".to_string(),
                },
            ],
        };
        let err = MappingTable::from_config(&file, &ActionClassRegistry::v0_1()).unwrap_err();
        assert_matches!(
            err,
            MappingTableError::DuplicateRule { index: 1, ref rule }
                if rule.action_class == "code.review.read"
        );
        assert_snapshot!(err.to_string(), @r#"rule 1: duplicate mapping tuple method="GET" host="api.github.com" path="/repos/*/*""#);
    }

    #[test]
    fn specific_rule_matches_first() {
        let file = MappingRulesFile {
            rules: vec![
                MappingRuleConfig {
                    method: Some(Method::POST),
                    host: "*".to_string(),
                    path: None,
                    action_class: "communication.internal.send".to_string(),
                },
                MappingRuleConfig {
                    method: Some(Method::POST),
                    host: "api.openai.com".to_string(),
                    path: Some("/v1/chat/completions".to_string()),
                    action_class: "communication.external.send".to_string(),
                },
            ],
        };
        let table = MappingTable::from_config(&file, &ActionClassRegistry::v0_1()).unwrap();

        match table.find_match(
            &Method::POST,
            &Authority::from_static("api.openai.com"),
            "/v1/chat/completions",
        ) {
            MatchResult::Matched(rule) => {
                assert_eq!(rule.action_class, "communication.external.send");
            }
            other @ MatchResult::UnclassifiedProtected => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_rule_matches_unknown_host() {
        let file = MappingRulesFile {
            rules: vec![
                MappingRuleConfig {
                    method: Some(Method::GET),
                    host: "api.other.com".to_string(),
                    path: None,
                    action_class: "communication.internal.send".to_string(),
                },
                MappingRuleConfig {
                    method: Some(Method::GET),
                    host: "*".to_string(),
                    path: None,
                    action_class: "filesystem.read".to_string(),
                },
            ],
        };
        let table = MappingTable::from_config(&file, &ActionClassRegistry::v0_1()).unwrap();

        match table.find_match(
            &Method::GET,
            &Authority::from_static("api.weather.com"),
            "/forecast",
        ) {
            MatchResult::Matched(rule) => assert_eq!(rule.action_class, "filesystem.read"),
            other @ MatchResult::UnclassifiedProtected => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn no_match_protected_returns_unclassified() {
        // Table with only specific rules, no wildcard
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table = MappingTable::from_config(&file, &ActionClassRegistry::v0_1()).unwrap();

        assert!(matches!(
            table.find_match(&Method::GET, &Authority::from_static("unknown.host"), "/"),
            MatchResult::UnclassifiedProtected
        ));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("api.openai.com", "api.openai.com"));
        assert!(!glob_match("api.openai.com", "api.anthropic.com"));
    }

    #[test]
    fn glob_match_wildcard_prefix() {
        assert!(glob_match("*.openai.com", "api.openai.com"));
        assert!(!glob_match("*.openai.com", "api.anthropic.com"));
    }

    #[test]
    fn glob_match_star_matches_all() {
        assert!(glob_match("*", "anything.at.all"));
    }

    #[test]
    fn glob_match_path_wildcard() {
        assert!(glob_match("/v1/*/completions", "/v1/chat/completions"));
        assert!(!glob_match("/v1/*/completions", "/v2/chat/completions"));
    }
}
