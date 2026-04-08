//! Capability token selection map.
//!
//! Holds pre-provisioned capability tokens issued by the Authority at
//! pre-flight and selects the best match for each intercepted request
//! based on action class and resource scope (ADR-002).
//!
//! Tokens are indexed by action class at construction time so that
//! per-request lookups avoid a full linear scan. The agent knows nothing
//! about Firma — the sidecar selects the correct token internally after
//! intent normalization.

use std::collections::HashMap;

use firma_core::CapabilityClaims;

use crate::enforcement::decision::{
    CapabilityValidationStage, EnforcementDecision, EnforcementStage,
};
use crate::enforcement::error::EnforcementError;

/// A pre-provisioned capability token with pre-parsed claims.
#[derive(Debug, Clone)]
pub struct CapabilityEntry {
    /// Raw signed token string for Stage 1 validation.
    pub raw_token: String,
    /// Pre-parsed claims for fast selection (parsed at load time).
    pub claims: CapabilityClaims,
}

/// Holds pre-provisioned capability tokens and selects the best match
/// based on action class and resource.
///
/// Tokens are indexed by action class at construction time so that
/// `select()` only scores the subset of entries that can possibly match,
/// avoiding a full linear scan on every request.
///
/// The agent knows nothing about Firma — the sidecar selects the correct
/// token internally after intent normalization (ADR-002).
#[derive(Debug)]
pub struct CapabilityMap {
    entries: Vec<CapabilityEntry>,
    /// `action_class` → indices into `entries` that list that action
    by_action: HashMap<String, Vec<usize>>,
    /// indices of entries whose `action_set` contains the wildcard `"*"`
    wildcard_indices: Vec<usize>,
}

impl CapabilityMap {
    /// Create a new capability map from pre-provisioned entries.
    ///
    /// Builds the action-class index at construction time (O(n·k) where
    /// k = average `action_set` size) so that per-request lookups are fast.
    #[must_use]
    pub fn new(entries: Vec<CapabilityEntry>) -> Self {
        let mut by_action: HashMap<String, Vec<usize>> = HashMap::new();
        let mut wildcard_indices = Vec::new();

        for (idx, entry) in entries.iter().enumerate() {
            for action in &entry.claims.action_set {
                if action == "*" {
                    wildcard_indices.push(idx);
                } else {
                    by_action.entry(action.clone()).or_default().push(idx);
                }
            }
        }

        Self {
            entries,
            by_action,
            wildcard_indices,
        }
    }

    /// Select the best-matching token for the given action and resource.
    ///
    /// Selection rules (most specific wins):
    /// 1. Token whose `action_set` contains the exact `action_class` AND `resource_scope` matches
    /// 2. Token whose `action_set` contains the exact `action_class` (any resource)
    /// 3. Token with wildcard `action_set` ("*")
    /// 4. No match -> DENY
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if no capability token matches the
    /// requested action class and resource.
    #[allow(clippy::result_large_err)]
    pub fn select(
        &self,
        _session_id: &str,
        action_class: &str,
        resource: &str,
    ) -> Result<&CapabilityEntry, EnforcementDecision> {
        let mut best_match: Option<(u32, &CapabilityEntry)> = None;

        let exact_indices = self.by_action.get(action_class);

        // Score exact-action candidates
        if let Some(indices) = exact_indices {
            for &idx in indices {
                let entry = &self.entries[idx];
                let score = Self::match_score(&entry.claims, action_class, resource);
                if score > 0 && best_match.is_none_or(|(best, _)| score > best) {
                    best_match = Some((score, entry));
                }
            }
        }

        // Score wildcard candidates (only if no exact-action match with
        // resource scope, or wildcard could still win on resource specificity)
        for &idx in &self.wildcard_indices {
            let entry = &self.entries[idx];
            let score = Self::match_score(&entry.claims, action_class, resource);
            if score > 0 && best_match.is_none_or(|(best, _)| score > best) {
                best_match = Some((score, entry));
            }
        }

        best_match.map(|(_, entry)| entry).ok_or_else(|| {
            EnforcementError::NoMatchingToken {
                detail: format!(
                    "no capability token covers action '{action_class}' on resource '{resource}'"
                ),
            }
            .into_deny(EnforcementStage::CapabilityValidation(
                CapabilityValidationStage::TokenSelection,
            ))
        })
    }

    fn match_score(claims: &CapabilityClaims, action_class: &str, resource: &str) -> u32 {
        let has_wildcard_action = claims.action_set.iter().any(|a| a == "*");
        let has_exact_action = claims.action_set.iter().any(|a| a == action_class);

        if !has_exact_action && !has_wildcard_action {
            return 0;
        }

        let mut score = 0u32;

        if has_exact_action {
            score += 100;
        } else {
            score += 10;
        }

        if claims.resource_scope == "*" {
            score += 1;
        } else if resource.starts_with(&claims.resource_scope) {
            score += 50;
        } else if !claims.resource_scope.is_empty() {
            return 0;
        }

        score
    }

    /// Return the number of entries in the map.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn test_claims(actions: Vec<&str>, resource_scope: &str) -> CapabilityClaims {
        CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent_test".to_string(),
            session_id: "sess_001".to_string(),
            action_set: actions.into_iter().map(String::from).collect(),
            resource_scope: resource_scope.to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    fn test_entry(actions: Vec<&str>, resource_scope: &str) -> CapabilityEntry {
        CapabilityEntry {
            raw_token: "v4.public.test_token".to_string(),
            claims: test_claims(actions, resource_scope),
        }
    }

    #[test]
    fn test_select_exact_action_match() {
        let map = CapabilityMap::new(vec![
            test_entry(vec!["llm.inference"], "api.openai.com"),
            test_entry(vec!["http.get"], "*"),
        ]);

        let result = map.select("sess_001", "llm.inference", "api.openai.com/v1/chat");
        assert!(result.is_ok());
        let entry = result.unwrap_or_else(|_| panic!("expected Ok"));
        assert!(
            entry
                .claims
                .action_set
                .contains(&"llm.inference".to_string())
        );
    }

    #[test]
    fn test_select_wildcard_action() {
        let map = CapabilityMap::new(vec![test_entry(vec!["*"], "*")]);

        let result = map.select("sess_001", "db.query", "any.resource");
        assert!(result.is_ok());
    }

    #[test]
    fn test_select_no_match_returns_deny() {
        let map = CapabilityMap::new(vec![test_entry(vec!["llm.inference"], "*")]);

        let result = map.select("sess_001", "file.delete", "any.resource");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert!(decision.is_deny());
    }

    #[test]
    fn test_select_prefers_specific_over_wildcard() {
        let map = CapabilityMap::new(vec![
            test_entry(vec!["*"], "*"),
            test_entry(vec!["llm.inference"], "api.openai.com"),
        ]);

        let result = map.select("sess_001", "llm.inference", "api.openai.com/v1/chat");
        assert!(result.is_ok());
        let entry = result.unwrap_or_else(|_| panic!("expected Ok"));
        // Should prefer the specific token over wildcard
        assert_eq!(entry.claims.resource_scope, "api.openai.com");
    }
}
