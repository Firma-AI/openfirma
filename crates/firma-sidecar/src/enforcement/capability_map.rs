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

use std::cmp::Ordering;
use std::collections::HashMap;

use firma_core::CapabilityClaims;
#[cfg(test)]
use firma_core::TokenId;

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
    /// # Note on `session_id`
    ///
    /// `session_id` is part of the selection key per ADR-002 to support
    /// multi-agent-per-sidecar deployments where a single map may hold tokens
    /// from multiple sessions. Entries whose `claims.session_id` does not match
    /// the request session are skipped, so a request from session B cannot
    /// select a token minted for session A.
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if no capability token matches the
    /// requested action class and resource.
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    pub fn select(
        &self,
        session_id: &str,
        action_class: &str,
        resource: &str,
    ) -> Result<&CapabilityEntry, EnforcementDecision> {
        let mut best_match: Option<(u32, &CapabilityEntry)> = None;

        let exact_indices = self.by_action.get(action_class);

        if let Some(indices) = exact_indices {
            for &idx in indices {
                let entry = &self.entries[idx];
                if entry.claims.session_id.as_ref() != session_id {
                    continue;
                }
                let score = Self::match_score(&entry.claims, action_class, resource);
                if Self::should_replace(score, entry, best_match.as_ref()) {
                    best_match = Some((score, entry));
                }
            }
        }

        for &idx in &self.wildcard_indices {
            let entry = &self.entries[idx];
            if entry.claims.session_id.as_ref() != session_id {
                continue;
            }
            let score = Self::match_score(&entry.claims, action_class, resource);
            if Self::should_replace(score, entry, best_match.as_ref()) {
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
        } else if resource_scope_matches(&claims.resource_scope, resource) {
            score += 50;
        } else if !claims.resource_scope.is_empty() {
            return 0;
        }

        score
    }

    fn should_replace(
        score: u32,
        entry: &CapabilityEntry,
        best_match: Option<&(u32, &CapabilityEntry)>,
    ) -> bool {
        if score == 0 {
            return false;
        }
        match best_match {
            None => true,
            Some((best_score, best_entry)) => {
                score > *best_score
                    || (score == *best_score
                        && Self::is_better_than(&entry.claims, &best_entry.claims))
            }
        }
    }

    /// ADR-002 tie-breaking: when two entries share the same primary score,
    /// prefer the narrowest scope, then the freshest token.
    ///
    /// 1. Fewer entries in `action_set` (least-privilege)
    /// 2. Non-wildcard `resource_scope` beats `"*"`
    /// 3. Latest `issued_at`
    fn is_better_than(candidate: &CapabilityClaims, current: &CapabilityClaims) -> bool {
        match candidate.action_set.len().cmp(&current.action_set.len()) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }

        let cand_specific = candidate.resource_scope != "*";
        let curr_specific = current.resource_scope != "*";
        match (cand_specific, curr_specific) {
            (true, false) => return true,
            (false, true) => return false,
            _ => {}
        }

        candidate.issued_at > current.issued_at
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

/// Check whether a `resource_scope` pattern authorizes access to `resource`.
///
/// Unlike raw `str::starts_with`, this enforces **host boundary** semantics
/// to prevent subdomain / path-extension bypasses (T-002).
///
/// Scope patterns take the form `<host>[/<path>]`:
///
/// | Scope pattern            | Resource                               | Match |
/// |--------------------------|-----------------------------------------|-------|
/// | `"*"`                    | (any)                                   | yes   |
/// | `"api.example.com"`      | `"api.example.com/v1/chat"`            | yes   |
/// | `"api.example.com"`      | `"api.example.com.evil.com/v1/chat"`   | **no**|
/// | `"api.example.com/v1"`   | `"api.example.com/v1/chat"`            | yes   |
/// | `"api.example.com/v1"`   | `"api.example.com/v2/chat"`            | **no**|
/// | `"*.example.com"`        | `"api.example.com/v1/chat"`           | yes   |
/// | `"*.example.com"`        | `"example.com/v1/chat"`                | **no**|
fn resource_scope_matches(scope: &str, resource: &str) -> bool {
    if scope == "*" {
        return true;
    }

    let (scope_host, scope_path) = split_host_path(scope);
    let (res_host, res_path) = split_host_path(resource);

    if !host_matches(scope_host, res_host) {
        return false;
    }

    if scope_path.is_empty() {
        return true;
    }

    res_path.starts_with(scope_path)
        && (res_path.len() == scope_path.len()
            || res_path.as_bytes().get(scope_path.len()) == Some(&b'/'))
}

/// Split a resource identifier into `(host, path)` at the first `/`.
///
/// `"api.example.com/v1/chat"` → `("api.example.com", "/v1/chat")`
/// `"api.example.com"`         → `("api.example.com", "")`
fn split_host_path(s: &str) -> (&str, &str) {
    match s.find('/') {
        Some(idx) => (&s[..idx], &s[idx..]),
        None => (s, ""),
    }
}

/// Match a scope host pattern against a resource host.
///
/// - Exact match: `scope_host == res_host`
/// - Wildcard prefix: `*.example.com` matches `api.example.com` but **not**
///   `example.com` (requires at least one subdomain label)
fn host_matches(scope_host: &str, res_host: &str) -> bool {
    if let Some(suffix) = scope_host.strip_prefix("*.") {
        if res_host == suffix {
            return false;
        }
        res_host.ends_with(suffix) && res_host.ends_with(&format!(".{suffix}"))
    } else {
        scope_host == res_host
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn test_claims(actions: Vec<&str>, resource_scope: &str) -> CapabilityClaims {
        CapabilityClaims {
            token_id: "3713c5fc-b569-650c-c780-c64051473370"
                .parse()
                .expect("literal token id"),
            agent_id: "agent_test".parse().expect("literal agent id"),
            session_id: "sess_001".parse().expect("literal session id"),
            action_set: actions.into_iter().map(String::from).collect(),
            resource_scope: resource_scope.to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
            budget_ceiling: None,
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
            test_entry(vec!["communication.external.send"], "api.openai.com"),
            test_entry(vec!["filesystem.read"], "*"),
        ]);

        let result = map.select(
            "sess_001",
            "communication.external.send",
            "api.openai.com/v1/chat",
        );
        assert!(result.is_ok());
        let entry = result.unwrap_or_else(|_| panic!("expected Ok"));
        assert!(
            entry
                .claims
                .action_set
                .contains(&"communication.external.send".to_string())
        );
    }

    #[test]
    fn test_select_wildcard_action() {
        let map = CapabilityMap::new(vec![test_entry(vec!["*"], "*")]);

        let result = map.select("sess_001", "payment.transfer", "any.resource");
        assert!(result.is_ok());
    }

    #[test]
    fn test_select_no_match_returns_deny() {
        let map = CapabilityMap::new(vec![test_entry(vec!["communication.external.send"], "*")]);

        let result = map.select("sess_001", "filesystem.delete", "any.resource");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert!(decision.is_deny());
    }

    #[test]
    fn test_select_prefers_specific_over_wildcard() {
        let map = CapabilityMap::new(vec![
            test_entry(vec!["*"], "*"),
            test_entry(vec!["communication.external.send"], "api.openai.com"),
        ]);

        let result = map.select(
            "sess_001",
            "communication.external.send",
            "api.openai.com/v1/chat",
        );
        assert!(result.is_ok());
        let entry = result.unwrap_or_else(|_| panic!("expected Ok"));
        // Should prefer the specific token over wildcard
        assert_eq!(entry.claims.resource_scope, "api.openai.com");
    }

    fn entry_with_issued(
        token_id: &str,
        actions: Vec<&str>,
        resource_scope: &str,
        issued_at: chrono::DateTime<Utc>,
    ) -> CapabilityEntry {
        CapabilityEntry {
            raw_token: format!("v4.public.{token_id}"),
            claims: CapabilityClaims {
                token_id: TokenId::new(),
                agent_id: "agent_test".parse().expect("literal agent id"),
                session_id: "sess_001".parse().expect("literal session id"),
                action_set: actions.into_iter().map(String::from).collect(),
                resource_scope: resource_scope.to_string(),
                issued_at,
                expiry: issued_at + chrono::Duration::hours(1),
                context_hash: String::new(),
                budget_ceiling: None,
            },
        }
    }

    #[test]
    fn test_tiebreak_prefers_narrower_action_set() {
        let now = Utc::now();
        let wide = entry_with_issued(
            "wide",
            vec!["communication.external.send", "filesystem.read"],
            "*",
            now,
        );
        let narrow = entry_with_issued("narrow", vec!["communication.external.send"], "*", now);

        // Insert wide first — without tie-breaking it would win by insertion order
        let map = CapabilityMap::new(vec![wide, narrow]);
        let result = map
            .select("sess_001", "communication.external.send", "any.resource")
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(result.raw_token, "v4.public.narrow");
    }

    #[test]
    fn test_tiebreak_prefers_specific_resource() {
        let now = Utc::now();
        let wildcard_res =
            entry_with_issued("wild_r", vec!["communication.external.send"], "*", now);
        let specific_res = entry_with_issued(
            "spec_r",
            vec!["communication.external.send"],
            "api.openai.com",
            now,
        );

        // Both have exact action match; wildcard resource scores 101, specific scores 150.
        // These actually have *different* primary scores, so test the reverse:
        // two wildcard-resource tokens where scope size differs.
        let broad = entry_with_issued(
            "broad",
            vec!["communication.external.send", "filesystem.read"],
            "*",
            now,
        );
        let slim = entry_with_issued("slim", vec!["communication.external.send"], "*", now);

        // Both score 101 (exact action + wildcard resource). Tie-break: slim has
        // fewer actions.
        let map = CapabilityMap::new(vec![broad, slim]);
        let result = map
            .select("sess_001", "communication.external.send", "some.resource")
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(result.raw_token, "v4.public.slim");

        // Now two tokens with same action_set size: one wildcard, one specific
        // resource. Primary scores differ here (101 vs 150) so the specific one
        // wins by score, not by tie-breaking. Verify the primary scoring still works.
        let map2 = CapabilityMap::new(vec![wildcard_res, specific_res]);
        let result2 = map2
            .select(
                "sess_001",
                "communication.external.send",
                "api.openai.com/v1/chat",
            )
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(result2.raw_token, "v4.public.spec_r");
    }

    #[test]
    fn test_tiebreak_prefers_latest_issued_at() {
        let old = Utc::now() - chrono::Duration::hours(2);
        let new = Utc::now();

        let stale = entry_with_issued("stale", vec!["communication.external.send"], "*", old);
        let fresh = entry_with_issued("fresh", vec!["communication.external.send"], "*", new);

        // Insert stale first — same score, same action_set size, same resource
        // specificity. Tie-break on issued_at: fresh wins.
        let map = CapabilityMap::new(vec![stale, fresh]);
        let result = map
            .select("sess_001", "communication.external.send", "any.resource")
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(result.raw_token, "v4.public.fresh");
    }

    #[test]
    fn test_tiebreak_three_way_deterministic() {
        let t1 = Utc::now() - chrono::Duration::hours(3);
        let t2 = Utc::now() - chrono::Duration::hours(1);
        let t3 = Utc::now();

        let a = entry_with_issued("a", vec!["communication.external.send"], "*", t1);
        let b = entry_with_issued("b", vec!["communication.external.send"], "*", t3);
        let c = entry_with_issued("c", vec!["communication.external.send"], "*", t2);

        // All identical except issued_at. b is freshest.
        // Try both orderings to verify order-independence.
        let map1 = CapabilityMap::new(vec![a.clone(), b.clone(), c.clone()]);
        let r1 = map1
            .select("sess_001", "communication.external.send", "any.resource")
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(r1.raw_token, "v4.public.b");

        let map2 = CapabilityMap::new(vec![c, a, b]);
        let r2 = map2
            .select("sess_001", "communication.external.send", "any.resource")
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(r2.raw_token, "v4.public.b");
    }

    #[test]
    fn test_select_resource_scope_mismatch_rejected() {
        // Token scoped to "api.stripe.com" should not match "api.openai.com"
        let map = CapabilityMap::new(vec![test_entry(
            vec!["communication.external.send"],
            "api.stripe.com",
        )]);

        let result = map.select(
            "sess_001",
            "communication.external.send",
            "api.openai.com/v1/chat",
        );
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert!(decision.is_deny());
    }

    #[test]
    fn test_select_resource_scope_prefix_match() {
        let map = CapabilityMap::new(vec![test_entry(
            vec!["communication.external.send"],
            "api.openai.com",
        )]);

        let result = map.select(
            "sess_001",
            "communication.external.send",
            "api.openai.com/v1/chat",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_select_empty_map_returns_deny() {
        let map = CapabilityMap::new(vec![]);
        let result = map.select("sess_001", "communication.external.send", "any.resource");
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(
            decision.stage(),
            Some(EnforcementStage::CapabilityValidation(
                CapabilityValidationStage::TokenSelection,
            ))
        );
    }

    #[test]
    fn test_select_multiple_resource_scopes_picks_best() {
        let now = Utc::now();
        let wildcard = entry_with_issued("wild", vec!["communication.external.send"], "*", now);
        let specific = entry_with_issued(
            "specific",
            vec!["communication.external.send"],
            "api.openai.com",
            now,
        );

        let map = CapabilityMap::new(vec![wildcard, specific]);
        let result = map
            .select(
                "sess_001",
                "communication.external.send",
                "api.openai.com/v1/chat",
            )
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(result.raw_token, "v4.public.specific");
    }

    #[test]
    fn test_len_and_is_empty() {
        let empty_map = CapabilityMap::new(vec![]);
        assert!(empty_map.is_empty());
        assert_eq!(empty_map.len(), 0);

        let map = CapabilityMap::new(vec![test_entry(vec!["filesystem.read"], "*")]);
        assert!(!map.is_empty());
        assert_eq!(map.len(), 1);
    }

    // ===== T-002: Resource scope boundary enforcement tests =====

    #[test]
    fn test_resource_scope_matches_wildcard_allows_any() {
        assert!(resource_scope_matches("*", "anything.example.com/path"));
    }

    #[test]
    fn test_resource_scope_matches_exact_host_with_path() {
        assert!(resource_scope_matches(
            "api.example.com",
            "api.example.com/v1/chat"
        ));
    }

    #[test]
    fn test_resource_scope_matches_exact_host_without_path() {
        assert!(resource_scope_matches("api.example.com", "api.example.com"));
    }

    #[test]
    fn test_resource_scope_rejects_subdomain_extension() {
        assert!(!resource_scope_matches(
            "api.example.com",
            "api.example.com.evil.com/v1/chat"
        ));
    }

    #[test]
    fn test_resource_scope_rejects_host_prefix_extension() {
        assert!(!resource_scope_matches(
            "api.example.com",
            "xapi.example.com/v1/chat"
        ));
    }

    #[test]
    fn test_resource_scope_matches_scoped_path() {
        assert!(resource_scope_matches(
            "api.example.com/v1",
            "api.example.com/v1/chat"
        ));
    }

    #[test]
    fn test_resource_scope_rejects_different_path_branch() {
        assert!(!resource_scope_matches(
            "api.example.com/v1",
            "api.example.com/v2/chat"
        ));
    }

    #[test]
    fn test_resource_scope_rejects_path_prefix_without_separator() {
        assert!(!resource_scope_matches(
            "api.example.com/v1",
            "api.example.com/v1alpha/chat"
        ));
    }

    #[test]
    fn test_resource_scope_wildcard_host_matches_subdomain() {
        assert!(resource_scope_matches(
            "*.example.com",
            "api.example.com/v1/chat"
        ));
    }

    #[test]
    fn test_resource_scope_wildcard_host_rejects_bare_domain() {
        assert!(!resource_scope_matches(
            "*.example.com",
            "example.com/v1/chat"
        ));
    }

    #[test]
    fn test_resource_scope_wildcard_host_rejects_unrelated_domain() {
        assert!(!resource_scope_matches(
            "*.example.com",
            "api.notexample.com/v1/chat"
        ));
    }

    #[test]
    fn test_resource_scope_wildcard_host_deep_subdomain() {
        assert!(resource_scope_matches(
            "*.example.com",
            "deep.api.example.com/v1/chat"
        ));
    }

    #[test]
    fn test_resource_scope_rejects_different_host() {
        assert!(!resource_scope_matches(
            "api.openai.com",
            "api.anthropic.com/v1/chat"
        ));
    }

    #[test]
    fn test_host_matches_exact() {
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(!host_matches("api.example.com", "other.example.com"));
    }

    #[test]
    fn test_host_matches_wildcard() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "deep.api.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "notexample.com"));
    }

    #[test]
    fn test_split_host_path() {
        assert_eq!(
            split_host_path("api.example.com/v1/chat"),
            ("api.example.com", "/v1/chat")
        );
        assert_eq!(split_host_path("api.example.com"), ("api.example.com", ""));
        assert_eq!(split_host_path(""), ("", ""));
    }

    #[test]
    fn test_select_rejects_subdomain_bypass() {
        let map = CapabilityMap::new(vec![
            test_entry(vec!["llm.inference"], "api.openai.com"),
            test_entry(vec!["http.get"], "*"),
        ]);

        let result = map.select(
            "sess_001",
            "llm.inference",
            "api.openai.com.evil.com/v1/chat",
        );
        assert!(
            result.is_err(),
            "subdomain extension must not match scope for api.openai.com"
        );
    }
}
