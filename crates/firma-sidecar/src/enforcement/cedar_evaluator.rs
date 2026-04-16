//! Concrete Cedar policy evaluator for Sidecar Stage 2.
//!
//! Implements [`PolicyEvaluation`] by evaluating a compiled Cedar policy set
//! against the context produced by
//! [`ConstraintEnforcer::build_context`][super::constraint_enforcement::ConstraintEnforcer].
//!
//! Evaluation is fully local — no network calls. [`CedarPolicyEvaluator`] is
//! constructed from a [`PolicyBundle`] received from the Authority and tracks
//! freshness against the bundle TTL.
//!
//! # Entity UID conventions (must match Authority's service.rs)
//!
//! | Cedar role  | Format                               |
//! |-------------|--------------------------------------|
//! | `principal` | `Firma::Agent::"<agent_id>"`         |
//! | `action`    | `Firma::Action::"<action_class>"`    |
//! | `resource`  | `Firma::Resource::"<resource_uri>"`  |

use std::time::Instant;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use firma_core::agent::AgentId;
use firma_core::policy::PolicyBundle;

use super::constraint_enforcement::PolicyEvaluation;

/// Concrete Cedar policy evaluator for Sidecar Stage 2.
///
/// Constructed from a [`PolicyBundle`] received from the Authority via
/// `WatchPolicyBundle`. Tracks freshness against the bundle's `ttl_seconds`
/// and evaluates Cedar policies schema-lessly.
pub struct CedarPolicyEvaluator {
    policy_set: PolicySet,
    version: String,
    received_at: Instant,
    ttl_secs: u64,
}

impl CedarPolicyEvaluator {
    /// Construct from a [`PolicyBundle`] received from the Authority.
    ///
    /// Parses the Cedar policy source in `bundle.policies`. Fails fast if
    /// the bytes are not valid UTF-8 or contain invalid Cedar syntax — this
    /// matches the Authority's own fail-fast loading behaviour.
    ///
    /// # Errors
    ///
    /// Returns an error string if policy bytes are not valid UTF-8 or contain
    /// invalid Cedar syntax.
    pub fn from_bundle(bundle: &PolicyBundle) -> Result<Self, String> {
        let src = std::str::from_utf8(&bundle.policies)
            .map_err(|e| format!("policy bundle bytes are not valid UTF-8: {e}"))?;

        let policy_set = if src.trim().is_empty() {
            PolicySet::new()
        } else {
            src.parse::<PolicySet>()
                .map_err(|e| format!("failed to parse Cedar policies from bundle: {e}"))?
        };

        let ttl_secs = u64::try_from(bundle.ttl_seconds.max(0)).unwrap_or(0u64);

        Ok(Self {
            policy_set,
            version: bundle.version.clone(),
            received_at: Instant::now(),
            ttl_secs,
        })
    }

    /// Build a Cedar `EntityUid` for the principal (agent).
    fn agent_uid(agent_id: &str) -> Result<EntityUid, String> {
        format!("Firma::Agent::\"{}\"", agent_id)
            .parse::<EntityUid>()
            .map_err(|e| format!("invalid agent UID for '{agent_id}': {e}"))
    }

    /// Build a Cedar `EntityUid` for the action class.
    fn action_uid(action_class: &str) -> Result<EntityUid, String> {
        format!("Firma::Action::\"{}\"", action_class)
            .parse::<EntityUid>()
            .map_err(|e| format!("invalid action UID for '{action_class}': {e}"))
    }

    /// Build a Cedar `EntityUid` for the resource.
    fn resource_uid(resource: &str) -> Result<EntityUid, String> {
        format!("Firma::Resource::\"{}\"", resource)
            .parse::<EntityUid>()
            .map_err(|e| format!("invalid resource UID for '{resource}': {e}"))
    }
}

impl PolicyEvaluation for CedarPolicyEvaluator {
    /// Evaluate Cedar policies for the given principal, action, and resource.
    ///
    /// Context attributes (`action_class`, `resource`, `agent_id`,
    /// `session_id`, `timestamp`) are passed as a Cedar `Context` built
    /// from the JSON object produced by `ConstraintEnforcer::build_context`.
    ///
    /// Entity UIDs use the `Firma` namespace to match the Authority's issuance
    /// evaluation. No schema validation is performed on the request — policies
    /// that reference unknown attributes will receive Cedar's default deny.
    ///
    /// # Errors
    ///
    /// Returns an error string if entity UIDs cannot be parsed, the context
    /// cannot be built from the JSON value, or the Cedar request is invalid.
    fn evaluate(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> Result<bool, String> {
        let principal_uid = Self::agent_uid(principal.as_ref())?;
        let action_uid = Self::action_uid(action)?;
        let resource_uid = Self::resource_uid(resource)?;

        // Build Cedar Context from the JSON object produced by build_context().
        // Schema is None — no context attribute validation.
        let cedar_context = Context::from_json_value(context.clone(), None)
            .map_err(|e| format!("failed to build Cedar context: {e}"))?;

        // Schema is None — principal/action/resource types are not validated.
        let request = Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            cedar_context,
            None,
        )
        .map_err(|e| format!("failed to build Cedar request: {e}"))?;

        let entities = Entities::empty();
        let response = Authorizer::new().is_authorized(&request, &self.policy_set, &entities);

        Ok(matches!(response.decision(), Decision::Allow))
    }

    fn is_fresh(&self) -> bool {
        self.received_at.elapsed().as_secs() < self.ttl_secs
    }

    fn version(&self) -> Option<String> {
        Some(self.version.clone())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use firma_core::policy::PolicyBundle;
    use serde_json::json;

    fn permit_all_bundle() -> PolicyBundle {
        PolicyBundle::new(
            "test-v1".to_string(),
            b"permit(principal, action, resource);".to_vec(),
            vec![],
            30,
        )
    }

    fn forbid_all_bundle() -> PolicyBundle {
        PolicyBundle::new(
            "test-v2".to_string(),
            b"forbid(principal, action, resource);".to_vec(),
            vec![],
            30,
        )
    }

    fn empty_bundle() -> PolicyBundle {
        PolicyBundle::new("test-v0".to_string(), vec![], vec![], 30)
    }

    fn test_context() -> serde_json::Value {
        json!({
            "action_class": "llm.inference",
            "resource": "api.openai.com/v1/chat/completions",
            "agent_id": "agent_test",
            "session_id": "sess_001",
            "timestamp": "2025-01-01T00:00:00Z"
        })
    }

    fn agent(id: &str) -> AgentId {
        id.parse().unwrap()
    }

    #[test]
    fn from_bundle_permit_all() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();
        assert_eq!(evaluator.version(), Some("test-v1".to_string()));
        assert!(evaluator.is_fresh());
    }

    #[test]
    fn from_bundle_empty_policies_deny() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&empty_bundle()).unwrap();
        // Empty policy set — Cedar default deny.
        let result = evaluator
            .evaluate(
                &agent("agent_test"),
                "llm.inference",
                "api.openai.com",
                &test_context(),
            )
            .unwrap();
        assert!(!result, "empty policy set should deny");
    }

    #[test]
    fn from_bundle_invalid_syntax_fails_fast() {
        let bad = PolicyBundle::new(
            "bad".to_string(),
            b"this is not valid cedar {{{".to_vec(),
            vec![],
            30,
        );
        assert!(CedarPolicyEvaluator::from_bundle(&bad).is_err());
    }

    #[test]
    fn evaluate_permit_all_allows() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();
        let result = evaluator
            .evaluate(
                &agent("agent_test"),
                "llm.inference",
                "api.openai.com",
                &test_context(),
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn evaluate_forbid_all_denies() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&forbid_all_bundle()).unwrap();
        let result = evaluator
            .evaluate(
                &agent("agent_test"),
                "llm.inference",
                "api.openai.com",
                &test_context(),
            )
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn is_fresh_with_30s_ttl() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();
        // Just constructed — should be fresh with 30s TTL.
        assert!(evaluator.is_fresh());
    }

    #[test]
    fn is_stale_with_zero_ttl() {
        let zero_ttl = PolicyBundle::new("v0".to_string(), vec![], vec![], 0);
        let evaluator = CedarPolicyEvaluator::from_bundle(&zero_ttl).unwrap();
        // TTL = 0 means immediately stale.
        assert!(!evaluator.is_fresh());
    }

    #[test]
    fn version_returned() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();
        assert_eq!(evaluator.version(), Some("test-v1".to_string()));
    }

    #[test]
    fn context_attributes_accessible_in_policy() {
        // Policy that references context.action_class — verifies context is wired through.
        let src = br#"permit(principal, action, resource) when { context.action_class == "llm.inference" };"#;
        let bundle = PolicyBundle::new("ctx-v1".to_string(), src.to_vec(), vec![], 30);
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();

        // Matching action_class — should allow.
        let allow = evaluator
            .evaluate(
                &agent("agent_test"),
                "llm.inference",
                "api.openai.com",
                &test_context(),
            )
            .unwrap();
        assert!(allow);

        // Different action_class in context — should deny.
        let deny_context = json!({
            "action_class": "file.delete",
            "resource": "api.openai.com",
            "agent_id": "agent_test",
            "session_id": "sess_001",
            "timestamp": "2025-01-01T00:00:00Z"
        });
        let deny = evaluator
            .evaluate(&agent("agent_test"), "file.delete", "api.openai.com", &deny_context)
            .unwrap();
        assert!(!deny);
    }
}
