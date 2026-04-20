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

use std::fmt;
use std::time::Instant;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema,
};
use firma_core::agent::AgentId;
use firma_core::policy::PolicyBundle;

use super::constraint_enforcement::PolicyEvaluation;

/// A typed Cedar entity UID in the `Firma` namespace.
///
/// Encodes the three roles used in policy evaluation — agent (principal),
/// action, and resource — and produces the Cedar entity UID string via
/// [`Display`]. Call [`FirmaEntityUid::to_cedar`] to parse into a Cedar
/// [`EntityUid`] for request construction.
///
/// Conventions (must match Authority's `service.rs`):
///
/// | Variant   | Cedar format                          |
/// |-----------|---------------------------------------|
/// | `Agent`   | `Firma::Agent::"<id>"`                |
/// | `Action`  | `Firma::Action::"<id>"`               |
/// | `Resource`| `Firma::Resource::"<id>"`             |
pub(crate) enum FirmaEntityUid {
    Agent(String),
    Action(String),
    Resource(String),
}

impl FirmaEntityUid {
    /// Parse into a Cedar [`EntityUid`].
    ///
    /// # Errors
    ///
    /// Returns an error string if the id contains characters that make the
    /// Cedar entity UID string unparseable (e.g. unescaped quotes).
    pub(crate) fn to_cedar(&self) -> Result<EntityUid, String> {
        self.to_string()
            .parse::<EntityUid>()
            .map_err(|e| format!("invalid entity UID '{self}': {e}"))
    }
}

impl fmt::Display for FirmaEntityUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent(id) => write!(f, "Firma::Agent::\"{id}\""),
            Self::Action(id) => write!(f, "Firma::Action::\"{id}\""),
            Self::Resource(id) => write!(f, "Firma::Resource::\"{id}\""),
        }
    }
}

/// Concrete Cedar policy evaluator for Sidecar Stage 2.
///
/// Constructed from a [`PolicyBundle`] received from the Authority via
/// `WatchPolicyBundle`. Tracks freshness against the bundle's `ttl_seconds`
/// and evaluates Cedar policies schema-lessly.
pub struct CedarPolicyEvaluator {
    policy_set: PolicySet,
    schema: Option<Schema>,
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

        let schema = if bundle.entity_schema.is_empty() {
            None
        } else {
            let schema_src = std::str::from_utf8(&bundle.entity_schema)
                .map_err(|e| format!("schema bytes are not valid UTF-8: {e}"))?;
            let (schema, _warnings) = Schema::from_cedarschema_str(schema_src)
                .map_err(|e| format!("failed to parse Cedar schema from bundle: {e}"))?;
            Some(schema)
        };

        Ok(Self {
            policy_set,
            schema,
            version: bundle.version.clone(),
            received_at: Instant::now(),
            ttl_secs,
        })
    }
}

impl PolicyEvaluation for CedarPolicyEvaluator {
    /// Evaluate Cedar policies for the given principal, action, and resource.
    ///
    /// Context attributes (`action_class`, `resource`, `agent_id`,
    /// `session_id`, `timestamp`) are passed as a Cedar `Context` built
    /// from the JSON object produced by `ConstraintEnforcer::build_context`.
    ///
    /// Entity UIDs are constructed via [`FirmaEntityUid`] to match the
    /// Authority's issuance evaluation. No schema validation is performed on
    /// the request — policies that reference unknown attributes will receive
    /// Cedar's default deny.
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
        let principal_uid = FirmaEntityUid::Agent(principal.as_ref().to_string()).to_cedar()?;
        let action_uid = FirmaEntityUid::Action(action.to_string()).to_cedar()?;
        let resource_uid = FirmaEntityUid::Resource(resource.to_string()).to_cedar()?;

        // Context::from_json_value takes Option<(&Schema, &EntityUid)> — the action
        // UID is used to look up the declared context shape for that action.
        let schema_with_action = self.schema.as_ref().map(|s| (s, &action_uid));
        let cedar_context = Context::from_json_value(context.clone(), schema_with_action)
            .map_err(|e| format!("failed to build Cedar context: {e}"))?;

        let request = Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            cedar_context,
            self.schema.as_ref(),
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

    /// The real Firma schema, same file loaded by the Authority at startup.
    const FIRMA_SCHEMA: &str = include_str!("../../../firma-authority/policies/schema.cedarschema");

    fn schema_bundle(policy_src: &[u8]) -> PolicyBundle {
        PolicyBundle::new(
            "schema-v1".to_string(),
            policy_src.to_vec(),
            FIRMA_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    fn full_context() -> serde_json::Value {
        json!({
            "session_id": "sess_001",
            "timestamp_ms": 1_700_000_000_000i64,
            "params": "{}",
            "risk_score": 0i64,
        })
    }

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
            "session_id": "sess_001",
            "timestamp_ms": 1_700_000_000_000i64,
            "params": "{}",
            "risk_score": 0i64,
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
        // Policy referencing context.session_id — verifies context is wired through.
        let src =
            br#"permit(principal, action, resource) when { context.session_id == "sess_001" };"#;
        let bundle = PolicyBundle::new("ctx-v1".to_string(), src.to_vec(), vec![], 30);
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();

        let allow = evaluator
            .evaluate(
                &agent("agent_test"),
                "llm.inference",
                "api.openai.com",
                &test_context(),
            )
            .unwrap();
        assert!(allow);

        let deny_context = json!({
            "session_id": "different_session",
            "timestamp_ms": 1_700_000_000_000i64,
            "params": "{}",
            "risk_score": 0i64,
        });
        let deny = evaluator
            .evaluate(
                &agent("agent_test"),
                "llm.inference",
                "api.openai.com",
                &deny_context,
            )
            .unwrap();
        assert!(!deny);
    }

    // ── Schema validation tests ───────────────────────────────────────────────

    #[test]
    fn schema_parses_from_bundle() {
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        assert!(
            evaluator.schema.is_some(),
            "schema must be parsed from bundle"
        );
    }

    #[test]
    fn schema_permit_all_allows_known_action() {
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        let result = evaluator
            .evaluate(
                &agent("agent_test"),
                "llm.inference",
                "api.openai.com",
                &full_context(),
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn schema_rejects_unknown_action() {
        // "unknown.action" is not declared in the schema — Request::new should fail.
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        let result = evaluator.evaluate(
            &agent("agent_test"),
            "unknown.action",
            "api.openai.com",
            &full_context(),
        );
        assert!(
            result.is_err(),
            "unknown action must fail schema validation"
        );
    }

    #[test]
    fn schema_rejects_missing_context_field() {
        // Context missing required fields — Context::from_json_value should fail.
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        let incomplete_context = json!({
            "session_id": "sess_001"
            // missing: timestamp_ms, params, risk_score
        });
        let result = evaluator.evaluate(
            &agent("agent_test"),
            "llm.inference",
            "api.openai.com",
            &incomplete_context,
        );
        assert!(
            result.is_err(),
            "context missing required fields must fail schema validation"
        );
    }

    #[test]
    fn schema_context_attribute_used_in_policy() {
        // Policy referencing context.session_id — verifies context wiring with schema.
        let src =
            br#"permit(principal, action, resource) when { context.session_id == "sess_001" };"#;
        let bundle = schema_bundle(src);
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();

        let allow = evaluator
            .evaluate(
                &agent("agent_test"),
                "llm.inference",
                "api.openai.com",
                &full_context(),
            )
            .unwrap();
        assert!(allow);
    }

    #[test]
    fn schema_all_15_actions_accepted() {
        let actions = [
            "http.get",
            "http.post",
            "http.put",
            "http.delete",
            "http.patch",
            "network.connect",
            "db.query",
            "db.mutate",
            "file.read",
            "file.write",
            "file.delete",
            "code.execute",
            "system.execute",
            "messaging.send",
            "llm.inference",
        ];
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();

        for action in actions {
            let result = evaluator.evaluate(
                &agent("agent_test"),
                action,
                "some.resource",
                &full_context(),
            );
            assert!(
                result.is_ok(),
                "action '{action}' must be accepted by schema"
            );
            assert!(
                result.unwrap(),
                "action '{action}' must be allowed by permit-all"
            );
        }
    }
}
