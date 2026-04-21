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

/// Errors produced by Cedar policy loading and evaluation.
#[derive(Debug, thiserror::Error)]
pub enum CedarEvaluatorError {
    #[error("policy bytes are not valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    #[error("policy bundle contains no policy statements")]
    EmptyPolicies,

    #[error("policy bundle contains no entity schema; schema is required")]
    MissingSchema,

    #[error("failed to parse Cedar policies: {0}")]
    PolicyParse(#[source] cedar_policy::ParseErrors),

    #[error("failed to parse Cedar schema: {0}")]
    SchemaParse(#[source] Box<cedar_policy::HumanSchemaError>),

    #[error("invalid entity UID: {0}")]
    EntityUidParse(#[source] cedar_policy::ParseErrors),

    #[error("failed to build Cedar context: {0}")]
    ContextBuild(#[source] Box<cedar_policy::ContextJsonError>),

    /// `cedar_policy::RequestValidationError` is intentionally not re-exported
    /// by the cedar-policy crate (it contains internal types), so we erase it
    /// via `Box<dyn Error>` while preserving the source chain.
    #[error("failed to build Cedar request: {0}")]
    RequestBuild(#[source] Box<dyn std::error::Error + Send + Sync>),
}

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
    /// Returns [`CedarEvaluatorError::EntityUidParse`] if the id contains
    /// characters that make the Cedar entity UID string unparseable (e.g.
    /// unescaped quotes).
    pub(crate) fn to_cedar(&self) -> Result<EntityUid, CedarEvaluatorError> {
        self.to_string()
            .parse::<EntityUid>()
            .map_err(CedarEvaluatorError::EntityUidParse)
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
#[derive(Debug)]
pub struct CedarPolicyEvaluator {
    policy_set: PolicySet,
    schema: Schema,
    version: String,
    received_at: Instant,
    ttl_secs: u32,
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
    /// Returns [`CedarEvaluatorError::InvalidUtf8`] if policy or schema bytes
    /// are not valid UTF-8, [`CedarEvaluatorError::PolicyParse`] if the Cedar
    /// policy source is syntactically invalid, or
    /// [`CedarEvaluatorError::SchemaParse`] if the Cedar schema is invalid.
    pub fn from_bundle(bundle: &PolicyBundle) -> Result<Self, CedarEvaluatorError> {
        let src = std::str::from_utf8(&bundle.policies)?;

        if src.trim().is_empty() {
            return Err(CedarEvaluatorError::EmptyPolicies);
        }

        let policy_set = src
            .parse::<PolicySet>()
            .map_err(CedarEvaluatorError::PolicyParse)?;

        if bundle.entity_schema.is_empty() {
            return Err(CedarEvaluatorError::MissingSchema);
        }
        let schema_src = std::str::from_utf8(&bundle.entity_schema)?;
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_src)
            .map_err(|e| CedarEvaluatorError::SchemaParse(Box::new(e)))?;

        Ok(Self {
            policy_set,
            schema,
            version: bundle.version.clone(),
            received_at: Instant::now(),
            ttl_secs: bundle.ttl_seconds,
        })
    }

    fn evaluate_inner(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> Result<bool, CedarEvaluatorError> {
        let principal_uid = FirmaEntityUid::Agent(principal.as_ref().to_string()).to_cedar()?;
        let action_uid = FirmaEntityUid::Action(action.to_string()).to_cedar()?;
        let resource_uid = FirmaEntityUid::Resource(resource.to_string()).to_cedar()?;

        let cedar_context =
            Context::from_json_value(context.clone(), Some((&self.schema, &action_uid)))
                .map_err(|e| CedarEvaluatorError::ContextBuild(Box::new(e)))?;

        let request = Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            cedar_context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEvaluatorError::RequestBuild(Box::new(e)))?;

        let entities = Entities::empty();
        let response = Authorizer::new().is_authorized(&request, &self.policy_set, &entities);

        Ok(matches!(response.decision(), Decision::Allow))
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
    /// Returns [`CedarEvaluatorError::EntityUidParse`] if any entity UID is
    /// unparseable, [`CedarEvaluatorError::ContextBuild`] if the context JSON
    /// is invalid for the action's schema, or [`CedarEvaluatorError::RequestBuild`]
    /// if the Cedar request fails schema validation.
    fn evaluate(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> Result<bool, String> {
        self.evaluate_inner(principal, action, resource, context)
            .map_err(|e| e.to_string())
    }

    fn is_fresh(&self) -> bool {
        self.received_at.elapsed().as_secs() < u64::from(self.ttl_secs)
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

    const TEST_SCHEMA: &str = "
namespace Firma {
    type EnforcementContext = { session_id: String, timestamp_ms: Long, params: String, risk_score: Long };
    entity Agent;
    entity Resource;
    action \"llm.inference\" appliesTo { principal: [Agent], resource: [Resource], context: EnforcementContext };
}";

    fn schema_bundle(policy_src: &[u8]) -> PolicyBundle {
        PolicyBundle::new(
            "schema-v1".to_string(),
            policy_src.to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
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
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    fn forbid_all_bundle() -> PolicyBundle {
        PolicyBundle::new(
            "test-v2".to_string(),
            b"forbid(principal, action, resource);".to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
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
        // Empty policy bytes are rejected at construction time so the caller
        // can surface a typed error rather than silently falling through to
        // Cedar's default deny (which is indistinguishable from a legitimate
        // forbid-all bundle).
        let err = CedarPolicyEvaluator::from_bundle(&empty_bundle()).unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::EmptyPolicies),
            "expected EmptyPolicies, got {err}"
        );
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
    fn missing_schema_rejected() {
        let no_schema = PolicyBundle::new(
            "no-schema".to_string(),
            b"permit(principal, action, resource);".to_vec(),
            vec![],
            30,
        );
        let err = CedarPolicyEvaluator::from_bundle(&no_schema).unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::MissingSchema),
            "expected MissingSchema, got {err}"
        );
    }

    #[test]
    fn is_stale_with_zero_ttl() {
        let zero_ttl = PolicyBundle::new(
            "v0".to_string(),
            b"permit(principal, action, resource);".to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            0,
        );
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
        let bundle = PolicyBundle::new(
            "ctx-v1".to_string(),
            src.to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        );
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
        // schema is now mandatory — from_bundle succeeds only when schema bytes
        // are present; the field is Schema (not Option<Schema>).
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
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
}
