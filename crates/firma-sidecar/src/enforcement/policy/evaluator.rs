//! Cedar-backed [`PolicyEvaluation`] implementation.
//!
//! Wraps an `ArcSwapOption<BundleSnapshot>`: readers on the hot path
//! never lock, writers never expose a torn snapshot. In-flight calls
//! evaluate against the snapshot they loaded (Component Reference §11).

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use cedar_policy::{
    Authorizer, Context, Decision, EntityId, EntityTypeName, EntityUid, Request,
    RestrictedExpression,
};

use super::snapshot::BundleSnapshot;
use crate::enforcement::constraint_enforcement::PolicyEvaluation;

/// Cedar policy evaluator with atomic bundle hot-swap.
///
/// Boots empty: until the first [`swap`](Self::swap) call lands, both
/// `is_fresh` and `is_available` return `false`, and `evaluate` errors
/// so Stage 2 surfaces `POLICY_BUNDLE_STALE` (Component Reference §12).
pub struct CedarPolicyEvaluator {
    current: ArcSwapOption<BundleSnapshot>,
    ttl: Duration,
    authorizer: Authorizer,
}

impl CedarPolicyEvaluator {
    /// Create an empty evaluator. Stage 2 fails closed with
    /// `POLICY_BUNDLE_STALE` until a bundle is installed.
    #[must_use]
    pub fn empty(ttl: Duration) -> Self {
        Self {
            current: ArcSwapOption::empty(),
            ttl,
            authorizer: Authorizer::new(),
        }
    }

    /// Atomically install `next` as the current bundle snapshot.
    pub fn swap(&self, next: BundleSnapshot) {
        self.current.store(Some(Arc::new(next)));
    }

    /// Load the current snapshot — `None` before the first swap.
    #[must_use]
    pub fn current(&self) -> Option<Arc<BundleSnapshot>> {
        self.current.load_full()
    }
}

impl PolicyEvaluation for CedarPolicyEvaluator {
    fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> Result<bool, String> {
        let snapshot = self
            .current()
            .ok_or_else(|| "no policy bundle loaded".to_string())?;

        let principal_uid = build_uid("Agent", principal)?;
        let action_uid = build_uid("Action", action)?;
        let resource_uid = build_uid("Resource", resource)?;

        let ctx = build_context(context)?;

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            ctx,
            snapshot.schema.as_ref(),
        )
        .map_err(|e| format!("cedar request validation failed: {e}"))?;

        let response =
            self.authorizer
                .is_authorized(&request, &snapshot.policies, &snapshot.entities);
        Ok(matches!(response.decision(), Decision::Allow))
    }

    fn is_fresh(&self) -> bool {
        self.current()
            .is_some_and(|snap| snap.loaded_at.elapsed() <= self.ttl)
    }

    fn is_available(&self) -> bool {
        self.current().is_some()
    }

    fn version(&self) -> Option<String> {
        self.current().map(|snap| snap.version.clone())
    }
}

fn build_uid(type_name: &str, eid: &str) -> Result<EntityUid, String> {
    let ty = EntityTypeName::from_str(type_name)
        .map_err(|e| format!("invalid entity type '{type_name}': {e}"))?;
    let id = EntityId::from_str(eid).map_err(|e| format!("invalid entity id '{eid}': {e}"))?;
    Ok(EntityUid::from_type_name_and_id(ty, id))
}

fn build_context(value: &serde_json::Value) -> Result<Context, String> {
    let serde_json::Value::Object(map) = value else {
        return Err(format!(
            "context must be a JSON object, got {}",
            kind(value)
        ));
    };
    let pairs = map
        .iter()
        .map(|(k, v)| {
            let expr = RestrictedExpression::from_str(&v.to_string())
                .map_err(|e| format!("context attribute '{k}' invalid: {e}"))?;
            Ok((k.clone(), expr))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Context::from_pairs(pairs).map_err(|e| format!("context build failed: {e}"))
}

fn kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::policy::loader::{BundleLoader, RawBundle};

    const ENTITIES_EMPTY: &str = "[]";

    fn raw(policies: &str, version: &str) -> RawBundle {
        RawBundle {
            policies_cedar: policies.to_string(),
            schema_json: None,
            entities_json: ENTITIES_EMPTY.to_string(),
            version: version.to_string(),
        }
    }

    fn new_evaluator() -> Arc<CedarPolicyEvaluator> {
        Arc::new(CedarPolicyEvaluator::empty(Duration::from_secs(30)))
    }

    #[test]
    fn empty_evaluator_reports_unavailable_and_stale() {
        let evaluator = CedarPolicyEvaluator::empty(Duration::from_secs(30));
        assert!(!evaluator.is_available());
        assert!(!evaluator.is_fresh());
        assert!(evaluator.version().is_none());
    }

    #[test]
    fn empty_evaluator_errors_on_evaluate() {
        let evaluator = CedarPolicyEvaluator::empty(Duration::from_secs(30));
        let ctx = serde_json::json!({});
        let err = evaluator
            .evaluate("agent_1", "llm.inference", "api.openai.com", &ctx)
            .unwrap_err();
        assert!(err.contains("no policy bundle"), "got: {err}");
    }

    #[test]
    fn swap_installs_snapshot_and_flips_freshness() {
        let evaluator = new_evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));
        loader
            .apply(raw("permit(principal, action, resource);", "v1"))
            .expect("valid bundle");

        assert!(evaluator.is_available());
        assert!(evaluator.is_fresh());
        assert_eq!(evaluator.version().as_deref(), Some("v1"));
    }

    #[test]
    fn allow_policy_evaluates_to_allow() {
        let evaluator = new_evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));
        loader
            .apply(raw("permit(principal, action, resource);", "v1"))
            .expect("valid bundle");

        let decision = evaluator
            .evaluate(
                "agent_1",
                "llm.inference",
                "api.openai.com",
                &serde_json::json!({}),
            )
            .expect("cedar eval");
        assert!(decision, "permit policy must allow");
    }

    #[test]
    fn empty_policy_set_defaults_deny() {
        let evaluator = new_evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));
        // No `permit` policies → Cedar default-deny.
        loader
            .apply(raw("forbid(principal, action, resource);", "v1"))
            .expect("valid bundle");

        let decision = evaluator
            .evaluate(
                "agent_1",
                "llm.inference",
                "api.openai.com",
                &serde_json::json!({}),
            )
            .expect("cedar eval");
        assert!(!decision, "forbid-only bundle must deny");
    }

    #[test]
    fn forbid_overrides_permit() {
        let evaluator = new_evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));
        loader
            .apply(raw(
                "permit(principal, action, resource); forbid(principal, action, resource);",
                "v1",
            ))
            .expect("valid bundle");

        let decision = evaluator
            .evaluate(
                "agent_1",
                "llm.inference",
                "api.openai.com",
                &serde_json::json!({}),
            )
            .expect("cedar eval");
        assert!(!decision, "forbid must override permit");
    }

    #[test]
    fn ttl_elapsed_marks_snapshot_stale() {
        let evaluator = Arc::new(CedarPolicyEvaluator::empty(Duration::from_millis(50)));
        let loader = BundleLoader::new(Arc::clone(&evaluator));
        loader
            .apply(raw("permit(principal, action, resource);", "v1"))
            .expect("valid bundle");
        assert!(evaluator.is_fresh());

        std::thread::sleep(Duration::from_millis(80));
        assert!(!evaluator.is_fresh(), "snapshot should have expired");
        // is_available does not depend on TTL — snapshot is still installed.
        assert!(evaluator.is_available());
    }

    #[test]
    fn context_attributes_reach_policy_evaluation() {
        let evaluator = new_evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));
        // Only permit when the budget is positive.
        loader
            .apply(raw(
                r#"permit(principal, action, resource) when { context.budget_remaining > 0 };"#,
                "v1",
            ))
            .expect("valid bundle");

        let allowed = evaluator
            .evaluate(
                "agent_1",
                "llm.inference",
                "api.openai.com",
                &serde_json::json!({"budget_remaining": 10}),
            )
            .expect("cedar eval");
        assert!(allowed, "positive budget must allow");

        let denied = evaluator
            .evaluate(
                "agent_1",
                "llm.inference",
                "api.openai.com",
                &serde_json::json!({"budget_remaining": 0}),
            )
            .expect("cedar eval");
        assert!(!denied, "zero budget must deny");
    }

    #[test]
    fn concurrent_swap_and_evaluate_never_tear() {
        use std::thread;

        let evaluator = new_evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));
        loader
            .apply(raw("permit(principal, action, resource);", "v0"))
            .expect("initial bundle");

        let writer_loader = BundleLoader::new(Arc::clone(&evaluator));
        let writer = thread::spawn(move || {
            for i in 1..=200 {
                let version = format!("v{i}");
                writer_loader
                    .apply(raw("permit(principal, action, resource);", &version))
                    .expect("swap bundle");
            }
        });

        let reader_eval = Arc::clone(&evaluator);
        let reader = thread::spawn(move || {
            for _ in 0..500 {
                let decision = reader_eval
                    .evaluate(
                        "agent_1",
                        "llm.inference",
                        "api.openai.com",
                        &serde_json::json!({}),
                    )
                    .expect("eval");
                assert!(decision);
            }
        });

        writer.join().expect("writer join");
        reader.join().expect("reader join");
    }
}
