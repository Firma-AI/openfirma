use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use firma_core::policy::PolicyBundle;
use firma_core::{ActionParams, CapabilityClaims, ExecutionIntent, HttpMethod, HttpParams};
use firma_http::HeaderMap;
use firma_sidecar::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use firma_sidecar::enforcement::session::RuntimeSignals;
use firma_sidecar::normalizer::NormalizedEnvelope;
use firma_sidecar::pipeline::{ConstraintEnforcer, PolicyVerdict};

#[test]
fn benchmark_and_demo_schemas_accept_the_worker_context() -> anyhow::Result<()> {
    let action = "communication.external.send";
    let now = Utc::now();
    let claims = CapabilityClaims {
        token_id: "ctok_01j0000000e008000000000001".parse()?,
        agent_id: "agt_01j0000000e008000000000001".parse()?,
        session_id: "schema-compatibility".parse()?,
        action_set: vec![action.to_owned()],
        resource_scope: "*".to_owned(),
        issued_at: now,
        expiry: now + chrono::Duration::hours(1),
        context_hash: String::new(),
    };
    let envelope = NormalizedEnvelope::new(
        ExecutionIntent {
            action_class: action.to_owned(),
            resource: ExecutionIntent::resource_map_from("api.bench.local/invoke"),
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::POST,
                headers: HeaderMap::new(),
                body: None,
                query: HashMap::new(),
            }),
            raw_transport: "https".to_owned(),
            raw_action_ref: "POST /invoke".to_owned(),
        },
        now,
    );

    for (name, policies, schema) in [
        (
            "benchmark",
            include_str!("../../benches/fixtures/reference_bundle.cedar"),
            include_str!("../../benches/fixtures/reference_schema.cedarschema"),
        ),
        (
            "demo",
            include_str!("../../../../examples/demo/policies/default.cedar"),
            include_str!("../../../../examples/demo/policies/schema.cedarschema"),
        ),
    ] {
        let bundle = PolicyBundle::new(
            name.to_owned(),
            policies.as_bytes().to_vec(),
            schema.as_bytes().to_vec(),
            300,
        );
        let enforcer =
            ConstraintEnforcer::new(Arc::new(CedarPolicyEvaluator::from_bundle(&bundle)?));
        let verdict = enforcer
            .evaluate(&envelope, &claims, &RuntimeSignals::default())
            .map_err(|decision| {
                anyhow::anyhow!("{name} rejected the worker context: {decision:?}")
            })?;
        assert_eq!(verdict, PolicyVerdict::Allow, "{name}");
    }

    Ok(())
}
