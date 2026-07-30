//! Host/path-level Cedar rules evaluate end-to-end through the Sidecar policy
//! evaluator.
//!
//! FIR-190 follow-up: the `Firma::Resource` entity now carries `host` / `path`
//! attributes, populated by the evaluator from the normalized resource string
//! and passed to Cedar in the authorizer's entity store. Before this, every
//! `resource.<attr>` access errored against an empty store, so host-level rules
//! (e.g. the cloud-metadata-endpoint block) could not be expressed in Cedar.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use firma_core::FIRMA_SCHEMA;
use firma_core::policy::PolicyBundle;
use firma_sidecar::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use firma_sidecar::enforcement::constraint_enforcement::PolicyEvaluation;
use serde_json::json;

/// Full canonical `EnforcementContext` record. Host/path live on the resource
/// entity, not the context, so the same context is reused across cases.
fn context() -> serde_json::Value {
    json!({
        "session_id": "sess_001",
        "timestamp_ms": 1_700_000_000_000i64,
        "params": "{}",
        "risk_score": 0i64,
        "session_duration_s": 0i64,
        "action_count": 1i64,
        "raw_transport": "https",
        "deny_count": 0i64,
        "prior_action_classes": [],
        "last_resource": "",
        "transfer_amount": 0i64,
        "daily_cumulative_amount": 0i64,
        "transfers_last_10m": 0i64,
        "same_payee_count_30m": 0i64,
        "session_transfer_count": 0i64,
    })
}

fn evaluator(policy: &str) -> CedarPolicyEvaluator {
    let bundle = PolicyBundle::new(
        "host-rules-v1".to_string(),
        policy.as_bytes().to_vec(),
        FIRMA_SCHEMA.as_bytes().to_vec(),
        30,
    );
    CedarPolicyEvaluator::from_bundle(&bundle).expect("bundle builds")
}

fn allowed(evaluator: &CedarPolicyEvaluator, resource: &str) -> bool {
    let agent = "agt_01j0000000e008000000000001"
        .parse()
        .expect("literal agent id");
    evaluator
        .evaluate(&agent, "communication.external.send", resource, context())
        .expect("evaluation succeeds")
}

#[test]
fn host_forbid_blocks_cloud_metadata_endpoint() {
    // The re-added metadata-endpoint block: forbid any action whose resource
    // host is the link-local IMDS address, on top of a permit-all baseline.
    let evaluator = evaluator(
        "permit(principal, action, resource);\n\
         forbid(principal, action, resource) \
         when { resource has host && resource.host == \"169.254.169.254\" };",
    );

    assert!(
        !allowed(
            &evaluator,
            "169.254.169.254/latest/meta-data/iam/security-credentials/"
        ),
        "requests to the cloud metadata host must be denied by the host forbid"
    );
    assert!(
        allowed(&evaluator, "api.openai.com/v1/chat/completions"),
        "unrelated hosts stay allowed by the permit baseline"
    );
}

#[test]
fn path_attribute_gates_permit() {
    // A permit conditioned on resource.path only admits the matching path.
    let evaluator = evaluator(
        "permit(principal, action, resource) \
         when { resource has path && resource.path == \"/v1/models\" };",
    );

    assert!(
        allowed(&evaluator, "api.openai.com/v1/models"),
        "matching path must be permitted"
    );
    assert!(
        !allowed(&evaluator, "api.openai.com/v1/chat/completions"),
        "non-matching path falls through to default-deny"
    );
}

#[test]
fn missing_host_attribute_does_not_error() {
    // A resource with no host (e.g. an empty display string) must leave the
    // `resource has host` guard false — the forbid is skipped rather than
    // erroring the whole evaluation, so the permit baseline still allows.
    let evaluator = evaluator(
        "permit(principal, action, resource);\n\
         forbid(principal, action, resource) \
         when { resource has host && resource.host == \"169.254.169.254\" };",
    );

    assert!(
        allowed(&evaluator, ""),
        "empty resource has no host attribute; forbid must not fire and eval must not error"
    );
}
