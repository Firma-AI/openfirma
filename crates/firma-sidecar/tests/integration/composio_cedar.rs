use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use firma_core::policy::PolicyBundle;
use firma_core::{
    ActionParams, CapabilityClaims, DenyReason, ExecutionIntent, HttpMethod, HttpParams,
};
use firma_sidecar::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use firma_sidecar::enforcement::session::RuntimeSignals;
use firma_sidecar::normalizer::NormalizedEnvelope;
use firma_sidecar::pipeline::{
    ConstraintEnforcer, EnforcementDecision, PolicyEvaluation, PolicyVerdict,
};

#[derive(Debug, Default)]
struct CapturePolicy {
    context: Mutex<Option<serde_json::Value>>,
}

impl PolicyEvaluation for CapturePolicy {
    fn evaluate(
        &self,
        _agent_id: &firma_core::AgentId,
        _action: &str,
        _resource: &str,
        context: serde_json::Value,
    ) -> Result<bool, String> {
        self.context
            .lock()
            .map_err(|_| "capture lock poisoned".to_string())?
            .replace(context);
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn version(&self) -> Option<String> {
        Some("composio-test-policy".to_string())
    }
}

fn intent() -> ExecutionIntent {
    let mut resource = ExecutionIntent::resource_map_from(
        "backend.composio.dev/api/v3.1/tool_router/session/trs_1/execute",
    );
    resource.extend([
        (
            "policy_resource".to_string(),
            "composio://gmail/GMAIL_FETCH_EMAILS".to_string(),
        ),
        ("composio_toolkit".to_string(), "gmail".to_string()),
        (
            "composio_tool_slug".to_string(),
            "GMAIL_FETCH_EMAILS".to_string(),
        ),
        (
            "composio_user_id".to_string(),
            "pai-assistant:bot-1".to_string(),
        ),
        ("composio_account".to_string(), "account-1".to_string()),
        ("composio_session_id".to_string(), "trs_1".to_string()),
        ("composio_batch_index".to_string(), "1".to_string()),
        ("composio_batch_size".to_string(), "2".to_string()),
    ]);
    ExecutionIntent {
        action_class: "communication.external.read".to_string(),
        resource,
        params: ActionParams::Http(HttpParams {
            method: HttpMethod::POST,
            headers: HashMap::new(),
            body: None,
            query: HashMap::new(),
        }),
        raw_transport: "https".to_string(),
        raw_action_ref: "POST /api/v3.1/tool_router/session/trs_1/execute".to_string(),
    }
}

fn envelope() -> NormalizedEnvelope {
    NormalizedEnvelope::new(intent(), Utc::now())
}

/// Builds the reference envelope with one Composio context entry overridden.
fn envelope_with(key: &str, value: &str) -> NormalizedEnvelope {
    let mut intent = intent();
    intent.resource.insert(key.to_string(), value.to_string());
    NormalizedEnvelope::new(intent, Utc::now())
}

fn claims() -> anyhow::Result<CapabilityClaims> {
    Ok(CapabilityClaims {
        token_id: "ctok_01j0000000e008000000000001".parse()?,
        agent_id: "agt_01j0000000e008000000000001".parse()?,
        session_id: "sess_composio".parse()?,
        action_set: vec!["communication.external.read".to_string()],
        resource_scope: "composio://gmail/*".to_string(),
        issued_at: Utc::now(),
        expiry: Utc::now() + chrono::Duration::hours(1),
        context_hash: String::new(),
    })
}

fn cedar_enforcer() -> anyhow::Result<ConstraintEnforcer> {
    let policies = br#"
permit (
    principal,
    action == Firma::Action::"communication.external.read",
    resource
)
when {
    context.composio_toolkit == "gmail" &&
    context.composio_tool_slug == "GMAIL_FETCH_EMAILS" &&
    context.composio_user_id == "pai-assistant:bot-1" &&
    context.composio_account == "account-1" &&
    context.composio_session_id == "trs_1" &&
    context.composio_batch_index == 1 &&
    context.composio_batch_size == 2
};
"#;
    let bundle = PolicyBundle::new(
        "composio-context-test".to_string(),
        policies.to_vec(),
        include_bytes!("../../../firma-core/firma.cedarschema").to_vec(),
        30,
    );
    Ok(ConstraintEnforcer::new(Arc::new(
        CedarPolicyEvaluator::from_bundle(&bundle)?,
    )))
}

#[test]
fn every_composio_field_is_available_to_cedar_with_integer_batch_values() -> anyhow::Result<()> {
    let policy = Arc::new(CapturePolicy::default());
    let enforcer = ConstraintEnforcer::new(policy.clone());

    let verdict = match enforcer.evaluate(&envelope(), &claims()?, &RuntimeSignals::default()) {
        Ok(verdict) => verdict,
        Err(decision) => anyhow::bail!("expected allowed evaluation, got {decision:?}"),
    };
    assert_eq!(verdict, PolicyVerdict::Allow);
    let context = policy
        .context
        .lock()
        .map_err(|_| anyhow::anyhow!("capture lock poisoned"))?
        .clone()
        .ok_or_else(|| anyhow::anyhow!("policy context was not captured"))?;

    assert_eq!(context["composio_toolkit"], "gmail");
    assert_eq!(context["composio_tool_slug"], "GMAIL_FETCH_EMAILS");
    assert_eq!(context["composio_user_id"], "pai-assistant:bot-1");
    assert_eq!(context["composio_account"], "account-1");
    assert_eq!(context["composio_session_id"], "trs_1");
    assert_eq!(context["composio_batch_index"], 1);
    assert_eq!(context["composio_batch_size"], 2);
    Ok(())
}

#[test]
fn malformed_batch_context_fails_closed_without_echoing_values() -> anyhow::Result<()> {
    let enforcer = ConstraintEnforcer::new(Arc::new(CapturePolicy::default()));
    let envelope = envelope_with("composio_batch_index", "secret-invalid-index");

    let decision = match enforcer.evaluate(&envelope, &claims()?, &RuntimeSignals::default()) {
        Ok(verdict) => anyhow::bail!("expected fail-closed denial, got {verdict:?}"),
        Err(decision) => decision,
    };

    let EnforcementDecision::Deny { reason, detail, .. } = decision else {
        anyhow::bail!("expected deny decision");
    };
    assert_eq!(reason, DenyReason::FailClosed);
    insta::assert_snapshot!(
        detail,
        @"invalid Composio batch context; failing closed"
    );
    Ok(())
}

#[test]
fn cedar_can_filter_on_every_composio_context_field() -> anyhow::Result<()> {
    let enforcer = cedar_enforcer()?;
    let allowed = match enforcer.evaluate(&envelope(), &claims()?, &RuntimeSignals::default()) {
        Ok(verdict) => verdict,
        Err(decision) => anyhow::bail!("expected allowed evaluation, got {decision:?}"),
    };
    assert_eq!(allowed, PolicyVerdict::Allow);

    for (key, value) in [
        ("composio_toolkit", "calendar"),
        ("composio_tool_slug", "GMAIL_SEND_EMAIL"),
        ("composio_user_id", "another-user"),
        ("composio_account", "another-account"),
        ("composio_session_id", "another-session"),
        ("composio_batch_index", "0"),
        ("composio_batch_size", "3"),
    ] {
        let denied_envelope = envelope_with(key, value);
        let denied = enforcer.evaluate(&denied_envelope, &claims()?, &RuntimeSignals::default());
        let Err(EnforcementDecision::Deny { reason, .. }) = denied else {
            anyhow::bail!("field {key} was not denied");
        };
        assert_eq!(
            reason,
            DenyReason::PolicyDenied,
            "field {key} did not produce a Cedar policy denial"
        );
    }
    Ok(())
}

fn document_envelope(toolkit: &str, slug: &str) -> NormalizedEnvelope {
    let mut resource = ExecutionIntent::resource_map_from(
        "backend.composio.dev/api/v3.1/tool_router/session/trs_1/execute",
    );
    resource.extend([
        (
            "policy_resource".to_string(),
            format!("composio://{toolkit}/{slug}"),
        ),
        ("composio_toolkit".to_string(), toolkit.to_string()),
        ("composio_tool_slug".to_string(), slug.to_string()),
    ]);
    NormalizedEnvelope::new(
        ExecutionIntent {
            action_class: "document.write".to_string(),
            resource,
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::POST,
                headers: HashMap::new(),
                body: None,
                query: HashMap::new(),
            }),
            raw_transport: "https".to_string(),
            raw_action_ref: "POST /api/v3.1/tool_router/session/trs_1/execute".to_string(),
        },
        Utc::now(),
    )
}

fn document_claims() -> anyhow::Result<CapabilityClaims> {
    Ok(CapabilityClaims {
        token_id: "ctok_01j0000000e008000000000002".parse()?,
        agent_id: "agt_01j0000000e008000000000002".parse()?,
        session_id: "sess_composio_document".parse()?,
        action_set: vec!["document.write".to_string()],
        resource_scope: "composio://*".to_string(),
        issued_at: Utc::now(),
        expiry: Utc::now() + chrono::Duration::hours(1),
        context_hash: String::new(),
    })
}

/// A Cedar bundle that permits Notion page creation and Slack canvas creation
/// and nothing else in the document domain.
fn document_enforcer() -> anyhow::Result<ConstraintEnforcer> {
    let policies = br#"
permit (
    principal,
    action == Firma::Action::"document.write",
    resource == Firma::Resource::"composio://notion/NOTION_CREATE_NOTION_PAGE"
);

permit (
    principal,
    action == Firma::Action::"document.write",
    resource
)
when {
    context.composio_toolkit == "slack" &&
    context.composio_tool_slug == "SLACK_CREATE_CANVAS"
};
"#;
    let bundle = PolicyBundle::new(
        "composio-document-test".to_string(),
        policies.to_vec(),
        include_bytes!("../../../firma-core/firma.cedarschema").to_vec(),
        30,
    );
    Ok(ConstraintEnforcer::new(Arc::new(
        CedarPolicyEvaluator::from_bundle(&bundle)?,
    )))
}

/// Cedar can admit and refuse individual Notion and Slack tools.
///
/// The permitted Notion tool is matched by logical resource and the permitted
/// Slack tool by context, so both addressing styles are covered. Anything else
/// in the same action class is denied, which is what makes a `document.write`
/// grant safe to hand to an agent.
#[test]
fn cedar_admits_and_refuses_individual_notion_and_slack_tools() -> anyhow::Result<()> {
    let enforcer = document_enforcer()?;

    for (toolkit, slug) in [
        ("notion", "NOTION_CREATE_NOTION_PAGE"),
        ("slack", "SLACK_CREATE_CANVAS"),
    ] {
        let verdict = match enforcer.evaluate(
            &document_envelope(toolkit, slug),
            &document_claims()?,
            &RuntimeSignals::default(),
        ) {
            Ok(verdict) => verdict,
            Err(decision) => anyhow::bail!("{toolkit}/{slug} was not allowed: {decision:?}"),
        };
        assert_eq!(verdict, PolicyVerdict::Allow);
    }

    for (toolkit, slug) in [
        ("notion", "NOTION_UPDATE_PAGE"),
        ("slack", "SLACK_EDIT_CANVAS"),
        ("slack", "NOTION_CREATE_NOTION_PAGE"),
    ] {
        let denied = enforcer.evaluate(
            &document_envelope(toolkit, slug),
            &document_claims()?,
            &RuntimeSignals::default(),
        );
        let Err(EnforcementDecision::Deny { reason, .. }) = denied else {
            anyhow::bail!("{toolkit}/{slug} was not denied");
        };
        assert_eq!(
            reason,
            DenyReason::PolicyDenied,
            "{toolkit}/{slug} did not produce a Cedar policy denial"
        );
    }
    Ok(())
}
