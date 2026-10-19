use firma_core::DenyReason;
use firma_http::{Authority, HeaderMap, Method};
use firma_sidecar::composio::{ComposioCatalogs, DecodeResult, decode};
use firma_sidecar::pipeline::{CompositeDisposition, EnforcementDecision, RawRequest};

use super::support::{Fixture, bundle, push, rule};

#[tokio::test]
async fn a_transport_denial_redacts_every_child_using_the_same_generation() -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;
    push(&tx, bundle("batch", vec![rule("code.read")])).await?;
    fixture.applied("batch").await?;
    let mut request = RawRequest {
        method: Method::POST,
        host: Authority::from_static("app.composio.dev"),
        path: "/tool_router/v3/session/mcp".into(),
        headers: HeaderMap::new(),
        is_https: true,
        body: Some(
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"COMPOSIO_MULTI_EXECUTE_TOOL","arguments":{"tools":[
                    {"tool_slug":"GMAIL_FETCH_EMAILS","arguments":{}},
                    {"tool_slug":"GMAIL_SEND_EMAIL","arguments":{}}
                ]}
            }})
            .to_string()
            .into_bytes(),
        ),
    };
    let DecodeResult::Actions(actions) = decode(&request, &ComposioCatalogs::builtin()?) else {
        anyhow::bail!("expected composite execution stimulus");
    };
    assert_eq!(actions.len(), 2);
    // The public composite API also redacts diagnostic paths supplied by callers.
    // MCP decoding itself rejects query-bearing routes before reaching this API.
    request
        .path
        .push_str("?private_query=custom-secret&token=standard-secret&visible=value");
    let composite = fixture
        .runtime
        .pipeline
        .enforce_composite(&request, "managed-test", &actions)
        .await;
    std::assert_matches!(
        composite.disposition,
        CompositeDisposition::Block { blocker_index: 0 }
    );
    assert_eq!(composite.children.len(), 2);
    for (child, action) in composite.children.into_iter().zip(&actions) {
        std::assert_matches!(
            child.decision,
            EnforcementDecision::Deny {
                reason: DenyReason::UnclassifiedIntent,
                ..
            }
        );
        let event = fixture.audit(child.audit_payload).await?;
        assert_eq!(event.action, action.envelope.intent().action_class);
        assert_eq!(event.bundle_version, "batch");
        assert!(!event.deny_reason.contains("custom-secret"));
        assert!(!event.deny_reason.contains("standard-secret"));
        assert!(event.deny_reason.contains("private_query=[REDACTED]"));
        assert!(event.deny_reason.contains("token=[REDACTED]"));
        assert!(event.deny_reason.contains("visible=value"));
        assert!(!event.resource.contains("custom-secret"));
        assert!(!event.resource.contains("standard-secret"));
    }
    Ok(())
}

#[tokio::test]
async fn admitted_composite_envelopes_keep_distinct_redacted_resources() -> anyhow::Result<()> {
    use firma_sidecar::composio::ComposioAction;
    use firma_sidecar::pipeline::{IntentNormalizer, MappingTable};
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;
    let mapping = rule("communication.external.read");
    push(&tx, bundle("admitted", vec![mapping.clone()])).await?;
    fixture.applied("admitted").await?;
    let transport = RawRequest {
        method: Method::POST,
        host: Authority::from_static("app.composio.dev"),
        path: "/tool_router/v3/session/mcp".into(),
        headers: HeaderMap::new(),
        is_https: true,
        body: Some(
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"COMPOSIO_MULTI_EXECUTE_TOOL","arguments":{"tools":[
                    {"tool_slug":"GMAIL_FETCH_EMAILS","arguments":{}},
                    {"tool_slug":"GMAIL_FETCH_EMAILS","arguments":{}}
                ]}
            }})
            .to_string()
            .into_bytes(),
        ),
    };
    let DecodeResult::Actions(decoded) = decode(&transport, &ComposioCatalogs::builtin()?) else {
        anyhow::bail!("composite fixture context");
    };
    let normalizer = IntentNormalizer::new(MappingTable::from_managed_rules(vec![
        firma_sidecar::config::MappingRuleConfig {
            method: None,
            host: "example.test".into(),
            path: None,
            action_class: "communication.external.read".into(),
        },
    ])?);
    // Trusted callers can provide distinct normalized resources to this API.
    let mut request = super::support::request();
    let mut actions = Vec::new();
    for (index, action) in decoded.into_iter().enumerate() {
        request.path =
            format!("/child-{index}?private_query=child-secret&token=token-secret&visible={index}");
        let envelope = normalizer
            .normalize(&request)
            .map_err(|error| anyhow::anyhow!("fixture normalization: {error:?}"))?;
        actions.push(ComposioAction {
            envelope,
            context: action.context,
        });
    }
    let result = fixture
        .runtime
        .pipeline
        .enforce_composite(&super::support::request(), "managed-test", &actions)
        .await;
    std::assert_matches!(result.disposition, CompositeDisposition::Dispatch { .. });
    for (index, child) in result.children.into_iter().enumerate() {
        std::assert_matches!(child.decision, EnforcementDecision::Allow { .. });
        let event = fixture.audit(child.audit_payload).await?;
        assert_eq!(
            event.resource,
            format!(
                "example.test/child-{index}?private_query=[REDACTED]&token=[REDACTED]&visible={index}"
            )
        );
        assert_eq!(event.bundle_version, "admitted");
    }
    Ok(())
}
