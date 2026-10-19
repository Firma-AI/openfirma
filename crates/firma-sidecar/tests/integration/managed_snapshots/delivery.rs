use firma_protobuf::v1::ActionMappingRule;
use firma_sidecar::pipeline::EnforcementDecision;
use pretty_assertions::assert_matches;

use super::fixture::{ACTION_A, Harness, SESSION, bundle, request, send};

#[tokio::test]
async fn complete_managed_snapshot_larger_than_default_transport_limit_is_activated()
-> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    let mut candidate = bundle("large", ACTION_A, ACTION_A);
    candidate.policies.resize(900 * 1024, b' ');
    let mappings = candidate
        .mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("mappings"))?;
    // Ten sets with 1,000 routes apiece fit Team's aggregate rule/byte budgets.
    // The effective wire rules repeat each set's 253-byte host on every route.
    for set in 0..10 {
        let host = format!(
            "{}.{}.{}.{set}{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(60)
        );
        for route in 0..1_000 {
            if set == 0 && route == 0 {
                continue; // Keep the fixture's routable positive control.
            }
            mappings.rules.push(ActionMappingRule {
                host: host.clone(),
                method: Some("GET".into()),
                path: Some(format!("/{route:069}")),
                action_class: "code.read".into(),
            });
        }
    }
    let content_bytes = candidate.policies.len()
        + mappings
            .rules
            .iter()
            .map(|rule| {
                rule.host.len()
                    + rule.path.as_deref().unwrap_or_default().len()
                    + rule.action_class.len()
                    + rule.method.as_deref().unwrap_or_default().len()
            })
            .sum::<usize>();
    assert!(content_bytes > 4 * 1024 * 1024);
    harness.publish(&subscription, candidate).await?;
    let (decision, payload) = harness.runtime.pipeline.enforce(&request(), SESSION).await;
    assert_matches!(decision, EnforcementDecision::Allow { .. });
    let events = harness.audit(vec![payload]).await?;
    assert_eq!(events[0].bundle_version, "large");
    Ok(())
}

#[tokio::test]
async fn oversized_update_reconnects_without_replacing_the_admitted_snapshot() -> anyhow::Result<()>
{
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    harness
        .publish(&subscription, bundle("retained", ACTION_A, ACTION_A))
        .await?;
    let mut oversized = bundle("oversized", ACTION_A, ACTION_A);
    oversized.policies.resize(16 * 1024 * 1024, b' ');
    send(&subscription, oversized).await?;
    // Keep the sender open: only transport rejection should cause this reconnect.
    let reconnected = harness.subscription().await?;
    assert_eq!(reconnected.request.current_version, "retained");
    let (decision, retained) = harness.runtime.pipeline.enforce(&request(), SESSION).await;
    assert_matches!(decision, EnforcementDecision::Allow { .. });
    harness
        .publish(&reconnected, bundle("recovered", ACTION_A, ACTION_A))
        .await?;
    let (decision, recovered) = harness.runtime.pipeline.enforce(&request(), SESSION).await;
    assert_matches!(decision, EnforcementDecision::Allow { .. });
    let events = harness.audit(vec![retained, recovered]).await?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.bundle_version.as_str())
            .collect::<Vec<_>>(),
        vec!["retained", "recovered"]
    );
    Ok(())
}
