use firma_core::DenyReason;
use firma_protobuf::v1::{ActionMappingSnapshot, PolicyBundleCapability};
use firma_sidecar::config::MappingRuleConfig;
use firma_sidecar::pipeline::EnforcementDecision;
use firma_sidecar::pipeline::MappingTable;
use pretty_assertions::assert_matches;

use super::fixture::{ACTION_A, ACTION_B, Harness, SESSION, bundle, request, rule, send};

#[test]
fn file_based_empty_must_match_managed_explicit_deny_all() {
    use firma_sidecar::config::MappingRulesFile;
    use firma_sidecar::pipeline::ActionClassRegistry;

    let file = MappingRulesFile { rules: Vec::new() };
    let registry = ActionClassRegistry::v0_1();
    let file_table = MappingTable::from_config(&file, &registry).unwrap();
    let managed_table = MappingTable::from_managed_rules(Vec::new()).unwrap();
    for table in [file_table, managed_table] {
        let normalizer = firma_sidecar::normalizer::IntentNormalizer::new(table);
        assert_matches!(
            normalizer.normalize(&request()),
            Err(EnforcementDecision::Deny {
                reason: DenyReason::UnclassifiedIntent,
                ..
            })
        );
    }
}

#[test]
fn managed_table_rejects_non_canonical_host_spelling() {
    let table = MappingTable::from_managed_rules(vec![MappingRuleConfig {
        method: Some(firma_http::Method::GET),
        host: "API.test".to_string(),
        path: Some("/request".to_string()),
        action_class: ACTION_A.to_string(),
    }]);
    let err = table.unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid mapping rules file: rule 0: invalid normalized host"
    );
}

#[test]
fn managed_table_rejects_nul_path() {
    let table = MappingTable::from_managed_rules(vec![MappingRuleConfig {
        method: Some(firma_http::Method::GET),
        host: "api.test".to_string(),
        path: Some("/\0".to_string()),
        action_class: ACTION_A.to_string(),
    }]);
    let err = table.unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid mapping rules file: rule 0: invalid path"
    );
}

#[tokio::test]
async fn managed_admission_rejects_downgrades_and_retains_the_last_complete_snapshot()
-> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let mut subscription = harness.subscription().await?;
    assert_eq!(
        subscription.request.supported_capabilities,
        vec![i32::from(PolicyBundleCapability::ActionMappingSnapshotV1)]
    );
    assert_eq!(
        subscription
            .request
            .credentials
            .as_ref()
            .map(|c| c.pre_shared_key.as_str()),
        Some("test-secret")
    );

    let mut absent = bundle("absent", ACTION_A, ACTION_A);
    absent.mappings = None;
    send(&subscription, absent.clone()).await?;
    drop(subscription);
    subscription = harness.subscription().await?;
    assert_eq!(subscription.request.current_version, "");
    assert!(!harness.runtime.readiness.snapshot().policy_bundle_ready);
    assert_matches!(
        harness
            .runtime
            .pipeline
            .enforce(&request(), SESSION)
            .await
            .0,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleNotReady,
            ..
        }
    );

    harness
        .publish(&subscription, bundle("accepted", ACTION_A, ACTION_A))
        .await?;
    assert_matches!(harness.runtime.pipeline.enforce(&request(), SESSION).await.0,
        EnforcementDecision::Allow { ref envelope, .. } if envelope.intent.action_class == ACTION_A);

    for candidate in rejected_bundles() {
        send(&subscription, candidate).await?;
        // EOF followed by a new subscription proves the rejected update was consumed.
        drop(subscription);
        subscription = harness.subscription().await?;
        assert_eq!(subscription.request.current_version, "accepted");
        assert_eq!(
            subscription.request.supported_capabilities,
            vec![i32::from(PolicyBundleCapability::ActionMappingSnapshotV1)]
        );
        assert_matches!(harness.runtime.pipeline.enforce(&request(), SESSION).await.0,
            EnforcementDecision::Allow { ref envelope, .. } if envelope.intent.action_class == ACTION_A);
    }

    let mut empty = bundle("empty", ACTION_B, ACTION_B);
    empty
        .mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture mapping missing"))?
        .rules
        .clear();
    harness.publish(&subscription, empty).await?;
    assert_matches!(
        harness
            .runtime
            .pipeline
            .enforce(&request(), SESSION)
            .await
            .0,
        EnforcementDecision::Deny {
            reason: DenyReason::UnclassifiedIntent,
            ..
        }
    );
    Ok(())
}

#[tokio::test]
async fn control_character_versions_never_poison_reconnect_state() -> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let mut subscription = harness.subscription().await?;
    harness
        .publish(&subscription, bundle("accepted", ACTION_A, ACTION_A))
        .await?;
    for version in [
        "bad\0version",
        "bad\x1bversion",
        "bad\x7fversion",
        "bad\u{202e}version",
    ] {
        let candidate = bundle(version, ACTION_B, ACTION_B);
        // Valid mappings and policy: only the version spelling is suspect.
        // A Team Authority rejects non-canonical versions, so persisting one
        // would break every future reconnect.
        send(&subscription, candidate).await?;
        drop(subscription);
        subscription = harness.subscription().await?;
        assert_eq!(
            subscription.request.current_version, "accepted",
            "control version {version:?} must not replace the last good generation"
        );
        assert_matches!(harness.runtime.pipeline.enforce(&request(), SESSION).await.0,
            EnforcementDecision::Allow { ref envelope, .. } if envelope.intent.action_class == ACTION_A);
    }
    Ok(())
}

#[tokio::test]
async fn authority_port_patterns_preserve_host_and_port_scope() -> anyhow::Result<()> {
    let mut harness = Harness::new(false)?;
    let subscription = harness.subscription().await?;
    let mut candidate = bundle("port-pattern", ACTION_A, ACTION_A);
    candidate
        .mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture mappings"))?
        .rules[0]
        .host = "localhost:8*".into();
    harness.publish(&subscription, candidate).await?;
    let mut matched = request();
    matched.host = firma_http::Authority::from_static("localhost:8080");
    assert_matches!(
        harness.runtime.pipeline.enforce(&matched, SESSION).await.0,
        EnforcementDecision::Allow { .. }
    );
    for host in ["localhost:9090", "other.test:8080"] {
        matched.host = host.parse()?;
        assert_matches!(
            harness.runtime.pipeline.enforce(&matched, SESSION).await.0,
            EnforcementDecision::Deny {
                reason: DenyReason::UnclassifiedIntent,
                ..
            }
        );
    }
    Ok(())
}

#[tokio::test]
async fn keyless_authority_connection_advertises_and_installs_managed_mappings()
-> anyhow::Result<()> {
    let mut harness = Harness::new(false)?;
    let subscription = harness.subscription().await?;
    assert_eq!(
        subscription.request.supported_capabilities,
        vec![firma_protobuf::v1::PolicyBundleCapability::ActionMappingSnapshotV1 as i32]
    );
    assert_eq!(subscription.request.credentials, None);
    harness
        .publish(&subscription, bundle("managed", ACTION_A, ACTION_A))
        .await?;
    drop(subscription);
    let subscription = harness.subscription().await?;
    assert_eq!(subscription.request.current_version, "managed");
    assert_matches!(harness.runtime.pipeline.enforce(&request(), SESSION).await.0,
        EnforcementDecision::Allow { ref envelope, .. } if envelope.intent.action_class == ACTION_A);
    Ok(())
}

#[tokio::test]
async fn managed_specificity_preserves_presence_and_stable_ties() -> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    let mut candidate = bundle("specificity", ACTION_A, ACTION_A);
    let mut omitted = rule(ACTION_B);
    omitted.path = None;
    let mut wildcard = rule(ACTION_A);
    wildcard.path = Some("*".into());
    candidate
        .mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture mapping missing"))?
        .rules = vec![omitted, wildcard];
    harness.publish(&subscription, candidate).await?;
    assert_matches!(harness.runtime.pipeline.enforce(&request(), SESSION).await.0,
        EnforcementDecision::Allow { ref envelope, .. } if envelope.intent.action_class == ACTION_A);

    let mut tied = bundle("tied", ACTION_A, ACTION_A);
    let mut first = rule(ACTION_A);
    first.host = "api.*".into();
    let mut second = rule(ACTION_B);
    second.host = "*.test".into();
    tied.mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture mapping missing"))?
        .rules = vec![first, second];
    harness.publish(&subscription, tied).await?;
    assert_matches!(harness.runtime.pipeline.enforce(&request(), SESSION).await.0,
        EnforcementDecision::Allow { ref envelope, .. } if envelope.intent.action_class == ACTION_A);
    Ok(())
}

#[tokio::test]
async fn aggregate_rule_limit_rejects_without_replacing_policy_or_extending_ttl()
-> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    let mut maximum = bundle("maximum", ACTION_A, ACTION_A);
    maximum.ttl_seconds = 60;
    let mut rules = (0..9_999)
        .map(|index| {
            let mut rule = rule(ACTION_A);
            rule.path = Some(format!("/other/{index}"));
            rule
        })
        .collect::<Vec<_>>();
    rules.push(rule(ACTION_A));
    maximum
        .mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture mapping missing"))?
        .rules = rules;
    harness.publish(&subscription, maximum.clone()).await?;
    assert_matches!(
        harness
            .runtime
            .pipeline
            .enforce(&request(), SESSION)
            .await
            .0,
        EnforcementDecision::Allow { .. }
    );

    maximum.version = "oversized".into();
    maximum.ttl_seconds = 3600;
    let mut extra = rule(ACTION_B);
    extra.path = Some("/extra".into());
    maximum
        .mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture mapping missing"))?
        .rules
        .push(extra);
    send(&subscription, maximum).await?;
    drop(subscription);
    let subscription = harness.subscription().await?;
    assert_eq!(subscription.request.current_version, "maximum");
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    assert_matches!(
        harness
            .runtime
            .pipeline
            .enforce(&request(), SESSION)
            .await
            .0,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleStale,
            ..
        }
    );
    Ok(())
}

fn rejected_bundles() -> Vec<firma_protobuf::v1::PolicyBundle> {
    let mut invalid = vec![{
        let mut absent = bundle("absent", ACTION_A, ACTION_A);
        absent.mappings = None;
        absent
    }];
    for snapshot in [
        ActionMappingSnapshot {
            format_version: 2,
            default_protected: true,
            rules: vec![rule(ACTION_A)],
        },
        ActionMappingSnapshot {
            format_version: 1,
            default_protected: false,
            rules: vec![rule(ACTION_A)],
        },
        ActionMappingSnapshot {
            format_version: 1,
            default_protected: true,
            rules: vec![rule(ACTION_A), rule(ACTION_A)],
        },
    ] {
        let mut candidate = bundle("rejected", ACTION_B, ACTION_B);
        candidate.mappings = Some(snapshot);
        invalid.push(candidate);
    }
    for (host, method, path, action) in [
        ("API.test", Some("GET"), Some("/request"), ACTION_A),
        ("api.test:0", Some("GET"), Some("/request"), ACTION_A),
        ("api.test/secret", Some("GET"), Some("/request"), ACTION_A),
        ("[not-ipv6]", Some("GET"), Some("/request"), ACTION_A),
        ("api.test", Some(""), Some("/request"), ACTION_A),
        ("api.test", Some("get"), Some("/request"), ACTION_A),
        ("api.test", Some("TRACE"), Some("/request"), ACTION_A),
        ("api.test", Some("GET"), Some(""), ACTION_A),
        ("api.test", Some("GET"), Some("/\0"), ACTION_A),
        ("api.test", Some("GET"), Some("/request"), "unknown.action"),
    ] {
        let mut candidate = bundle("rejected", ACTION_B, ACTION_B);
        candidate.mappings = Some(ActionMappingSnapshot {
            format_version: 1,
            default_protected: true,
            rules: vec![firma_protobuf::v1::ActionMappingRule {
                host: host.into(),
                method: method.map(str::to_owned),
                path: path.map(str::to_owned),
                action_class: action.into(),
            }],
        });
        invalid.push(candidate);
    }
    for (policies, schema, ttl, version) in [
        (
            b"broken".to_vec(),
            bundle("", ACTION_A, ACTION_A).entity_schema,
            300,
            "rejected",
        ),
        (
            bundle("", ACTION_A, ACTION_A).policies,
            b"broken".to_vec(),
            300,
            "rejected",
        ),
        (
            bundle("", ACTION_A, ACTION_A).policies,
            bundle("", ACTION_A, ACTION_A).entity_schema,
            0,
            "rejected",
        ),
        (
            bundle("", ACTION_A, ACTION_A).policies,
            bundle("", ACTION_A, ACTION_A).entity_schema,
            300,
            "",
        ),
    ] {
        let mut candidate = bundle(version, ACTION_B, ACTION_B);
        candidate.policies = policies;
        candidate.entity_schema = schema;
        candidate.ttl_seconds = ttl;
        invalid.push(candidate);
    }
    invalid
}
