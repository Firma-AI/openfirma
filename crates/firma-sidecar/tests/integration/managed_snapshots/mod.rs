mod admission;
mod atomic;
mod composite_audit;
mod coverage;
mod delivery;
mod evidence;
mod fixture;
mod freshness;
mod query_names;
mod recovery;
mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use firma_core::{Connector, ConnectorError, ConnectorResponse, DenyReason, TransportView};
use firma_http::{Authority, HeaderMap, Method};
use firma_protobuf::v1::PolicyBundleCapability;
use firma_sidecar::audit::Decision;
use firma_sidecar::composio::ComposioCatalogs;
use firma_sidecar::connector::ConnectorRegistry;
use firma_sidecar::handler::{HandledResponse, RequestHandler};
use firma_sidecar::pipeline::EnforcementDecision;
use tonic::Status;

use support::{Fixture, bundle, push, request, rule};

#[tokio::test]
async fn complete_bundles_replace_mapping_policy_and_preserve_redaction() -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (handshake, tx) = fixture.connection().await?;
    assert_eq!(
        handshake.supported_capabilities,
        [PolicyBundleCapability::ActionMappingSnapshotV1 as i32]
    );
    assert_eq!(handshake.current_version, "");

    let mut initial = bundle("7", vec![rule("code.write"), support::rule("code.read")]);
    initial
        .mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("missing mappings"))?
        .rules[1]
        .path = Some("*".into());
    push(&tx, initial).await?;
    fixture.applied("7").await?;
    let (decision, audit) = fixture.observe(&request()).await?;
    std::assert_matches!(decision, EnforcementDecision::Allow { .. });
    assert_eq!(audit.bundle_version, "7");
    assert_eq!(audit.action, "code.read"); // Present wildcard outranks omitted path.
    assert_eq!(
        audit.resource,
        "example.test/resource?private_query=[REDACTED]&visible=value"
    );

    let mut next = bundle("8", vec![rule("code.write")]);
    next.policies =
        b"forbid(principal, action == Firma::Action::\"code.write\", resource);".to_vec();
    push(&tx, next).await?;
    fixture.applied("8").await?;
    let (decision, audit) = fixture.observe(&request()).await?;
    std::assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyDenied,
            ..
        }
    );
    assert_eq!(audit.bundle_version, "8");
    assert_eq!(audit.action, "code.write");
    assert_eq!(audit.decision, Decision::Deny);
    Ok(())
}

fn invalid_candidates() -> anyhow::Result<Vec<firma_protobuf::v1::PolicyBundle>> {
    let mut candidates = Vec::new();
    let mut missing = bundle("bad", vec![]);
    missing.mappings = None;
    candidates.push(missing);
    for (format, protected) in [(0, true), (2, true), (1, false)] {
        let mut candidate = bundle("bad", vec![]);
        let mappings = candidate
            .mappings
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("mappings"))?;
        mappings.format_version = format;
        mappings.default_protected = protected;
        candidates.push(candidate);
    }
    for invalid in [
        firma_protobuf::v1::ActionMappingRule {
            method: Some(String::new()),
            ..rule("code.read")
        },
        firma_protobuf::v1::ActionMappingRule {
            method: Some("get".into()),
            ..rule("code.read")
        },
        firma_protobuf::v1::ActionMappingRule {
            host: String::new(),
            ..rule("code.read")
        },
        firma_protobuf::v1::ActionMappingRule {
            host: "*.".into(),
            ..rule("code.read")
        },
        firma_protobuf::v1::ActionMappingRule {
            path: Some(String::new()),
            ..rule("code.read")
        },
        rule("unknown.action"),
    ] {
        candidates.push(bundle("bad", vec![invalid]));
    }
    let mut duplicate = rule("code.write");
    duplicate.host = "EXAMPLE.TEST.:443".into();
    candidates.push(bundle("bad", vec![rule("code.read"), duplicate]));
    let mut policy = bundle("bad", vec![rule("code.write")]);
    policy.policies = b"not Cedar".to_vec();
    candidates.push(policy);
    let mut schema = bundle("bad", vec![rule("code.write")]);
    schema.entity_schema = b"not a schema".to_vec();
    candidates.push(schema);
    let mut ttl = bundle("bad", vec![]);
    ttl.ttl_seconds = 0;
    candidates.push(ttl);
    candidates.push(bundle("", vec![]));
    // Blank or padded versions must not poison reconnect state: the Team
    // Authority rejects non-canonical versions, so persisting one would break
    // future reconnects. The standalone hash versions contain no whitespace.
    candidates.push(bundle(" ", vec![rule("code.write")]));
    candidates.push(bundle(" 7 ", vec![rule("code.write")]));
    candidates.push(bundle("1 2", vec![rule("code.write")]));
    Ok(candidates)
}

#[tokio::test]
async fn rejected_candidates_preserve_generation_deadline_and_reconnect_version()
-> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, mut tx) = fixture.connection().await?;
    let mut good = bundle("1", vec![rule("code.read")]);
    good.ttl_seconds = 3;
    push(&tx, good).await?;
    fixture.applied("1").await?;
    let accepted_at = std::time::Instant::now();

    for candidate in invalid_candidates()? {
        push(&tx, candidate).await?;
        // Stream order makes the subsequent reconnect an observation barrier:
        // all preceding candidates have been consumed before this error.
        tx.send(Err(Status::unavailable("disconnect after candidate")))
            .await?;
        let (handshake, next_tx) = fixture.connection().await?;
        assert_eq!(handshake.current_version, "1");
        assert_eq!(
            handshake.supported_capabilities,
            [PolicyBundleCapability::ActionMappingSnapshotV1 as i32]
        );
        let (_, audit) = fixture.observe(&request()).await?;
        assert_eq!(audit.bundle_version, "1");
        assert_eq!(audit.action, "code.read");
        tx = next_tx;
    }
    tokio::time::sleep(Duration::from_secs(2).saturating_sub(accepted_at.elapsed())).await;
    let rejected_at = std::time::Instant::now();
    let mut late_invalid = bundle("late-invalid", vec![]);
    late_invalid.mappings = None;
    push(&tx, late_invalid).await?;
    tx.send(Err(Status::unavailable("late rejection barrier")))
        .await?;
    let (handshake, next_tx) = fixture.connection().await?;
    assert_eq!(handshake.current_version, "1");
    tx = next_tx;
    tokio::time::sleep(Duration::from_millis(3100).saturating_sub(accepted_at.elapsed())).await;
    assert!(
        rejected_at.elapsed() < Duration::from_secs(3),
        "must observe before a rejection-renewed deadline"
    );
    let (decision, audit) = fixture.observe(&request()).await?;
    std::assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleStale,
            ..
        }
    );
    assert_eq!(audit.bundle_version, "1");
    push(&tx, bundle("2", vec![rule("code.write")])).await?;
    fixture.applied("2").await?;
    let (decision, audit) = fixture.observe(&request()).await?;
    std::assert_matches!(decision, EnforcementDecision::Allow { .. });
    assert_eq!(audit.action, "code.write");
    Ok(())
}

#[tokio::test]
async fn missing_initial_mappings_never_establish_readiness_and_empty_is_protected()
-> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;
    let mut legacy = bundle("legacy", vec![]);
    legacy.mappings = None;
    push(&tx, legacy).await?;
    tx.send(Err(Status::unavailable("reconnect barrier")))
        .await?;
    let (handshake, tx) = fixture.connection().await?;
    assert_eq!(handshake.current_version, "");
    assert!(!fixture.runtime.readiness.snapshot().policy_bundle_ready);
    let (decision, audit) = fixture.observe(&request()).await?;
    std::assert_matches!(decision, EnforcementDecision::Deny { .. });
    assert_eq!(audit.bundle_version, "");
    push(&tx, bundle("empty", vec![])).await?;
    fixture.applied("empty").await?;
    assert!(fixture.runtime.readiness.snapshot().policy_bundle_ready);
    let (decision, audit) = fixture.observe(&request()).await?;
    std::assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::UnclassifiedIntent,
            ..
        }
    );
    assert_eq!(audit.bundle_version, "empty");
    Ok(())
}

#[tokio::test]
async fn policy_only_bundle_cannot_make_connected_sidecar_ready() -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (handshake, tx) = fixture.connection().await?;
    assert_eq!(
        handshake.supported_capabilities,
        vec![PolicyBundleCapability::ActionMappingSnapshotV1 as i32]
    );
    let mut legacy = bundle("local", vec![]);
    legacy.mappings = None;
    push(&tx, legacy).await?;
    tx.send(Err(Status::unavailable("reconnect barrier")))
        .await?;
    let (handshake, tx) = fixture.connection().await?;
    assert_eq!(handshake.current_version, "");
    let (decision, _) = fixture.observe(&request()).await?;
    std::assert_matches!(decision, EnforcementDecision::Deny { .. });
    push(&tx, bundle("managed", vec![rule("code.write")])).await?;
    fixture.applied("managed").await?;
    let (decision, audit) = fixture.observe(&request()).await?;
    std::assert_matches!(decision, EnforcementDecision::Allow { .. });
    assert_eq!(audit.action, "code.write");
    Ok(())
}

#[tokio::test]
async fn managed_composio_protocol_denials_redact_queries_and_record_generation()
-> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;
    push(&tx, bundle("17", vec![])).await?;
    fixture.applied("17").await?;
    let connector = Arc::new(CountingConnector::default());
    let handler = RequestHandler::new(
        Arc::clone(&fixture.runtime.pipeline),
        Arc::new(ConnectorRegistry::new(connector.clone())),
        fixture.audit_tx.clone(),
    )
    .with_composio_catalogs(Arc::new(composio_catalogs()?));
    let mut malformed = request();
    malformed.host = Authority::from_static("backend.composio.dev");
    malformed.path = "/unsupported?private_query=custom-secret&visible=value".into();
    std::assert_matches!(
        handler.handle(malformed, "managed-test").await,
        HandledResponse::Deny {
            reason: DenyReason::MalformedRequest,
            ..
        }
    );
    let audit = fixture.event().await?;
    assert_eq!(
        audit.resource,
        "backend.composio.dev/unsupported?private_query=[REDACTED]&visible=value"
    );
    assert_eq!(audit.bundle_version, "17");
    assert_eq!(audit.decision, Decision::Deny);
    assert!(!audit.deny_reason.contains("custom-secret"));

    let (_, upgrade) = composio_requests();
    std::assert_matches!(
        handler.authorize_upgrade(upgrade, "managed-test").await,
        firma_sidecar::handler::UpgradeAuthorization::Deny {
            reason: DenyReason::FailClosed,
            ..
        }
    );
    let audit = fixture.event().await?;
    assert_composio_audit(&audit, "17", false);
    assert_eq!(audit.decision, Decision::Deny);
    assert_eq!(connector.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[derive(Default)]
struct CountingConnector(AtomicUsize, std::sync::Mutex<Vec<String>>);

#[async_trait]
impl Connector for CountingConnector {
    async fn dispatch(&self, view: &TransportView) -> Result<ConnectorResponse, ConnectorError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        self.1
            .lock()
            .map_err(|error| ConnectorError::InvalidRequest(error.to_string()))?
            .push(view.envelope().intent().resource_display());
        Ok(ConnectorResponse {
            status: 200,
            headers: HeaderMap::new(),
            body: vec![],
            dispatch_latency: Duration::ZERO,
            response_size: 0,
        })
    }
}

#[tokio::test]
async fn managed_composio_transport_gates_execution_and_discovery_at_the_handler()
-> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;
    let connector = Arc::new(CountingConnector::default());
    let handler = RequestHandler::new(
        Arc::clone(&fixture.runtime.pipeline),
        Arc::new(ConnectorRegistry::new(connector.clone())),
        fixture.audit_tx.clone(),
    )
    .with_composio_catalogs(Arc::new(composio_catalogs()?));
    let (execution, discovery) = composio_requests();

    for (version, rules, allowed) in [
        ("empty", vec![], false),
        ("unrelated", vec![rule("code.read")], false),
        (
            "matched",
            vec![firma_protobuf::v1::ActionMappingRule {
                host: "backend.composio.dev".into(),
                ..rule("code.read")
            }],
            true,
        ),
    ] {
        let mut candidate = bundle(version, rules);
        candidate.policies = b"permit(principal, action, resource); forbid(principal, action == Firma::Action::\"code.read\", resource);".to_vec();
        push(&tx, candidate).await?;
        fixture.applied(version).await?;
        let before = connector.0.load(Ordering::SeqCst);
        for raw in [&execution, &discovery] {
            let response = handler
                .handle(
                    firma_sidecar::pipeline::RawRequest {
                        method: raw.method.clone(),
                        host: raw.host.clone(),
                        path: raw.path.clone(),
                        headers: raw.headers.clone(),
                        body: raw.body.clone(),
                        is_https: true,
                    },
                    "managed-test",
                )
                .await;
            if allowed {
                std::assert_matches!(
                    response,
                    HandledResponse::Ok(_) | HandledResponse::Passthrough(_)
                );
            } else {
                std::assert_matches!(
                    response,
                    HandledResponse::Deny {
                        reason: DenyReason::UnclassifiedIntent,
                        ..
                    }
                );
            }
            let audit = fixture.event().await?;
            assert_composio_audit(&audit, version, raw.method == Method::POST);
        }
        assert_eq!(
            connector.0.load(Ordering::SeqCst) - before,
            if allowed { 2 } else { 0 }
        );
    }
    let mut expired = bundle(
        "expired",
        vec![firma_protobuf::v1::ActionMappingRule {
            host: "backend.composio.dev".into(),
            ..rule("code.read")
        }],
    );
    expired.ttl_seconds = 1;
    push(&tx, expired).await?;
    fixture.applied("expired").await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::assert_matches!(
        handler.handle(execution, "managed-test").await,
        HandledResponse::Deny {
            reason: DenyReason::PolicyBundleStale,
            ..
        }
    );
    fixture.event().await?;
    std::assert_matches!(
        handler.handle(discovery, "managed-test").await,
        HandledResponse::Deny {
            reason: DenyReason::PolicyBundleStale,
            ..
        }
    );
    fixture.event().await?;
    assert_eq!(connector.0.load(Ordering::SeqCst), 2);
    assert_eq!(
        connector
            .1
            .lock()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?[1],
        "backend.composio.dev/api/v3/tools?private_query=custom-secret&key=default-secret&token=pipeline-secret&api-key=baseline-secret"
    );
    Ok(())
}

fn composio_requests() -> (
    firma_sidecar::pipeline::RawRequest,
    firma_sidecar::pipeline::RawRequest,
) {
    let mut execution = request();
    execution.method = Method::POST;
    execution.host = Authority::from_static("backend.composio.dev");
    execution.path = "/api/v3.1/tools/execute/GMAIL_FETCH_EMAILS".into();
    execution.body = Some(br#"{"version":"20251111_00","user_id":"demo","arguments":{}}"#.to_vec());
    let mut discovery = request();
    discovery.host = execution.host.clone();
    discovery.path =
        "/api/v3/tools?private_query=custom-secret&key=default-secret&token=pipeline-secret&api-key=baseline-secret".into();
    (execution, discovery)
}

fn composio_catalogs() -> anyhow::Result<ComposioCatalogs> {
    Ok(ComposioCatalogs::from_json_pairs([(
        r#"{"toolkit":"gmail","version":"20251111_00","tools":[{"toolkit":"gmail","version":"20251111_00","slug":"GMAIL_FETCH_EMAILS","name":"Fetch","description":"Fetch"}]}"#,
        r#"{"toolkit":"gmail","version":"20251111_00","mappings":{"GMAIL_FETCH_EMAILS":"communication.external.read"}}"#,
    )])?)
}

fn assert_composio_audit(
    audit: &firma_sidecar::audit::ExecutionEvent,
    version: &str,
    execution: bool,
) {
    assert_eq!(audit.bundle_version, version);
    assert!(!audit.resource.contains("custom-secret"));
    assert!(!audit.resource.contains("default-secret"));
    assert!(!audit.deny_reason.contains("custom-secret"));
    assert!(!audit.deny_reason.contains("default-secret"));
    assert!(!audit.resource.contains("pipeline-secret"));
    assert!(!audit.deny_reason.contains("pipeline-secret"));
    assert!(!audit.resource.contains("baseline-secret"));
    assert!(!audit.deny_reason.contains("baseline-secret"));
    if execution {
        assert_eq!(audit.action, "communication.external.read");
        assert_eq!(audit.resource, "composio://gmail/GMAIL_FETCH_EMAILS");
    } else {
        assert_eq!(
            audit.resource,
            "backend.composio.dev/api/v3/tools?private_query=[REDACTED]&key=[REDACTED]&token=[REDACTED]&api-key=[REDACTED]"
        );
    }
}

/// An expired snapshot cannot classify anything, so every request it would
/// govern must be denied as stale. Classifying against the expired rules first
/// reports unmatched traffic as unclassified, sending operators to fix
/// mappings when the Authority connection is what lapsed.
#[tokio::test]
async fn expired_snapshots_deny_unmatched_requests_as_stale() -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;
    let mut expiring = bundle("expiring", vec![rule("code.read")]);
    expiring.ttl_seconds = 1;
    push(&tx, expiring).await?;
    fixture.applied("expiring").await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let unmatched = firma_sidecar::pipeline::RawRequest {
        host: Authority::from_static("unmapped.test"),
        ..request()
    };
    let (decision, audit) = fixture.observe(&unmatched).await?;
    std::assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleStale,
            ..
        }
    );
    assert_eq!(audit.bundle_version, "expiring");
    Ok(())
}
