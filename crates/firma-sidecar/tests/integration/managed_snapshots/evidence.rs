use std::io::{Read, Seek};
use std::sync::Mutex;

use firma_core::DenyReason;
use firma_sidecar::pipeline::EnforcementDecision;
use pretty_assertions::assert_matches;

use super::fixture::{ACTION_A, ACTION_B, Harness, SESSION, bundle, request};

#[tokio::test]
async fn managed_normalization_denials_retain_only_the_admitted_mapping_version()
-> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    let (decision, uninitialized) = harness.runtime.pipeline.enforce(&request(), SESSION).await;
    assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleNotReady,
            ..
        }
    );
    harness
        .publish(&subscription, bundle("allowed", ACTION_A, ACTION_A))
        .await?;
    assert_matches!(
        harness
            .runtime
            .pipeline
            .enforce(&request(), SESSION)
            .await
            .0,
        EnforcementDecision::Allow { .. }
    );

    let mut removed = bundle("removed", ACTION_A, ACTION_A);
    removed
        .mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("mappings"))?
        .rules
        .clear();
    harness.publish(&subscription, removed).await?;
    let (decision, denied) = harness.runtime.pipeline.enforce(&request(), SESSION).await;
    assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::UnclassifiedIntent,
            ..
        }
    );
    harness
        .publish(&subscription, bundle("restored", ACTION_A, ACTION_A))
        .await?;
    let (decision, allowed) = harness.runtime.pipeline.enforce(&request(), SESSION).await;
    assert_matches!(decision, EnforcementDecision::Allow { .. });
    let events = harness.audit(vec![uninitialized, denied, allowed]).await?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.bundle_version.as_str())
            .collect::<Vec<_>>(),
        vec!["", "removed", "restored"]
    );
    Ok(())
}

#[tokio::test]
async fn keyless_authority_normalization_denial_retains_snapshot_version() -> anyhow::Result<()> {
    let mut harness = Harness::new(false)?;
    let subscription = harness.subscription().await?;
    let policy = bundle("snapshot", ACTION_A, ACTION_B);
    harness.publish(&subscription, policy).await?;
    let mut request = request();
    request.method = "UNRECOGNIZED".parse()?;
    let (decision, payload) = harness.runtime.pipeline.enforce(&request, SESSION).await;
    assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::UnclassifiedIntent,
            ..
        }
    );
    let events = harness.audit(vec![payload]).await?;
    assert_eq!(events[0].bundle_version, "snapshot");
    Ok(())
}

#[tokio::test]
async fn rejected_numeric_versions_remain_identifiable() -> anyhow::Result<()> {
    let mut output = tempfile::tempfile()?;
    let subscriber = tracing_subscriber::fmt()
        .with_writer(Mutex::new(output.try_clone()?))
        .with_ansi(false)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let mut fixture = super::support::Fixture::start().await?;
    let (_, mut tx) = fixture.connection().await?;
    super::support::push(
        &tx,
        super::support::bundle("41", vec![super::support::rule("code.read")]),
    )
    .await?;
    fixture.applied("41").await?;

    for (version, invalid_mapping) in [("42", true), ("18446744073709551615", false)] {
        output.set_len(0)?;
        output.rewind()?;
        let mut candidate =
            super::support::bundle(version, vec![super::support::rule("code.write")]);
        if invalid_mapping {
            candidate.mappings = None;
        } else {
            candidate.policies = b"invalid Cedar".to_vec();
        }
        super::support::push(&tx, candidate).await?;
        tx.send(Err(tonic::Status::unavailable("rejection barrier")))
            .await?;
        let (handshake, next_tx) = fixture.connection().await?;
        assert_eq!(handshake.current_version, "41");
        tx = next_tx;
        output.rewind()?;
        let mut logs = String::new();
        output.read_to_string(&mut logs)?;
        let warning = logs
            .lines()
            .find(|line| line.contains("enforcement snapshot compilation failed"))
            .ok_or_else(|| anyhow::anyhow!("missing snapshot rejection diagnostic"))?;
        assert!(
            warning.contains(&format!("version=\"{version}\"")),
            "{warning}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejected_metadata_logs_diagnostics_without_raw_versions() -> anyhow::Result<()> {
    let mut output = tempfile::tempfile()?;
    let subscriber = tracing_subscriber::fmt()
        .with_writer(Mutex::new(output.try_clone()?))
        .with_ansi(false)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let mut fixture = super::support::Fixture::start().await?;
    let (_, mut tx) = fixture.connection().await?;
    super::support::push(
        &tx,
        super::support::bundle("accepted", vec![super::support::rule("code.read")]),
    )
    .await?;
    fixture.applied("accepted").await?;

    for (version, ttl) in [
        ("rejected-ttl".repeat(1_024), 0),
        ("rejected\nforged-log\x1b[2J".to_string(), 300),
    ] {
        output.set_len(0)?;
        output.rewind()?;
        let mut candidate =
            super::support::bundle(&version, vec![super::support::rule("code.write")]);
        candidate.ttl_seconds = ttl;
        super::support::push(&tx, candidate).await?;
        tx.send(Err(tonic::Status::unavailable("rejection barrier")))
            .await?;
        let (handshake, next_tx) = fixture.connection().await?;
        assert_eq!(handshake.current_version, "accepted");
        let (decision, audit) = fixture.observe(&super::support::request()).await?;
        assert_matches!(decision, EnforcementDecision::Allow { .. });
        assert_eq!(audit.action, "code.read");
        assert_eq!(audit.bundle_version, "accepted");
        tx = next_tx;

        output.rewind()?;
        let mut logs = String::new();
        output.read_to_string(&mut logs)?;
        assert!(logs.contains("enforcement snapshot compilation failed"));
        assert!(
            !logs.contains(&version),
            "rejected version leaked into logs"
        );
        assert!(!logs.contains('\x1b'), "terminal escape leaked into logs");
        assert!(logs.len() < 2_048, "rejection log grew with payload");
        assert!(logs.contains(&format!("ttl_seconds={ttl}")));
        assert!(logs.contains(&format!("version_bytes={}", version.len())));
    }
    Ok(())
}

#[tokio::test]
async fn oversized_versions_never_activate_nor_log_raw_payload() -> anyhow::Result<()> {
    let mut output = tempfile::tempfile()?;
    let subscriber = tracing_subscriber::fmt()
        .with_writer(Mutex::new(output.try_clone()?))
        .with_ansi(false)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let mut fixture = super::support::Fixture::start().await?;
    let (_, mut tx) = fixture.connection().await?;
    super::support::push(
        &tx,
        super::support::bundle("accepted", vec![super::support::rule("code.read")]),
    )
    .await?;
    fixture.applied("accepted").await?;

    let huge = "A".repeat(8_192);
    for rules in [
        vec![super::support::rule("code.write")],
        vec![{
            let mut invalid = super::support::rule("code.write");
            invalid.host = "API.test".into();
            invalid
        }],
    ] {
        output.set_len(0)?;
        output.rewind()?;
        super::support::push(&tx, super::support::bundle(&huge, rules)).await?;
        tx.send(Err(tonic::Status::unavailable("rejection barrier")))
            .await?;
        let (handshake, next_tx) = fixture.connection().await?;
        assert_eq!(handshake.current_version, "accepted");
        let (decision, audit) = fixture.observe(&super::support::request()).await?;
        assert_matches!(decision, EnforcementDecision::Allow { .. });
        assert_eq!(audit.action, "code.read");
        assert_eq!(audit.bundle_version, "accepted");
        tx = next_tx;

        output.rewind()?;
        let mut logs = String::new();
        output.read_to_string(&mut logs)?;
        assert!(logs.contains("enforcement snapshot compilation failed"));
        assert!(!logs.contains(&huge), "oversized version leaked into logs");
        assert!(logs.len() < 2_048, "rejection log grew with payload");
        assert!(logs.contains(&format!("version_bytes={}", huge.len())));
    }
    Ok(())
}

#[tokio::test]
async fn version_length_boundary_256_accepted_257_rejected() -> anyhow::Result<()> {
    let mut fixture = super::support::Fixture::start().await?;
    let (_, mut tx) = fixture.connection().await?;
    super::support::push(
        &tx,
        super::support::bundle("accepted", vec![super::support::rule("code.read")]),
    )
    .await?;
    fixture.applied("accepted").await?;

    let longest = "V".repeat(256);
    super::support::push(
        &tx,
        super::support::bundle(&longest, vec![super::support::rule("code.write")]),
    )
    .await?;
    fixture.applied(&longest).await?;
    let (decision, audit) = fixture.observe(&super::support::request()).await?;
    assert_matches!(decision, EnforcementDecision::Allow { .. });
    assert_eq!(audit.action, "code.write");
    assert_eq!(audit.bundle_version, longest);
    tx.send(Err(tonic::Status::unavailable("version barrier")))
        .await?;
    let (handshake, next_tx) = fixture.connection().await?;
    assert_eq!(handshake.current_version, longest);
    tx = next_tx;

    let overlong = "V".repeat(257);
    super::support::push(
        &tx,
        super::support::bundle(&overlong, vec![super::support::rule("code.read")]),
    )
    .await?;
    tx.send(Err(tonic::Status::unavailable("rejection barrier")))
        .await?;
    let (handshake, next_tx) = fixture.connection().await?;
    assert_eq!(handshake.current_version, longest);
    let (decision, audit) = fixture.observe(&super::support::request()).await?;
    assert_matches!(decision, EnforcementDecision::Allow { .. });
    assert_eq!(audit.action, "code.write");
    assert_eq!(audit.bundle_version, longest);
    tx = next_tx;

    for (version, action) in [
        ("18446744073709551615", "code.read"),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "code.write",
        ),
    ] {
        super::support::push(
            &tx,
            super::support::bundle(version, vec![super::support::rule(action)]),
        )
        .await?;
        fixture.applied(version).await?;
        let (decision, audit) = fixture.observe(&super::support::request()).await?;
        assert_matches!(decision, EnforcementDecision::Allow { .. });
        assert_eq!(audit.action, action);
        assert_eq!(audit.bundle_version, version);
    }
    Ok(())
}
