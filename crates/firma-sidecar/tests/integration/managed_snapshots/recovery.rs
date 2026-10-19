use std::time::Duration;

use firma_core::DenyReason;
use firma_sidecar::pipeline::EnforcementDecision;
use pretty_assertions::assert_matches;
use tonic::Status;

use super::fixture::{ACTION_A, ACTION_B, Harness, SESSION, bundle, request};

#[tokio::test]
async fn expired_reconnect_requests_content_and_recovers_with_the_same_version()
-> anyhow::Result<()> {
    for credentialed in [false, true] {
        let mut harness = Harness::new(credentialed)?;
        let subscription = harness.subscription().await?;
        let candidate = bundle("retained", ACTION_B, ACTION_B);
        harness.publish(&subscription, candidate.clone()).await?;
        subscription
            .updates
            .send(Err(Status::unavailable("connection lost")))
            .await?;
        let reconnected = harness.subscription().await?;
        assert_eq!(reconnected.request.current_version, "retained");

        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(301)).await;
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
        tokio::time::resume();
        reconnected
            .updates
            .send(Err(Status::unavailable("connection lost")))
            .await?;
        let expired = harness.subscription().await?;
        assert_eq!(expired.request.current_version, "");
        // Match the standalone producer: matching versions suppress initial send.
        if expired.request.current_version != candidate.version {
            harness.publish(&expired, candidate).await?;
        }
        assert_matches!(
            harness
                .runtime
                .pipeline
                .enforce(&request(), SESSION)
                .await
                .0,
            EnforcementDecision::Allow { .. }
        );
    }
    Ok(())
}

#[tokio::test]
async fn keyless_authority_enforces_complete_snapshot_transport_limit() -> anyhow::Result<()> {
    let mut harness = Harness::new(false)?;
    let subscription = harness.subscription().await?;
    let mut oversized = bundle("too-large", ACTION_A, ACTION_B);
    oversized.policies.resize(16 * 1024 * 1024, b' ');
    super::fixture::send(&subscription, oversized).await?;
    let reconnected = harness.subscription().await?;
    assert_eq!(reconnected.request.current_version, "");
    assert!(!harness.runtime.readiness.snapshot().policy_bundle_ready);
    let valid = bundle("recovered", ACTION_A, ACTION_A);
    harness.publish(&reconnected, valid).await?;
    assert_matches!(
        harness
            .runtime
            .pipeline
            .enforce(&request(), SESSION)
            .await
            .0,
        EnforcementDecision::Allow { .. }
    );
    Ok(())
}
