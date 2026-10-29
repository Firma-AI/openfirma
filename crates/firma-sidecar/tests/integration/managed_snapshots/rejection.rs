//! A Sidecar shuts down only when the Authority rejects its run.

use std::time::Duration;

use tonic::Status;

use super::fixture::Harness;

/// Long enough for a reconnect to the fixture, whose backoff is milliseconds.
const SETTLE: Duration = Duration::from_secs(2);

#[tokio::test]
async fn a_rejected_runtime_credential_shuts_the_sidecar_down() -> anyhow::Result<()> {
    let mut harness = Harness::with_runtime_credential()?;
    let subscription = harness.subscription().await?;
    subscription
        .updates
        .send(Err(Status::unauthenticated("run closed")))
        .await?;
    assert!(harness.shuts_down_within(Duration::from_secs(10)).await);
    Ok(())
}

#[tokio::test]
async fn a_rejected_pre_shared_key_keeps_reconnecting() -> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    subscription
        .updates
        .send(Err(Status::unauthenticated("key revoked")))
        .await?;
    harness.subscription().await?;
    assert!(!harness.shuts_down_within(SETTLE).await);
    Ok(())
}

#[tokio::test]
async fn another_failure_of_a_run_keeps_reconnecting() -> anyhow::Result<()> {
    let mut harness = Harness::with_runtime_credential()?;
    let subscription = harness.subscription().await?;
    subscription
        .updates
        .send(Err(Status::unavailable("restarting")))
        .await?;
    harness.subscription().await?;
    assert!(!harness.shuts_down_within(SETTLE).await);
    Ok(())
}
