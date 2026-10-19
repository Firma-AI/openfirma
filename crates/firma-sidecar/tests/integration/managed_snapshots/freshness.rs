//! Readiness and logs reflect enforced snapshot expiry.

use std::time::Duration;

use super::support::{Fixture, Logs, bundle, push, rule};

const EXPIRED: &str = "enforcement snapshot expired";

fn capture() -> (Logs, tracing::subscriber::DefaultGuard) {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    (logs, tracing::subscriber::set_default(subscriber))
}

/// Moves the paused clock past `ttl` and lets woken tasks run.
async fn elapse(ttl: Duration) {
    tokio::time::pause();
    tokio::time::advance(ttl + Duration::from_secs(1)).await;
    tokio::time::resume();
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

async fn wait_for_fresh(fixture: &Fixture, fresh: bool) -> anyhow::Result<()> {
    let mut readiness = fixture.runtime.readiness.subscribe();
    tokio::time::timeout(Duration::from_secs(5), async {
        while readiness.borrow_and_update().policy_bundle_fresh != fresh {
            readiness.changed().await?;
        }
        anyhow::Ok(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn expiry_clears_serving_once_and_a_fresh_snapshot_restores_it() -> anyhow::Result<()> {
    let (logs, _guard) = capture();
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;

    // The initial deny-all generation was never fresh, so it never expires.
    elapse(Duration::from_secs(60)).await;
    assert_eq!(logs.count(EXPIRED)?, 0);

    push(&tx, bundle("1", vec![rule("code.read")])).await?;
    fixture.applied("1").await?;
    wait_for_fresh(&fixture, true).await?;

    elapse(Duration::from_secs(60)).await;
    wait_for_fresh(&fixture, false).await?;
    let state = fixture.runtime.readiness.snapshot();
    assert!(state.policy_bundle_ready, "hydration must survive expiry");
    assert!(!state.serving());
    logs.wait(EXPIRED, 1).await?;
    assert!(logs.count("version=\"1\" ttl_seconds=60")? >= 1);

    push(&tx, bundle("2", vec![rule("code.read")])).await?;
    wait_for_fresh(&fixture, true).await?;
    assert_eq!(
        logs.count(EXPIRED)?,
        1,
        "one warning per expired generation"
    );
    Ok(())
}

#[tokio::test]
async fn a_swap_racing_the_expiry_check_stays_fresh() -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;
    push(&tx, bundle("1", vec![rule("code.read")])).await?;
    fixture.applied("1").await?;

    // Wake the watcher at the deadline and deliver a fresh generation before
    // it is observed, so either interleaving must end fresh.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    tokio::time::resume();
    push(&tx, bundle("2", vec![rule("code.read")])).await?;
    fixture.applied("2").await?;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(fixture.runtime.readiness.snapshot().policy_bundle_fresh);
    Ok(())
}

#[tokio::test]
async fn each_accepted_snapshot_replaces_the_published_enforcement_state() -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;

    push(&tx, bundle("1", vec![rule("code.read")])).await?;
    let first = fixture.published("1").await?;
    assert_eq!(first.ttl_seconds, 60);
    let swapped_at = chrono::DateTime::parse_from_rfc3339(&first.swapped_at)?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&first.expires_at)?;
    assert_eq!(expires_at - swapped_at, chrono::Duration::seconds(60));

    push(&tx, bundle("2", vec![rule("code.read")])).await?;
    fixture.published("2").await?;
    Ok(())
}
