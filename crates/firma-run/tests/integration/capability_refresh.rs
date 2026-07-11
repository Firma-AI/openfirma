//! Lifecycle coverage for the background capability refresher
//! ([`firma_run::capability::refresh::CapabilityRefresher`]).
//!
//! The scheduling maths (`compute_wait`) is unit-tested in-module; these tests
//! cover the thread lifecycle that unit tests cannot reach: `spawn` parks the
//! worker on the stop channel, and `Drop` must interrupt it and join promptly —
//! whether the worker is idle waiting for a far-off renewal or actively looping
//! through failed re-mints and backoff.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Utc;

use firma_run::capability::issue::IssueParams;
use firma_run::capability::refresh::CapabilityRefresher;
use firma_run::config::{CapabilityLeaseConfig, CapabilitySource};

fn lease() -> CapabilityLeaseConfig {
    CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        refresh_ratio: 0.60,
        grace_seconds: 30,
    }
}

/// `IssueParams` pointing at a dead Authority with a missing public-key file.
/// `mint()` reads the key before any network call, so a re-mint attempt fails
/// fast and network-free — the refresher can never actually succeed here.
fn dead_params() -> IssueParams {
    IssueParams {
        authority_url: "http://127.0.0.1:1".to_string(),
        authority_pub_key_path: PathBuf::from("/nonexistent/firma-authority.pub"),
        authority_ca_cert_path: None,
        credentials: None,
        agent_id: "agent_refresh".to_string(),
        session_id: "sess_refresh".to_string(),
        requested_actions: vec!["communication.external.send".to_string()],
        resource_scope: "*".to_string(),
        ttl_seconds: 900,
    }
}

#[test]
fn drop_interrupts_the_scheduled_wait() {
    // A far-off expiry schedules the first renewal ~tens of minutes out, so the
    // worker blocks in `recv_timeout`. Drop must wake it via the stop channel
    // rather than blocking on that timeout.
    let far_future = Utc::now() + chrono::Duration::hours(1);
    let refresher = CapabilityRefresher::spawn(
        dead_params(),
        Path::new("/tmp/firma-refresh-test-seed.toml"),
        far_future,
        &lease(),
    )
    .expect("spawn refresher");

    // Let the worker reach its `recv_timeout` park.
    std::thread::sleep(Duration::from_millis(50));

    let start = Instant::now();
    drop(refresher);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "Drop must interrupt the long scheduled wait, not block on it"
    );
}

#[test]
fn drop_joins_while_retrying_failed_mints() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    // An already-elapsed expiry drives the loop to attempt a re-mint at the
    // minimum interval; every attempt fails fast (missing key) and enters
    // backoff. Drop must still join the worker mid-retry.
    let past = Utc::now() - chrono::Duration::seconds(10);
    let refresher = CapabilityRefresher::spawn(dead_params(), &seed_path, past, &lease())
        .expect("spawn refresher");

    // Long enough for at least one mint attempt (fires at the ~1s floor) and
    // entry into the backoff wait.
    std::thread::sleep(Duration::from_millis(1200));

    let start = Instant::now();
    drop(refresher);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "Drop must join the worker even while it is retrying failed re-mints"
    );

    // A failed mint must never write a seed file.
    assert!(
        !seed_path.exists(),
        "a failed re-mint must not leave a seed file behind"
    );
}
