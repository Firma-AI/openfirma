//! Integration coverage for local-exec management-token resolution at
//! startup ([`firma_sidecar::startup::spawn_local_exec_endpoint`]).
//!
//! The handler-level approval/rejection logic is covered by unit tests in
//! `local_exec/handler.rs`; this suite exercises the startup plumbing that
//! resolves the configured management-token source (env var or file) and
//! fails closed on misconfiguration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::PathBuf;

use firma_sidecar::config::{LocalExecConfig, SidecarConfig};
use firma_sidecar::local_exec::handler::DefaultAction;
use firma_sidecar::startup::spawn_local_exec_endpoint;
use tokio_util::sync::CancellationToken;

/// Unique env var name. nextest runs one process per test, so each test owns
/// an isolated environment.
const ENV_VAR: &str = "FIRMA_TEST_LOCAL_EXEC_MGMT_TOKEN";

fn local_exec_config() -> LocalExecConfig {
    LocalExecConfig {
        socket_path: PathBuf::from("/tmp/firma-test-local-exec-unused.sock"),
        default_action: DefaultAction::PendingHitl,
        token_ttl_secs: 300,
        retry_after_ms: 500,
        management_token_env: None,
        management_token_path: None,
    }
}

fn sidecar_with(local_exec: LocalExecConfig) -> SidecarConfig {
    SidecarConfig {
        local_exec: Some(local_exec),
        ..SidecarConfig::default()
    }
}

/// Assert a spawn result is `Ok(Some(handle))` and abort the handle without
/// driving the endpoint's bind/accept loop. The new startup lines execute
/// synchronously before `tokio::spawn`, so coverage is hit without polling.
fn assert_spawned(result: anyhow::Result<Option<tokio::task::JoinHandle<()>>>) {
    let handle = result
        .expect("spawn should succeed when the management-token source resolves")
        .expect("spawn should return a JoinHandle when local_exec is configured");
    handle.abort();
}

/// Assert a spawn result is an `Err` whose message contains `needle`.
fn assert_spawn_error(result: anyhow::Result<Option<tokio::task::JoinHandle<()>>>, needle: &str) {
    let err = result.expect_err("spawn should fail on a misconfigured token source");
    assert!(
        format!("{err:#}").contains(needle),
        "expected error containing {needle:?}, got: {err:#}"
    );
}

#[expect(
    unsafe_code,
    reason = "nextest runs one process per test; env is set before test work starts"
)]
fn set_env(value: &str) {
    unsafe { std::env::set_var(ENV_VAR, value) };
}

#[expect(
    unsafe_code,
    reason = "nextest runs one process per test; env is cleared before test work starts"
)]
fn clear_env() {
    unsafe { std::env::remove_var(ENV_VAR) };
}

#[tokio::test]
async fn absent_local_exec_section_spawns_nothing() {
    let cfg = SidecarConfig {
        local_exec: None,
        ..SidecarConfig::default()
    };
    let result = spawn_local_exec_endpoint(&cfg, None, CancellationToken::new());
    assert!(result.is_ok_and(|o| o.is_none()));
}

#[tokio::test]
async fn management_token_env_resolves_and_trims_trailing_newlines() {
    set_env("operator-secret\n\n");
    let mut le = local_exec_config();
    le.management_token_env = Some(ENV_VAR.to_string());
    let result = spawn_local_exec_endpoint(&sidecar_with(le), None, CancellationToken::new());
    assert_spawned(result);
    clear_env();
}

#[tokio::test]
async fn management_token_env_unset_is_a_startup_error() {
    clear_env();
    let mut le = local_exec_config();
    le.management_token_env = Some(ENV_VAR.to_string());
    let result = spawn_local_exec_endpoint(&sidecar_with(le), None, CancellationToken::new());
    assert_spawn_error(result, "is not set");
}

#[tokio::test]
async fn management_token_env_empty_is_a_startup_error() {
    set_env("\n");
    let mut le = local_exec_config();
    le.management_token_env = Some(ENV_VAR.to_string());
    let result = spawn_local_exec_endpoint(&sidecar_with(le), None, CancellationToken::new());
    assert_spawn_error(result, "is empty");
    clear_env();
}

#[tokio::test]
async fn management_token_path_resolves_and_trims_trailing_newlines() {
    let dir = tempfile::tempdir().expect("tempdir for management token file");
    let token_file = dir.path().join("mgmt-token");
    std::fs::write(&token_file, "path-secret\r\n").expect("write management token file");

    let mut le = local_exec_config();
    le.management_token_path = Some(token_file);
    let result = spawn_local_exec_endpoint(&sidecar_with(le), None, CancellationToken::new());
    assert_spawned(result);
}

#[tokio::test]
async fn management_token_path_unreadable_is_a_startup_error() {
    let dir = tempfile::tempdir().expect("tempdir for missing token file");
    let missing = dir.path().join("does-not-exist");

    let mut le = local_exec_config();
    le.management_token_path = Some(missing);
    let result = spawn_local_exec_endpoint(&sidecar_with(le), None, CancellationToken::new());
    assert_spawn_error(result, "read management_token_path");
}

#[tokio::test]
async fn management_token_path_empty_is_a_startup_error() {
    let dir = tempfile::tempdir().expect("tempdir for empty token file");
    let token_file = dir.path().join("empty");
    std::fs::write(&token_file, "\n\r\n").expect("write empty management token file");

    let mut le = local_exec_config();
    le.management_token_path = Some(token_file);
    let result = spawn_local_exec_endpoint(&sidecar_with(le), None, CancellationToken::new());
    assert_spawn_error(result, "is empty");
}

#[tokio::test]
async fn management_disabled_when_neither_source_configured() {
    let le = local_exec_config();
    let result = spawn_local_exec_endpoint(&sidecar_with(le), None, CancellationToken::new());
    assert_spawned(result);
}
