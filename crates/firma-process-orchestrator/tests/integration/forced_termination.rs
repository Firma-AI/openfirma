//! Regression: forced termination retains state until owned targets disappear.

#![cfg(unix)]

use std::fs::OpenOptions;
use std::io::Read as _;
use std::process::Command;
use std::time::Duration;

use firma_process_orchestrator::{OrchestratorError, State};

use crate::support::wait_for_file;

#[test]
fn forced_termination_retains_state_until_target_disappears() {
    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");

    let ready = state_dir.join("authority.ready");
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            "trap '' TERM; printf ready > \"$AUTHORITY_READY\"; while :; do sleep 1; done",
        ])
        .env("AUTHORITY_READY", &ready);
    let mut child = firma_process_orchestrator::test_support::spawn_raw_owned_into_group(
        state_dir,
        "authority",
        &mut command,
    )
    .expect("spawn authority");
    wait_for_file(&ready);

    let error = firma_process_orchestrator::stop_components(
        state_dir,
        Duration::ZERO,
        &["authority", "sidecar"],
    )
    .expect_err("zombie target remains");
    assert!(
        matches!(
            error,
            OrchestratorError::TerminationTimeout { timeout_secs: 2 }
        ),
        "unexpected stop error: {error}"
    );
    insta::assert_snapshot!(error.to_string(), @"termination targets remained present after 2s");
    assert!(state_dir.join("authority.pid").exists());
    assert!(state_dir.join("stack.lock").exists());

    child.wait().expect("collect authority");
    let outcome = firma_process_orchestrator::stop_components(
        state_dir,
        Duration::ZERO,
        &["authority", "sidecar"],
    )
    .expect("retry stop");
    assert!(!outcome.forced);
    assert!(!state_dir.join("authority.pid").exists());
    assert!(!state_dir.join("stack.lock").exists());
}

#[test]
fn status_probe_does_not_collect_owned_leader() {
    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path();
    let exit_fifo = state_dir.join("authority.exit");
    nix::unistd::mkfifo(
        &exit_fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("create exit FIFO");

    let mut command = Command::new("sh");
    command
        .args(["-c", "exec 3>\"$EXIT_FIFO\"; exit 0"])
        .env("EXIT_FIFO", &exit_fifo);
    let mut child = firma_process_orchestrator::test_support::spawn_raw_owned_into_group(
        state_dir,
        "authority",
        &mut command,
    )
    .expect("spawn authority");

    let mut exit_reader = OpenOptions::new()
        .read(true)
        .open(&exit_fifo)
        .expect("open exit FIFO");
    exit_reader
        .read_to_end(&mut Vec::new())
        .expect("wait for authority exit");

    let status =
        firma_process_orchestrator::status_components(state_dir, &["authority", "sidecar"])
            .expect("probe stack status");
    let authority = status
        .components
        .iter()
        .find(|component| component.name == "authority")
        .expect("authority status");
    assert_eq!(authority.state, State::Unhealthy);
    assert!(
        child
            .wait()
            .expect("collect authority after probe")
            .success(),
        "authority did not exit successfully"
    );
}
