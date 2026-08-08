//! Verifies that stack stop kills a Unix process group, including grandchildren.

#[cfg(unix)]
use crate::topology;

#[cfg(unix)]
#[test]
fn unix_pgrp_kills_grandchild() {
    use std::process::Command;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path();
    let child_ready_marker = state_dir.join("grandchild.ready");
    let parent_ready_marker = state_dir.join("parent.ready");
    let terminated_marker = state_dir.join("grandchild.terminated");

    // The outer shell models a stack component and the inner shell its
    // grandchild. Both inherit the process group created by the stack helper.
    // The grandchild installs its TERM trap before publishing readiness; the
    // parent publishes its own marker only after capturing `$!` and observing
    // that readiness. Its TERM trap waits for the grandchild so it is reaped
    // before the component exits.
    let mut cmd = Command::new("sh");
    cmd.args([
        "-c",
        "trap 'wait \"$grandchild\"; exit 0' TERM; \
         sh -c \"$GRANDCHILD_SCRIPT\" & grandchild=$!; \
         until [ \"$(cat \"$CHILD_READY_MARKER\" 2>/dev/null)\" = ready ]; do sleep 0.05; done; \
         printf ready > \"$PARENT_READY_MARKER\"; wait \"$grandchild\"",
    ])
    .env(
        "GRANDCHILD_SCRIPT",
        "trap 'printf terminated > \"$TERMINATED_MARKER\"; exit 0' TERM; \
         printf ready > \"$CHILD_READY_MARKER\"; while :; do sleep 1; done",
    )
    .env("CHILD_READY_MARKER", &child_ready_marker)
    .env("PARENT_READY_MARKER", &parent_ready_marker)
    .env("TERMINATED_MARKER", &terminated_marker);
    firma_process_orchestrator::test_support::spawn_raw_into_group(
        state_dir,
        "authority",
        &mut cmd,
    )
    .expect("spawn");

    // Poll the marker contents rather than its existence: shell redirection
    // creates the file before `printf` writes the readiness payload.
    let deadline = Instant::now() + Duration::from_secs(5);
    let ready = loop {
        let ready =
            std::fs::read_to_string(&parent_ready_marker).is_ok_and(|contents| contents == "ready");
        if ready || Instant::now() >= deadline {
            break ready;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    // Stop even when readiness timed out so a failed fixture cannot leak its
    // process group into subsequent tests.
    let stop_result =
        firma_process_orchestrator::stop_components(state_dir, Duration::from_secs(5), &topology());

    assert!(ready, "grandchild never became ready");
    let outcome = stop_result.expect("stop");
    assert!(!outcome.forced, "stack stop unexpectedly required SIGKILL");

    // A PID probe cannot distinguish a live process from an unreaped zombie.
    // The marker directly proves that the process-group TERM reached the
    // grandchild; the clean outcome above proves the parent reaped it.
    assert_eq!(
        std::fs::read_to_string(terminated_marker).expect("termination marker"),
        "terminated",
    );
}
