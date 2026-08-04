//! Cross-platform ownership and detached-observation lifecycle coverage.

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use firma_runtime_state::{UserProcessId, pidfile};

const CHILD_MARKER: &str = "FIRMA_STACK_TEST_CHILD_MARKER";
const SUPERVISOR_STATE_DIR: &str = "FIRMA_STACK_TEST_SUPERVISOR_STATE_DIR";
const SUPERVISOR_ACKNOWLEDGE: &str = "FIRMA_STACK_TEST_SUPERVISOR_ACKNOWLEDGE";

#[derive(Clone, Copy)]
enum SupervisorExitPhase {
    BeforeReady,
    AfterReady,
}

#[test]
fn owned_shutdown_is_idempotent_and_ignores_pidfiles() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");

    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let mut stack =
        firma_stack::test_support::running_stack_from_raw(state_dir, authority, sidecar);

    std::fs::remove_file(state_dir.join("authority.pid")).expect("remove authority pidfile");
    std::fs::write(state_dir.join("sidecar.pid"), "not-a-pid\n").expect("corrupt sidecar pidfile");

    stack
        .shutdown(Duration::ZERO)
        .expect("initial owned shutdown");
    let repeated = stack
        .shutdown(Duration::ZERO)
        .expect("repeated owned shutdown");

    assert!(!repeated.forced);
    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
    assert!(!state_dir.join("stack.lock").exists());
}

#[test]
fn dropping_owner_transfers_child_collection() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");

    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let stack = firma_stack::test_support::running_stack_from_raw(state_dir, authority, sidecar);

    drop(stack);
    firma_stack::stop(state_dir, Duration::ZERO).expect("stop observed stack");

    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
}

#[test]
fn detached_supervisor_child_is_collected_for_long_lived_launcher() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");
    let (supervisor, supervisor_pid) = spawn_fixture(state_dir, "stack");
    let collector = firma_stack::test_support::collect_raw_child_in_background(supervisor);

    firma_stack::stop(state_dir, Duration::ZERO).expect("stop detached supervisor");
    join_collector(collector);

    assert_process_absent(supervisor_pid);
    assert!(!state_dir.join("stack.pid").exists());
}

#[test]
fn detached_attachment_rejects_supervisor_that_exits_before_ready() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let mut supervisor = spawn_exiting_supervisor(state_dir, SupervisorExitPhase::BeforeReady);

    // The fixture exits before the spawned -> ready -> attached handshake can
    // cross its first publication boundary.
    let error = firma_stack::test_support::wait_for_supervisor_attachment(
        state_dir,
        &mut supervisor,
        Duration::from_secs(2),
    )
    .expect_err("supervisor exited before readiness");

    assert!(
        matches!(error, firma_stack::StackError::Platform(_)),
        "unexpected attachment error: {error}"
    );
    insta::assert_snapshot!(error.to_string(), @"platform error: detached supervisor exited before attaching");
}

#[test]
#[ignore = "Racy: the supervisor may fail to exit before the state probe from the parent process"]
fn detached_attachment_rejects_supervisor_that_exits_after_ready() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let mut supervisor = spawn_exiting_supervisor(state_dir, SupervisorExitPhase::AfterReady);

    // Readiness is published, but the fixture exits before attachment is
    // confirmed, exercising the second handshake boundary.
    let error = firma_stack::test_support::wait_for_supervisor_attachment(
        state_dir,
        &mut supervisor,
        Duration::from_secs(2),
    )
    .expect_err("supervisor exited after readiness");

    assert!(
        matches!(error, firma_stack::StackError::Platform(_)),
        "unexpected attachment error: {error}"
    );
    assert!(
        matches!(
            error.to_string().as_str(),
            "platform error: detached supervisor exited before attaching"
                | "platform error: detached supervisor exited after acknowledging attachment"
        ),
        "unexpected attachment timing: {error}"
    );
}

#[test]
fn component_exit_tears_down_peer_without_signalling_observer() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    // The background collector owns the children. The supervisor thread below
    // is only an observer and must never mistake its own PID for a teardown
    // target when one component exits.
    let owner = firma_stack::test_support::collect_raw_in_background(authority, sidecar);

    let state_dir_for_supervisor = state_dir.to_path_buf();
    let (result_tx, result_rx) = mpsc::channel();
    let supervisor = std::thread::spawn(move || {
        let result = firma_stack::test_support::supervise_with_timeout(
            &state_dir_for_supervisor,
            Duration::ZERO,
        );
        let _ = result_tx.send(result);
    });

    wait_for_pidfile(&state_dir.join("stack.pid"));
    firma_stack::test_support::terminate_raw(authority_pid).expect("terminate authority");

    let result = match result_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(result) => result,
        Err(error) => {
            let _ = firma_stack::test_support::terminate_raw(sidecar_pid);
            join_collector(owner);
            panic!("detached observer did not tear down sidecar: {error}");
        }
    };
    result.expect("detached observation");
    supervisor.join().expect("join detached observer");
    join_collector(owner);

    let current_pid = UserProcessId::new(std::process::id()).expect("current process ID");
    assert!(
        current_pid
            .process_exists()
            .expect("probe observer process"),
        "component teardown signalled its own observer"
    );
    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
}

#[test]
fn detached_observer_does_not_acknowledge_missing_component() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (mut authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (mut sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");

    firma_stack::test_support::terminate_raw(authority_pid).expect("terminate authority");
    authority.wait().expect("collect authority");

    let error = firma_stack::test_support::supervise_with_timeout(state_dir, Duration::ZERO)
        .expect_err("missing authority must prevent attachment");

    assert!(
        matches!(error, firma_stack::StackError::Platform(_)),
        "unexpected attachment error: {error}"
    );
    insta::assert_snapshot!(error.to_string(), @"platform error: authority exited before detached supervisor attached");
    assert!(!state_dir.join("stack.ready").exists());

    firma_stack::test_support::terminate_raw(sidecar_pid).expect("terminate sidecar");
    sidecar.wait().expect("collect sidecar");
    pidfile::remove(&state_dir.join("stack.pid")).expect("remove supervisor pidfile");
}

#[cfg(windows)]
#[test]
fn windows_pidfile_setup_failure_collects_spawned_child() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let marker = state_dir.join("failed-child.ready");
    let mut command = fixture_command(&marker);
    let pid = firma_stack::test_support::simulate_spawn_setup_failure(
        state_dir,
        "authority",
        &mut command,
    )
    .expect("simulate component setup failure");

    assert_process_absent(pid);
}

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn owned_child_fixture() {
    if let Some(state_dir) = std::env::var_os(SUPERVISOR_STATE_DIR) {
        let pid = UserProcessId::new(std::process::id()).expect("supervisor fixture PID");
        pidfile::write(&Path::new(&state_dir).join("stack.pid"), pid)
            .expect("write supervisor pidfile");
        if std::env::var_os(SUPERVISOR_ACKNOWLEDGE).is_some() {
            pidfile::write(&Path::new(&state_dir).join("stack.ready"), pid)
                .expect("write supervisor readiness");
        }
        return;
    }
    if let Some(marker) = std::env::var_os(CHILD_MARKER) {
        std::fs::write(marker, std::process::id().to_string()).expect("write ready marker");
    }
    println!("{}", std::process::id());
    std::io::stdout().flush().expect("flush child PID");
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}

fn spawn_fixture(state_dir: &Path, name: &str) -> (Child, u32) {
    let marker = state_dir.join(format!("{name}.ready"));
    let mut command = fixture_command(&marker);
    let child =
        firma_stack::test_support::spawn_raw_owned_into_group(state_dir, name, &mut command)
            .expect("spawn lifecycle fixture");
    let pid = wait_for_marker(&marker);
    assert_eq!(pid, child.id());
    (child, pid)
}

fn fixture_command(marker: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", "ownership::owned_child_fixture", "--ignored"])
        .env(CHILD_MARKER, marker);
    command
}

fn spawn_exiting_supervisor(state_dir: &Path, phase: SupervisorExitPhase) -> Child {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", "ownership::owned_child_fixture", "--ignored"])
        .env(SUPERVISOR_STATE_DIR, state_dir);
    if matches!(phase, SupervisorExitPhase::AfterReady) {
        command.env(SUPERVISOR_ACKNOWLEDGE, "1");
    }
    firma_stack::test_support::spawn_raw_owned_into_group(
        state_dir,
        "supervisor-fixture",
        &mut command,
    )
    .expect("spawn supervisor fixture")
}

fn wait_for_marker(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(contents) = std::fs::read_to_string(path) {
            return contents.trim().parse().expect("fixture PID");
        }
        assert!(Instant::now() < deadline, "fixture did not become ready");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_pidfile(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if pidfile::read(path)
            .expect("read observer pidfile")
            .is_some()
        {
            return;
        }
        assert!(Instant::now() < deadline, "observer pidfile not written");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_process_absent(pid: u32) {
    let pid = UserProcessId::new(pid).expect("fixture PID");
    assert!(!pid.process_exists().expect("probe fixture process"));
}

fn join_collector(collector: Option<std::thread::JoinHandle<()>>) {
    if let Some(collector) = collector {
        collector.join().expect("join child collector");
    }
}
