//! Cross-platform ownership and detached-observation lifecycle coverage.

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use firma_runtime_state::{UserProcessId, pidfile};

const CHILD_MARKER: &str = "FIRMA_STACK_TEST_CHILD_MARKER";

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
fn component_exit_tears_down_peer_without_signalling_observer() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
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
            let _ = owner.join();
            panic!("detached observer did not tear down sidecar: {error}");
        }
    };
    result.expect("detached observation");
    supervisor.join().expect("join detached observer");
    owner.join().expect("join component owner");

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

#[cfg(windows)]
#[test]
fn windows_pidfile_setup_failure_collects_spawned_child() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::create_dir(state_dir.join("authority.pid")).expect("block pidfile write");
    let exe = std::env::current_exe().expect("test executable");
    let error = firma_stack::test_support::spawn_raw_component(
        state_dir,
        "authority",
        &exe,
        &["--exact", "ownership::owned_child_fixture", "--ignored"],
    )
    .expect_err("pidfile directory must fail component setup");
    assert!(
        matches!(error, firma_stack::StackError::RuntimeState(_)),
        "unexpected setup error: {error}"
    );

    if let Ok(contents) = std::fs::read_to_string(state_dir.join("authority.log"))
        && let Some(pid) = contents.lines().find_map(|line| line.parse::<u32>().ok())
    {
        assert_process_absent(pid);
    }
}

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn owned_child_fixture() {
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
