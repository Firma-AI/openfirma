//! Cross-platform ownership and detached-observation lifecycle coverage.

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use firma_runtime_state::{UserProcessId, pidfile};

const CHILD_MARKER: &str = "FIRMA_STACK_TEST_CHILD_MARKER";
const TRANSACTION_STATE_DIR: &str = "FIRMA_STACK_TEST_TRANSACTION_STATE_DIR";
const TRANSACTION_READY: &str = "FIRMA_STACK_TEST_TRANSACTION_READY";
const TRANSACTION_RELEASE: &str = "FIRMA_STACK_TEST_TRANSACTION_RELEASE";
const SUPERVISOR_STATE_DIR: &str = "FIRMA_STACK_TEST_SUPERVISOR_STATE_DIR";
const SUPERVISOR_ACKNOWLEDGE: &str = "FIRMA_STACK_TEST_SUPERVISOR_ACKNOWLEDGE";

#[test]
fn owned_shutdown_is_idempotent_and_ignores_pidfiles() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let mut stack =
        firma_stack::test_support::running_stack_from_raw(state_dir, authority, sidecar)
            .expect("claim stack generation");

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
fn owned_shutdown_terminates_children_when_state_transaction_is_busy() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let mut stack =
        firma_stack::test_support::running_stack_from_raw(state_dir, authority, sidecar)
            .expect("claim stack generation");
    let transaction_ready = state_dir.join("transaction.ready");
    let transaction_release = state_dir.join("transaction.release");
    let mut transaction_holder = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "ownership::owned_child_fixture", "--ignored"])
        .env(TRANSACTION_STATE_DIR, state_dir)
        .env(TRANSACTION_READY, &transaction_ready)
        .env(TRANSACTION_RELEASE, &transaction_release)
        .spawn()
        .expect("spawn transaction holder");
    wait_for_file(&transaction_ready);

    let started = Instant::now();
    let shutdown = stack.shutdown(Duration::ZERO);
    std::fs::write(&transaction_release, []).expect("release state transaction");
    assert!(
        transaction_holder
            .wait()
            .expect("wait for transaction holder")
            .success(),
        "transaction holder failed"
    );
    let error = shutdown.expect_err("busy state cleanup must be reported");

    assert!(matches!(
        error,
        firma_stack::StackError::RuntimeStateBusy { .. }
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
    stack
        .shutdown(Duration::ZERO)
        .expect("retry state cleanup after transaction release");
}

#[test]
fn external_stop_terminates_targets_but_retains_malformed_generation_state() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let authority_collector = firma_stack::test_support::collect_raw_child_in_background(authority);
    let sidecar_collector = firma_stack::test_support::collect_raw_child_in_background(sidecar);
    std::fs::write(state_dir.join("stack.lock"), "not-a-generation\n")
        .expect("write malformed generation");

    let error = firma_stack::stop(state_dir, Duration::ZERO)
        .expect_err("malformed generation must prevent cleanup");

    assert!(matches!(
        &error,
        firma_stack::StackError::InvalidStackGeneration { .. }
    ));
    insta::assert_snapshot!(error.to_string(), @"invalid stack.lock generation");
    join_collector(authority_collector);
    join_collector(sidecar_collector);
    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
    assert_eq!(
        std::fs::read_to_string(state_dir.join("stack.lock")).expect("read retained generation"),
        "not-a-generation\n"
    );
    assert!(state_dir.join("authority.pid").exists());
    assert!(state_dir.join("sidecar.pid").exists());
}

#[test]
fn generation_scoped_stop_does_not_signal_targets_with_malformed_lock() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let startup =
        firma_stack::test_support::begin_raw_startup(state_dir).expect("begin startup generation");
    let generation = startup.generation();
    drop(startup);
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    std::fs::write(state_dir.join("stack.lock"), "not-a-generation\n")
        .expect("write malformed generation");

    let error =
        firma_stack::test_support::stop_stack_generation(state_dir, Duration::ZERO, generation)
            .expect_err("malformed generation must reject scoped stop");

    assert!(matches!(
        error,
        firma_stack::StackError::InvalidStackGeneration { .. }
    ));
    assert_process_present(authority_pid);
    assert_process_present(sidecar_pid);

    let authority_collector = firma_stack::test_support::collect_raw_child_in_background(authority);
    let sidecar_collector = firma_stack::test_support::collect_raw_child_in_background(sidecar);
    std::fs::remove_file(state_dir.join("stack.lock")).expect("remove malformed generation");
    firma_stack::stop(state_dir, Duration::ZERO).expect("clean up fixtures");
    join_collector(authority_collector);
    join_collector(sidecar_collector);
}

#[test]
fn old_owner_does_not_remove_new_generation_state() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let mut stack =
        firma_stack::test_support::running_stack_from_raw(state_dir, authority, sidecar)
            .expect("claim old stack generation");
    firma_stack::test_support::replace_stack_generation(state_dir)
        .expect("claim new stack generation");
    let new_generation =
        std::fs::read_to_string(state_dir.join("stack.lock")).expect("read new generation");

    let new_owner = UserProcessId::new(std::process::id()).expect("new owner PID");
    pidfile::write(&state_dir.join("stack.pid"), new_owner).expect("write new owner");
    pidfile::write(&state_dir.join("authority.pid"), new_owner).expect("write new authority");
    pidfile::write(&state_dir.join("sidecar.pid"), new_owner).expect("write new sidecar");
    let new_ready = firma_stack::test_support::supervisor_ready_path(state_dir, new_owner.get());
    pidfile::write(&new_ready, new_owner).expect("write new readiness");

    stack.shutdown(Duration::ZERO).expect("stop old owner");

    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
    assert_eq!(
        pidfile::read(&state_dir.join("stack.pid")).expect("read owner"),
        Some(new_owner)
    );
    assert_eq!(
        std::fs::read_to_string(state_dir.join("stack.lock")).expect("read lock"),
        new_generation
    );
    assert!(new_ready.exists());
}

#[test]
fn old_startup_rollback_does_not_remove_replacement_state() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let startup = firma_stack::test_support::begin_raw_startup(state_dir)
        .expect("begin old startup generation");

    firma_stack::test_support::force_replace_stack_generation(state_dir)
        .expect("publish replacement generation");
    let replacement =
        std::fs::read_to_string(state_dir.join("stack.lock")).expect("read replacement lock");
    std::fs::write(state_dir.join("authority.listen"), "replacement\n")
        .expect("write replacement state");

    startup.cleanup(state_dir).expect("run delayed rollback");

    assert_eq!(
        std::fs::read_to_string(state_dir.join("stack.lock")).expect("read retained lock"),
        replacement
    );
    assert_eq!(
        std::fs::read_to_string(state_dir.join("authority.listen")).expect("read retained state"),
        "replacement\n"
    );
}

#[test]
fn stale_detached_rollback_does_not_signal_replacement_processes() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let startup = firma_stack::test_support::begin_raw_startup(state_dir)
        .expect("begin old startup generation");
    let stale_generation = startup.generation();
    firma_stack::test_support::force_replace_stack_generation(state_dir)
        .expect("publish replacement generation");
    drop(startup);
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");

    firma_stack::test_support::stop_stack_generation(state_dir, Duration::ZERO, stale_generation)
        .expect("skip stale rollback");

    assert!(
        UserProcessId::new(authority_pid)
            .expect("authority PID")
            .process_exists()
            .expect("probe authority")
    );
    assert!(
        UserProcessId::new(sidecar_pid)
            .expect("sidecar PID")
            .process_exists()
            .expect("probe sidecar")
    );
    let authority_collector = firma_stack::test_support::collect_raw_child_in_background(authority);
    let sidecar_collector = firma_stack::test_support::collect_raw_child_in_background(sidecar);
    firma_stack::stop(state_dir, Duration::ZERO).expect("stop replacement");
    join_collector(authority_collector);
    join_collector(sidecar_collector);
    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
}

#[test]
fn stop_waits_for_each_startup_transition_before_snapshot() {
    for component_count in 0..=2 {
        let dir = tempfile::tempdir().expect("state dir");
        let state_dir = dir.path();
        let startup = firma_stack::test_support::begin_raw_startup(state_dir)
            .expect("begin startup generation");
        let mut collectors = Vec::new();
        let mut pids = Vec::new();
        for name in ["authority", "sidecar"].into_iter().take(component_count) {
            let (child, pid) = spawn_fixture(state_dir, name);
            collectors.push(firma_stack::test_support::collect_raw_child_in_background(
                child,
            ));
            pids.push(pid);
        }

        let stop_state_dir = state_dir.to_path_buf();
        let (result_tx, result_rx) = mpsc::channel();
        let stop_thread = std::thread::spawn(move || {
            let _ = result_tx.send(firma_stack::stop(&stop_state_dir, Duration::ZERO));
        });

        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(startup);
        result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("stop result after startup transaction release")
            .expect("stop partial startup");
        stop_thread.join().expect("join stop thread");
        for collector in collectors {
            join_collector(collector);
        }
        for pid in pids {
            assert_process_absent(pid);
        }
        assert!(!state_dir.join("stack.lock").exists());
    }
}

#[test]
fn generation_publication_is_atomic_for_concurrent_readers() {
    let dir = tempfile::tempdir().expect("state dir");
    for attempt in 0..50 {
        let state_dir = dir.path().join(format!("attempt-{attempt}"));
        std::fs::create_dir(&state_dir).expect("create attempt state dir");
        let writer_state_dir = state_dir.clone();
        let (start_tx, start_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            start_rx.recv().expect("wait to publish generation");
            drop(
                firma_stack::test_support::begin_raw_startup(&writer_state_dir)
                    .expect("atomically publish generation"),
            );
        });
        start_tx.send(()).expect("start generation publication");

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(generation) = std::fs::read_to_string(state_dir.join("stack.lock")) {
                uuid::Uuid::parse_str(generation.trim()).expect("read complete generation UUID");
                break;
            }
            assert!(Instant::now() < deadline, "generation was not published");
            std::thread::yield_now();
        }
        writer.join().expect("join generation writer");
    }
}

#[test]
fn dropping_owner_transfers_child_collection() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let stack = firma_stack::test_support::running_stack_from_raw(state_dir, authority, sidecar)
        .expect("claim stack generation");

    drop(stack);
    firma_stack::stop(state_dir, Duration::ZERO).expect("stop observed stack");

    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
}

#[test]
fn reaper_start_failure_returns_owned_children_alive() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");

    let mut children =
        firma_stack::test_support::recover_raw_children_after_reaper_failure(authority, sidecar);

    assert_eq!(children.len(), 2);
    assert!(
        UserProcessId::new(authority_pid)
            .expect("authority PID")
            .process_exists()
            .expect("probe authority")
    );
    assert!(
        UserProcessId::new(sidecar_pid)
            .expect("sidecar PID")
            .process_exists()
            .expect("probe sidecar")
    );
    for child in &mut children {
        child.kill().expect("kill recovered child");
        child.wait().expect("collect recovered child");
    }
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
fn detached_owner_collects_failed_component_and_tears_down_peer() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");

    let state_dir_for_owner = state_dir.to_path_buf();
    let (result_tx, result_rx) = mpsc::channel();
    let owner = std::thread::spawn(move || {
        let result = firma_stack::test_support::supervise_raw_owned(
            &state_dir_for_owner,
            Duration::ZERO,
            authority,
            sidecar,
        );
        let _ = result_tx.send(result);
    });

    let owner_ready =
        firma_stack::test_support::supervisor_ready_path(state_dir, std::process::id());
    wait_for_file(&owner_ready);
    std::fs::remove_file(&owner_ready).expect("acknowledge owner readiness");
    let owner_attached =
        firma_stack::test_support::supervisor_attached_path(state_dir, std::process::id());
    wait_for_file(&owner_attached);
    std::fs::remove_file(owner_attached).expect("acknowledge owner attachment");
    firma_stack::test_support::terminate_raw(authority_pid).expect("terminate authority");

    let result = match result_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(result) => result,
        Err(error) => {
            let _ = firma_stack::test_support::terminate_raw(sidecar_pid);
            panic!("detached owner did not tear down sidecar: {error}");
        }
    };
    result.expect("detached owner supervision");
    owner.join().expect("join detached owner");

    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
    assert!(!state_dir.join("stack.pid").exists());
    assert!(!state_dir.join("stack.lock").exists());
}

#[test]
fn detached_attachment_rejects_supervisor_that_exits_before_ready() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let unrelated_owner = UserProcessId::new(if std::process::id() == 1 { 2 } else { 1 })
        .expect("unrelated owner PID");
    let unrelated_ready =
        firma_stack::test_support::supervisor_ready_path(state_dir, unrelated_owner.get());
    pidfile::write(&unrelated_ready, unrelated_owner).expect("write unrelated readiness");
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", "ownership::owned_child_fixture", "--ignored"])
        .env(SUPERVISOR_STATE_DIR, state_dir);
    let mut supervisor = firma_stack::test_support::spawn_raw_owned_into_group(
        state_dir,
        "supervisor-fixture",
        &mut command,
    )
    .expect("spawn supervisor fixture");

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
    insta::assert_snapshot!(error.to_string(), @"platform error: detached supervisor exited before announcing readiness");
    assert!(unrelated_ready.exists(), "unrelated readiness was removed");
}

#[test]
fn detached_attachment_rejects_supervisor_that_exits_after_ready() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", "ownership::owned_child_fixture", "--ignored"])
        .env(SUPERVISOR_STATE_DIR, state_dir)
        .env(SUPERVISOR_ACKNOWLEDGE, "1");
    let mut supervisor = firma_stack::test_support::spawn_raw_owned_into_group(
        state_dir,
        "supervisor-fixture",
        &mut command,
    )
    .expect("spawn supervisor fixture");

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
    insta::assert_snapshot!(error.to_string(), @"platform error: detached supervisor exited after readiness but before confirming attachment");
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
    if let Some(state_dir) = std::env::var_os(TRANSACTION_STATE_DIR) {
        let _transaction =
            firma_stack::test_support::hold_runtime_state_transaction(Path::new(&state_dir))
                .expect("hold state transaction");
        let ready = std::env::var_os(TRANSACTION_READY).expect("transaction ready marker");
        let release = std::env::var_os(TRANSACTION_RELEASE).expect("transaction release marker");
        std::fs::write(ready, []).expect("write transaction ready marker");
        while !Path::new(&release).exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        return;
    }
    if let Some(state_dir) = std::env::var_os(SUPERVISOR_STATE_DIR) {
        let pid = UserProcessId::new(std::process::id()).expect("supervisor fixture PID");
        pidfile::write(&Path::new(&state_dir).join("stack.pid"), pid)
            .expect("write supervisor pidfile");
        if std::env::var_os(SUPERVISOR_ACKNOWLEDGE).is_some() {
            let ready =
                firma_stack::test_support::supervisor_ready_path(Path::new(&state_dir), pid.get());
            pidfile::write(&ready, pid).expect("write supervisor readiness");
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

fn wait_for_marker(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && let Ok(pid) = contents.trim().parse()
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "fixture did not become ready");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} was not written",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_process_absent(pid: u32) {
    let pid = UserProcessId::new(pid).expect("fixture PID");
    assert!(!pid.process_exists().expect("probe fixture process"));
}

fn assert_process_present(pid: u32) {
    let pid = UserProcessId::new(pid).expect("fixture PID");
    assert!(pid.process_exists().expect("probe fixture process"));
}

fn join_collector(collector: Option<std::thread::JoinHandle<()>>) {
    if let Some(collector) = collector {
        collector.join().expect("join child collector");
    }
}
