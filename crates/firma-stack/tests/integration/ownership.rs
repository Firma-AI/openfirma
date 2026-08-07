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

#[derive(Clone, Copy)]
enum ComponentExitRole {
    Authority,
    Sidecar,
}

struct ProcessCleanup(Vec<u32>);

impl ProcessCleanup {
    fn new(pid: u32) -> Self {
        Self(vec![pid])
    }

    fn push(&mut self, pid: u32) {
        self.0.push(pid);
    }

    fn disarm(&mut self) {
        self.0.clear();
    }
}

impl Drop for ProcessCleanup {
    fn drop(&mut self) {
        for pid in &self.0 {
            let _ = firma_stack::test_support::terminate_raw(*pid);
        }
    }
}

#[cfg(unix)]
struct ProcessGroupCleanup(Option<nix::unistd::Pid>);

#[cfg(unix)]
impl ProcessGroupCleanup {
    fn new(pid: u32) -> Self {
        Self(i32::try_from(pid).ok().map(nix::unistd::Pid::from_raw))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupCleanup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
        }
    }
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

/// Successful shutdown consumes process ownership, so dropping the stopped
/// handle must not attempt to transfer those capabilities to a reaper.
#[test]
fn owned_shutdown_disarms_reaper_transfer() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");

    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let mut stack = firma_stack::test_support::running_stack_from_raw_with_forbidden_reaper(
        state_dir, authority, sidecar,
    );

    stack.shutdown(Duration::ZERO).expect("owned shutdown");
    drop(stack);

    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
    assert!(!state_dir.join("stack.lock").exists());
}

/// An Authority exit ends foreground supervision and tears down the Sidecar
/// without separating either component's process capabilities.
#[test]
fn authority_exit_tears_down_owned_foreground_stack() {
    assert_component_exit_tears_down_foreground_stack(ComponentExitRole::Authority);
}

/// A Sidecar exit ends foreground supervision and tears down the Authority
/// without separating either component's process capabilities.
#[test]
fn sidecar_exit_tears_down_owned_foreground_stack() {
    assert_component_exit_tears_down_foreground_stack(ComponentExitRole::Sidecar);
}

#[test]
fn old_owner_does_not_remove_new_generation_state() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let mut stack =
        firma_stack::test_support::running_stack_from_raw(state_dir, authority, sidecar);
    let old_owner = if std::process::id() == 1 { 2 } else { 1 };
    firma_stack::test_support::set_running_stack_owner(&mut stack, old_owner);

    let new_owner = UserProcessId::new(std::process::id()).expect("new owner PID");
    pidfile::write(&state_dir.join("stack.pid"), new_owner).expect("write new owner");
    pidfile::write(&state_dir.join("authority.pid"), new_owner).expect("write new authority");
    pidfile::write(&state_dir.join("sidecar.pid"), new_owner).expect("write new sidecar");
    std::fs::write(state_dir.join("stack.lock"), "new generation").expect("write new lock");
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
        "new generation"
    );
    assert!(new_ready.exists());
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

/// Reaper creation failure falls back to synchronously terminating and
/// collecting every child rather than dropping the only reaping handles.
#[test]
fn reaper_start_failure_terminates_and_collects_owned_children() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");

    firma_stack::test_support::terminate_raw_children_after_reaper_failure(authority, sidecar)
        .expect("terminate and collect children after reaper failure");

    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
}

/// Dropping the in-process owner exercises the production transfer boundary:
/// if its reaper cannot start, both children are synchronously terminated and
/// collected while runtime state remains available for external cleanup.
#[test]
fn dropping_owner_falls_back_when_reaper_cannot_start() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let stack = firma_stack::test_support::running_stack_from_raw_with_reaper_start_failure(
        state_dir, authority, sidecar,
    );

    drop(stack);

    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
    assert!(state_dir.join("stack.lock").exists());
    assert!(state_dir.join("authority.pid").exists());
    assert!(state_dir.join("sidecar.pid").exists());

    firma_stack::stop(state_dir, Duration::ZERO).expect("clean retained runtime state");
    assert!(!state_dir.join("stack.lock").exists());
    assert!(!state_dir.join("authority.pid").exists());
    assert!(!state_dir.join("sidecar.pid").exists());
}

/// On Unix, failed ownership transfer must retain the process-group capability,
/// not merely the direct-child handle, so synchronous fallback also terminates
/// a descendant that ignores graceful termination.
#[cfg(unix)]
#[test]
fn failed_reaper_transfer_terminates_owned_process_group() {
    use std::fs::OpenOptions;
    use std::io::{ErrorKind, Read as _};
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");
    let liveness_fifo = state_dir.join("descendant.liveness");
    let ready_marker = state_dir.join("descendant.ready");
    nix::unistd::mkfifo(
        &liveness_fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("create liveness FIFO");
    let mut liveness_reader = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(&liveness_fifo)
        .expect("open liveness FIFO");

    let mut authority_command = Command::new("sh");
    authority_command
        .args([
            "-c",
            "trap 'wait \"$descendant\"; exit 0' TERM; \
             sh -c \"$DESCENDANT_SCRIPT\" & descendant=$!; wait \"$descendant\"",
        ])
        .env(
            "DESCENDANT_SCRIPT",
            "trap '' TERM; exec 3>\"$LIVENESS_FIFO\"; \
             printf ready > \"$READY_MARKER\"; while :; do sleep 1; done",
        )
        .env("LIVENESS_FIFO", &liveness_fifo)
        .env("READY_MARKER", &ready_marker);
    let authority = firma_stack::test_support::spawn_raw_owned_into_group(
        state_dir,
        "authority",
        &mut authority_command,
    )
    .expect("spawn authority process group");
    let mut cleanup = ProcessGroupCleanup::new(authority.id());
    wait_for_file(&ready_marker);
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    let stack = firma_stack::test_support::running_stack_from_raw_with_reaper_start_failure(
        state_dir, authority, sidecar,
    );

    drop(stack);

    assert_process_absent(sidecar_pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    let fifo_closed = loop {
        match liveness_reader.read(&mut [0_u8; 1]) {
            Ok(0) => break true,
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            _ => break false,
        }
    };
    assert!(fifo_closed, "descendant still holds its liveness FIFO");
    cleanup.disarm();

    firma_stack::stop(state_dir, Duration::ZERO).expect("clean retained runtime state");
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
    assert!(unrelated_ready.exists(), "unrelated readiness was removed");
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

fn assert_component_exit_tears_down_foreground_stack(exit_role: ComponentExitRole) {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();
    std::fs::write(state_dir.join("stack.lock"), "").expect("write lock");
    let (authority, authority_pid) = spawn_fixture(state_dir, "authority");
    let mut cleanup = ProcessCleanup::new(authority_pid);
    let (sidecar, sidecar_pid) = spawn_fixture(state_dir, "sidecar");
    cleanup.push(sidecar_pid);
    let terminated_pid = match exit_role {
        ComponentExitRole::Authority => authority_pid,
        ComponentExitRole::Sidecar => sidecar_pid,
    };

    let state_dir_for_supervisor = state_dir.to_path_buf();
    let (result_tx, result_rx) = mpsc::channel();
    let supervisor = std::thread::spawn(move || {
        let result = firma_stack::test_support::supervise_raw_owned_until_exit(
            &state_dir_for_supervisor,
            Duration::ZERO,
            authority,
            sidecar,
        );
        let _ = result_tx.send(result);
    });
    firma_stack::test_support::terminate_raw(terminated_pid).expect("terminate selected component");

    result_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("foreground supervisor did not finish within 10 seconds")
        .expect("supervise owned components");
    drop(supervisor);
    assert_process_absent(authority_pid);
    assert_process_absent(sidecar_pid);
    assert!(!state_dir.join("stack.lock").exists());
    cleanup.disarm();
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

fn join_collector(collector: Option<std::thread::JoinHandle<()>>) {
    if let Some(collector) = collector {
        collector.join().expect("join child collector");
    }
}
