//! Regression coverage for detached observer-initiated component teardown.

use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use firma_runtime_state::{UserProcessId, pidfile};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

#[test]
fn component_exit_tears_down_peers_without_signalling_supervisor() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path();

    let mut authority = Command::new("sh");
    authority.args(["-c", "while :; do sleep 1; done"]);
    let mut authority = firma_stack::test_support::spawn_raw_owned_into_group(
        state_dir,
        "authority",
        &mut authority,
    )
    .expect("spawn authority");
    let authority_pid = authority.id();

    let mut sidecar = Command::new("sh");
    sidecar.args(["-c", "trap 'exit 0' TERM; while :; do sleep 0.1; done"]);
    let mut sidecar =
        firma_stack::test_support::spawn_raw_owned_into_group(state_dir, "sidecar", &mut sidecar)
            .expect("spawn sidecar");
    let sidecar_pid = sidecar.id();

    let sidecar_waiter =
        std::thread::spawn(move || sidecar.wait().expect("collect sidecar leader"));
    let state_dir_for_supervisor = state_dir.to_path_buf();
    let (result_tx, result_rx) = mpsc::channel();
    let supervisor = std::thread::spawn(move || {
        let _ = result_tx.send(firma_stack::supervise(&state_dir_for_supervisor));
    });

    wait_for_pidfile(&state_dir.join("stack.pid"));
    killpg(as_pid(authority_pid), Signal::SIGKILL).expect("kill authority group");
    authority.wait().expect("collect authority leader");

    let result = match result_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(result) => result,
        Err(error) => {
            let _ = killpg(as_pid(sidecar_pid), Signal::SIGKILL);
            let _ = sidecar_waiter.join();
            panic!("detached supervisor did not tear down sidecar: {error}");
        }
    };
    result.expect("detached supervision");
    supervisor.join().expect("join detached supervisor");
    sidecar_waiter.join().expect("join sidecar waiter");

    let current_pid = UserProcessId::new(std::process::id()).expect("current process ID");
    assert!(
        current_pid
            .process_exists()
            .expect("probe supervisor process"),
        "component teardown signalled its own supervisor"
    );
    for name in [
        "authority.pid",
        "authority.listen",
        "sidecar.pid",
        "sidecar.listen",
        "stack.pid",
    ] {
        assert!(!state_dir.join(name).exists(), "teardown left {name}");
    }
}

fn as_pid(pid: u32) -> Pid {
    Pid::from_raw(i32::try_from(pid).expect("PID fits pid_t"))
}

fn wait_for_pidfile(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if pidfile::read(path)
            .expect("read supervisor pidfile")
            .is_some()
        {
            return;
        }
        assert!(Instant::now() < deadline, "supervisor pidfile not written");
        std::thread::sleep(Duration::from_millis(10));
    }
}
