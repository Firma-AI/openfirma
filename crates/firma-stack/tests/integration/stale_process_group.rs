//! Regression: stale detection retains component groups after leaders exit.

#![cfg(unix)]

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::process::Command;
use std::time::{Duration, Instant};

use firma_stack::{StackConfig, StackError};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

struct ProcessGroupCleanup(Option<Pid>);

impl ProcessGroupCleanup {
    fn new(pid: u32) -> Self {
        Self(i32::try_from(pid).ok().map(Pid::from_raw))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroupCleanup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
        }
    }
}

#[test]
fn start_recovers_missing_lock_for_orphaned_component_group() {
    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path();
    let child_ready_marker = state_dir.join("grandchild.ready");
    let liveness_fifo = state_dir.join("grandchild.liveness");

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

    let mut command = Command::new("sh");
    command.args([
        "-c",
        "sh -c 'trap \"\" TERM; exec 3>\"$2\"; printf ready > \"$1\"; \
         while :; do sleep 1; done' sh \"$CHILD_READY_MARKER\" \"$LIVENESS_FIFO\" & \
         while [ ! -f \"$CHILD_READY_MARKER\" ]; do sleep 0.01; done",
    ]);
    command
        .env("CHILD_READY_MARKER", &child_ready_marker)
        .env("LIVENESS_FIFO", &liveness_fifo);
    let group_pid =
        firma_stack::test_support::spawn_raw_into_group(state_dir, "authority", &mut command)
            .expect("spawn authority group");
    let mut cleanup = ProcessGroupCleanup::new(group_pid);

    let deadline = Instant::now() + Duration::from_secs(5);
    while !child_ready_marker.exists() {
        assert!(
            Instant::now() < deadline,
            "orphaned grandchild did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let leader = Pid::from_raw(i32::try_from(group_pid).expect("group PID fits i32"));
    assert_eq!(
        waitpid(leader, Some(WaitPidFlag::empty())).expect("reap authority leader"),
        WaitStatus::Exited(leader, 0),
    );
    let config = StackConfig {
        state_dir: Some(state_dir.to_path_buf()),
        config_file: state_dir.join("missing-firma.toml"),
        firma_bin: None,
    };
    let lock_path = state_dir.join("stack.lock");

    let result = firma_stack::spawn_stack(&config, state_dir);
    let error = result
        .err()
        .expect("orphaned component group must block a second start");
    match error {
        StackError::AlreadyRunning { path } => assert_eq!(path, lock_path),
        other => panic!("unexpected startup error: {other}"),
    }
    assert!(
        lock_path.exists(),
        "startup did not recover the missing lock"
    );
    assert!(
        state_dir.join("authority.pid").exists(),
        "live process-group pidfile was reaped"
    );

    let result = firma_stack::spawn_stack(&config, state_dir);
    let error = result
        .err()
        .expect("recovered lock must continue to block startup");
    match error {
        StackError::AlreadyRunning { path } => assert_eq!(path, lock_path),
        other => panic!("unexpected startup error: {other}"),
    }

    let outcome = firma_stack::stop(state_dir, Duration::from_millis(100))
        .expect("stop retained process group");
    assert!(
        outcome.forced,
        "TERM-ignoring grandchild was not hard-killed"
    );

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
    assert!(fifo_closed, "grandchild still holds its liveness FIFO");
    cleanup.disarm();
}
