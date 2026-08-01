//! Regression: stack stop tracks Unix process groups after their leaders exit.

struct ProcessGroupCleanup(Option<nix::unistd::Pid>);

impl ProcessGroupCleanup {
    fn new(pid: u32) -> Self {
        Self(i32::try_from(pid).ok().map(nix::unistd::Pid::from_raw))
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
fn unix_pgrp_kills_grandchild_after_leader_exits() {
    use std::fs::OpenOptions;
    use std::io::{ErrorKind, Read as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::process::Command;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path();
    let liveness_fifo = state_dir.join("grandchild.liveness");
    let child_ready_marker = state_dir.join("grandchild.ready");
    let parent_ready_marker = state_dir.join("parent.ready");
    let leader_exited_marker = state_dir.join("leader.exited");

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

    let mut cmd = Command::new("sh");
    cmd.args([
        "-c",
        "trap 'printf exited > \"$LEADER_EXITED_MARKER\"; exit 0' TERM; \
         sh -c \"$GRANDCHILD_SCRIPT\" & grandchild=$!; \
         printf ready > \"$PARENT_READY_MARKER\"; wait \"$grandchild\"",
    ])
    .env(
        "GRANDCHILD_SCRIPT",
        "trap '' TERM; exec 3>\"$LIVENESS_FIFO\"; \
         until [ -f \"$PARENT_READY_MARKER\" ]; do sleep 1; done; \
         printf ready > \"$CHILD_READY_MARKER\"; while :; do sleep 1; done",
    )
    .env("LIVENESS_FIFO", &liveness_fifo)
    .env("CHILD_READY_MARKER", &child_ready_marker)
    .env("PARENT_READY_MARKER", &parent_ready_marker)
    .env("LEADER_EXITED_MARKER", &leader_exited_marker);
    let group_pid =
        firma_stack::test_support::spawn_raw_into_group(state_dir, "authority", &mut cmd)
            .expect("spawn");
    let mut cleanup = ProcessGroupCleanup::new(group_pid);

    let deadline = Instant::now() + Duration::from_secs(5);
    let ready = loop {
        let ready =
            std::fs::read_to_string(&child_ready_marker).is_ok_and(|contents| contents == "ready");
        if ready || Instant::now() >= deadline {
            break ready;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let stop_result = firma_stack::stop(state_dir, Duration::from_millis(100));

    assert!(ready, "grandchild never became ready");
    let outcome = stop_result.expect("stop");
    assert!(
        outcome.forced,
        "surviving process group did not trigger SIGKILL"
    );
    assert_eq!(
        std::fs::read_to_string(leader_exited_marker).expect("leader exit marker"),
        "exited",
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
