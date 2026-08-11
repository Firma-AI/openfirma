//! Verifies that forced stack stop kills TERM-ignoring Unix grandchildren.

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

#[cfg(unix)]
#[test]
fn unix_pgrp_force_kills_term_ignoring_grandchild() {
    use firma_process_orchestrator::StackTopology;
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

    // The grandchild ignores TERM and holds the FIFO writer open. Its parent
    // waits for it after TERM, keeping the process-group leader alive until
    // `stop` exhausts its grace period and escalates to SIGKILL. This fixture
    // specifically covers that forced path; a leader that exits before an
    // uncooperative descendant is a separate lifecycle case.
    let mut cmd = Command::new("sh");
    cmd.args([
        "-c",
        "trap 'wait \"$grandchild\"; exit 0' TERM; \
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
    .env("PARENT_READY_MARKER", &parent_ready_marker);
    let topology = StackTopology::new(["authority"]).expect("valid fixture topology");
    let mut stack = crate::support::spawn_managed_component(state_dir, &topology, cmd);
    let group_pid = firma_runtime_state::pidfile::read(&state_dir.join("authority.pid"))
        .expect("read authority pidfile")
        .expect("authority pid")
        .get();
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

    // Stop before asserting readiness so a broken fixture cannot leak its
    // process group into subsequent tests.
    stack.detach().expect("detach stack owner");
    let stop_result = firma_process_orchestrator::stop_components(
        state_dir,
        Duration::from_millis(100),
        &topology,
    );

    assert!(ready, "grandchild never became ready");
    let outcome = stop_result.expect("stop");
    assert!(outcome.forced, "stack stop did not escalate to SIGKILL");

    // Process death closes file descriptors before zombie reaping. EOF is
    // therefore a deterministic proof that no descendant still holds the FIFO
    // writer, unlike a PID probe that reports zombies as present.
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
