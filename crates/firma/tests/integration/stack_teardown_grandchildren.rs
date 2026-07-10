//! Regression: stack stop kills a Unix process group, including grandchildren.

#[cfg(unix)]
#[test]
fn unix_pgrp_kills_grandchild() {
    use std::process::Command;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path();
    let grandchild_pidfile = state_dir.join("grandchild.pid");
    let script = format!(
        "sleep 9999 & echo $! > {pidfile}; wait",
        pidfile = grandchild_pidfile.display()
    );
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &script]);
    firma_stack::test_support::spawn_raw_into_group(state_dir, "authority", &mut cmd)
        .expect("spawn");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !grandchild_pidfile.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(grandchild_pidfile.exists(), "grandchild never started");
    let grandchild_pid: i32 = std::fs::read_to_string(&grandchild_pidfile)
        .expect("read")
        .trim()
        .parse()
        .expect("parse");

    let _ = firma_stack::stop(state_dir, Duration::from_secs(5)).expect("stop");

    // A killed non-child process can remain briefly visible as a zombie until
    // its parent or the OS reaps it, so wait for the pid to fully disappear.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match nix::sys::signal::kill(nix::unistd::Pid::from_raw(grandchild_pid), None) {
            Err(nix::errno::Errno::ESRCH) => break,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => panic!("grandchild pid {grandchild_pid} still present"),
        }
    }
}
