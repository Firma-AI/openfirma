//! Regression: foreground startup owns rollback before component readiness.
//!
//! Process tree during the interrupted readiness check:
//! ```text
//! test harness -> foreground launcher -> Authority leader
//!                                      `-> TERM-ignoring grandchild (holds FIFO)
//! ```

#![cfg(unix)]

use std::fs::{OpenOptions, Permissions};
use std::io::{ErrorKind, Read as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use firma_stack::{StackConfig, StartMode};
use nix::unistd::Pid;

use crate::support::{ProcessGroupCleanup, wait_for_file, wait_for_pidfile};

const CHILD_ENV: &str = "FIRMA_TEST_FOREGROUND_STARTUP_CHILD";
const CONFIG_ENV: &str = "FIRMA_TEST_FOREGROUND_STARTUP_CONFIG";
const STATE_ENV: &str = "FIRMA_TEST_FOREGROUND_STARTUP_STATE";

#[test]
fn sigterm_during_foreground_readiness_rolls_back_components() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_foreground_child();
        return;
    }

    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path().join("state");
    let config_path = dir.path().join("firma.toml");
    let fixture_path = dir.path().join("fixture.sh");
    let liveness_fifo = dir.path().join("grandchild.liveness");
    let child_ready_marker = dir.path().join("grandchild.ready");

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

    std::fs::write(
        &fixture_path,
        "#!/bin/sh\n\
         root=${0%/*}\n\
         if [ \"$1\" = authority ]; then\n\
           sh -c 'trap \"\" TERM; exec 3>\"$1/grandchild.liveness\"; \
             printf ready > \"$1/grandchild.ready\"; while :; do sleep 1; done' sh \"$root\" &\n\
           trap \"\" TERM\n\
           while :; do sleep 1; done\n\
         fi\n",
    )
    .expect("write fixture");
    std::fs::set_permissions(&fixture_path, Permissions::from_mode(0o700))
        .expect("make fixture executable");

    // A valid [sidecar] section lets the eager plan build succeed; the signal
    // still interrupts authority readiness, which is what this test exercises.
    std::fs::write(
        &config_path,
        "[authority]\nlisten_addr = \"127.0.0.1:9\"\n\
         [sidecar.interceptor]\nlisten_addr = \"127.0.0.1:9\"\n",
    )
    .expect("write config");

    let mut launcher = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "foreground_startup_signal::sigterm_during_foreground_readiness_rolls_back_components",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(CONFIG_ENV, &config_path)
        .env(STATE_ENV, &state_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn foreground launcher");

    // Wait until both the Authority group and its FIFO-holding grandchild are ready.
    let authority_pid = wait_for_pidfile(&state_dir.join("authority.pid"));
    let mut cleanup = ProcessGroupCleanup::new(authority_pid);
    wait_for_file(&child_ready_marker);

    // Interrupt foreground startup while it is still waiting for Authority readiness.
    nix::sys::signal::kill(
        Pid::from_raw(i32::try_from(launcher.id()).expect("launcher PID fits pid_t")),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("signal foreground launcher");

    // The launcher must finish its rollback before reporting a successful test exit.
    let status = wait_for_child(&mut launcher, Duration::from_secs(10));
    assert!(status.success(), "foreground launcher failed: {status}");

    // FIFO EOF proves rollback killed the TERM-ignoring grandchild as well as its leader.
    assert_fifo_closed(&mut liveness_reader);
    cleanup.disarm();

    for name in [
        "authority.pid",
        "authority.listen",
        "sidecar.pid",
        "sidecar.listen",
        "stack.lock",
    ] {
        assert!(!state_dir.join(name).exists(), "rollback left {name}");
    }
}

fn run_foreground_child() {
    let config_path = PathBuf::from(std::env::var_os(CONFIG_ENV).expect("config path"));
    let state_dir = PathBuf::from(std::env::var_os(STATE_ENV).expect("state path"));
    let config = StackConfig {
        state_dir: Some(state_dir.clone()),
        config_file: config_path,
        firma_bin: Some(state_dir.parent().expect("state parent").join("fixture.sh")),
    };

    let Err(error) = firma_stack::start(&config, &state_dir, StartMode::Foreground) else {
        panic!("signal must interrupt foreground readiness");
    };
    assert_eq!(
        error.to_string(),
        "platform error: termination requested during stack startup"
    );
}

fn wait_for_child(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll foreground launcher") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "foreground launcher did not exit"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_fifo_closed(reader: &mut std::fs::File) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match reader.read(&mut [0_u8; 1]) {
            Ok(0) => return,
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            result => panic!("grandchild still holds its liveness FIFO: {result:?}"),
        }
    }
}
