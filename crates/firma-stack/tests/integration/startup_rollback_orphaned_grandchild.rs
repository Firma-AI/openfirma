//! Regression: startup rollback tracks Unix process groups after leaders exit.
//!
//! Timeline: Authority forks a TERM-ignoring grandchild, its leader exits and is
//! reaped, readiness is released, then sidecar startup fails and rollback must
//! kill the orphaned group member.

#![cfg(unix)]

use std::fs::{OpenOptions, Permissions};
use std::io::{ErrorKind, Read as _};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::time::{Duration, Instant};

use firma_stack::{StackConfig, StackError};

use crate::support::{ProcessGroupCleanup, wait_for_file, wait_for_pidfile};

#[test]
fn startup_rollback_kills_grandchild_after_leader_exits() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path();
    let state_dir = root.join("state");
    let config_path = root.join("firma.toml");
    let fixture_path = root.join("fixture.sh");
    let liveness_fifo = root.join("grandchild.liveness");
    let child_ready_marker = root.join("grandchild.ready");

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
           while [ ! -f \"$root/grandchild.ready\" ]; do sleep 0.01; done\n\
         fi\n",
    )
    .expect("write fixture");
    std::fs::set_permissions(&fixture_path, Permissions::from_mode(0o700))
        .expect("make fixture executable");

    let port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve authority port")
        .local_addr()
        .expect("authority address");
    // A valid [sidecar] section lets the eager plan build succeed; the authority
    // leader still exits during readiness, driving the rollback this test covers.
    std::fs::write(
        &config_path,
        format!(
            "[authority]\nlisten_addr = \"{port}\"\n\
             [sidecar.interceptor]\nlisten_addr = \"127.0.0.1:9\"\n"
        ),
    )
    .expect("write config");
    let config = StackConfig {
        state_dir: Some(state_dir.clone()),
        config_file: config_path,
        firma_bin: Some(fixture_path),
    };

    let (result, mut cleanup) = std::thread::scope(|scope| {
        let startup = scope.spawn(|| firma_stack::spawn_stack(&config, &state_dir));
        let authority_pid = wait_for_pidfile(&state_dir.join("authority.pid"));
        let cleanup = ProcessGroupCleanup::new(authority_pid);
        wait_for_file(&child_ready_marker);

        let result = startup.join().expect("startup thread");
        (result, cleanup)
    });

    let error = result
        .err()
        .expect("authority exit must fail startup readiness");
    let StackError::Orchestrator(
        firma_process_orchestrator::OrchestratorError::ReadinessProcessExited { component, .. },
    ) = error
    else {
        panic!("unexpected startup error: {error}");
    };
    assert_eq!(component, "authority");

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
