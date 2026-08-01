//! `firma sidecar start` launches from a default `firma config` scaffold.
//!
//! Regression guard: the daemon readiness path used to wait
//! for sidecar CA material unconditionally, but CA material is only written
//! when HTTPS MITM is active. The default Anthropic-only scaffold ships MITM
//! disabled, so the daemon timed out and never came up. Readiness now gates
//! the CA-material probe on `HttpsMitmConfig::is_active()`.
//! On Unix, the teardown half also sends `SIGTERM` to the detached supervisor
//! and verifies that its preinstalled handler owns component cleanup.
//! A second detached start with a missing lock must not claim or terminate the
//! existing stack.

#![allow(
    clippy::expect_used,
    reason = "test code: panics acceptable on test failure"
)]

use std::fs::File;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use firma_config_loader::CONFIG_FILE_NAME;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

fn assert_failed_restart_preserves_stack(cfg_path: &std::path::Path, state_dir: &std::path::Path) {
    let authority_pid = firma_stack::test_support::pidfile::read(&state_dir.join("authority.pid"))
        .expect("read authority pidfile")
        .expect("authority pid");
    let sidecar_pid = firma_stack::test_support::pidfile::read(&state_dir.join("sidecar.pid"))
        .expect("read sidecar pidfile")
        .expect("sidecar pid");

    std::fs::remove_file(state_dir.join("stack.lock")).expect("remove stack lock");
    let restart_stderr = state_dir.join("restart.stderr.log");
    let restart_status = firma()
        .args(["sidecar", "start", "--detach", "--config"])
        .arg(cfg_path)
        .args(["--state-dir"])
        .arg(state_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            File::create(&restart_stderr).expect("create restart log"),
        ))
        .status()
        .expect("run second firma sidecar start");
    assert!(
        !restart_status.success(),
        "second start unexpectedly succeeded"
    );
    let restart_diagnostics = std::fs::read_to_string(&restart_stderr).unwrap_or_default();
    assert!(
        authority_pid.process_exists().expect("probe authority"),
        "failed startup rollback terminated the existing authority: {restart_diagnostics}"
    );
    assert!(
        sidecar_pid.process_exists().expect("probe sidecar"),
        "failed startup rollback terminated the existing sidecar: {restart_diagnostics}"
    );
    assert!(
        !state_dir.join("stack.lock").exists(),
        "blocked startup published a generation it does not own"
    );
}

#[test]
fn start_launches_from_anthropic_scaffold() {
    let tmp = tempfile::tempdir().expect("tmp");
    let config_dir = tmp.path().join("cfg");
    let state_dir = tmp.path().join("state");

    // Reserve two distinct loopback ports by holding both listeners open at the
    // same time: two sequential ephemeral binds could hand back the same port
    // (each releases before the next binds), colliding the authority and
    // interceptor. The listeners stay bound while every config file is written,
    // then drop just before the stack binds the ports itself.
    let authority_listener = TcpListener::bind("127.0.0.1:0").expect("reserve authority port");
    let interceptor_listener = TcpListener::bind("127.0.0.1:0").expect("reserve interceptor port");
    let authority_addr = authority_listener.local_addr().expect("authority addr");
    let interceptor_addr = interceptor_listener.local_addr().expect("interceptor addr");

    // Default agent-local scaffold: Anthropic mapping only → HTTPS MITM is
    // disabled, so the sidecar never writes CA material.
    let init = firma()
        .args(["config", "--yes", "--mode", "agent-local", "--output-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .args(["--authority-listen"])
        .arg(authority_addr.to_string())
        .output()
        .expect("run firma config");
    assert!(init.status.success(), "config scaffold failed: {init:?}");

    // Retarget the interceptor off the fixed default (127.0.0.1:8080); the
    // scaffold has no flag for this.
    let cfg_path = config_dir.join(CONFIG_FILE_NAME);
    let text = std::fs::read_to_string(&cfg_path).expect("read firma.toml");
    let text = text.replace("127.0.0.1:8080", &interceptor_addr.to_string());
    std::fs::write(&cfg_path, text).expect("write firma.toml");

    // Release the reserved ports so the stack can bind them.
    drop(authority_listener);
    drop(interceptor_listener);

    // Preserve launcher diagnostics while the detached supervisor writes to its
    // own log file and outlives this command.
    std::fs::create_dir_all(&state_dir).expect("state dir");
    let start_stderr = state_dir.join("start.stderr.log");
    let start_status = firma()
        .args(["sidecar", "start", "--detach", "--config"])
        .arg(&cfg_path)
        .args(["--state-dir"])
        .arg(&state_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            File::create(&start_stderr).expect("create start log"),
        ))
        .status()
        .expect("run firma sidecar start");
    assert!(
        start_status.success(),
        "sidecar start failed (MITM-inactive scaffold must not block on CA material): {}",
        std::fs::read_to_string(&start_stderr).unwrap_or_default()
    );

    // Detached start returns only after the owning supervisor acknowledges
    // component readiness.
    let stack_pid = state_dir.join("stack.pid");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !stack_pid.exists() {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        stack_pid.exists(),
        "stack did not come up: stack.pid missing"
    );

    assert_failed_restart_preserves_stack(&cfg_path, &state_dir);

    let authority_pid = firma_stack::test_support::pidfile::read(&state_dir.join("authority.pid"))
        .expect("read authority pidfile")
        .expect("authority pid");
    let sidecar_pid = firma_stack::test_support::pidfile::read(&state_dir.join("sidecar.pid"))
        .expect("read sidecar pidfile")
        .expect("sidecar pid");
    let supervisor_pid = firma_stack::test_support::pidfile::read(&stack_pid)
        .expect("read supervisor pidfile")
        .expect("supervisor pid");

    #[cfg(unix)]
    {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(
                i32::try_from(supervisor_pid.get()).expect("supervisor PID fits pid_t"),
            ),
            nix::sys::signal::Signal::SIGTERM,
        )
        .expect("SIGTERM detached supervisor");
    }
    #[cfg(windows)]
    firma_stack::test_support::terminate_raw(authority_pid.get()).expect("terminate authority");

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline
        && (supervisor_pid.process_exists().expect("probe supervisor")
            || authority_pid.process_exists().expect("probe authority")
            || sidecar_pid.process_exists().expect("probe sidecar"))
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !supervisor_pid.process_exists().expect("probe supervisor"),
        "detached supervisor still exists after termination"
    );
    assert!(
        !authority_pid.process_exists().expect("probe authority"),
        "authority still exists after owner teardown"
    );
    assert!(
        !sidecar_pid.process_exists().expect("probe sidecar"),
        "sidecar peer still exists after authority exit"
    );

    let stop_status = firma()
        .args(["sidecar", "stop", "--state-dir"])
        .arg(&state_dir)
        .status()
        .expect("clean retained state");
    assert!(stop_status.success(), "could not clean retained state");
    assert!(!state_dir.join("stack.pid").exists());
}
