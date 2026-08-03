//! `firma sidecar start` launches from a default `firma config` scaffold.
//!
//! Regression guard: the daemon readiness path used to wait
//! for sidecar CA material unconditionally, but CA material is only written
//! when HTTPS MITM is active. The default Anthropic-only scaffold ships MITM
//! disabled, so the daemon timed out and never came up. Readiness now gates
//! the CA-material probe on `HttpsMitmConfig::is_active()`.
//! On Unix, the teardown half also sends `SIGTERM` to the detached supervisor
//! and verifies that its preinstalled handler owns component cleanup.
//! On Windows, abruptly terminating the supervisor verifies that retained Job
//! Object ownership terminates both production components.
//! A second detached start with a missing lock must not claim or terminate the
//! existing stack.

#![allow(
    clippy::expect_used,
    reason = "test code: panics acceptable on test failure"
)]

use std::fs::File;
use std::io::{Read, Seek};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::CONFIG_FILE_NAME;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

fn start_detached(cfg_path: &Path, state_dir: &Path) -> std::process::Output {
    // A detached supervisor may retain inherited handles after the launcher
    // exits. File-backed capture lets `status` return without waiting for pipe
    // EOF, which would otherwise hang indefinitely on Windows.
    let mut stderr = tempfile::tempfile_in(state_dir).expect("create start stderr log");
    let status = firma()
        .args(["sidecar", "start", "--detach", "--config"])
        .arg(cfg_path)
        .args(["--state-dir"])
        .arg(state_dir)
        .env("FIRMA_SIDECAR_HEALTH_BIND_ADDR", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            stderr.try_clone().expect("clone start stderr log"),
        ))
        .status()
        .expect("run firma sidecar start");
    stderr.rewind().expect("rewind start stderr log");
    let mut diagnostics = Vec::new();
    stderr
        .read_to_end(&mut diagnostics)
        .expect("read start stderr log");
    std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: diagnostics,
    }
}

fn daemon_status(state_dir: &Path) -> (std::process::ExitStatus, serde_json::Value) {
    let output = firma()
        .args(["sidecar", "status", "--daemon", "--json"])
        .env("FIRMA_STATE_DIR", state_dir)
        .output()
        .expect("run firma sidecar status");
    let rows = serde_json::from_slice(&output.stdout).expect("status returns JSON");
    (output.status, rows)
}

struct StackCleanup<'a>(&'a Path);

impl Drop for StackCleanup<'_> {
    fn drop(&mut self) {
        let _ = firma()
            .args(["sidecar", "stop", "--state-dir"])
            .arg(self.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
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
    assert_eq!(restart_status.code(), Some(2));
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

    std::fs::create_dir_all(&state_dir).expect("state dir");
    let _cleanup = StackCleanup(&state_dir);
    let start = start_detached(&cfg_path, &state_dir);
    assert!(
        start.status.success(),
        "sidecar start failed (MITM-inactive scaffold must not block on CA material): {}",
        String::from_utf8_lossy(&start.stderr)
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

    let (status, rows) = daemon_status(&state_dir);
    assert!(status.success(), "running daemon status was {status}");
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["sandbox_id"], "daemon");
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["listen"], interceptor_addr.to_string());

    assert_failed_restart_preserves_stack(&cfg_path, &state_dir);

    let stop = firma()
        .args(["sidecar", "stop", "--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("stop running daemon");
    assert!(
        stop.status.success(),
        "sidecar stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let (status, rows) = daemon_status(&state_dir);
    assert_eq!(status.code(), Some(1));
    assert_eq!(rows[0]["state"], "stopped");

    let restart = start_detached(&cfg_path, &state_dir);
    assert!(
        restart.status.success(),
        "sidecar restart failed: {}",
        String::from_utf8_lossy(&restart.stderr)
    );
    assert_owner_teardown(&state_dir, &stack_pid);
}

fn assert_owner_teardown(state_dir: &Path, stack_pid: &Path) {
    let authority_pid = firma_stack::test_support::pidfile::read(&state_dir.join("authority.pid"))
        .expect("read authority pidfile")
        .expect("authority pid");
    let sidecar_pid = firma_stack::test_support::pidfile::read(&state_dir.join("sidecar.pid"))
        .expect("read sidecar pidfile")
        .expect("sidecar pid");
    let supervisor_pid = firma_stack::test_support::pidfile::read(stack_pid)
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
    firma_stack::test_support::terminate_raw(supervisor_pid.get())
        .expect("terminate detached supervisor");

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
        "authority still exists after supervisor teardown"
    );
    assert!(
        !sidecar_pid.process_exists().expect("probe sidecar"),
        "sidecar still exists after supervisor teardown"
    );

    let stop_status = firma()
        .args(["sidecar", "stop", "--state-dir"])
        .arg(state_dir)
        .status()
        .expect("clean retained state");
    assert!(stop_status.success(), "could not clean retained state");
    assert!(!state_dir.join("stack.pid").exists());
}
