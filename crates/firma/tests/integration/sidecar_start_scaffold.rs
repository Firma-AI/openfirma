//! Exercises the detached sidecar lifecycle from the default Anthropic-only
//! `firma config` scaffold, where HTTPS MITM and CA material are absent.
//!
//! The scenarios cover startup readiness and JSON status, a rejected duplicate
//! startup with missing lock state, stop and restart, and supervisor-owned
//! component teardown.

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

struct Scaffold {
    _tmp: tempfile::TempDir,
    cfg_path: std::path::PathBuf,
    state_dir: std::path::PathBuf,
    interceptor_addr: std::net::SocketAddr,
}

impl Scaffold {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tmp");
        let config_dir = tmp.path().join("cfg");
        let state_dir = tmp.path().join("state");

        // Holding both reservations prevents sequential ephemeral binds from
        // selecting the same port. Health binding remains independently
        // ephemeral through `start_detached`.
        let authority_listener = TcpListener::bind("127.0.0.1:0").expect("reserve authority port");
        let interceptor_listener =
            TcpListener::bind("127.0.0.1:0").expect("reserve interceptor port");
        let authority_addr = authority_listener.local_addr().expect("authority addr");
        let interceptor_addr = interceptor_listener.local_addr().expect("interceptor addr");

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

        let cfg_path = config_dir.join(CONFIG_FILE_NAME);
        let text = std::fs::read_to_string(&cfg_path).expect("read firma.toml");
        let text = text.replace("127.0.0.1:8080", &interceptor_addr.to_string());
        std::fs::write(&cfg_path, text).expect("write firma.toml");

        drop(authority_listener);
        drop(interceptor_listener);
        std::fs::create_dir_all(&state_dir).expect("state dir");

        Self {
            _tmp: tmp,
            cfg_path,
            state_dir,
            interceptor_addr,
        }
    }

    fn start(&self) -> std::process::Output {
        start_detached(&self.cfg_path, &self.state_dir)
    }

    fn cleanup(&self) -> StackCleanup<'_> {
        StackCleanup(&self.state_dir)
    }

    fn stack_pid_path(&self) -> std::path::PathBuf {
        self.state_dir.join("stack.pid")
    }
}

fn assert_stack_pid_published(stack_pid: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !stack_pid.exists() {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        stack_pid.exists(),
        "stack did not come up: stack.pid missing"
    );
}

#[test]
fn scaffold_start_reaches_readiness_and_reports_running_json_status() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();

    let start = scaffold.start();
    assert!(
        start.status.success(),
        "sidecar start failed (MITM-inactive scaffold must not block on CA material): {}",
        String::from_utf8_lossy(&start.stderr)
    );
    assert_stack_pid_published(&scaffold.stack_pid_path());

    let (status, rows) = daemon_status(&scaffold.state_dir);
    assert!(status.success(), "running daemon status was {status}");
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["sandbox_id"], "daemon");
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["listen"], scaffold.interceptor_addr.to_string());
}

#[test]
fn failed_second_start_does_not_claim_or_terminate_existing_stack() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();
    let start = scaffold.start();
    assert!(start.status.success(), "initial start failed: {start:?}");

    let state_dir = &scaffold.state_dir;
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
        .arg(&scaffold.cfg_path)
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
fn stopped_stack_reports_stopped_and_can_restart() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();
    let start = scaffold.start();
    assert!(start.status.success(), "initial start failed: {start:?}");

    let stop = firma()
        .args(["sidecar", "stop", "--state-dir"])
        .arg(&scaffold.state_dir)
        .output()
        .expect("stop running daemon");
    assert!(
        stop.status.success(),
        "sidecar stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let (status, rows) = daemon_status(&scaffold.state_dir);
    assert_eq!(status.code(), Some(1));
    assert_eq!(rows[0]["state"], "stopped");

    let restart = scaffold.start();
    assert!(
        restart.status.success(),
        "sidecar restart failed: {}",
        String::from_utf8_lossy(&restart.stderr)
    );
    assert_stack_pid_published(&scaffold.stack_pid_path());
}

#[test]
fn concurrent_starts_publish_exactly_one_stack() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();
    let barrier = std::sync::Barrier::new(3);

    let outputs = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            scaffold.start()
        });
        let second = scope.spawn(|| {
            barrier.wait();
            scaffold.start()
        });
        // The test thread is the third participant, releasing both launcher
        // threads from the same in-process barrier before either spawns `firma`.
        barrier.wait();
        [
            first.join().expect("first start thread"),
            second.join().expect("second start thread"),
        ]
    });

    let successes = outputs
        .iter()
        .filter(|output| output.status.success())
        .count();
    assert_eq!(successes, 1, "concurrent start outputs: {outputs:#?}");
    let failure = outputs
        .iter()
        .find(|output| !output.status.success())
        .expect("one start must lose the race");
    assert_eq!(failure.status.code(), Some(2));

    let (status, rows) = daemon_status(&scaffold.state_dir);
    assert!(status.success(), "winning stack status was {status}");
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["listen"], scaffold.interceptor_addr.to_string());
}

#[test]
fn supervisor_owner_teardown_terminates_components() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();
    let start = scaffold.start();
    assert!(start.status.success(), "initial start failed: {start:?}");

    let state_dir = &scaffold.state_dir;
    let stack_pid = scaffold.stack_pid_path();
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
