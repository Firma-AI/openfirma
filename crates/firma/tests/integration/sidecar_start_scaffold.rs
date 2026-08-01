//! `firma sidecar start` launches from a default `firma config` scaffold.
//!
//! Regression guard: the daemon readiness path used to wait
//! for sidecar CA material unconditionally, but CA material is only written
//! when HTTPS MITM is active. The default Anthropic-only scaffold ships MITM
//! disabled, so the daemon timed out and never came up. Readiness now gates
//! the CA-material probe on `HttpsMitmConfig::is_active()`.
//! On Windows, abruptly terminating the detached supervisor also verifies that
//! its retained Job Object ownership terminates both production components.

#![allow(
    clippy::expect_used,
    reason = "test code: panics acceptable on test failure"
)]

use std::fs::File;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::CONFIG_FILE_NAME;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
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
    let _cleanup = StackCleanup(&state_dir);
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

    assert_owner_teardown(&state_dir, &stack_pid);
}

fn assert_owner_teardown(state_dir: &Path, _stack_pid: &Path) {
    let authority_pid = firma_stack::test_support::pidfile::read(&state_dir.join("authority.pid"))
        .expect("read authority pidfile")
        .expect("authority pid");
    let sidecar_pid = firma_stack::test_support::pidfile::read(&state_dir.join("sidecar.pid"))
        .expect("read sidecar pidfile")
        .expect("sidecar pid");
    #[cfg(windows)]
    let supervisor_pid = firma_stack::test_support::pidfile::read(_stack_pid)
        .expect("read supervisor pidfile")
        .expect("supervisor pid");

    #[cfg(not(windows))]
    firma_stack::test_support::terminate_raw(authority_pid.get()).expect("terminate authority");

    #[cfg(windows)]
    firma_stack::test_support::terminate_raw(supervisor_pid.get())
        .expect("terminate detached supervisor");

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let components_running = authority_pid.process_exists().expect("probe authority")
            || sidecar_pid.process_exists().expect("probe sidecar");
        #[cfg(windows)]
        let teardown_incomplete =
            components_running || supervisor_pid.process_exists().expect("probe supervisor");
        #[cfg(not(windows))]
        let teardown_incomplete = components_running;
        if !teardown_incomplete || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let components_stopped = !authority_pid.process_exists().expect("probe authority")
        && !sidecar_pid.process_exists().expect("probe sidecar");
    assert!(
        components_stopped,
        "component processes survived owning supervisor teardown"
    );
    assert!(
        !authority_pid.process_exists().expect("probe authority"),
        "authority still exists after supervisor teardown"
    );
    assert!(
        !sidecar_pid.process_exists().expect("probe sidecar"),
        "sidecar still exists after supervisor teardown"
    );

    #[cfg(not(windows))]
    {
        assert!(!state_dir.join("stack.lock").exists());
        assert!(!state_dir.join("stack.pid").exists());
    }

    #[cfg(windows)]
    {
        assert!(
            !supervisor_pid.process_exists().expect("probe supervisor"),
            "detached supervisor still exists after forced termination"
        );
        let stop_status = firma()
            .args(["sidecar", "stop", "--state-dir"])
            .arg(state_dir)
            .status()
            .expect("clean retained state");
        assert!(stop_status.success(), "could not clean retained state");
    }
}
