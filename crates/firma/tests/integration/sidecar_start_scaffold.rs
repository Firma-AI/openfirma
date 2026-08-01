//! `firma sidecar start` launches from a default `firma config` scaffold.
//!
//! Regression guard: the daemon readiness path used to wait
//! for sidecar CA material unconditionally, but CA material is only written
//! when HTTPS MITM is active. The default Anthropic-only scaffold ships MITM
//! disabled, so the daemon timed out and never came up. Readiness now gates
//! the CA-material probe on `HttpsMitmConfig::is_active()`.

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

    let authority_pid = firma_stack::test_support::pidfile::read(&state_dir.join("authority.pid"))
        .expect("read authority pidfile")
        .expect("authority pid");
    let sidecar_pid = firma_stack::test_support::pidfile::read(&state_dir.join("sidecar.pid"))
        .expect("read sidecar pidfile")
        .expect("sidecar pid");
    firma_stack::test_support::terminate_raw(authority_pid.get()).expect("terminate authority");

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && state_dir.join("stack.lock").exists() {
        std::thread::sleep(Duration::from_millis(100));
    }
    let cleaned_up = !state_dir.join("stack.lock").exists();
    if !cleaned_up {
        let _ = firma()
            .args(["sidecar", "stop", "--state-dir"])
            .arg(&state_dir)
            .status();
    }
    assert!(
        cleaned_up,
        "owning supervisor did not clean up after authority exit"
    );
    assert!(
        !authority_pid.process_exists().expect("probe authority"),
        "authority still exists after owner teardown"
    );
    assert!(
        !sidecar_pid.process_exists().expect("probe sidecar"),
        "sidecar peer still exists after authority exit"
    );
    assert!(!state_dir.join("stack.pid").exists());
}
