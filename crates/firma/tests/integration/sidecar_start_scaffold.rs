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

use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

use firma_config_loader::CONFIG_FILE_NAME;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

/// Grab a currently-free loopback port. Racy by nature (the port is released
/// when the listener drops), but adequate for an `#[ignore]`d local e2e.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

#[test]
#[ignore = "spawns the authority+sidecar stack and binds ports"]
fn start_launches_from_anthropic_scaffold() {
    let tmp = tempfile::tempdir().expect("tmp");
    let config_dir = tmp.path().join("cfg");
    let state_dir = tmp.path().join("state");

    // Default agent-local scaffold: Anthropic mapping only → HTTPS MITM is
    // disabled, so the sidecar never writes CA material.
    let init = firma()
        .args(["config", "--yes", "--mode", "agent-local", "--output-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .args(["--authority-listen"])
        .arg(format!("127.0.0.1:{}", free_port()))
        .output()
        .expect("run firma config");
    assert!(init.status.success(), "config scaffold failed: {init:?}");

    // Retarget the interceptor off the fixed default (127.0.0.1:8080) to dodge
    // collisions; the scaffold has no flag for this.
    let cfg_path = config_dir.join(CONFIG_FILE_NAME);
    let text = std::fs::read_to_string(&cfg_path).expect("read firma.toml");
    let text = text.replace("127.0.0.1:8080", &format!("127.0.0.1:{}", free_port()));
    std::fs::write(&cfg_path, text).expect("write firma.toml");

    let start = firma()
        .args(["sidecar", "start", "--detach", "--config"])
        .arg(&cfg_path)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("run firma sidecar start");
    assert!(
        start.status.success(),
        "sidecar start failed (MITM-inactive scaffold must not block on CA material): {}",
        String::from_utf8_lossy(&start.stderr)
    );

    // Detached start returns only after readiness, so the supervisor pidfile
    // should already be present (or appear momentarily).
    let stack_pid = state_dir.join("stack.pid");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !stack_pid.exists() {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        stack_pid.exists(),
        "stack did not come up: stack.pid missing"
    );

    let stop = firma()
        .args(["sidecar", "stop", "--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("run firma sidecar stop");
    assert!(
        stop.status.success(),
        "sidecar stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
}
