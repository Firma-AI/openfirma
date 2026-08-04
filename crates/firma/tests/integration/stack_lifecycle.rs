//! End-to-end stack lifecycle smoke test.

use std::process::Command;
use std::time::{Duration, Instant};

use super::CONFIG_FILE_NAME;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

#[test]
#[ignore = "requires demo fixtures and ports"]
fn lifecycle_detached() {
    let tmp = tempfile::tempdir().expect("tmp");
    let config_dir = tmp.path().join("cfg");
    let state_dir = tmp.path().join("state");

    // Scaffold the unified `firma.toml` (single sectioned config).
    let init = firma()
        .args(["stack", "init", "--config-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("init");
    assert!(init.status.success(), "init failed: {init:?}");
    let cfg_path = config_dir.join(CONFIG_FILE_NAME);
    assert!(cfg_path.is_file(), "scaffolded firma.toml missing");

    let out = firma()
        .args(["stack", "start", "--detach", "--config"])
        .arg(&cfg_path)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("start");
    assert!(out.status.success(), "start failed: {out:?}");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !state_dir.join("stack.pid").exists() {
        std::thread::sleep(Duration::from_millis(100));
    }

    let status_out = firma()
        .args(["stack", "status", "--json", "--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("status");
    let stdout = String::from_utf8_lossy(&status_out.stdout);
    assert!(stdout.contains("running"), "status: {stdout}");

    let stop_out = firma()
        .args(["stack", "stop", "--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("stop");
    assert!(stop_out.status.success());
}
