//! End-to-end stack lifecycle smoke test.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../firma-demo-fixture")
}

#[test]
#[ignore = "requires demo fixtures and ports"]
fn lifecycle_detached() {
    let tmp = tempfile::tempdir().expect("tmp");
    let state_dir = tmp.path();
    let cfg_path = state_dir.join("firma-stack.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "authority_config = {:?}\nsidecar_config = {:?}\n",
            fixture_dir().join("authority.toml"),
            fixture_dir().join("sidecar.toml"),
        ),
    )
    .expect("cfg");

    let out = firma()
        .args(["stack", "start", "--detach", "--config"])
        .arg(&cfg_path)
        .args(["--state-dir"])
        .arg(state_dir)
        .output()
        .expect("start");
    assert!(out.status.success(), "start failed: {out:?}");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !state_dir.join("stack.pid").exists() {
        std::thread::sleep(Duration::from_millis(100));
    }

    let status_out = firma()
        .args(["stack", "status", "--json", "--state-dir"])
        .arg(state_dir)
        .output()
        .expect("status");
    let stdout = String::from_utf8_lossy(&status_out.stdout);
    assert!(stdout.contains("running"), "status: {stdout}");

    let stop_out = firma()
        .args(["stack", "stop", "--state-dir"])
        .arg(state_dir)
        .output()
        .expect("stop");
    assert!(stop_out.status.success());
}
