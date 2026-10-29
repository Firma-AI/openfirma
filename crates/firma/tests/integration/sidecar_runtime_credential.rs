//! A Sidecar started for one run lives only as long as the `firma run`
//! that started it.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use firma_config_schema::sidecar::authority::SidecarCredentials;

use super::firma_bin;
use super::sidecar_startup_contract::startup_fixture;

/// The launcher names itself in `FIRMA_RUN_PID`, hands the Sidecar none of
/// its pipes, reports the Sidecar's pid, and leaves when its stdin closes.
const LAUNCHER: &str = r#"
FIRMA_RUN_PID=$$ "$0" sidecar --config "$1" --health-bind-addr 127.0.0.1:0 --enforcement-state "$2" </dev/null >/dev/null 2>"$3" &
echo $!
read -r _ || true
"#;

/// Whether `pid` still runs; an orphan nobody reaped yet is a zombie, which
/// has exited.
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .is_ok_and(|status| !status.contains("State:\tZ"))
}

fn wait_for(log: &std::path::Path, line: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if std::fs::read_to_string(log).is_ok_and(|text| text.contains(line)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn a_sidecar_serving_a_run_stops_when_its_firma_run_is_gone() {
    let fixture = startup_fixture(|config| {
        config.authority.credentials = Some(SidecarCredentials {
            workspace_id: "wsp_01j0000000e008000000000001".to_string(),
            sidecar_id: "sc_01j0000000e008000000000001".to_string(),
            pre_shared_key_env: None,
            pre_shared_key_path: None,
            run_id: Some("run_01j0000000e008000000000001".to_string()),
            runtime_credential_env: Some("FIRMA_RUNTIME_CREDENTIAL".to_string()),
        });
    });
    let stderr_log = fixture.temp_dir.path().join("sidecar.stderr.log");
    let stderr = || std::fs::read_to_string(&stderr_log).unwrap_or_default();

    let mut launcher = Command::new("sh")
        .arg("-c")
        .arg(LAUNCHER)
        .arg(firma_bin())
        .arg(&fixture.config_path)
        .arg(fixture.temp_dir.path().join("enforcement.toml"))
        .arg(&stderr_log)
        .env("FIRMA_STATE_DIR", fixture.temp_dir.path().join("state"))
        .env("FIRMA_RUNTIME_CREDENTIAL", "runtime-credential-value")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run the launcher");
    let mut pid = String::new();
    BufReader::new(launcher.stdout.take().unwrap())
        .read_line(&mut pid)
        .unwrap();
    let pid: u32 = pid.trim().parse().unwrap();
    assert!(wait_for(&stderr_log, "sidecar ready"), "{}", stderr());

    // Closing its stdin ends the launcher: the Sidecar's parent is gone.
    drop(launcher.stdin.take());
    assert!(launcher.wait().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(10);
    while running(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !running(pid),
        "the Sidecar outlived its firma run:\n{}",
        stderr()
    );
    let log = stderr();
    assert!(log.contains("parent process gone"), "{log}");
    assert!(
        !log.contains("runtime-credential-value"),
        "the credential is never logged"
    );
}
