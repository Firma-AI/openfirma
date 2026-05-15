//! End-to-end-ish: spawn a fake sidecar that emits the seven-line ready
//! contract then sleeps. Drop the supervisor and assert the child exits
//! within the SIGTERM grace period.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics acceptable on test failure"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use firma_run::sidecar::supervisor::{SidecarSupervisor, SpawnRequest};
use tempfile::TempDir;

// `exec sleep 60` replaces sh with sleep so the supervisor's SIGTERM in
// Drop kills the actual descendant rather than an orphaned grandchild.
const READY_SCRIPT: &str = "#!/bin/sh\n\
echo 'INFO firma_sidecar::startup::log_contract: config loaded path=\"/x.toml\"' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: mapping table loaded rules=44' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: policy bundle loaded version=\"ab12cd34\" policies=3' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: authority stream connected endpoint=\"(disabled)\"' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: connector registry built hosts=12 default_timeout_ms=5000' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: interceptor listening addr=\"x.sock\"' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: ready' 1>&2\n\
exec sleep 60\n";

fn write_fake_sidecar(dir: &std::path::Path, body: &str) -> PathBuf {
    let path = dir.join("fake-sidecar.sh");
    fs::write(&path, body).expect("write");
    let mut perm = fs::metadata(&path).expect("meta").permissions();
    perm.set_mode(0o755);
    fs::set_permissions(&path, perm).expect("chmod");
    path
}

fn is_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw), None).is_ok()
}

#[test]
fn drop_terminates_child_within_grace() {
    let tmp = TempDir::new().expect("tmp");
    let exe = write_fake_sidecar(tmp.path(), READY_SCRIPT);
    let marker = tmp.path().join("run").join("sandbox-1");

    let supervisor = SidecarSupervisor::spawn(SpawnRequest {
        sandbox_id: "sandbox-1",
        agent_id: "generic",
        session_id: "session-1",
        marker_dir: marker.clone(),
        template_path: None,
        env_template: None,
        cwd_template: None,
        firma_exe: exe,
        startup_timeout: Duration::from_secs(5),
        authority_url: None,
    })
    .expect("supervisor spawned");

    let pid = supervisor.pid();
    assert!(is_alive(pid), "child should be alive after spawn");

    // The fake sidecar traps SIGTERM. Drop must escalate to SIGKILL after
    // the 5s grace window.
    drop(supervisor);

    let deadline = Instant::now() + Duration::from_secs(8);
    while is_alive(pid) {
        assert!(
            Instant::now() < deadline,
            "sidecar pid {pid} still alive after Drop + SIGKILL"
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert!(!marker.exists(), "marker dir should be GC'd on Drop");
}

#[test]
fn marker_files_present_between_ready_and_drop() {
    let tmp = TempDir::new().expect("tmp");
    let exe = write_fake_sidecar(tmp.path(), READY_SCRIPT);
    let marker = tmp.path().join("run").join("sandbox-2");

    let supervisor = SidecarSupervisor::spawn(SpawnRequest {
        sandbox_id: "sandbox-2",
        agent_id: "claude-code",
        session_id: "session-7",
        marker_dir: marker,
        template_path: None,
        env_template: None,
        cwd_template: None,
        firma_exe: exe,
        startup_timeout: Duration::from_secs(5),
        authority_url: None,
    })
    .expect("supervisor spawned");

    let metadata_path = supervisor.marker_dir().join("metadata.toml");
    let pid_path = supervisor.marker_dir().join("sidecar.pid");
    assert!(metadata_path.exists(), "metadata.toml missing");
    assert!(pid_path.exists(), "sidecar.pid missing");

    let text = fs::read_to_string(&metadata_path).expect("read metadata");
    let parsed: toml::Value = toml::from_str(&text).expect("parse metadata");
    let table = parsed.as_table().expect("table");

    assert_eq!(
        table.get("sandbox_id").and_then(|v| v.as_str()),
        Some("sandbox-2")
    );
    assert_eq!(
        table.get("agent_id").and_then(|v| v.as_str()),
        Some("claude-code")
    );
    assert_eq!(
        table.get("session_id").and_then(|v| v.as_str()),
        Some("session-7")
    );
    assert_eq!(
        table.get("policy_bundle_version").and_then(|v| v.as_str()),
        Some("ab12cd34")
    );
    assert_eq!(
        table.get("authority_url").and_then(|v| v.as_str()),
        Some(""),
        "(disabled) endpoint should be scrubbed to empty string"
    );
    assert_eq!(
        table.get("pid").and_then(toml::Value::as_integer),
        Some(i64::from(supervisor.pid()))
    );
    let started_at = table
        .get("started_at")
        .and_then(|v| v.as_str())
        .expect("started_at present");
    assert!(
        started_at.contains('T') && (started_at.ends_with('Z') || started_at.contains('+')),
        "started_at not RFC 3339: {started_at}"
    );
}
