//! Asserts that `SidecarSupervisor::spawn` propagates the per-run
//! sandbox identity into the child's environment as
//! `FIRMA_RUN_SANDBOX_ID`. The sidecar reads this variable at startup
//! to stamp `sandbox_id` on every `ExecutionEvent` (FIR-185).

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
use std::time::Duration;

use firma_run::sidecar::supervisor::{SidecarSupervisor, SpawnRequest};
use tempfile::TempDir;

fn write_fake_sidecar(dir: &std::path::Path, capture_path: &std::path::Path) -> PathBuf {
    let script = format!(
        "#!/bin/sh\n\
printf '%s' \"$FIRMA_RUN_SANDBOX_ID\" > {captured}\n\
echo 'INFO firma_sidecar::startup::log_contract: config loaded path=\"/x.toml\"' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: mapping table loaded rules=44' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: policy bundle loaded version=\"ab12cd34\" policies=3' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: authority stream connected endpoint=\"(disabled)\"' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: connector registry built hosts=12 default_timeout_ms=5000' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: interceptor listening addr=\"x.sock\"' 1>&2\n\
echo 'INFO firma_sidecar::startup::log_contract: sidecar ready' 1>&2\n\
exec sleep 60\n",
        captured = capture_path.display(),
    );
    let path = dir.join("fake-sidecar.sh");
    fs::write(&path, script).expect("write");
    let mut perm = fs::metadata(&path).expect("meta").permissions();
    perm.set_mode(0o755);
    fs::set_permissions(&path, perm).expect("chmod");
    path
}

#[test]
fn spawned_sidecar_inherits_sandbox_id_env() {
    let tmp = TempDir::new().expect("tmp");
    let capture_path = tmp.path().join("captured-sandbox-id");
    let exe = write_fake_sidecar(tmp.path(), &capture_path);
    let sandbox_id = firma_run::identity::SandboxId::generate();
    let marker = tmp.path().join("run").join(sandbox_id.to_string());

    let _supervisor = SidecarSupervisor::spawn(SpawnRequest {
        sandbox_id: &sandbox_id,
        agent_id: super::helper::agent_id(),
        execution_profile: firma_config_loader::AgentProfile::Generic,
        session_id: "session-env",
        marker_dir: marker,
        template_path: None,
        env_template: None,
        cwd_template: None,
        firma_exe: exe,
        startup_timeout: Duration::from_secs(5),
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        authority_credentials: None,
        capability_seed_path: None,
        use_http_proxy_interceptor: false,
        audit_fallback_path: None,
        monitor_mode: false,
    })
    .expect("supervisor spawned");

    let captured = fs::read_to_string(&capture_path).expect("capture file written");
    assert_eq!(captured, sandbox_id.to_string());
}
