//! Verifies that `SidecarSupervisor::spawn` returns
//! [`RunError::SidecarReadyTimeout`] when the spawned process fails to
//! emit the seventh `ready` line within the configured budget.

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

use firma_run::error::RunError;
use firma_run::sidecar::supervisor::{SidecarSupervisor, SpawnRequest};
use tempfile::TempDir;

fn write_fake_sidecar(dir: &std::path::Path, body: &str) -> PathBuf {
    let path = dir.join("fake-sidecar.sh");
    fs::write(&path, body).expect("write fake sidecar");
    let mut perm = fs::metadata(&path).expect("metadata").permissions();
    perm.set_mode(0o755);
    fs::set_permissions(&path, perm).expect("chmod");
    path
}

#[test]
fn returns_ready_timeout_when_no_ready_line_observed() {
    let tmp = TempDir::new().expect("tmp");
    // Print two contract lines, then sleep forever — never emits `ready`.
    let exe = write_fake_sidecar(
        tmp.path(),
        "#!/bin/sh\n\
         echo 'INFO firma_sidecar::startup::log_contract: config loaded path=\"x\"' 1>&2\n\
         echo 'INFO firma_sidecar::startup::log_contract: mapping table loaded rules=0' 1>&2\n\
         exec sleep 60\n",
    );
    let marker = tmp.path().join("run").join("sandbox-xyz");

    let result = SidecarSupervisor::spawn(SpawnRequest {
        sandbox_id: &firma_run::identity::SandboxId::from("sandbox-xyz"),
        agent_id: "generic",
        session_id: "session-1",
        marker_dir: marker.clone(),
        template_path: None,
        env_template: None,
        cwd_template: None,
        firma_exe: exe,
        startup_timeout: Duration::from_millis(500),
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        use_http_proxy_interceptor: false,
        audit_fallback_path: None,
    });
    let Err(err) = result else {
        panic!("expected timeout, got Ok");
    };

    match err {
        RunError::SidecarReadyTimeout {
            timeout_secs,
            log_path,
        } => {
            assert_eq!(
                timeout_secs, 0,
                "sub-second budget is reported as 0 seconds"
            );
            assert!(
                log_path.starts_with(&marker),
                "log path {} should live under marker dir {}",
                log_path.display(),
                marker.display()
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
