//! Preparation boundary tests for local Sidecar launches.

#![cfg(unix)]
#![allow(clippy::expect_used, reason = "test code")]

use std::ffi::OsStr;

use firma_run::config::SidecarEndpoint;
use firma_run::sidecar::prepare::{PrepareRequest, prepare};

fn request(
    sandbox_id: &firma_run::identity::SandboxId,
    marker_dir: std::path::PathBuf,
    tcp: bool,
) -> PrepareRequest<'_> {
    PrepareRequest {
        sandbox_id,
        agent_id: super::helper::agent_id(),
        execution_profile: firma_config_loader::AgentProfile::Generic,
        session_id: "prepared-session",
        marker_dir,
        template_path: None,
        env_template: None,
        cwd_template: None,
        firma_exe: "/bin/false".into(),
        authority_url: Some("http://127.0.0.1:50051"),
        authority_ca_cert: None,
        authority_pub_key: None,
        authority_credentials: None,
        capability_seed_path: None,
        use_http_proxy_interceptor: tcp,
        audit_fallback_path: None,
        monitor_mode: true,
    }
}

#[test]
fn preparation_absolutizes_unix_paths_and_materializes_launch_contract() {
    let cwd = std::env::current_dir().expect("current directory");
    let temp = tempfile::Builder::new()
        .prefix("sidecar-prepare-")
        .tempdir_in(&cwd)
        .expect("temporary directory");
    let relative = temp.path().strip_prefix(&cwd).expect("relative temp path");
    let sandbox_id = firma_run::identity::SandboxId::generate();

    let prepared =
        prepare(request(&sandbox_id, relative.join("marker"), false)).expect("prepare Sidecar");

    assert!(prepared.marker_dir.is_absolute());
    assert_eq!(
        prepared.expected_endpoint,
        SidecarEndpoint::Unix {
            path: prepared.marker_dir.join("sidecar.sock")
        }
    );
    let config = std::fs::read_to_string(&prepared.config_path).expect("read config");
    assert!(
        config.contains(
            &prepared
                .marker_dir
                .join("sidecar.sock")
                .display()
                .to_string()
        )
    );
    let env: std::collections::HashMap<_, _> = prepared
        .command()
        .expect("command is available")
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .collect();
    assert_eq!(
        env.get(OsStr::new("FIRMA_RUN_SANDBOX_ID")),
        Some(&sandbox_id.to_string().as_ref())
    );
    assert_eq!(
        env.get(OsStr::new("FIRMA_SIDECAR_HEALTH_BIND_ADDR")),
        Some(&OsStr::new("127.0.0.1:0"))
    );
    assert_eq!(
        env.get(OsStr::new("FIRMA_RUN_AUDIT_SOCK")),
        Some(&prepared.audit_socket_path.as_os_str())
    );
    assert_eq!(
        env.get(OsStr::new("FIRMA_ALLOW_MONITOR_MODE")),
        Some(&OsStr::new("1"))
    );
    assert_eq!(prepared.planned_authority_url, "http://127.0.0.1:50051");
    assert!(!prepared.planned_policy_bundle_version.is_empty());
}

#[test]
fn prepared_command_can_only_be_taken_once() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let sandbox_id = firma_run::identity::SandboxId::generate();
    let mut prepared =
        prepare(request(&sandbox_id, temp.path().join("marker"), false)).expect("prepare Sidecar");

    let _command = prepared.take_command().expect("first command handoff");
    assert!(prepared.command().is_none());
    assert!(prepared.take_command().is_err());
    assert!(!prepared.planned_policy_bundle_version.is_empty());
}

#[test]
fn tcp_preparation_leaves_port_selection_to_child() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let sandbox_id = firma_run::identity::SandboxId::generate();
    let prepared =
        prepare(request(&sandbox_id, temp.path().join("marker"), true)).expect("prepare Sidecar");

    assert_eq!(
        prepared.expected_endpoint,
        SidecarEndpoint::Tcp {
            addr: "127.0.0.1:0".parse().expect("socket address")
        }
    );
    let config = std::fs::read_to_string(prepared.config_path).expect("read config");
    assert!(config.contains("listen_addr = \"127.0.0.1:0\""));
}
