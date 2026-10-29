//! Preparation boundary tests for local Sidecar launches.

#![cfg(unix)]
#![allow(clippy::expect_used, reason = "test code")]

use std::assert_matches;
use std::ffi::{OsStr, OsString};

use firma_identifiers::SandboxId;
use firma_run::config::SidecarEndpoint;
use firma_run::sidecar::prepare::{
    PrepareRequest, PreparedSidecarLaunch, prepare, publish_metadata,
};

fn request(
    sandbox_id: &SandboxId,
    marker_dir: std::path::PathBuf,
    tcp: bool,
) -> PrepareRequest<'_> {
    PrepareRequest {
        state: firma_runtime_state::RuntimeLayout::from_root(marker_dir.join("state")),
        sandbox_id,
        agent_id: super::helper::agent_id(),
        execution_profile: firma_config_loader::AgentProfile::Generic,
        session_id: "prepared-session",
        marker_dir,
        template: firma_run::sidecar::config::resolve_template_sources(None)
            .expect("resolve minimal Sidecar template"),
        firma_exe: "/bin/false".into(),
        authority_url: Some("http://127.0.0.1:50051"),
        authority_ca_cert: None,
        authority_pub_key: None,
        authority_credentials: None,
        capability_seed_path: None,
        use_http_proxy_interceptor: tcp,
        audit_fallback_path: None,
        audit_signing_key_path: None,
        secret_gateway_addr: None,
        http_secret_providers: &[],
        credential: None,
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
    let sandbox_id = SandboxId::generate();

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
    assert_eq!(prepared.planned_authority_url, "http://127.0.0.1:50051");
    let args: Vec<_> = prepared
        .command()
        .expect("command is available")
        .get_args()
        .collect();
    let enforcement_state = prepared.marker_dir.join("enforcement.toml");
    assert!(
        args.windows(2).any(|pair| pair
            == [
                OsStr::new("--enforcement-state"),
                enforcement_state.as_os_str()
            ]),
        "Sidecar must publish its enforced bundle beside the marker: {args:?}"
    );
}

#[test]
fn prepared_command_can_only_be_taken_once() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let sandbox_id = SandboxId::generate();
    let mut prepared =
        prepare(request(&sandbox_id, temp.path().join("marker"), false)).expect("prepare Sidecar");

    let _command = prepared.take_command().expect("first command handoff");
    assert!(prepared.command().is_none());
    assert!(prepared.take_command().is_err());
}

#[test]
fn tcp_preparation_leaves_port_selection_to_child() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let sandbox_id = SandboxId::generate();
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

#[test]
fn publication_writes_effective_endpoint_and_complete_marker_schema() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let sandbox_id = SandboxId::generate();
    let prepared =
        prepare(request(&sandbox_id, temp.path().join("marker"), true)).expect("prepare Sidecar");
    let endpoint = SidecarEndpoint::Tcp {
        addr: "127.0.0.1:43127".parse().expect("effective endpoint"),
    };
    let pid = firma_runtime_state::UserProcessId::new(4242).expect("nonzero user PID");

    publish_metadata(&prepared, &endpoint, pid).expect("publish Sidecar metadata");

    assert_eq!(
        firma_runtime_state::pidfile::read(&prepared.pid_path).expect("read sidecar.pid"),
        Some(pid)
    );
    let text = std::fs::read_to_string(&prepared.metadata_path).expect("read metadata.toml");
    let metadata: firma_runtime_state::sidecar_markers::MetadataFile =
        toml::from_str(&text).expect("parse metadata.toml");
    assert_eq!(metadata.sandbox_id, sandbox_id);
    assert_eq!(metadata.agent_id, super::helper::agent_id().to_string());
    assert_eq!(metadata.session_id, "prepared-session");
    assert_eq!(metadata.authority_url, prepared.planned_authority_url);
    assert_eq!(metadata.policy_bundle_version, "");
    assert_eq!(metadata.pid, pid);
    assert_eq!(metadata.listen, "127.0.0.1:43127");
    chrono::DateTime::parse_from_rfc3339(&metadata.started_at).expect("RFC 3339 started_at");
}

/// The value of `key` in the Sidecar's environment.
fn env(prepared: &PreparedSidecarLaunch, key: &str) -> Option<OsString> {
    prepared
        .command()
        .expect("command is available")
        .get_envs()
        .find(|(name, _)| *name == OsStr::new(key))
        .and_then(|(_, value)| value.map(OsStr::to_owned))
}

#[test]
fn a_runtime_credential_reaches_the_sidecar_process_alone() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let sandbox_id = SandboxId::generate();
    let credentials = super::helper::runtime_credentials();
    let credential = credentials
        .runtime_credential("bearer-value")
        .expect("a bearer a header can carry");

    let prepared = prepare(PrepareRequest {
        authority_credentials: Some(credentials),
        credential: Some(&credential),
        ..request(&sandbox_id, temp.path().join("marker"), false)
    })
    .expect("prepare Sidecar");

    assert_eq!(
        env(&prepared, "FIRMA_RUNTIME_CREDENTIAL").as_deref(),
        Some(OsStr::new("bearer-value"))
    );
    assert_eq!(
        env(&prepared, "FIRMA_RUN_PID").as_deref(),
        Some(OsStr::new(&std::process::id().to_string()))
    );
    let config = std::fs::read_to_string(&prepared.config_path).expect("read config");
    assert!(
        !config.contains("bearer-value"),
        "the credential never touches the disk: {config}"
    );
}

#[test]
fn a_runtime_source_without_its_credential_is_refused() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let sandbox_id = SandboxId::generate();

    let Err(error) = prepare(PrepareRequest {
        authority_credentials: Some(super::helper::runtime_credentials()),
        credential: None,
        ..request(&sandbox_id, temp.path().join("marker"), false)
    }) else {
        panic!("a Sidecar must not start without its credential");
    };

    assert_matches!(error, firma_run::error::RunError::Internal(_));
    insta::assert_snapshot!(
        error.to_string(),
        @"internal runtime error: FIRMA_RUNTIME_CREDENTIAL is configured but no runtime credential was resolved"
    );
}
