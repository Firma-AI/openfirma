//! Production-path coverage for local Authority preparation and publication.

#![cfg(unix)]
#![allow(clippy::expect_used, reason = "test code")]

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use firma_run::backend::{BackendKind, EnforcementProof, NetworkConfinement, SandboxHandle};
use firma_run::config::{CapabilityLeaseConfig, CapabilitySource, NetworkPolicy, SidecarEndpoint};
use firma_run::routing::{
    AutostartFlags, OwnedAuthorityPlan, ResolvedAuthority, prepare_network_runtime,
};

#[derive(serde::Deserialize)]
struct AuthorityMetadata {
    sandbox_id: firma_run::identity::SandboxId,
    agent_id: firma_core::AgentId,
    session_id: String,
    profile: String,
    listen_addr: String,
    pid: firma_runtime_state::UserProcessId,
    started_at: String,
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one production-path scenario keeps launch, publication, and marker assertions together"
)]
fn local_authority_publishes_effective_component_handle_and_metadata() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let fixture = temp.path().join("authority-fixture");
    std::os::unix::fs::symlink(std::env::current_exe().expect("test executable"), &fixture)
        .expect("link fixture executable");
    let launcher = temp.path().join("fake-firma.sh");
    std::fs::write(
        &launcher,
        format!(
            "#!/bin/sh\nexport FIRMA_TEST_STARTUP_REPORT=\"$5\"\nexec '{}' --exact authority_autostart_marker::authority_fixture --ignored --nocapture\n",
            fixture.display()
        ),
    )
    .expect("write fixture launcher");
    let mut permissions = std::fs::metadata(&launcher)
        .expect("launcher metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&launcher, permissions).expect("make launcher executable");

    let identity = firma_run::identity::RunIdentity::new(*super::helper::agent_id(), "generic");
    let external_sidecar = TcpListener::bind("127.0.0.1:0").expect("external Sidecar listener");
    let sidecar_endpoint = SidecarEndpoint::Tcp {
        addr: external_sidecar.local_addr().expect("Sidecar endpoint"),
    };
    let handle = SandboxHandle {
        backend: BackendKind::Vz,
        runtime_dir: temp.path().join("sandbox-runtime"),
        identity: identity.clone(),
        mounts: Vec::new(),
        network_policy: NetworkPolicy {
            enforce_network_namespace: false,
            fail_closed: true,
        },
    };
    let proof = EnforcementProof {
        backend: BackendKind::Vz,
        structural: false,
        fail_closed: true,
        detail: "Authority publication test".into(),
        network_confinement: NetworkConfinement::ProxyOnly,
    };
    let authority = ResolvedAuthority {
        url: "http://[::1]:0".into(),
        ca_cert_path: None,
        pub_key_path: None,
        credentials: None,
        credentials_config: None,
        owned: Some(OwnedAuthorityPlan {
            profile_name: "developer".into(),
            firma_exe: launcher,
            user_config_path: None,
        }),
    };
    let flags = AutostartFlags {
        startup_timeout: Duration::from_secs(5),
        ..AutostartFlags::default()
    };
    let capability = CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        public_key_path: None,
        refresh_ratio: 0.6,
        grace_seconds: 30,
        requested_actions: CapabilityLeaseConfig::default_requested_actions(),
    };

    let runtime = prepare_network_runtime(
        &handle,
        &proof,
        &sidecar_endpoint,
        &identity,
        &flags,
        authority,
        &capability,
    )
    .expect("prepare run with owned Authority");

    let marker = firma_runtime_state::runtime_paths::run_entry_from(
        &firma_runtime_state::runtime_paths::default_runtime_dir(),
        &identity.sandbox_id,
    );
    let authority_marker = marker.join("authority");
    let config =
        std::fs::read_to_string(authority_marker.join("authority.toml")).expect("Authority config");
    assert!(config.contains("listen_addr = \"[::1]:0\""), "{config}");
    assert!(authority_marker.join("keys/authority.key").is_file());
    assert!(authority_marker.join("keys/authority.pub").is_file());
    let cedar = std::fs::read_to_string(authority_marker.join("policy_dir/developer.cedar"))
        .expect("developer policy");
    assert!(cedar.contains("permit(principal, action, resource)"));

    let pid = firma_runtime_state::pidfile::read(&authority_marker.join("authority.pid"))
        .expect("read authority.pid")
        .expect("published Authority PID");
    let metadata: AuthorityMetadata = toml::from_str(
        &std::fs::read_to_string(authority_marker.join("metadata.toml"))
            .expect("Authority metadata"),
    )
    .expect("parse Authority metadata");
    let identity_env = identity.env_pairs();
    assert_eq!(metadata.sandbox_id, identity.sandbox_id);
    assert_eq!(metadata.agent_id, *super::helper::agent_id());
    assert_eq!(
        metadata.session_id,
        identity_env
            .get("FIRMA_RUN_SESSION_ID")
            .expect("session identity")
            .as_str()
    );
    assert_eq!(metadata.profile, "developer");
    assert_eq!(metadata.pid, pid);
    let effective: std::net::SocketAddr = metadata
        .listen_addr
        .parse()
        .expect("effective Authority endpoint");
    assert_ne!(effective.port(), 0);
    chrono::DateTime::parse_from_rfc3339(&metadata.started_at).expect("RFC 3339 started_at");

    drop(runtime);
    let _ = std::fs::remove_dir_all(marker);
}

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn authority_fixture() {
    let report = std::env::var_os("FIRMA_TEST_STARTUP_REPORT")
        .map(std::path::PathBuf::from)
        .expect("startup report path");
    let listener = TcpListener::bind("[::1]:0").expect("bind dynamic Authority endpoint");
    let endpoint = listener.local_addr().expect("effective Authority endpoint");
    firma_process_orchestrator::publish_startup_report(
        &report,
        &firma_process_orchestrator::ComponentEndpoint::Tcp(endpoint),
    )
    .expect("publish startup report");
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}
