//! Production-path coverage for local Authority preparation and publication.

#![cfg(unix)]
#![allow(clippy::expect_used, reason = "test code")]

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::Duration;

use firma_run::backend::{BackendKind, EnforcementProof, NetworkConfinement, SandboxHandle};
use firma_run::config::{CapabilityLeaseConfig, CapabilitySource, NetworkPolicy, SidecarEndpoint};
use firma_run::error::RunError;
use firma_run::routing::{
    AutostartFlags, NetworkRuntime, OwnedAuthorityPlan, ResolvedAuthority, prepare_network_runtime,
};

#[derive(serde::Deserialize)]
struct AuthorityMetadata {
    sandbox_id: firma_run::identity::SandboxId,
    agent_id: firma_identifiers::AgentId,
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
fn confirmed_runtime_assembly_rollback_cleans_run_markers() {
    let (result, marker) = prepare_failing_runtime(true, true, false);
    let Err(error) = result else {
        panic!("missing adapter parent must fail runtime assembly");
    };
    let RunError::RunStackPostReadyRollback {
        operation: _,
        rollback,
    } = error
    else {
        panic!("unexpected error: {error}");
    };

    assert!(matches!(
        rollback,
        firma_process_orchestrator::ShutdownError::StateCleanup(_)
    ));
    assert!(
        !marker.exists(),
        "confirmed rollback must remove the enclosing run marker"
    );
}

#[test]
fn confirmed_publication_rollback_preserves_marker_cleanup_failure() {
    let (result, marker) = prepare_failing_runtime(false, false, true);
    let Err(error) = result else {
        panic!("unreachable external Sidecar must fail publication");
    };
    let RunError::RunMarkerCleanup { operation, cleanup } = &error else {
        panic!("unexpected error: {error}");
    };
    let RunError::RunStackPostReadyRollback {
        operation: original,
        rollback,
    } = operation.as_ref()
    else {
        panic!("cleanup must wrap the rollback failure: {operation}");
    };

    assert!(matches!(
        original.as_ref(),
        RunError::SidecarUnreachable { .. }
    ));
    assert!(matches!(
        rollback,
        firma_process_orchestrator::ShutdownError::StateCleanup(_)
    ));
    assert!(matches!(cleanup.as_ref(), RunError::Internal(_)));
    assert!(
        marker.exists(),
        "failed marker cleanup must preserve evidence"
    );
    let rendered = error.to_string();
    assert!(
        rendered.find("sidecar endpoint").is_some_and(|original| {
            rendered
                .find("run component stack rollback failed")
                .is_some_and(|rollback| {
                    rendered
                        .find("run marker cleanup failed")
                        .is_some_and(|cleanup| original < rollback && rollback < cleanup)
                })
        }),
        "error chain is incomplete or out of order: {rendered}"
    );

    let mut permissions = std::fs::metadata(&marker)
        .expect("retained marker metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&marker, permissions).expect("restore marker permissions");
    std::fs::remove_dir_all(marker).expect("remove retained marker");
}

fn prepare_failing_runtime(
    structural: bool,
    sidecar_available: bool,
    block_marker_cleanup: bool,
) -> (Result<NetworkRuntime, RunError>, PathBuf) {
    let temp = tempfile::tempdir().expect("temporary directory");
    let fixture = temp.path().join("authority-fixture");
    std::os::unix::fs::symlink(std::env::current_exe().expect("test executable"), &fixture)
        .expect("link fixture executable");
    let launcher = temp.path().join("fake-firma.sh");
    std::fs::write(
        &launcher,
        format!(
            concat!(
                "#!/bin/sh\n",
                "export FIRMA_TEST_STARTUP_REPORT=\"$5\"\n",
                "export FIRMA_TEST_BLOCK_STATE_CLEANUP=1\n",
                "export FIRMA_TEST_BLOCK_MARKER_CLEANUP={}\n",
                "exec '{}' --exact authority_autostart_marker::authority_fixture --ignored --nocapture\n",
            ),
            u8::from(block_marker_cleanup),
            fixture.display(),
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
    if !sidecar_available {
        drop(external_sidecar);
    }
    let runtime_dir = temp.path().join("sandbox-runtime");
    if structural {
        std::fs::write(&runtime_dir, "block adapter directory\n")
            .expect("block adapter directory creation");
    }
    let handle = SandboxHandle {
        backend: BackendKind::Vz,
        runtime_dir,
        identity: identity.clone(),
        mounts: Vec::new(),
        network_policy: NetworkPolicy {
            enforce_network_namespace: structural,
            fail_closed: true,
        },
    };
    let proof = EnforcementProof {
        backend: BackendKind::Vz,
        structural,
        fail_closed: true,
        detail: "Authority rollback test".into(),
        network_confinement: if structural {
            NetworkConfinement::LinuxNetworkNamespace
        } else {
            NetworkConfinement::ProxyOnly
        },
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
    let marker = firma_runtime_state::runtime_paths::run_entry_from(
        &firma_runtime_state::runtime_paths::default_runtime_dir(),
        &identity.sandbox_id,
    );
    let result = prepare_network_runtime(
        &handle,
        &proof,
        &sidecar_endpoint,
        &identity,
        &flags,
        authority,
        &capability,
    );
    (result, marker)
}

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn authority_fixture() {
    let report = std::env::var_os("FIRMA_TEST_STARTUP_REPORT")
        .map(std::path::PathBuf::from)
        .expect("startup report path");
    let listener = TcpListener::bind("[::1]:0").expect("bind dynamic Authority endpoint");
    let endpoint = listener.local_addr().expect("effective Authority endpoint");
    if std::env::var_os("FIRMA_TEST_BLOCK_STATE_CLEANUP").is_some() {
        let orchestrator_dir = report
            .parent()
            .and_then(std::path::Path::parent)
            .expect("orchestrator state directory");
        let pidfile = orchestrator_dir.join("authority.pid");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !pidfile.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::remove_file(&pidfile).expect("remove Authority pidfile");
        std::fs::create_dir(&pidfile).expect("block Authority pidfile cleanup");
        if std::env::var_os("FIRMA_TEST_BLOCK_MARKER_CLEANUP").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            let marker = orchestrator_dir.parent().expect("run marker directory");
            let mut permissions = std::fs::metadata(marker)
                .expect("run marker metadata")
                .permissions();
            permissions.set_mode(0o500);
            std::fs::set_permissions(marker, permissions).expect("block marker cleanup");
        }
    }
    firma_process_orchestrator::publish_startup_report(
        &report,
        &firma_process_orchestrator::ComponentEndpoint::Tcp(endpoint),
    )
    .expect("publish startup report");
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}
