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
use firma_test_helpers::{process_fixture, unix_fixture_script};

/// Translate the real `firma authority` argument contract into the environment
/// the fixture consumes, by flag rather than by position.
///
/// Also asserts the contract itself: the autostarted Authority is reached over
/// loopback `http://`, so it must be launched with `--no-tls`. Without it the
/// child re-adopts TLS material from the state directory — which a host that
/// ran `firma config` has — and every run fails to connect.
const AUTHORITY_ARG_SETUP: &str = r#"
saw_no_tls=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-tls) saw_no_tls=1 ;;
    --startup-report) shift; export FIRMA_TEST_STARTUP_REPORT="$1" ;;
  esac
  shift
done
if [ "$saw_no_tls" -ne 1 ]; then
  echo "autostarted Authority must be launched with --no-tls" >&2
  exit 64
fi
"#;

#[derive(serde::Deserialize, serde::Serialize)]
struct AuthorityFixtureConfig {
    block_state_cleanup: bool,
    block_marker_cleanup: bool,
}

#[derive(serde::Deserialize)]
struct AuthorityMetadata {
    sandbox_id: firma_identifiers::SandboxId,
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
    let launcher = fixture_launcher(
        temp.path(),
        AuthorityFixtureConfig {
            block_state_cleanup: false,
            block_marker_cleanup: false,
        },
    );

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
        trust: firma_sidecar::config::AuthorityTrust::PlatformStore,
        connect_addr: None,
        pub_key_path: None,
        credentials: None,
        credentials_config: None,
        owned: Some(OwnedAuthorityPlan {
            profile_name: "developer".into(),
            firma_exe: launcher,
            user_config_path: None,
        }),
        capability_public_key: None,
    };
    let flags = AutostartFlags {
        startup_timeout: Duration::from_secs(5),
        ..AutostartFlags::default()
    };
    let capability = CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        public_key_path: None,
        refresh_ratio: 0.6,
        grace: Duration::from_secs(30),
    };

    let runtime_layout =
        firma_runtime_state::RuntimeLayout::resolve(None).expect("resolve runtime layout");
    let runtime = prepare_network_runtime(
        &runtime_layout,
        &handle,
        &proof,
        &sidecar_endpoint,
        &identity,
        &flags,
        authority,
        &capability,
    )
    .expect("prepare run with owned Authority");

    let marker = runtime_layout
        .run_entry_layout(&identity.sandbox_id)
        .into_root();
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

/// The persisted-config branch of autostart, which an operator reaches by
/// pointing `firma run` at a `firma.toml` that configures the Authority.
///
/// Two things have to hold there and nowhere else: the operator's own TLS paths
/// are dropped, because autostart dials loopback `http://` no matter what the
/// persisted section asked for, and every artifact path the section leaves
/// unset resolves under the state root this run was handed rather than the
/// ambient one. The state directory below holds a complete TLS pair, which is
/// what a host that ran `firma config` looks like.
#[test]
fn persisted_authority_config_drops_tls_and_resolves_artifacts_under_the_run_state_root() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state_root = temp.path().join("state");
    let tls_dir = state_root.join("tls");
    std::fs::create_dir_all(&tls_dir).expect("state TLS directory");
    std::fs::write(tls_dir.join("authority.crt"), "cert").expect("state TLS certificate");
    std::fs::write(tls_dir.join("authority.key"), "key").expect("state TLS private key");

    let user_config = temp.path().join("firma.toml");
    std::fs::write(
        &user_config,
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\ntls_cert_path = \"operator.crt\"\ntls_key_path = \"operator.key\"\n",
    )
    .expect("write persisted Authority config");
    std::fs::write(temp.path().join("mapping-rules.toml"), "rules = []\n")
        .expect("write selected mappings");

    let runtime_layout = firma_runtime_state::RuntimeLayout::from_root(&state_root);
    let (runtime, marker) =
        prepare_with_persisted_config(temp.path(), &runtime_layout, user_config)
            .expect("prepare run with a persisted Authority config");

    let config = std::fs::read_to_string(marker.join("authority/authority.toml"))
        .expect("synthesized Authority config");
    assert!(
        !config.contains("tls_"),
        "the child must be handed a plaintext config: {config}"
    );
    let key_file = state_root.join("authority.key");
    assert!(
        config.contains(&format!("key_file = \"{}\"", key_file.display())),
        "unset key_file must resolve under the run's state root: {config}"
    );
    assert!(
        key_file.is_file(),
        "the signing key must be generated there"
    );

    drop(runtime);
}

/// A missing authored mapping file is an operator configuration error: it must
/// be reported as such and name the configured file, not surface as an
/// internal runtime failure.
#[test]
fn missing_persisted_mapping_input_is_a_configuration_error() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let user_config = temp.path().join("firma.toml");
    std::fs::write(
        &user_config,
        "[authority]\nmapping_rules_paths = ['missing-rules.toml']\n",
    )
    .expect("write persisted Authority config");

    let runtime_layout = firma_runtime_state::RuntimeLayout::from_root(temp.path().join("state"));
    let Err(error) = prepare_with_persisted_config(temp.path(), &runtime_layout, user_config)
    else {
        panic!("a missing mapping input must fail preparation");
    };

    // Preparation may run inside the stack lock, which wraps planning failures.
    let cause = match &error {
        RunError::RunComponentOrchestration(start) => match start.as_ref() {
            firma_process_orchestrator::StartError::Plan(cause) => cause,
            _ => &error,
        },
        _ => &error,
    };
    assert!(
        matches!(
            cause,
            RunError::ConfigValidation(_) | RunError::ConfigParse { .. }
        ),
        "unexpected error class: {error:?}"
    );
    assert!(error.to_string().contains("missing-rules.toml"), "{error}");
}

/// Prepare a run whose owned Authority is configured by `user_config`,
/// returning the runtime with its run marker directory.
fn prepare_with_persisted_config(
    dir: &std::path::Path,
    runtime_layout: &firma_runtime_state::RuntimeLayout,
    user_config: PathBuf,
) -> Result<(NetworkRuntime, PathBuf), RunError> {
    let launcher = fixture_launcher(
        dir,
        AuthorityFixtureConfig {
            block_state_cleanup: false,
            block_marker_cleanup: false,
        },
    );
    let identity = firma_run::identity::RunIdentity::new(*super::helper::agent_id(), "generic");
    let external_sidecar = TcpListener::bind("127.0.0.1:0").expect("external Sidecar listener");
    let sidecar_endpoint = SidecarEndpoint::Tcp {
        addr: external_sidecar.local_addr().expect("Sidecar endpoint"),
    };
    let handle = SandboxHandle {
        backend: BackendKind::Vz,
        runtime_dir: dir.join("sandbox-runtime"),
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
        detail: "persisted Authority config test".into(),
        network_confinement: NetworkConfinement::ProxyOnly,
    };
    let authority = ResolvedAuthority {
        url: "http://[::1]:0".into(),
        ca_cert_path: None,
        trust: firma_sidecar::config::AuthorityTrust::PlatformStore,
        connect_addr: None,
        pub_key_path: None,
        credentials: None,
        credentials_config: None,
        owned: Some(OwnedAuthorityPlan {
            profile_name: "developer".into(),
            firma_exe: launcher,
            user_config_path: Some(user_config),
        }),
        capability_public_key: None,
    };
    let flags = AutostartFlags {
        startup_timeout: Duration::from_secs(5),
        ..AutostartFlags::default()
    };
    let capability = CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        public_key_path: None,
        refresh_ratio: 0.6,
        grace: Duration::from_secs(30),
    };

    let runtime = prepare_network_runtime(
        runtime_layout,
        &handle,
        &proof,
        &sidecar_endpoint,
        &identity,
        &flags,
        authority,
        &capability,
    )?;
    let marker = runtime_layout
        .run_entry_layout(&identity.sandbox_id)
        .into_root();
    Ok((runtime, marker))
}

#[test]
fn confirmed_runtime_assembly_rollback_cleans_run_markers() {
    let (result, marker) = prepare_failing_runtime(&FailingRuntime {
        structural: true,
        sidecar_available: true,
        block_marker_cleanup: false,
    });
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
    let (result, marker) = prepare_failing_runtime(&FailingRuntime {
        structural: false,
        sidecar_available: false,
        block_marker_cleanup: true,
    });
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

/// Write an executable `firma` stand-in into `dir` and return its path.
///
/// The fixture stands in for the autostarted Authority child, so it also
/// enforces the launch contract in [`AUTHORITY_ARG_SETUP`].
fn fixture_launcher(dir: &std::path::Path, config: AuthorityFixtureConfig) -> PathBuf {
    let launcher = dir.join("fake-firma.sh");
    let fixture = authority_fixture(config);
    std::fs::write(
        &launcher,
        unix_fixture_script(&fixture, AUTHORITY_ARG_SETUP),
    )
    .expect("write fixture launcher");
    let mut permissions = std::fs::metadata(&launcher)
        .expect("launcher metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&launcher, permissions).expect("make launcher executable");
    launcher
}

/// Which failure a [`prepare_failing_runtime`] call is staging.
///
/// A struct rather than positional flags: `prepare_failing_runtime(true, true,
/// false)` named none of the three conditions it was setting up, and the two
/// call sites differ in all three.
struct FailingRuntime {
    /// Claim structural enforcement, and block the sandbox adapter directory
    /// so structural assembly is what fails.
    structural: bool,
    /// Keep the external Sidecar listener bound, so the endpoint is reachable.
    sidecar_available: bool,
    /// Make marker-directory cleanup fail during rollback.
    block_marker_cleanup: bool,
}

fn prepare_failing_runtime(config: &FailingRuntime) -> (Result<NetworkRuntime, RunError>, PathBuf) {
    let FailingRuntime {
        structural,
        sidecar_available,
        block_marker_cleanup,
    } = *config;
    let temp = tempfile::tempdir().expect("temporary directory");
    let launcher = fixture_launcher(
        temp.path(),
        AuthorityFixtureConfig {
            block_state_cleanup: true,
            block_marker_cleanup,
        },
    );

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
        trust: firma_sidecar::config::AuthorityTrust::PlatformStore,
        connect_addr: None,
        pub_key_path: None,
        credentials: None,
        credentials_config: None,
        owned: Some(OwnedAuthorityPlan {
            profile_name: "developer".into(),
            firma_exe: launcher,
            user_config_path: None,
        }),
        capability_public_key: None,
    };
    let flags = AutostartFlags {
        startup_timeout: Duration::from_secs(5),
        ..AutostartFlags::default()
    };
    let capability = CapabilityLeaseConfig {
        source: CapabilitySource::Disabled,
        public_key_path: None,
        refresh_ratio: 0.6,
        grace: Duration::from_secs(30),
    };
    let runtime_layout =
        firma_runtime_state::RuntimeLayout::resolve(None).expect("resolve runtime layout");
    let marker = runtime_layout
        .run_entry_layout(&identity.sandbox_id)
        .into_root();
    let result = prepare_network_runtime(
        &runtime_layout,
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

process_fixture! {
    fn authority_fixture(config: AuthorityFixtureConfig) {
        let report = std::env::var_os("FIRMA_TEST_STARTUP_REPORT")
            .map(std::path::PathBuf::from)
            .expect("startup report path");
        let listener = TcpListener::bind("[::1]:0").expect("bind dynamic Authority endpoint");
        let endpoint = listener.local_addr().expect("effective Authority endpoint");
        if config.block_state_cleanup {
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
            if config.block_marker_cleanup {
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
}
