//! Secret-service lifecycle and placement invariants.
//!
//! CLI secret mediation relies on two host-side sockets: the plaintext-holding
//! gateway (per-run control-plane directory, masked from the agent) and the
//! redaction-only broker (sandbox runtime directory, reachable from inside).
//! These tests pin the ownership contract: services stop when the owning run
//! ends, their sockets disappear, and the gateway never lives inside the
//! sandbox-visible runtime directory.

#![cfg(target_os = "linux")]

use std::path::PathBuf;

use firma_run::backend::{
    BackendKind, SandboxHandle, SecretShimSupport, SecretShimUnsupportedReason,
};
use firma_run::config::resolve_profile;
use firma_run::identity::RunIdentity;
use firma_run::runtime::RunInput;
use firma_run::runtime::secret_shims::SecretServices;
use firma_runtime_state::RuntimeLayout;

fn run_input(config: Option<PathBuf>) -> RunInput {
    RunInput {
        profile: "generic".to_string(),
        config,
        backend: Some(BackendKind::Bwrap),
        sidecar_cli: firma_run::sidecar::SidecarCli::Unset,
        capability_file: None,
        identity_mode: None,
        preserve_host_user: false,
        print_effective_config: false,
        no_autostart: false,
        sidecar_startup_timeout_secs: 10,
        command: vec!["echo".to_string(), "ok".to_string()],
        authority_cli: firma_run::authority::AuthorityCli::Unset,
        authority_profile: firma_authority::DEFAULT_PROFILE.to_string(),
        user_config_path: None,
        allow_non_structural: true,
        monitor_mode: false,
    }
}

#[expect(clippy::expect_used, reason = "this is a test")]
fn config_toml(dir: &std::path::Path, secret_providers: &str) -> PathBuf {
    let path = dir.join("firma.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[run.profiles.generic]
backend = "bwrap"

[run.profiles.generic.network]
enforce_network_namespace = false

[run.defaults]
secret_providers = [{secret_providers}]
"#
        ),
    )
    .expect("write");
    path
}

#[expect(clippy::expect_used, reason = "this is a test")]
fn sandbox_handle() -> SandboxHandle {
    let dir = tempfile::tempdir().expect("tempdir");
    let runtime_dir = dir.keep().join("firma-run").join("sandbox");
    std::fs::create_dir_all(&runtime_dir).expect("create sandbox runtime dir");
    SandboxHandle {
        backend: BackendKind::Bwrap,
        runtime_dir,
        identity: RunIdentity::new(
            "agt_01j0000000e008000000000001"
                .parse()
                .expect("valid agent id"),
            "generic",
        ),
        mounts: Vec::new(),
        network_policy: firma_run::config::NetworkPolicy {
            enforce_network_namespace: false,
            fail_closed: true,
        },
    }
}

#[test]
fn secret_services_stop_and_remove_sockets_when_dropped() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let layout = RuntimeLayout::from_root(state_dir.path().to_path_buf());
    let handle = sandbox_handle();
    let identity = handle.identity.clone();
    let providers_config = config_toml(state_dir.path(), "\"bws\"");
    let profile = resolve_profile(&run_input(Some(providers_config))).expect("resolve profile");

    let support = SecretShimSupport::Unsupported {
        reason: SecretShimUnsupportedReason::HostCallable,
    };
    let services = SecretServices::start(&layout, &handle, &identity, &profile, &support)
        .expect("start secret services");
    let gateway_path = layout
        .run_entry_layout(&identity.sandbox_id)
        .into_root()
        .join("gateway.sock");
    let broker_path = handle.runtime_dir.join("secret-shims").join("broker.sock");
    #[cfg(unix)]
    {
        assert!(gateway_path.exists(), "gateway socket must be bound");
        assert!(broker_path.exists(), "broker socket must be bound");
    }

    drop(services);

    #[cfg(unix)]
    {
        assert!(
            !gateway_path.exists(),
            "gateway socket must be removed after the run"
        );
        assert!(
            !broker_path.exists(),
            "broker socket must be removed after the run"
        );
    }
}

#[test]
fn gateway_socket_lives_outside_the_sandbox_runtime_dir() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let layout = RuntimeLayout::from_root(state_dir.path().to_path_buf());
    let handle = sandbox_handle();
    let identity = handle.identity.clone();
    let providers_config = config_toml(state_dir.path(), "\"bws\"");
    let profile = resolve_profile(&run_input(Some(providers_config))).expect("resolve profile");

    let support = SecretShimSupport::Unsupported {
        reason: SecretShimUnsupportedReason::HostCallable,
    };
    let services = SecretServices::start(&layout, &handle, &identity, &profile, &support)
        .expect("start secret services");

    // The plaintext gateway must never live inside the sandbox runtime dir the
    // agent can reach; the broker, which only returns redacted output, does.
    let gateway_root = layout.run_entry_layout(&identity.sandbox_id).into_root();
    assert!(
        !gateway_root.starts_with(&handle.runtime_dir),
        "gateway dir {} must be outside sandbox runtime {}",
        gateway_root.display(),
        handle.runtime_dir.display()
    );
    assert!(services.gateway_addr.starts_with("unix://"));
    assert!(services.broker_addr().starts_with("unix://"));

    drop(services);
}
