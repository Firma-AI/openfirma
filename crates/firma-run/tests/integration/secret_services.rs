//! Secret-service lifecycle and placement invariants.
//!
//! CLI secret mediation relies on two host-side sockets: the plaintext-holding
//! gateway (per-run control-plane directory, masked from the agent) and the
//! redaction-only broker (sandbox runtime directory, reachable from inside).
//! These tests pin the ownership contract: services stop when the owning run
//! ends, their sockets disappear, and the gateway never lives inside the
//! sandbox-visible runtime directory.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use firma_run::backend::{BackendKind, ResolvedSecretShimSupport, SandboxHandle};
use firma_run::config::resolve_profile;
use firma_run::identity::RunIdentity;
use firma_run::runtime::RunInput;
use firma_run::runtime::secret_shims::{SecretServices, testing};
use firma_runtime_state::RuntimeLayout;

struct SandboxFixture {
    handle: SandboxHandle,
    _dir: tempfile::TempDir,
}

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
fn sandbox_fixture() -> SandboxFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let runtime_dir = dir.path().join("firma-run").join("sandbox");
    std::fs::create_dir_all(&runtime_dir).expect("create sandbox runtime dir");
    SandboxFixture {
        handle: SandboxHandle {
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
        },
        _dir: dir,
    }
}

#[expect(clippy::expect_used, reason = "this is a test")]
fn write_file_with_mode(path: &std::path::Path, mode: u32) {
    std::fs::write(path, "#!/bin/sh\n").expect("write executable fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set executable fixture mode");
}

#[expect(clippy::expect_used, reason = "this is a test")]
fn shimmed_firma(dir: &std::path::Path) -> PathBuf {
    let firma = dir.join(format!("firma{}", std::env::consts::EXE_SUFFIX));
    let shim = dir.join(format!("firma-secret-shim{}", std::env::consts::EXE_SUFFIX));
    write_file_with_mode(&firma, 0o700);
    let mut elf = vec![0_u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&3_u16.to_le_bytes());
    #[cfg(target_arch = "x86_64")]
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    #[cfg(target_arch = "aarch64")]
    elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    std::fs::write(&shim, elf).expect("write shim ELF fixture");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700))
        .expect("set shim fixture mode");
    firma
}

fn host_callable_support() -> ResolvedSecretShimSupport {
    ResolvedSecretShimSupport::NotRequired
}

#[test]
fn secret_services_stop_and_remove_sockets_when_dropped() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let layout = RuntimeLayout::from_root(state_dir.path().to_path_buf());
    let sandbox = sandbox_fixture();
    let handle = &sandbox.handle;
    let identity = handle.identity.clone();
    let providers_config = config_toml(state_dir.path(), "\"bws\"");
    let profile = resolve_profile(&run_input(Some(providers_config))).expect("resolve profile");

    let support = host_callable_support();
    let services = SecretServices::start(&layout, handle, &identity, &profile, &support)
        .expect("start secret services");
    let gateway_path = layout
        .run_entry_layout(&identity.sandbox_id)
        .into_root()
        .join("gateway.sock");
    let broker_path = handle.runtime_dir.join("secret-shims").join("broker.sock");
    assert!(gateway_path.exists(), "gateway socket must be bound");
    assert!(broker_path.exists(), "broker socket must be bound");

    drop(services);

    assert!(
        !gateway_path.exists(),
        "gateway socket must be removed after the run"
    );
    assert!(
        !broker_path.exists(),
        "broker socket must be removed after the run"
    );
}

#[test]
fn gateway_socket_lives_outside_the_sandbox_runtime_dir() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let layout = RuntimeLayout::from_root(state_dir.path().to_path_buf());
    let sandbox = sandbox_fixture();
    let handle = &sandbox.handle;
    let identity = handle.identity.clone();
    let providers_config = config_toml(state_dir.path(), "\"bws\"");
    let profile = resolve_profile(&run_input(Some(providers_config))).expect("resolve profile");

    let support = host_callable_support();
    let services = SecretServices::start(&layout, handle, &identity, &profile, &support)
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
    assert!(services.gateway_addr().starts_with("unix://"));
    assert!(services.broker_addr().starts_with("unix://"));

    drop(services);
}

#[test]
fn prepare_overlays_every_executable_match_and_deduplicates_path_entries() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let layout = RuntimeLayout::from_root(state_dir.path().to_path_buf());
    let sandbox = sandbox_fixture();
    let identity = sandbox.handle.identity.clone();
    let providers_config = config_toml(state_dir.path(), "\"bws\"");
    let profile = resolve_profile(&run_input(Some(providers_config))).expect("resolve profile");
    let support = host_callable_support();
    let services = SecretServices::start(&layout, &sandbox.handle, &identity, &profile, &support)
        .expect("start secret services");
    let first_bin = state_dir.path().join("first-bin");
    let second_bin = state_dir.path().join("second-bin");
    let second_bin_alias = state_dir.path().join("second-bin-alias");
    std::fs::create_dir_all(&first_bin).expect("create first bin");
    std::fs::create_dir_all(&second_bin).expect("create second bin");
    std::os::unix::fs::symlink(&second_bin, &second_bin_alias).expect("create PATH alias");
    let first_bws = first_bin.join("bws");
    let second_bws = second_bin.join("bws");
    write_file_with_mode(&first_bws, 0o700);
    write_file_with_mode(&second_bws, 0o700);
    let effective_path =
        std::env::join_paths([&first_bin, &second_bin, &first_bin, &second_bin_alias])
            .expect("join effective PATH")
            .to_string_lossy()
            .into_owned();
    let mut env =
        firma_run::env::ExecutionEnv::from(BTreeMap::from([("PATH".to_string(), effective_path)]));
    let firma = shimmed_firma(state_dir.path());
    let mut handle = Some(sandbox.handle);

    let targets = testing::prepare_mount_targets(
        &mut handle,
        &profile,
        &mut env,
        &firma,
        Some(std::path::Path::new("/unused-host-path")),
        &services,
    )
    .expect("prepare shims");

    assert_eq!(
        targets,
        vec![first_bws, second_bws, second_bin_alias.join("bws")]
    );
}

#[test]
fn prepare_skips_a_non_executable_match_before_an_executable() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let layout = RuntimeLayout::from_root(state_dir.path().to_path_buf());
    let sandbox = sandbox_fixture();
    let identity = sandbox.handle.identity.clone();
    let providers_config = config_toml(state_dir.path(), "\"bws\"");
    let profile = resolve_profile(&run_input(Some(providers_config))).expect("resolve profile");
    let support = host_callable_support();
    let services = SecretServices::start(&layout, &sandbox.handle, &identity, &profile, &support)
        .expect("start secret services");
    let first_bin = state_dir.path().join("non-executable-bin");
    let second_bin = state_dir.path().join("executable-bin");
    std::fs::create_dir_all(&first_bin).expect("create first bin");
    std::fs::create_dir_all(&second_bin).expect("create second bin");
    write_file_with_mode(&first_bin.join("bws"), 0o600);
    let executable_bws = second_bin.join("bws");
    write_file_with_mode(&executable_bws, 0o700);
    let effective_path = std::env::join_paths([first_bin, second_bin])
        .expect("join effective PATH")
        .to_string_lossy()
        .into_owned();
    let mut env =
        firma_run::env::ExecutionEnv::from(BTreeMap::from([("PATH".to_string(), effective_path)]));
    let firma = shimmed_firma(state_dir.path());
    let mut handle = Some(sandbox.handle);

    let targets =
        testing::prepare_mount_targets(&mut handle, &profile, &mut env, &firma, None, &services)
            .expect("prepare shims");

    assert_eq!(targets, vec![executable_bws]);
}
