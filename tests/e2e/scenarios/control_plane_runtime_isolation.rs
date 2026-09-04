use std::fmt::Write as _;
use std::net::TcpListener;
use std::path::Path;

use crate::harness::{TestWorld, run_bounded};

const PROBE_ATTEMPTED: &str = "CONTROL-PLANE PROBE ATTEMPTED";
const ASSET_EXPOSED: &str = "CONTROL-PLANE ASSET EXPOSED";
const CA_TRUST_READABLE: &str = "CA TRUST READABLE";
const CA_KEY_EXPOSED: &str = "CA KEY EXPOSED";

#[test]
fn root_process_cannot_reach_run_control_plane_assets() {
    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let state = tempfile::tempdir_in(std::env::current_dir().expect("resolve repository cwd"))
        .expect("create control-plane state outside sandbox tmpfs paths");
    let state_dir = state.path().to_path_buf();
    let workspace = world.workspace_path();

    let probe_tool = workspace.join("control-plane-probe");
    write_control_plane_probe(&probe_tool);
    assert_probe_positive_control(&world, &workspace, &probe_tool);

    world.scaffold_config(
        "generic",
        &cfg_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );

    let evidence = workspace.join("control-plane-probe-ran");
    let output = world.run_firma_with_state_dir(
        &cfg_dir.join("firma.toml"),
        &state_dir,
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &probe_tool,
        [&state_dir, &evidence],
    );

    assert!(output.success(), "root process probe failed:\n{output}");
    assert!(
        output.stdout.contains(PROBE_ATTEMPTED) && evidence.is_file(),
        "the root process did not execute the isolation probe:\n{output}"
    );
    assert!(
        !output.stdout.contains(ASSET_EXPOSED) && !output.stderr.contains(ASSET_EXPOSED),
        "the root process reached host-side control-plane material:\n{output}"
    );
    assert!(
        !state_dir.join("run/forged-sidecar.sock").exists(),
        "the root process forged a host-side control-plane path"
    );
}

#[test]
fn profile_mount_cannot_source_control_plane_runtime() {
    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let state = tempfile::tempdir_in(std::env::current_dir().expect("resolve repository cwd"))
        .expect("create control-plane state outside sandbox tmpfs paths");
    let state_dir = state.path().to_path_buf();
    let workspace = world.workspace_path();
    world.scaffold_config(
        "generic",
        &cfg_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );

    let protected_source = state_dir.join("authority.key");
    assert!(
        protected_source.is_file(),
        "config scaffold did not create the expected authority key"
    );
    let alias = workspace.join("exposed-authority.key");
    append_profile_mount(&cfg_dir.join("firma.toml"), &protected_source, &alias);

    let output = world.run_firma_with_state_dir(
        &cfg_dir.join("firma.toml"),
        &state_dir,
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        "/bin/true",
        std::iter::empty::<&str>(),
    );

    assert!(
        !output.success(),
        "firma run accepted a profile mount sourced from FIRMA_STATE_DIR:\n{output}"
    );
    assert!(
        output.stderr.contains("refusing mount source")
            && output.stderr.contains("inside the control-plane runtime"),
        "firma run did not explain the protected-runtime mount rejection:\n{output}"
    );
    assert!(
        !alias.exists(),
        "rejected mount unexpectedly created its alias"
    );
}

#[test]
fn absent_control_plane_runtime_cannot_be_forged() {
    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let workspace = world.workspace_path();
    world.scaffold_config(
        "generic",
        &cfg_dir,
        &world.state_path(),
        Some(&workspace),
        &workspace,
    );

    let state_dir = workspace.join("future-control-plane-state");
    assert!(!state_dir.exists(), "state path must begin absent");
    let forge_tool = workspace.join("forge-control-plane-state");
    write_forge_tool(&forge_tool);
    let evidence = workspace.join("control-plane-forge-ran");

    let authority = tcp_probe_endpoint("http");
    let sidecar = tcp_probe_endpoint("tcp");
    let output = world.run_firma_with_state_dir(
        &cfg_dir.join("firma.toml"),
        &state_dir,
        &workspace,
        &[
            "--no-autostart",
            "--authority",
            &authority,
            "--sidecar",
            &sidecar,
        ],
        &forge_tool,
        [&state_dir, &evidence],
    );

    assert!(
        output.success(),
        "root process forge probe failed:\n{output}"
    );
    assert!(evidence.is_file(), "root process forge probe did not run");
    assert!(
        !state_dir.join("forged-control-plane-file").exists(),
        "root process forged the previously absent control-plane runtime"
    );
}

/// The control-plane mask hides `FIRMA_STATE_DIR`, but the trust environment
/// (`SSL_CERT_FILE` and friends) points at CA files inside it. The mask must
/// therefore expose the public CA while still hiding its private key: an
/// unreadable trust store makes OpenSSL and Go fall back to the system roots,
/// which breaks every MITM-intercepted handshake.
#[test]
fn sandbox_reads_sidecar_ca_without_reaching_its_private_key() {
    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let state = tempfile::tempdir_in(std::env::current_dir().expect("resolve repository cwd"))
        .expect("create control-plane state outside sandbox tmpfs paths");
    let state_dir = state.path().to_path_buf();
    let workspace = world.workspace_path();

    world.scaffold_config(
        "generic",
        &cfg_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );
    let config_file = cfg_dir.join("firma.toml");
    enable_https_mitm(&config_file);

    let probe_tool = workspace.join("ca-trust-probe");
    write_ca_trust_probe(&probe_tool);
    let evidence = workspace.join("ca-trust-probe-ran");

    let output = world.run_firma_with_state_dir(
        &config_file,
        &state_dir,
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &probe_tool,
        [&evidence],
    );

    assert!(output.success(), "CA trust probe failed:\n{output}");
    assert!(evidence.is_file(), "the CA trust probe did not run");
    assert!(
        output.stdout.contains(CA_TRUST_READABLE),
        "the sandbox could not read the trust store named by SSL_CERT_FILE:\n{output}"
    );
    assert!(
        !output.stdout.contains(CA_KEY_EXPOSED),
        "the sandbox reached the Sidecar CA private key:\n{output}"
    );
}

/// Turns on HTTPS MITM in a scaffolded config so the Sidecar generates CA
/// material. Fails when the generated setting is absent, so the patch cannot
/// silently become a no-op.
fn enable_https_mitm(config_file: &Path) {
    let config = std::fs::read_to_string(config_file).expect("read scaffolded config");
    let patched = config.replace(
        "[sidecar.interceptor.https_mitm]\nenabled = false\n",
        "[sidecar.interceptor.https_mitm]\nenabled = true\n",
    );
    assert_ne!(patched, config, "expected generated https_mitm setting");
    std::fs::write(config_file, patched).expect("write MITM-enabled config");
}

/// Reports whether the injected trust store is readable and whether the CA
/// private key leaked. Neither the certificate nor the key contents are
/// printed.
fn write_ca_trust_probe(path: &Path) {
    let script = format!(
        r#"#!/bin/sh
set -eu
evidence="$1"
printf '%s\n' attempted >"$evidence"
if [ -n "${{SSL_CERT_FILE:-}}" ] && [ -r "${{SSL_CERT_FILE}}" ]; then
  echo "{CA_TRUST_READABLE}"
fi
if [ -n "${{FIRMA_SIDECAR_CA_DIR:-}}" ] && [ -r "${{FIRMA_SIDECAR_CA_DIR}}/firma-ca.key" ]; then
  echo "{CA_KEY_EXPOSED}"
fi
"#,
    );
    std::fs::write(path, script).expect("write CA trust probe");
    set_executable(path);
}

fn assert_probe_positive_control(world: &TestWorld, workspace: &Path, probe_tool: &Path) {
    let control_root = world.path("control-assets");
    let control_evidence = world.path("control-probe-ran");
    std::fs::create_dir_all(control_root.join("authority/keys"))
        .expect("create control asset directory");
    std::fs::write(
        control_root.join("authority/keys/authority.key"),
        "positive-control-key",
    )
    .expect("write control asset");
    let mut control = world.isolated_command_in(probe_tool, workspace);
    control.args([&control_root, &control_evidence]);
    let control = run_bounded(&mut control, std::time::Duration::from_secs(15));

    assert!(control.success(), "control-plane probe failed:\n{control}");
    assert!(
        control.stdout.contains(PROBE_ATTEMPTED) && control.stdout.contains(ASSET_EXPOSED),
        "positive control did not find the planted asset:\n{control}"
    );
    assert!(control_evidence.is_file(), "positive control did not run");
}

fn write_control_plane_probe(path: &Path) {
    let script = format!(
        r#"#!/bin/sh
set -eu
control_root="$1"
evidence="$2"
echo "{PROBE_ATTEMPTED} root=$control_root"
for asset in \
  "$control_root"/authority.key \
  "$control_root"/authority/keys/authority.key \
  "$control_root"/run/*/authority/keys/authority.key \
  "$control_root"/run/*/sidecar.toml \
  "$control_root"/run/*/metadata.toml \
  "$control_root"/capabilities/*.toml
do
  if [ -e "$asset" ] && {{ : <"$asset"; }} 2>/dev/null; then
    echo "{ASSET_EXPOSED} path=$asset"
  fi
done
printf '%s\n' forged >"$control_root/run/forged-sidecar.sock" 2>/dev/null || true
printf '%s\n' attempted >"$evidence"
"#,
    );
    std::fs::write(path, script).expect("write control-plane probe");
    set_executable(path);
}

fn write_forge_tool(path: &Path) {
    let script = r#"#!/bin/sh
set -eu
control_root="$1"
evidence="$2"
mkdir -p "$control_root"
printf '%s\n' forged >"$control_root/forged-control-plane-file"
printf '%s\n' attempted >"$evidence"
"#;
    std::fs::write(path, script).expect("write control-plane forge tool");
    set_executable(path);
}

fn append_profile_mount(config_file: &Path, source: &Path, target: &Path) {
    let mut config = std::fs::read_to_string(config_file).expect("read generated config");
    write!(
        config,
        "\n[[run.profiles.generic.mounts]]\n\
         source = \"{}\"\n\
         target = \"{}\"\n\
         read_only = false\n",
        source.display(),
        target.display(),
    )
    .expect("render profile mount");
    std::fs::write(config_file, config).expect("append profile mount");
}

fn tcp_probe_endpoint(scheme: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP probe endpoint");
    let address = listener.local_addr().expect("resolve TCP probe address");
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    format!("{scheme}://{address}")
}

fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .expect("stat control-plane probe")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod control-plane probe");
}
