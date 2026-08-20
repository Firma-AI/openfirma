use std::path::Path;

use crate::harness::{TestWorld, run_bounded};

const PROBE_ATTEMPTED: &str = "CONTROL-PLANE PROBE ATTEMPTED";
const ASSET_EXPOSED: &str = "CONTROL-PLANE ASSET EXPOSED";

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

fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .expect("stat control-plane probe")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod control-plane probe");
}
