//! The sandbox runs in its own PID namespace with its own procfs, which is what
//! keeps `/proc/<pid>/root/<host path>` from walking around every filesystem
//! mask through an ancestor's mount namespace. A profile mount must not be able
//! to hand that alias back.

use std::fmt::Write as _;
use std::path::Path;

use crate::harness::TestWorld;

const PROBE_ATTEMPTED: &str = "PROCFS PROBE ATTEMPTED";
const PROCFS_PRESENT: &str = "PROCFS PRESENT";
const PID_PREFIX: &str = "PROCFS PID ";

#[test]
fn profile_mount_cannot_replace_the_sandbox_procfs() {
    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let state_dir = world.state_path();
    let workspace = world.workspace_path();
    world.scaffold_config(
        "generic",
        &cfg_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );

    let payload = workspace.join("payload");
    std::fs::create_dir_all(&payload).expect("create mount source");
    append_profile_mount(&cfg_dir.join("firma.toml"), &payload, Path::new("/proc"));

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
        "firma run accepted a profile mount over the sandbox procfs:\n{output}"
    );
    assert!(
        output.stderr.contains("/proc") && output.stderr.contains("reserved"),
        "firma run did not explain the reserved-target rejection:\n{output}"
    );
}

#[test]
fn profile_mount_cannot_source_the_host_procfs() {
    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let state_dir = world.state_path();
    let workspace = world.workspace_path();
    world.scaffold_config(
        "generic",
        &cfg_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );

    let alias = workspace.join("host-proc");
    append_profile_mount(&cfg_dir.join("firma.toml"), Path::new("/proc"), &alias);

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
        "firma run accepted a profile mount sourced from the host procfs:\n{output}"
    );
    assert!(
        output.stderr.contains("procfs-backed mount source"),
        "firma run did not explain the procfs-source rejection:\n{output}"
    );
}

/// A recursive mount of a tree containing the host procfs is legitimate — it is
/// how an operator exposes a large read-only tree — so the launch must succeed.
/// What must not survive is the host procfs inside it: `<alias>/<pid>/root`
/// walks an ancestor's mount namespace around every filesystem mask.
#[test]
fn profile_mount_alias_exposes_only_the_sandbox_procfs() {
    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let state_dir = world.state_path();
    let workspace = world.workspace_path();
    world.scaffold_config(
        "generic",
        &cfg_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );

    let probe_tool = workspace.join("procfs-probe");
    write_procfs_probe(&probe_tool);
    assert_probe_positive_control(&world, &workspace, &probe_tool);

    let host_root_alias = workspace.join("host-root");
    std::fs::create_dir_all(&host_root_alias).expect("create alias directory");
    append_profile_mount(
        &cfg_dir.join("firma.toml"),
        Path::new("/"),
        &host_root_alias,
    );

    let evidence = workspace.join("procfs-probe-ran");
    let output = world.run_firma_with_state_dir(
        &cfg_dir.join("firma.toml"),
        &state_dir,
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &probe_tool,
        [&host_root_alias.join("proc"), &evidence],
    );

    assert!(output.success(), "aliased-procfs probe failed:\n{output}");
    assert!(
        output.stdout.contains(PROBE_ATTEMPTED) && evidence.is_file(),
        "the sandbox did not execute the aliased-procfs probe:\n{output}"
    );
    assert!(
        output.stdout.contains(PROCFS_PRESENT),
        "the alias is not a working procfs, so the seal replaced it with the wrong thing:\n{output}"
    );
    assert!(
        !output.stdout.contains(&host_pid_marker()),
        "the aliased procfs exposed a host process:\n{output}"
    );
}

/// Proves the probe reports host processes when it reads a host procfs, so its
/// silence inside the sandbox is evidence about the seal rather than about the
/// probe.
fn assert_probe_positive_control(world: &TestWorld, workspace: &Path, probe_tool: &Path) {
    let evidence = workspace.join("procfs-probe-control-ran");
    let mut command = world.isolated_command_in(probe_tool, workspace);
    command.arg("/proc").arg(&evidence);
    let output = crate::harness::run_bounded(&mut command, std::time::Duration::from_secs(30));

    assert!(output.success(), "procfs probe control failed:\n{output}");
    assert!(
        output.stdout.contains(&host_pid_marker()),
        "the probe cannot observe host processes even outside the sandbox:\n{output}"
    );
}

/// Marker the probe prints for this test process, which is a host process the
/// sandbox must not see.
fn host_pid_marker() -> String {
    format!("{PID_PREFIX}{}", std::process::id())
}

fn write_procfs_probe(path: &Path) {
    let script = format!(
        r#"#!/bin/sh
set -eu
procfs="$1"
evidence="$2"
printf '%s\n' attempted >"$evidence"
echo "{PROBE_ATTEMPTED}"
if [ -e "$procfs/self/status" ]; then
  echo "{PROCFS_PRESENT}"
fi
for pid_dir in "$procfs"/[0-9]*
do
  [ -d "$pid_dir" ] || continue
  echo "{PID_PREFIX}${{pid_dir##*/}}"
done
"#,
    );
    std::fs::write(path, script).expect("write procfs probe");
    set_executable(path);
}

fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .expect("stat procfs probe")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod procfs probe");
}

fn append_profile_mount(config_file: &Path, source: &Path, target: &Path) {
    let mut config = std::fs::read_to_string(config_file).expect("read generated config");
    write!(
        config,
        "\n[[run.profiles.generic.mounts]]\n\
         source = \"{}\"\n\
         target = \"{}\"\n\
         read_only = true\n",
        source.display(),
        target.display(),
    )
    .expect("render profile mount");
    std::fs::write(config_file, config).expect("append profile mount");
}
