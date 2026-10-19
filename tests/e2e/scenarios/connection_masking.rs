//! A host login directory must stay outside the wrapped agent's filesystem.

use std::fmt::Write as _;
use std::path::Path;

use crate::harness::{ProcessOutput, TestWorld};

const SENTINEL: &str = "host-login-credential-sentinel";
const RAN: &str = "CONNECTION-MASK-SHELL-RAN";

#[test]
fn a_host_connection_override_is_masked_at_its_path_and_bind_alias() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_file = scaffold(&world);
    let connection_dir = workspace.join("login-state");
    let alias = world.path("workspace-alias");
    std::fs::create_dir_all(&connection_dir).expect("create login directory");
    std::fs::create_dir_all(&alias).expect("create alias target");
    std::fs::write(connection_dir.join("connection.json"), SENTINEL).expect("plant sentinel");
    append_mount(&config_file, &workspace, &alias);
    let shell = format!(
        "cat {direct} 2>/dev/null; cat {aliased} 2>/dev/null; echo {RAN}",
        direct = shell_quote(&connection_dir.join("connection.json")),
        aliased = shell_quote(&alias.join("login-state/connection.json")),
    );

    let control = run(&world, &config_file, &shell, &[]);
    assert_ran(&control);
    assert_eq!(control.stdout.matches(SENTINEL).count(), 2, "{control}");

    let masked = run(
        &world,
        &config_file,
        &shell,
        &[("FIRMA_CONNECTION_DIR", &connection_dir)],
    );
    assert_ran(&masked);
    assert!(!masked.stdout.contains(SENTINEL), "{masked}");
    assert_eq!(
        std::fs::read_to_string(connection_dir.join("connection.json")).expect("host connection"),
        SENTINEL
    );
}

#[test]
fn an_xdg_relocated_host_connection_is_masked_without_an_explicit_override() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_file = scaffold(&world);
    let relocated = workspace.join("custom-xdg");
    let connection_dir = relocated.join("firma");
    std::fs::create_dir_all(&connection_dir).expect("create login directory");
    std::fs::write(connection_dir.join("connection.json"), SENTINEL).expect("plant sentinel");
    let shell = format!(
        "cat {record} 2>/dev/null; echo {RAN}",
        record = shell_quote(&connection_dir.join("connection.json")),
    );

    let control = run(&world, &config_file, &shell, &[]);
    assert_ran(&control);
    assert!(control.stdout.contains(SENTINEL), "{control}");

    let masked = run(
        &world,
        &config_file,
        &shell,
        &[("XDG_CONFIG_HOME", &relocated)],
    );
    assert_ran(&masked);
    assert!(!masked.stdout.contains(SENTINEL), "{masked}");
}

#[test]
fn a_connection_directory_overlapping_the_runtime_is_rejected_before_agent_launch() {
    use std::os::unix::fs::PermissionsExt as _;

    let world = TestWorld::isolated();
    let config_file = scaffold(&world);
    let runtime_parent = world.path("tmp/firma-run");
    std::fs::create_dir_all(&runtime_parent).expect("create runtime parent");
    std::fs::set_permissions(&runtime_parent, std::fs::Permissions::from_mode(0o700))
        .expect("protect runtime parent");
    std::fs::write(runtime_parent.join("connection.json"), SENTINEL).expect("plant sentinel");

    let control = run(&world, &config_file, &format!("echo {RAN}"), &[]);
    assert_ran(&control);

    let rejected = run(
        &world,
        &config_file,
        &format!("echo {RAN}"),
        &[("FIRMA_CONNECTION_DIR", &runtime_parent)],
    );
    assert!(!rejected.success(), "{rejected}");
    assert!(
        rejected.stderr.contains("overlaps required sandbox mount"),
        "{rejected}"
    );
    assert!(!rejected.stdout.contains(RAN), "{rejected}");
}

#[test]
fn a_bind_sourced_from_a_connection_file_is_rejected_before_agent_launch() {
    let world = TestWorld::isolated();
    let workspace = world.workspace_path();
    let config_file = scaffold(&world);
    let connection_dir = workspace.join("login-state");
    let connection_file = connection_dir.join("connection.json");
    let control_file = workspace.join("control.json");
    let alias = world.path("login-alias.json");
    std::fs::create_dir_all(&connection_dir).expect("create login directory");
    std::fs::write(&connection_file, SENTINEL).expect("plant connection file");
    std::fs::write(&control_file, SENTINEL).expect("plant control file");
    std::fs::write(&alias, "").expect("create alias target");
    append_mount(&config_file, &control_file, &alias);
    let shell = format!("cat {}; echo {RAN}", shell_quote(&alias));

    let control = run(
        &world,
        &config_file,
        &shell,
        &[("FIRMA_CONNECTION_DIR", &connection_dir)],
    );
    assert_ran(&control);
    assert!(control.stdout.contains(SENTINEL), "{control}");

    let config = std::fs::read_to_string(&config_file).expect("read config");
    let changed = config.replace(
        control_file.to_str().expect("control path"),
        connection_file.to_str().expect("connection path"),
    );
    assert_ne!(config, changed, "control source was absent from config");
    std::fs::write(&config_file, changed).expect("replace mount source");
    let rejected = run(
        &world,
        &config_file,
        &shell,
        &[("FIRMA_CONNECTION_DIR", &connection_dir)],
    );
    assert!(!rejected.success(), "{rejected}");
    assert!(
        rejected.stderr.contains("exposes host connection state"),
        "{rejected}"
    );
    assert!(!rejected.stdout.contains(RAN), "{rejected}");
}

fn scaffold(world: &TestWorld) -> std::path::PathBuf {
    let workspace = world.workspace_path();
    let config_dir = workspace.join(".firma");
    world.scaffold_config(
        "generic",
        &config_dir,
        &world.state_path(),
        Some(&workspace),
        &workspace,
    );
    let config_file = config_dir.join("firma.toml");
    TestWorld::disable_host_home_masks(&config_file);
    config_file
}

fn append_mount(config_file: &Path, source: &Path, target: &Path) {
    let mut config = std::fs::read_to_string(config_file).expect("read config");
    write!(
        config,
        "\n[[run.profiles.generic.mounts]]\n\
         source = \"{}\"\n\
         target = \"{}\"\n\
         read_only = false\n",
        source.display(),
        target.display(),
    )
    .expect("render mount");
    std::fs::write(config_file, config).expect("append mount");
}

fn run(
    world: &TestWorld,
    config_file: &Path,
    shell: &str,
    host_env: &[(&str, &Path)],
) -> ProcessOutput {
    world.run_firma_with_host_env(
        "generic",
        Some(config_file),
        &world.workspace_path(),
        &["--backend", "bwrap"],
        "sh",
        ["-c", shell],
        host_env,
    )
}

fn assert_ran(output: &ProcessOutput) {
    assert!(output.success(), "firma run failed:\n{output}");
    assert!(output.stdout.contains(RAN), "agent did not run:\n{output}");
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}
