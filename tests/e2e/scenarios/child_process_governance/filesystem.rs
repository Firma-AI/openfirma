use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::harness::{TestWorld, run_bounded};

use super::support::{
    assert_only_root_governed, first_existing, patch_local_exec_allowlist, set_executable,
    shell_quote, spawn_allow_all_endpoint,
};

const FILESYSTEM_SENTINEL: &str = "firma-child-filesystem-sentinel";

#[test]
fn ungoverned_child_remains_filesystem_confined() {
    let bash = first_existing(&["/usr/bin/bash", "/bin/bash"])
        .unwrap_or_else(|| panic!("bash must be installed in the test environment"));
    let bash_canonical = std::fs::canonicalize(&bash)
        .unwrap_or_else(|e| panic!("canonicalize {}: {e}", bash.display()));

    assert_unconfined_filesystem_control();

    let world = TestWorld::new();
    let workspace = world.workspace_path();
    let config = world.config_path();
    plant_filesystem_sentinel(&config);
    let socket_dir = world.path("sockets");
    std::fs::create_dir_all(&socket_dir).expect("create socket directory");
    let governance_sock = socket_dir.join("local-exec.sock");
    patch_local_exec_allowlist(
        &config,
        &socket_dir.join("traffic.sock"),
        &governance_sock,
        &bash_canonical,
    );
    let pristine_config = std::fs::read_to_string(&config).expect("read pristine config");
    let governed = Arc::new(Mutex::new(Vec::<String>::new()));
    spawn_allow_all_endpoint(&governance_sock, Arc::clone(&governed));

    let tool = workspace.join("child-filesystem-tool");
    let copy = workspace.join("enforced-copy.toml");
    write_filesystem_tool(&tool);
    let nonce = format!("child-fs-enforced-{}", uuid::Uuid::new_v4().simple());
    let script = format!(
        "{tool} {config} {copy} {nonce}",
        tool = shell_quote(&tool),
        config = shell_quote(&config),
        copy = shell_quote(&copy),
        nonce = shell_quote(Path::new(&nonce)),
    );
    let output = world.run_firma(
        "generic",
        Some(&config),
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &bash,
        ["-c", &script],
    );
    assert!(output.success(), "allowed bash root failed:\n{output}");
    assert!(
        output
            .stdout
            .contains(&format!("CHILD FILESYSTEM ATTEMPTED nonce={nonce}")),
        "the ungoverned child did not attempt the filesystem operations:\n{output}"
    );
    assert!(
        output.stdout.contains("CHILD FILESYSTEM WRITE BLOCKED")
            && !output.stdout.contains("CHILD FILESYSTEM WRITE SUCCEEDED"),
        "the selected config was writable from the ungoverned child:\n{output}"
    );
    assert_eq!(
        std::fs::read_to_string(&copy).expect("read enforced config copy"),
        "",
        "the ungoverned child read the masked config"
    );
    assert_eq!(
        std::fs::read_to_string(&config).expect("read config after enforced child"),
        pristine_config,
        "the ungoverned child modified the host config"
    );
    let governed = governed.lock().expect("lock governance log").clone();
    assert_only_root_governed(&governed, &bash_canonical);
}

fn assert_unconfined_filesystem_control() {
    let control_world = TestWorld::new();
    let control_config = control_world.config_path();
    plant_filesystem_sentinel(&control_config);
    let control_tool = control_world.workspace_path().join("child-filesystem-tool");
    let control_copy = control_world.workspace_path().join("control-copy.toml");
    write_filesystem_tool(&control_tool);
    let control_nonce = format!("child-fs-control-{}", uuid::Uuid::new_v4().simple());
    let mut control =
        control_world.isolated_command_in(&control_tool, &control_world.workspace_path());
    control
        .arg(&control_config)
        .arg(&control_copy)
        .arg(&control_nonce);
    let control_output = run_bounded(&mut control, Duration::from_secs(15));
    assert!(
        control_output.success(),
        "child filesystem control failed:\n{control_output}"
    );
    assert!(
        control_output
            .stdout
            .contains(&format!("CHILD FILESYSTEM ATTEMPTED nonce={control_nonce}")),
        "control child did not attempt the filesystem operations:\n{control_output}"
    );
    assert!(
        control_output
            .stdout
            .contains("CHILD FILESYSTEM WRITE SUCCEEDED"),
        "control child could not write the unmasked config:\n{control_output}"
    );
    assert!(
        std::fs::read_to_string(&control_copy)
            .expect("read control config copy")
            .contains(FILESYSTEM_SENTINEL),
        "control child could not read the unmasked config"
    );
    assert!(
        std::fs::read_to_string(&control_config)
            .expect("read control config after write")
            .contains(&format!("# CHILD WRITE {control_nonce}")),
        "control child did not modify the unmasked config"
    );
}

fn plant_filesystem_sentinel(config: &Path) {
    let generated = std::fs::read_to_string(config).expect("read generated config");
    std::fs::write(config, format!("{generated}\n# {FILESYSTEM_SENTINEL}\n"))
        .expect("plant filesystem sentinel");
}

fn write_filesystem_tool(path: &Path) {
    let script = r#"#!/bin/sh
echo "CHILD FILESYSTEM ATTEMPTED nonce=$3"
cat "$1" > "$2"
if printf '# CHILD WRITE %s\n' "$3" >> "$1"; then
  echo "CHILD FILESYSTEM WRITE SUCCEEDED"
else
  echo "CHILD FILESYSTEM WRITE BLOCKED"
fi
"#;
    std::fs::write(path, script).expect("write child-filesystem-tool");
    set_executable(path);
}
