use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::harness::{ProcessOutput, TestWorld};

use super::support::{
    assert_only_root_governed, first_existing, patch_local_exec_allowlist, set_executable,
    shell_quote, spawn_allow_all_endpoint,
};

const FORBIDDEN_MARKER: &str = "FORBIDDEN-TOOL EXECUTED";

#[test]
#[ignore = "integration test — run with --include-ignored (regression target for FIR-366; fails until child-process governance lands)"]
fn child_process_escapes_run_governance() {
    let bash = first_existing(&["/usr/bin/bash", "/bin/bash"])
        .unwrap_or_else(|| panic!("bash must be installed in the test environment"));
    let bash_canonical = std::fs::canonicalize(&bash)
        .unwrap_or_else(|e| panic!("canonicalize {}: {e}", bash.display()));

    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let state_dir = world.state_path();
    let workspace = world.workspace_path();
    let socket_dir = world.path("sockets");
    std::fs::create_dir_all(&socket_dir).expect("create socket directory");

    let forbidden_tool = workspace.join("forbidden-tool");
    let forbidden_marker = workspace.join("forbidden-ran");
    write_forbidden_tool(&forbidden_tool, &forbidden_marker);

    world.scaffold_config(
        "generic",
        &cfg_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );

    let governance_sock = socket_dir.join("local-exec.sock");
    let traffic_sock = socket_dir.join("traffic.sock");
    patch_local_exec_allowlist(
        &cfg_dir.join("firma.toml"),
        &traffic_sock,
        &governance_sock,
        &bash_canonical,
    );

    let governed = Arc::new(Mutex::new(Vec::<String>::new()));
    spawn_allow_all_endpoint(&governance_sock, Arc::clone(&governed));

    let _ = std::fs::remove_file(&forbidden_marker);
    let scenario_a = world.run_firma(
        "generic",
        Some(&cfg_dir.join("firma.toml")),
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &forbidden_tool,
        ["as-root"],
    );
    assert!(
        !scenario_a.success(),
        "control failed: forbidden-tool as the root command should be denied, but firma run exited 0\n{scenario_a}"
    );
    assert!(
        !forbidden_marker.exists(),
        "control failed: forbidden-tool ran as the root command despite being absent from the allowlist\n{scenario_a}"
    );

    let _ = std::fs::remove_file(&forbidden_marker);
    let bash_script = format!(
        "{tool} as-child-of-bash; echo \"bash-done exit=$?\"",
        tool = shell_quote(&forbidden_tool),
    );
    let scenario_b = world.run_firma(
        "generic",
        Some(&cfg_dir.join("firma.toml")),
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &bash,
        ["-c", &bash_script],
    );

    assert!(
        scenario_b.stdout.contains("bash-done"),
        "the allowed bash root did not execute — `firma run` could not start the sandbox in this environment.\n{scenario_b}"
    );

    let governed = governed.lock().expect("lock governance log").clone();
    assert_only_root_governed(&governed, &bash_canonical);

    assert!(
        !forbidden_marker.exists() && !output_contains(&scenario_b, FORBIDDEN_MARKER),
        "FIR-366: the forbidden-tool child executed ungoverned under an allowed bash root.\n{scenario_b}"
    );
}

fn output_contains(output: &ProcessOutput, needle: &str) -> bool {
    output.stdout.contains(needle) || output.stderr.contains(needle)
}

fn write_forbidden_tool(path: &Path, marker: &Path) {
    let script = format!(
        "#!/bin/sh\necho \"{FORBIDDEN_MARKER} pid=$$ argv=$*\"\n: > {marker}\n",
        marker = shell_quote(marker),
    );
    std::fs::write(path, script).expect("write forbidden-tool");
    set_executable(path);
}
