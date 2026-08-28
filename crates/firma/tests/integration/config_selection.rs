//! Black-box config-selection contract for commands that consume the unified
//! `firma.toml` outside normal runtime startup.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::Path;
use std::process::{Command, Output};

const FIRMA_BIN: &str = env!("CARGO_BIN_EXE_firma");

fn write_invalid(path: &Path) {
    std::fs::write(path, "not valid TOML").expect("write invalid config");
}

fn run(
    command: &str,
    current_dir: &Path,
    explicit: Option<&Path>,
    canonical: Option<&Path>,
    removed: &Path,
) -> Output {
    let mut process = Command::new(FIRMA_BIN);
    process.arg(command);
    if command == "monitor" {
        process.arg("--no-follow");
    }
    if let Some(explicit) = explicit {
        process.arg("--config").arg(explicit);
    }
    process
        .current_dir(current_dir)
        .env_remove("FIRMA_CONFIG")
        .env("FIRMA_STACK_CONFIG", removed)
        .env("FIRMA_LOG_FILTER", "off");
    if let Some(canonical) = canonical {
        process.env("FIRMA_CONFIG", canonical);
    }
    process
        .output()
        .unwrap_or_else(|error| panic!("spawn firma {command}: {error}"))
}

fn assert_selected(output: &Output, selected: &Path, rejected: &[&Path]) {
    assert!(
        !output.status.success(),
        "invalid selected config must fail; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(selected.to_string_lossy().as_ref()),
        "diagnostic must identify selected config '{}'; got: {stderr}",
        selected.display()
    );
    for rejected in rejected {
        assert!(
            !stderr.contains(rejected.to_string_lossy().as_ref()),
            "diagnostic must not identify unselected config '{}'; got: {stderr}",
            rejected.display()
        );
    }
}

#[test]
fn control_and_monitor_use_only_canonical_config_selection() {
    let temp = tempfile::tempdir().expect("tempdir");
    let explicit = temp.path().join("explicit.toml");
    let canonical = temp.path().join("canonical.toml");
    let removed = temp.path().join("removed.toml");
    let discovered_dir = temp.path().join(".firma");
    let discovered = discovered_dir.join("firma.toml");
    std::fs::create_dir(&discovered_dir).expect("create project config directory");
    for path in [&explicit, &canonical, &removed, &discovered] {
        write_invalid(path);
    }

    for command in ["control", "monitor"] {
        let canonical_output = run(command, temp.path(), None, Some(&canonical), &removed);
        assert_selected(
            &canonical_output,
            &canonical,
            &[&explicit, &removed, &discovered],
        );

        let explicit_output = run(
            command,
            temp.path(),
            Some(&explicit),
            Some(&canonical),
            &removed,
        );
        assert_selected(
            &explicit_output,
            &explicit,
            &[&canonical, &removed, &discovered],
        );

        let discovered_output = run(command, temp.path(), None, None, &removed);
        assert_selected(
            &discovered_output,
            &discovered,
            &[&explicit, &canonical, &removed],
        );
    }
}
