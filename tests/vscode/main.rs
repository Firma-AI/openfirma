//! Black-box coverage for the managed VS Code launch contract.

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn firma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

fn command_available(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path)
            // An empty PATH entry means the current directory; a launcher found
            // there is not one the user meaningfully has installed.
            .filter(|dir| !dir.as_os_str().is_empty())
            .any(|dir| {
                std::fs::metadata(dir.join(name)).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
    })
}

fn output_text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn prepend_path(bin_dir: &Path) -> String {
    let previous = std::env::var_os("PATH")
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();
    if previous.is_empty() {
        bin_dir.display().to_string()
    } else {
        format!("{}:{previous}", bin_dir.display())
    }
}

fn scaffold_vscode_config(config_dir: &Path, state_dir: &Path, workspace: &Path) {
    let output = Command::new(firma_bin())
        .args([
            "config",
            "-y",
            "--mode",
            "agent-local",
            "--profile",
            "vscode",
            "--posture",
            "dev",
            "--workspace",
        ])
        .arg(workspace)
        .arg("--output-dir")
        .arg(config_dir)
        .arg("--state-dir")
        .arg(state_dir)
        .output()
        .expect("spawn firma config");
    let (stdout, stderr) = output_text(&output);
    assert!(
        output.status.success(),
        "firma config failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn run_vscode_profile(
    config_path: &Path,
    workspace: &Path,
    path: Option<String>,
    code_args: &[&str],
) -> Output {
    let mut command = Command::new(firma_bin());
    command
        .args(["run", "--profile", "vscode"])
        .arg("--config")
        .arg(config_path)
        .args(["--", "code"])
        .args(code_args)
        .current_dir(workspace)
        .env("NO_COLOR", "1");
    if let Some(path) = path {
        command.env("PATH", path);
    }
    // The shim passes `--wait`, so this blocks until the launcher exits. Both
    // callers use a launcher that returns immediately; the run-away case is
    // bounded by the nextest `slow-timeout` in `.config/nextest.toml`.
    command.output().expect("spawn firma run")
}

fn assert_run_succeeded(output: &Output) -> (String, String) {
    let (stdout, stderr) = output_text(output);
    assert!(
        output.status.success(),
        "firma run failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    (stdout, stderr)
}

fn write_fake_code(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(
        path,
        "#!/bin/sh\n\
         set -eu\n\
         {\n\
         printf 'PWD=%s\\n' \"$PWD\"\n\
         i=0\n\
         for arg in \"$@\"; do\n\
         printf 'ARG_%s=%s\\n' \"$i\" \"$arg\"\n\
         i=$((i + 1))\n\
         done\n\
         } > vscode-invocation.txt\n",
    )
    .expect("write fake code");

    let mut permissions = std::fs::metadata(path)
        .expect("fake code metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).expect("chmod fake code");
}

#[test]
#[ignore = "requires a bubblewrap-capable sandbox host; run with --run-ignored all -E 'test(fake_vscode)'"]
fn fake_vscode_receives_managed_launch_contract_through_firma_run() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_dir = tmp.path().join("cfg");
    let state_dir = tmp.path().join("state");
    let workspace = tmp.path().join("workspace");
    let host_bin = workspace.join("host-bin");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    std::fs::create_dir_all(&host_bin).expect("create host bin");

    let fake_code = host_bin.join("code");
    write_fake_code(&fake_code);
    scaffold_vscode_config(&config_dir, &state_dir, &workspace);

    let output = run_vscode_profile(
        &config_dir.join("firma.toml"),
        &workspace,
        Some(prepend_path(&host_bin)),
        &["."],
    );
    assert_run_succeeded(&output);

    let user_data_dir = config_dir.join("vscode").join("user-data");
    let extensions_dir = config_dir.join("vscode").join("extensions");
    let record = std::fs::read_to_string(workspace.join("vscode-invocation.txt"))
        .expect("read fake VS Code invocation");
    // The managed argument contract is restated here on purpose rather than
    // shared with `firma-run`: this suite pins what the shipped binary emits, so
    // importing the producer's own constants would make the check circular.
    let expected = [
        format!("PWD={}", workspace.display()),
        "ARG_0=--no-sandbox".to_string(),
        "ARG_1=--wait".to_string(),
        "ARG_2=--new-window".to_string(),
        "ARG_3=--user-data-dir".to_string(),
        format!("ARG_4={}", user_data_dir.display()),
        "ARG_5=--extensions-dir".to_string(),
        format!("ARG_6={}", extensions_dir.display()),
        "ARG_7=.".to_string(),
    ]
    .join("\n");
    assert_eq!(record.trim_end(), expected);

    let settings = std::fs::read_to_string(user_data_dir.join("User").join("settings.json"))
        .expect("read VS Code settings");
    let parsed: serde_json::Value = serde_json::from_str(&settings).expect("parse settings");
    assert_eq!(parsed["github-authentication.preferDeviceCodeFlow"], true);
}

// `#[ignore]` is the only gate: selecting this test is an explicit opt-in, so
// it must never report success without exercising a real VS Code binary.
#[test]
#[ignore = "requires real VS Code desktop binary and a desktop-capable sandbox host"]
fn real_vscode_accepts_managed_launch_contract() {
    assert!(
        command_available("code"),
        "real VS Code 'code' binary not found on PATH"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let config_dir = tmp.path().join("cfg");
    let state_dir = tmp.path().join("state");
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    scaffold_vscode_config(&config_dir, &state_dir, &workspace);

    let output = run_vscode_profile(
        &config_dir.join("firma.toml"),
        &workspace,
        None,
        &["--version"],
    );
    let (stdout, stderr) = assert_run_succeeded(&output);
    // `firma run` writes its own output too, so a merely non-empty first line
    // proves nothing. `code --version` emits a semver line, a commit hash, and
    // an architecture; pin the version line specifically.
    assert!(
        stdout.lines().any(is_semver_line),
        "expected a VS Code version line in stdout\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Reports whether a line looks like `code --version`'s leading semver line.
fn is_semver_line(line: &str) -> bool {
    let parts: Vec<&str> = line.trim().split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}
