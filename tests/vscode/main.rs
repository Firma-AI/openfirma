//! Black-box coverage for the managed VS Code launch contract.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code: panics are acceptable test failures"
)]

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Command, Output};

#[cfg(target_os = "linux")]
const SANDBOX_UNAVAILABLE_MARKERS: &[&str] = &[
    "bubblewrap is not installed",
    "backend error (bwrap)",
    "user namespace creation is restricted",
    "unprivileged user namespaces",
    "max_user_namespaces",
    "requires unprivileged user namespaces",
    "WSL",
];

#[cfg(target_os = "linux")]
fn firma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

#[cfg(target_os = "linux")]
fn command_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(target_os = "linux")]
fn output_text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[cfg(target_os = "linux")]
fn sandbox_unavailable(stderr: &str) -> bool {
    SANDBOX_UNAVAILABLE_MARKERS
        .iter()
        .any(|marker| stderr.contains(marker))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
    command.output().expect("spawn firma run")
}

#[cfg(target_os = "linux")]
fn assert_run_succeeded_or_skip(output: &Output) -> Option<(String, String)> {
    let (stdout, stderr) = output_text(output);
    if !output.status.success() && sandbox_unavailable(&stderr) {
        eprintln!("skipping: sandbox unavailable on this host:\n{stderr}");
        return None;
    }
    assert!(
        output.status.success(),
        "firma run failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    Some((stdout, stderr))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[test]
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
    if assert_run_succeeded_or_skip(&output).is_none() {
        return;
    }

    let user_data_dir = config_dir.join("vscode").join("user-data");
    let extensions_dir = config_dir.join("vscode").join("extensions");
    let record = std::fs::read_to_string(workspace.join("vscode-invocation.txt"))
        .expect("read fake VS Code invocation");
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
    assert_eq!(
        parsed.get("github-authentication.preferDeviceCodeFlow"),
        Some(&serde_json::Value::Bool(true))
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires real VS Code desktop binary and a desktop-capable sandbox host"]
fn real_vscode_accepts_managed_launch_contract() {
    if std::env::var("FIRMA_E2E_REAL_VSCODE").as_deref() != Ok("1") {
        eprintln!("skipping: set FIRMA_E2E_REAL_VSCODE=1 to run the real VS Code e2e test");
        return;
    }
    if !command_available("code") {
        eprintln!("skipping: real VS Code 'code' binary not found on PATH");
        return;
    }

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
    let Some((stdout, stderr)) = assert_run_succeeded_or_skip(&output) else {
        return;
    };
    assert!(
        stdout
            .lines()
            .next()
            .is_some_and(|line| !line.trim().is_empty()),
        "expected VS Code version output\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
