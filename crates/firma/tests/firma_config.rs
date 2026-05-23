//! Tests for `firma config`.
//!
//! Verifies that the scaffolded unified `firma.toml` is syntactically
//! valid, round-trips through the strict section loader, and that both
//! component config types deserialize from their sections. Regression
//! guard for Windows path serialization: backslash-bearing paths must not
//! be emitted into TOML basic strings (where `\t`, `\s`, etc. are invalid
//! escape sequences).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::Path;
use std::process::Command;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

fn run_init(config_dir: &Path, state_dir: &Path) {
    let output = firma()
        .args(["config", "--yes", "--output-dir"])
        .arg(config_dir)
        .args(["--state-dir"])
        .arg(state_dir)
        .output()
        .expect("spawn firma config");
    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn extract_dry_run_file(stdout: &[u8], file_name: &str) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let header = stdout
        .lines()
        .find(|line| line.starts_with("=== ") && line.trim_end_matches(" ===").ends_with(file_name))
        .unwrap_or_else(|| panic!("missing dry-run file {file_name} in stdout:\n{stdout}"));
    let start = stdout
        .find(header)
        .unwrap_or_else(|| panic!("missing dry-run header {header}"))
        + header.len();
    let content = stdout[start..].trim_start_matches('\n');
    let end = content.find("\n=== ").unwrap_or(content.len());
    content[..end].to_string()
}

fn assert_unified_config_parses(firma_toml: &Path) {
    let text = std::fs::read_to_string(firma_toml)
        .unwrap_or_else(|e| panic!("read {}: {e}", firma_toml.display()));
    toml::from_str::<toml::Value>(&text)
        .unwrap_or_else(|e| panic!("parse {}: {e}\n---\n{text}", firma_toml.display()));

    let abody = firma_config::load_section(firma_toml, "authority")
        .unwrap_or_else(|e| panic!("[authority] section: {e}"));
    toml::from_str::<firma_authority::AuthorityConfig>(&abody)
        .unwrap_or_else(|e| panic!("[authority] deserialize: {e}\n---\n{abody}"));

    let sbody = firma_config::load_section(firma_toml, "sidecar")
        .unwrap_or_else(|e| panic!("[sidecar] section: {e}"));
    toml::from_str::<firma_sidecar::config::SidecarConfig>(&sbody)
        .unwrap_or_else(|e| panic!("[sidecar] deserialize: {e}\n---\n{sbody}"));
}

#[test]
#[allow(clippy::too_many_lines, reason = "linear scenario test")]
fn reads_existing_config_as_defaults_and_allows_overrides() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");
    let workspace = tmp.path().join("workspace");
    let override_workspace = tmp.path().join("override-workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&override_workspace).unwrap();

    let first = firma()
        .args(["config", "--yes", "--output-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .args([
            "--name",
            "existing-agent",
            "--posture",
            "strict",
            "--mapping",
            "github",
            "--authority-listen",
            "127.0.0.1:9555",
            "--workspace",
        ])
        .arg(&workspace)
        .output()
        .expect("spawn initial firma config");
    assert!(
        first.status.success(),
        "initial firma config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    let firma_toml_path = config_dir.join("firma.toml");
    let mut existing_config: toml::Value =
        toml::from_str(&std::fs::read_to_string(&firma_toml_path).unwrap()).unwrap();
    existing_config["sidecar"]["preflight"]["requested_actions"] = toml::Value::Array(vec![
        toml::Value::String("credential.read".to_string()),
        toml::Value::String("issue.read".to_string()),
    ]);
    std::fs::write(
        &firma_toml_path,
        toml::to_string_pretty(&existing_config).unwrap(),
    )
    .unwrap();
    let firma_run_path = config_dir.join("firma-run.toml");
    let mut existing_firma_run = std::fs::read_to_string(&firma_run_path).unwrap();
    existing_firma_run = existing_firma_run.replace(
        "FIRMA_RUN_BWRAP_ROOTFS_MODE = \"readonly\"",
        "FIRMA_RUN_BWRAP_ROOTFS_MODE = \"readonly\"\nCUSTOM_WRAPPER_DEFAULT = \"kept\"",
    );
    std::fs::write(&firma_run_path, existing_firma_run).unwrap();

    let defaults = firma()
        .args(["config", "--yes", "--dry-run", "--output-dir"])
        .arg(&config_dir)
        .output()
        .expect("spawn defaulted firma config");
    assert!(
        defaults.status.success(),
        "defaulted firma config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&defaults.stdout),
        String::from_utf8_lossy(&defaults.stderr),
    );
    let firma_toml = extract_dry_run_file(&defaults.stdout, "firma.toml");
    let firma_run_toml = extract_dry_run_file(&defaults.stdout, "firma-run.toml");
    let value: toml::Value = toml::from_str(&firma_toml).unwrap();
    assert_eq!(
        value["authority"]["listen_addr"].as_str(),
        Some("127.0.0.1:9555"),
    );
    assert_eq!(
        value["sidecar"]["preflight"]["agent_id"].as_str(),
        Some("existing-agent"),
    );
    assert_eq!(
        value["sidecar"]["mapping"]["rules_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>(),
        vec!["mappings/github.toml"],
    );
    assert!(
        value["sidecar"]["preflight"]["requested_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("issue.read")),
        "custom preflight actions should be preserved"
    );
    assert!(
        !value["sidecar"]["preflight"]["requested_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("code.write")),
        "custom preflight actions should not be replaced by inferred posture"
    );
    assert!(
        firma_run_toml.contains(&format!("source = '{}'", workspace.display())),
        "workspace should be preserved in firma-run.toml:\n{firma_run_toml}"
    );
    assert!(
        firma_run_toml.contains("CUSTOM_WRAPPER_DEFAULT = \"kept\""),
        "existing wrapper config should be preserved when no wrapper flag overrides it:\n{firma_run_toml}"
    );

    let override_output = firma()
        .args(["config", "--yes", "--dry-run", "--output-dir"])
        .arg(&config_dir)
        .args([
            "--name",
            "override-agent",
            "--posture",
            "dev",
            "--mapping",
            "openai",
            "--authority-listen",
            "127.0.0.1:9666",
            "--workspace",
        ])
        .arg(&override_workspace)
        .output()
        .expect("spawn overriding firma config");
    assert!(
        override_output.status.success(),
        "overriding firma config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&override_output.stdout),
        String::from_utf8_lossy(&override_output.stderr),
    );
    let firma_toml = extract_dry_run_file(&override_output.stdout, "firma.toml");
    let firma_run_toml = extract_dry_run_file(&override_output.stdout, "firma-run.toml");
    let value: toml::Value = toml::from_str(&firma_toml).unwrap();
    assert_eq!(
        value["authority"]["listen_addr"].as_str(),
        Some("127.0.0.1:9666"),
    );
    assert_eq!(
        value["sidecar"]["preflight"]["agent_id"].as_str(),
        Some("override-agent"),
    );
    assert_eq!(
        value["sidecar"]["mapping"]["rules_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>(),
        vec!["mappings/openai.toml"],
    );
    assert!(
        value["sidecar"]["preflight"]["requested_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("code.write")),
        "explicit dev posture should override existing strict posture"
    );
    assert!(
        firma_run_toml.contains(&format!("source = '{}'", override_workspace.display())),
        "workspace override should be rendered in firma-run.toml:\n{firma_run_toml}"
    );
    // toml_edit merge contract: workspace override changes only the
    // [[profiles.generic.mounts]] entry — independent env_set
    // customizations the operator added by hand survive.
    assert!(
        firma_run_toml.contains("CUSTOM_WRAPPER_DEFAULT = \"kept\""),
        "merge must preserve unrelated env_set customizations across workspace override:\n{firma_run_toml}"
    );
    // The previous workspace mount must be gone so the agent does not
    // accidentally retain RW access to the old path.
    assert!(
        !firma_run_toml.contains(&format!("source = '{}'", workspace.display())),
        "previous workspace mount should be dropped on override:\n{firma_run_toml}"
    );
}

#[test]
fn agent_remote_switch_drops_local_authority_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let output = firma()
        .args([
            "config",
            "--yes",
            "--dry-run",
            "--force",
            "--mode",
            "agent-remote",
            "--output-dir",
        ])
        .arg(&config_dir)
        .args([
            "--authority-url",
            "https://authority.example.com:9443",
            "--authority-ca-cert",
        ])
        .arg(state_dir.join("remote-ca.crt"))
        .args(["--authority-pub-key"])
        .arg(state_dir.join("remote-authority.pub"))
        .output()
        .expect("spawn remote switch firma config");
    assert!(
        output.status.success(),
        "remote switch failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let firma_toml = extract_dry_run_file(&output.stdout, "firma.toml");
    let value: toml::Value = toml::from_str(&firma_toml).unwrap();
    assert!(
        value.get("authority").is_none(),
        "agent-remote config must not retain [authority]:\n{firma_toml}"
    );
    assert_eq!(
        value["sidecar"]["authority"]["url"].as_str(),
        Some("https://authority.example.com:9443"),
    );
}

#[test]
fn agent_remote_switch_warns_about_existing_local_authority_without_force() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let output = firma()
        .args([
            "config",
            "--yes",
            "--dry-run",
            "--mode",
            "agent-remote",
            "--output-dir",
        ])
        .arg(&config_dir)
        .args([
            "--authority-url",
            "https://authority.example.com:9443",
            "--authority-ca-cert",
        ])
        .arg(state_dir.join("remote-ca.crt"))
        .args(["--authority-pub-key"])
        .arg(state_dir.join("remote-authority.pub"))
        .output()
        .expect("spawn remote switch firma config");
    assert!(
        output.status.success(),
        "remote switch failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("local [authority] section"),
        "expected local authority warning in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("firma run starts the Authority locally"),
        "expected local startup consequence in stderr:\n{stderr}"
    );
}

#[test]
fn authority_mode_honors_selected_posture() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    let output = firma()
        .args([
            "config",
            "--yes",
            "--dry-run",
            "--mode",
            "authority",
            "--posture",
            "dev-with-delete-watch",
            "--output-dir",
        ])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("spawn authority-only firma config");
    assert!(
        output.status.success(),
        "authority config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("policies/dev-with-delete-watch.cedar"),
        "selected authority policy posture should be generated:\n{stdout}"
    );
    assert!(
        !stdout.contains("policies/dev.cedar"),
        "authority mode should not also generate the default dev policy:\n{stdout}"
    );
    let firma_toml = extract_dry_run_file(&output.stdout, "firma.toml");
    let value: toml::Value = toml::from_str(&firma_toml).unwrap();
    assert!(
        value.get("authority").is_some(),
        "authority mode must include [authority]:\n{firma_toml}"
    );
    assert!(
        value.get("sidecar").is_none(),
        "authority mode must not include [sidecar]:\n{firma_toml}"
    );
}

#[test]
fn explicit_posture_rewrites_selected_policy_without_force() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");
    let policies_dir = config_dir.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(
        policies_dir.join("strict.cedar"),
        "// stale strict policy\n",
    )
    .unwrap();

    let output = firma()
        .args([
            "config",
            "--yes",
            "--mode",
            "authority",
            "--posture",
            "strict",
            "--output-dir",
        ])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("spawn authority-only firma config");
    assert!(
        output.status.success(),
        "authority config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let policy = std::fs::read_to_string(policies_dir.join("strict.cedar")).unwrap();
    assert!(
        policy.contains("Strict posture"),
        "explicit posture should rewrite selected policy file:\n{policy}"
    );
    assert!(
        !policy.contains("stale strict policy"),
        "stale selected policy file should not be preserved:\n{policy}"
    );
}

#[test]
fn init_writes_parseable_config() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let firma_toml = config_dir.join("firma.toml");
    assert!(firma_toml.is_file(), "firma.toml in config_dir");
    assert!(!config_dir.join("authority.toml").exists());
    assert!(!config_dir.join("sidecar.toml").exists());

    // Keys must be in state_dir, not config_dir.
    assert!(
        state_dir.join("authority.key").is_file(),
        "authority.key in state_dir"
    );
    assert!(
        state_dir.join("audit.key").is_file(),
        "audit.key in state_dir"
    );
    assert!(
        !config_dir.join("authority.key").exists(),
        "no authority.key in config_dir"
    );

    assert_unified_config_parses(&firma_toml);
}

#[test]
fn init_state_paths_in_config_are_absolute() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let text = std::fs::read_to_string(config_dir.join("firma.toml")).unwrap();
    let value: toml::Value = toml::from_str(&text).unwrap();

    let key_file = value["authority"]["key_file"]
        .as_str()
        .expect("authority.key_file");
    assert!(
        Path::new(key_file).is_absolute(),
        "authority.key_file must be absolute, got {key_file}"
    );

    let audit_path = value["sidecar"]["audit"]["file_path"]
        .as_str()
        .expect("sidecar.audit.file_path");
    assert!(
        Path::new(audit_path).is_absolute(),
        "sidecar.audit.file_path must be absolute, got {audit_path}"
    );
}

#[test]
fn init_handles_relative_paths() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let work = tmp.path().join("workdir");
    std::fs::create_dir_all(&work).unwrap();
    let state_dir = tmp.path().join("state");

    let output = firma()
        .current_dir(&work)
        .args([
            "config",
            "--yes",
            "--output-dir",
            "../config",
            "--state-dir",
        ])
        .arg(&state_dir)
        .output()
        .expect("spawn firma config");
    assert!(
        output.status.success(),
        "init (relative) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let firma_toml = work.join("../config/firma.toml");
    assert!(
        firma_toml.is_file(),
        "firma.toml does not exist: {}",
        firma_toml.display()
    );
    assert_unified_config_parses(&firma_toml);
}

#[cfg(unix)]
#[test]
fn init_writes_sensitive_dirs_with_mode_0700() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    for path in [
        &config_dir,
        &config_dir.join("policies"),
        &config_dir.join("issuance-policies"),
        &state_dir,
        &state_dir.join("generated-firma-ca"),
    ] {
        let mode = std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o700,
            "expected {} to be mode 0700, got {mode:o}",
            path.display()
        );
    }
}
