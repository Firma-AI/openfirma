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
    let sidecar: firma_sidecar::config::SidecarConfig = toml::from_str(&sbody)
        .unwrap_or_else(|e| panic!("[sidecar] deserialize: {e}\n---\n{sbody}"));

    // A fresh `firma config` must produce a sidecar config that starts
    // cleanly under standalone `firma sidecar --config` — i.e. it must pass
    // strict validation, not merely deserialize. Guards against an empty
    // `https_mitm.intercept_hosts` being treated as fatal.
    sidecar
        .validate()
        .unwrap_or_else(|e| panic!("[sidecar] validate: {e}\n---\n{sbody}"));
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
    // Add a custom env_set key inside [run.profiles.generic.env_set] so the
    // merge contract test can verify it survives subsequent firma config runs.
    let mut existing_firma_toml_text = std::fs::read_to_string(&firma_toml_path).unwrap();
    existing_firma_toml_text = existing_firma_toml_text.replace(
        "FIRMA_RUN_BWRAP_ROOTFS_MODE = \"readonly\"",
        "FIRMA_RUN_BWRAP_ROOTFS_MODE = \"readonly\"\nCUSTOM_WRAPPER_DEFAULT = \"kept\"",
    );
    std::fs::write(
        &firma_toml_path,
        toml::to_string_pretty(&toml::from_str::<toml::Value>(&existing_firma_toml_text).unwrap())
            .unwrap(),
    )
    .unwrap();

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
    let firma_toml_out = extract_dry_run_file(&defaults.stdout, "firma.toml");
    let value: toml::Value = toml::from_str(&firma_toml_out).unwrap();
    assert_eq!(
        value["authority"]["listen_addr"].as_str(),
        Some("127.0.0.1:9555"),
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
        value["run"]["profiles"]["generic"]["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["source"].as_str() == Some(workspace.to_string_lossy().as_ref())),
        "workspace should be preserved in firma.toml [run.profiles.generic]:\n{firma_toml_out}"
    );
    assert!(
        firma_toml_out.contains("CUSTOM_WRAPPER_DEFAULT = \"kept\""),
        "existing wrapper config should be preserved when no wrapper flag overrides it:\n{firma_toml_out}"
    );

    let override_output = firma()
        .args(["config", "--yes", "--dry-run", "--output-dir"])
        .arg(&config_dir)
        .args([
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
    let firma_toml_out = extract_dry_run_file(&override_output.stdout, "firma.toml");
    let value: toml::Value = toml::from_str(&firma_toml_out).unwrap();
    assert_eq!(
        value["authority"]["listen_addr"].as_str(),
        Some("127.0.0.1:9666"),
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
        value["run"]["profiles"]["generic"]["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["source"].as_str() == Some(override_workspace.to_string_lossy().as_ref())),
        "workspace override should be rendered in firma.toml [run.profiles.generic]:\n{firma_toml_out}"
    );
    // toml_edit merge contract: workspace override changes only the
    // [[run.profiles.generic.mounts]] entry — independent env_set
    // customizations the operator added by hand survive.
    assert!(
        firma_toml_out.contains("CUSTOM_WRAPPER_DEFAULT = \"kept\""),
        "merge must preserve unrelated env_set customizations across workspace override:\n{firma_toml_out}"
    );
    // The previous workspace mount must be gone so the agent does not
    // accidentally retain RW access to the old path.
    assert!(
        !value["run"]["profiles"]["generic"]["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["source"].as_str() == Some(workspace.to_string_lossy().as_ref())),
        "previous workspace mount should be dropped on override:\n{firma_toml_out}"
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
    assert!(
        firma_toml.contains("# [sidecar.authority.credentials]"),
        "agent-remote scaffold should include commented Sidecar PSK guidance:\n{firma_toml}"
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
fn agent_remote_requires_connect_material_without_existing_defaults() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");

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
        .output()
        .expect("spawn incomplete remote firma config");

    assert!(
        !output.status.success(),
        "agent-remote without authority material must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--authority-url"),
        "error should name missing remote URL:\n{stderr}"
    );

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
        .args(["--authority-url", "https://authority.example.com:9443"])
        .output()
        .expect("spawn remote firma config without CA");
    assert!(
        !output.status.success(),
        "agent-remote without CA material must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--authority-ca-cert"),
        "error should name missing remote CA:\n{stderr}"
    );

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
        .arg(tmp.path().join("remote-ca.crt"))
        .output()
        .expect("spawn remote firma config without public key");
    assert!(
        !output.status.success(),
        "agent-remote without public key material must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--authority-pub-key"),
        "error should name missing remote public key:\n{stderr}"
    );
}

#[test]
fn agent_remote_to_local_switch_persists_authority_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    // Bootstrap as agent-remote first.
    let remote = firma()
        .args(["config", "--yes", "--mode", "agent-remote", "--output-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .args([
            "--authority-url",
            "https://authority.example.com:9443",
            "--authority-ca-cert",
        ])
        .arg(state_dir.join("remote-ca.crt"))
        .args(["--authority-pub-key"])
        .arg(state_dir.join("remote-authority.pub"))
        .output()
        .expect("spawn initial remote firma config");
    assert!(
        remote.status.success(),
        "initial remote config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&remote.stdout),
        String::from_utf8_lossy(&remote.stderr),
    );

    let firma_toml_path = config_dir.join("firma.toml");
    let before: toml::Value =
        toml::from_str(&std::fs::read_to_string(&firma_toml_path).unwrap()).unwrap();
    assert!(
        before.get("authority").is_none(),
        "agent-remote bootstrap must not write [authority]:\n{}",
        std::fs::read_to_string(&firma_toml_path).unwrap()
    );

    // Switch to agent-local. Merge contract: [authority] must be added
    // without requiring --force, because toml_edit merge is non-destructive
    // and the previous mode shape (just [sidecar.authority]) survives.
    let switch = firma()
        .args([
            "config",
            "--yes",
            "--mode",
            "agent-local",
            "--authority-listen",
            "127.0.0.1:9443",
            "--output-dir",
        ])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("spawn switch firma config");
    assert!(
        switch.status.success(),
        "switch to local failed: stdout={} stderr={}",
        String::from_utf8_lossy(&switch.stdout),
        String::from_utf8_lossy(&switch.stderr),
    );

    let after: toml::Value =
        toml::from_str(&std::fs::read_to_string(&firma_toml_path).unwrap()).unwrap();
    assert!(
        after.get("authority").is_some(),
        "switching to agent-local must persist [authority]:\n{}",
        std::fs::read_to_string(&firma_toml_path).unwrap()
    );
    assert_eq!(
        after["authority"]["listen_addr"].as_str(),
        Some("127.0.0.1:9443"),
    );
    // Remote connect coords must be replaced with local daemon coordinates.
    assert_eq!(
        after["sidecar"]["authority"]["url"].as_str(),
        Some("https://127.0.0.1:9443"),
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

/// A fresh `firma config` must scaffold a `firma.toml` whose `[sidecar]`
/// section starts cleanly standalone. Beyond `validate()` (covered by
/// [`assert_unified_config_parses`]) this pins the scaffold contract for the
/// interceptor listen address and the authority public-key path.
#[test]
fn scaffold_supports_standalone_sidecar_startup() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let firma_toml = config_dir.join("firma.toml");
    let text = std::fs::read_to_string(&firma_toml).unwrap();
    let value: toml::Value = toml::from_str(&text).unwrap();

    // interceptor listen_addr is scaffolded, so the stack readiness probe
    // (`read_sidecar_listen_addr`) and standalone bind both resolve.
    assert!(
        value["sidecar"]["interceptor"]["listen_addr"]
            .as_str()
            .is_some(),
        "scaffold must emit [sidecar.interceptor].listen_addr:\n{text}"
    );

    // The authority public key path must be present for capability-seed
    // verification.
    assert!(
        value["sidecar"]["authority"]["public_key_path"]
            .as_str()
            .is_some(),
        "scaffold must emit [sidecar.authority].public_key_path:\n{text}"
    );

    // No [sidecar.preflight] section must be emitted; that concept is removed.
    assert!(
        value["sidecar"].get("preflight").is_none(),
        "scaffold must not emit [sidecar.preflight]:\n{text}"
    );

    // The whole section must pass strict validation.
    let sbody = firma_config::load_section(&firma_toml, "sidecar").unwrap();
    let sidecar: firma_sidecar::config::SidecarConfig = toml::from_str(&sbody).unwrap();
    sidecar
        .validate()
        .unwrap_or_else(|e| panic!("standalone sidecar config invalid: {e}\n---\n{sbody}"));
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

/// Every shipped posture, scaffolded via the real `firma config` binary, must
/// pass the real `firma policy validate` binary — end-to-end through the CLI,
/// not just the library validator. Regression guard for FIR-190.
#[test]
fn scaffolded_postures_pass_cli_policy_validate() {
    for posture in ["strict", "dev", "dev-with-delete-watch"] {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let config_dir = tmp.path().join("config");
        let state_dir = tmp.path().join("state");

        let out = firma()
            .args(["config", "--yes", "--posture", posture, "--output-dir"])
            .arg(&config_dir)
            .args(["--state-dir"])
            .arg(&state_dir)
            .output()
            .expect("spawn firma config");
        assert!(
            out.status.success(),
            "`firma config --posture {posture}` failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );

        for rel in [
            format!("policies/{posture}.cedar"),
            "issuance-policies/issuance.cedar".to_string(),
        ] {
            let policy = config_dir.join(&rel);
            assert!(policy.is_file(), "scaffolded policy missing: {rel}");

            let v = firma()
                .args(["policy", "validate"])
                .arg(&policy)
                .output()
                .expect("spawn firma policy validate");
            assert!(
                v.status.success(),
                "`firma policy validate {rel}` expected exit 0, got {:?}; stderr: {}",
                v.status,
                String::from_utf8_lossy(&v.stderr),
            );
            assert!(
                String::from_utf8_lossy(&v.stdout).contains("OK"),
                "{rel}: validate stdout missing OK",
            );
        }
    }
}
