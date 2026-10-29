//! Tests for `firma config`.
//!
//! Verifies that the scaffolded unified `firma.toml` is syntactically
//! valid and has the external configuration shape expected by users.
//! Regression guard for Windows path serialization: backslash-bearing paths
//! must not be emitted into TOML basic strings (where `\t`, `\s`, etc. are
//! invalid escape sequences).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::Path;
use std::process::Command;

use firma_http::{Authority, Method};
use firma_identifiers::AgentId;
use firma_sidecar::config::MappingRulesFile;
use firma_sidecar::enforcement::registry::ActionClassRegistry;
use firma_sidecar::normalizer::{MappingTable, MatchResult};

use super::CONFIG_FILE_NAME;

const REGISTERED_AGENT_ID: &str = "agt_01j0000000e008000000000001";

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

fn scaffold_mapping_table(
    config_dir: &Path,
) -> (firma_config_schema::sidecar::SidecarConfig, MappingTable) {
    let config: toml::Value = toml::from_str(
        &std::fs::read_to_string(config_dir.join(CONFIG_FILE_NAME)).expect("read config"),
    )
    .expect("parse config");
    let sidecar: firma_config_schema::sidecar::SidecarConfig = config["sidecar"]
        .clone()
        .try_into()
        .expect("parse Sidecar section");
    let authority: firma_config_schema::authority::AuthorityConfig = config["authority"]
        .clone()
        .try_into()
        .expect("parse Authority section");
    let mut merged = MappingRulesFile { rules: Vec::new() };
    for path in &authority.mapping_rules_paths {
        let text = std::fs::read_to_string(config_dir.join(path)).expect("read selected mapping");
        let file: MappingRulesFile = toml::from_str(&text).expect("parse selected mapping");
        merged.rules.extend(file.rules);
    }
    let table = MappingTable::from_config(&merged, &ActionClassRegistry::v0_1())
        .expect("build selected mapping table");
    (sidecar, table)
}

#[test]
fn vscode_scaffold_classifies_decrypted_github_requests() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");
    let output = firma()
        .args(["config", "--yes", "--profile", "vscode", "--output-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("spawn firma config");
    assert!(
        output.status.success(),
        "config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (sidecar, table) = scaffold_mapping_table(&config_dir);
    let mitm = &sidecar.interceptor.https_mitm;
    let host = Authority::from_static("api.github.com");
    assert!(mitm.enabled);
    assert_eq!(mitm.intercept_hosts, ["*"]);
    assert!(!mitm.bypass_hosts.contains(&host.to_string()));
    assert!(matches!(
        table.find_match(&Method::GET, &Authority::from_static("vscode.dev"), "/"),
        MatchResult::Matched(_)
    ));
    assert!(matches!(
        table.find_match(&Method::GET, &host, "/unknown-endpoint"),
        MatchResult::UnclassifiedProtected
    ));
    match table.find_match(
        &Method::GET,
        &host,
        "/repos/Firma-AI/firma-team/contents/README.md",
    ) {
        MatchResult::Matched(rule) => assert_eq!(rule.action_class, "code.read"),
        other @ MatchResult::UnclassifiedProtected => {
            panic!("VS Code's selected mappings must classify repository reads, got {other:?}")
        }
    }
}

#[test]
fn copilot_scaffold_upgrade_keeps_intercepted_requests_classifiable() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(config_dir.join("mappings")).expect("create mappings dir");
    std::fs::write(
        config_dir.join(CONFIG_FILE_NAME),
        format!(
            r#"[run]
profile = "copilot"
[sidecar.authority]
agent_id = "{REGISTERED_AGENT_ID}"
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.anthropic.com"]
strict_hosts = ["api.anthropic.com"]
bypass_hosts = ["github.com", "api.github.com", "uploads.github.com"]
[authority]
listen_addr = "127.0.0.1:50051"
mapping_rules_paths = ["mapping-rules.toml", "mappings/copilot.toml"]
"#
        ),
    )
    .expect("write previous config");
    std::fs::write(
        config_dir.join("mappings/copilot.toml"),
        r#"[[rules]]
method = "CONNECT"
host = "api.individual.githubcopilot.com"
action_class = "communication.external.send"
[[rules]]
method = "CONNECT"
host = "telemetry.individual.githubcopilot.com"
action_class = "communication.external.send"
[[rules]]
method = "CONNECT"
host = "api.github.com"
action_class = "code.write"
[[rules]]
method = "CONNECT"
host = "github.com"
action_class = "code.write"
[[rules]]
method = "CONNECT"
host = "uploads.github.com"
action_class = "communication.external.send"
"#,
    )
    .expect("write previous Copilot mapping");

    run_init(&config_dir, &state_dir);

    let (sidecar, table) = scaffold_mapping_table(&config_dir);
    let mitm = &sidecar.interceptor.https_mitm;
    let host = Authority::from_static("api.individual.githubcopilot.com");
    assert!(mitm.enabled);
    assert_eq!(mitm.intercept_hosts, ["*"]);
    assert_eq!(mitm.strict_hosts, ["*"]);
    assert!(!mitm.bypass_hosts.contains(&host.to_string()));
    assert!(matches!(
        table.find_match(&Method::CONNECT, &host, "/"),
        MatchResult::Matched(_)
    ));
    match table.find_match(&Method::POST, &host, "/chat/completions") {
        MatchResult::Matched(rule) => {
            assert_eq!(rule.action_class, "communication.external.send");
        }
        other @ MatchResult::UnclassifiedProtected => {
            panic!("upgrading the scaffold must preserve Copilot classification, got {other:?}")
        }
    }
}

#[test]
fn composio_mapping_leaves_interception_to_the_sidecar_default() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");
    let output = firma()
        .args([
            "config",
            "--yes",
            "--dry-run",
            "--mapping",
            "composio",
            "--output-dir",
        ])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("spawn firma config");
    assert!(
        output.status.success(),
        "config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let rendered = extract_dry_run_file(&output.stdout, CONFIG_FILE_NAME);
    let config: toml::Value = toml::from_str(&rendered).expect("parse rendered firma.toml");
    // The sidecar intercepts every host and fails closed by default, so the
    // generated config pins no interception keys for the selected mapping.
    assert!(
        config["sidecar"]["interceptor"].get("https_mitm").is_none(),
        "{rendered}"
    );
    assert_eq!(
        config["authority"]["mapping_rules_paths"][1].as_str(),
        Some("mappings/composio.toml")
    );

    let mapping = extract_dry_run_file(&output.stdout, "mappings/composio.toml");
    assert!(mapping.contains("/api/v3.1/tools/execute/*"));
    assert!(mapping.contains("/tool_router/v3/*/mcp"));
}

#[test]
fn rerun_clears_stale_interception_keys_from_a_parent_inline_table() {
    // A hand-written `interceptor = { ... }` inline table carries the same
    // keys as the block form. The re-run normalizes an inline `https_mitm`
    // table before dropping the managed interception keys, so it must do the
    // same one level up — otherwise the pinned posture either survives the
    // re-run or fails it entirely.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);
    let path = config_dir.join(CONFIG_FILE_NAME);
    let body = std::fs::read_to_string(&path).expect("read scaffolded config");
    let patched = body.replacen(
        "[sidecar]\n\n[sidecar.interceptor]\nmode = \"http_proxy\"\nlisten_addr = \"127.0.0.1:8080\"",
        "[sidecar]\ninterceptor = { mode = \"http_proxy\", listen_addr = \"127.0.0.1:8080\", \
         https_mitm = { enabled = false, intercept_hosts = [\"api.github.com\"] } }",
        1,
    );
    assert_ne!(
        patched, body,
        "expected a scaffolded interceptor block to rewrite"
    );
    std::fs::write(&path, patched).expect("write parent-inline config");

    run_init(&config_dir, &state_dir);
    let rerun = std::fs::read_to_string(&path).expect("read re-run config");
    let config: toml::Value = toml::from_str(&rerun).expect("parse re-run config");
    assert_eq!(
        config["sidecar"]["interceptor"]["mode"].as_str(),
        Some("http_proxy"),
        "{rerun}"
    );
    assert!(
        config["sidecar"]["interceptor"].get("https_mitm").is_none(),
        "stale inline interception keys must not survive a re-run: {rerun}"
    );
}

#[test]
fn rerun_does_not_duplicate_bypass_hosts_with_different_spelling() {
    // Host matching lowercases, so an existing bypass entry that differs from
    // a requested one only in spelling names the same host. Merging must not
    // append a duplicate for it.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    let output = firma()
        .args(["config", "--yes", "--mapping", "copilot", "--output-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("spawn firma config");
    assert!(
        output.status.success(),
        "config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let path = config_dir.join(CONFIG_FILE_NAME);
    let body = std::fs::read_to_string(&path).expect("read scaffolded config");
    let patched = body.replacen("\"api.github.com\"", "\"API.GitHub.COM\"", 1);
    assert_ne!(patched, body, "expected a copilot bypass entry to respell");
    std::fs::write(&path, &patched).expect("write respelled config");

    let output = firma()
        .args(["config", "--yes", "--mapping", "copilot", "--output-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("spawn firma config re-run");
    assert!(
        output.status.success(),
        "re-run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let rerun = std::fs::read_to_string(&path).expect("read re-run config");
    let config: toml::Value = toml::from_str(&rerun).expect("parse re-run config");
    let bypass: Vec<&str> = config["sidecar"]["interceptor"]["https_mitm"]["bypass_hosts"]
        .as_array()
        .expect("bypass_hosts array")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    let mut lowered: Vec<String> = bypass
        .iter()
        .map(|host| host.to_ascii_lowercase())
        .collect();
    lowered.sort();
    lowered.dedup();
    assert_eq!(
        lowered,
        vec!["api.github.com", "github.com", "uploads.github.com"],
        "re-run must not duplicate a bypass host over spelling: {rerun}"
    );
    assert_eq!(bypass.len(), 3, "no duplicate entries: {rerun}");
}

#[test]
fn remote_agent_id_is_persisted() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    let output = firma()
        .args([
            "config",
            "--yes",
            "--mode",
            "agent-remote",
            "--agent-id",
            REGISTERED_AGENT_ID,
            "--output-dir",
        ])
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
        .expect("spawn firma config");

    assert!(
        output.status.success(),
        "config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = std::fs::read_to_string(config_dir.join(CONFIG_FILE_NAME)).expect("read config");
    let config: toml::Value = toml::from_str(&body).expect("parse config");
    assert_eq!(
        config["sidecar"]["authority"]["agent_id"].as_str(),
        Some(REGISTERED_AGENT_ID)
    );
}

#[test]
fn new_local_config_generates_agent_id_and_rerun_preserves_it() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);
    let path = config_dir.join(CONFIG_FILE_NAME);
    let first_body = std::fs::read_to_string(&path).expect("read first config");
    let first: toml::Value = toml::from_str(&first_body).expect("parse first config");
    let generated = first["sidecar"]["authority"]["agent_id"]
        .as_str()
        .expect("generated agent id");
    generated
        .parse::<AgentId>()
        .expect("generated agent ID must be valid");

    run_init(&config_dir, &state_dir);
    let second_body = std::fs::read_to_string(&path).expect("read second config");
    let second: toml::Value = toml::from_str(&second_body).expect("parse second config");
    assert_eq!(
        second["sidecar"]["authority"]["agent_id"].as_str(),
        Some(generated)
    );
}

#[test]
fn remote_non_interactive_setup_requires_agent_id() {
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
        .args([
            "--authority-url",
            "https://authority.example.com:9443",
            "--authority-ca-cert",
        ])
        .arg(tmp.path().join("remote-ca.crt"))
        .args(["--authority-pub-key"])
        .arg(tmp.path().join("remote-authority.pub"))
        .output()
        .expect("spawn firma config");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--agent-id"),
        "error must identify the required flag: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn existing_config_without_agent_id_fails_without_mutation() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    let path = config_dir.join(CONFIG_FILE_NAME);
    let original =
        "[sidecar.authority]\nurl = \"http://127.0.0.1:50051\"\n\n[run]\nprofile = \"codex\"\n";
    std::fs::write(&path, original).expect("write legacy config");

    let output = firma()
        .args(["config", "--yes", "--mode", "agent-local", "--output-dir"])
        .arg(&config_dir)
        .output()
        .expect("spawn firma config");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--agent-id"));
    assert_eq!(
        std::fs::read_to_string(path).expect("read config"),
        original
    );
}

/// A removed `[sidecar.mapping]` table in a file that configures a local
/// Authority fails `firma config` with guidance toward that Authority's
/// mapping paths and leaves the file untouched.
#[test]
fn existing_legacy_sidecar_mapping_fails_without_mutation() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    let path = config_dir.join(CONFIG_FILE_NAME);
    let original = "[authority]\nlisten_addr = \"127.0.0.1:50051\"\n\n[sidecar.mapping]\nrules_path = \"mapping-rules.toml\"\n\n[sidecar.authority]\nagent_id = \"agt_01j0000000e008000000000001\"\nurl = \"http://127.0.0.1:50051\"\n\n[run]\nprofile = \"codex\"\n";
    std::fs::write(&path, original).expect("write legacy config");

    let output = firma()
        .args(["config", "--yes", "--mode", "agent-local", "--output-dir"])
        .arg(&config_dir)
        .output()
        .expect("spawn firma config");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let config_path = path.display().to_string();
    assert!(stderr.contains(&config_path), "{stderr}");
    insta::assert_snapshot!(stderr.replace(&config_path, "[CONFIG]"), @"[ERR]  merge [CONFIG]: firma.toml: `[sidecar.mapping]` is no longer supported because the Authority owns mappings; delete it and list its files in `[authority].mapping_rules_paths`");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read config"),
        original
    );
}

#[test]
fn explicit_agent_id_does_not_rewrite_invalid_existing_value() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    let path = config_dir.join(CONFIG_FILE_NAME);
    let original = "[sidecar.authority]\nagent_id = \"codex\"\nurl = \"http://127.0.0.1:50051\"\n\n[run]\nprofile = \"codex\"\n";
    std::fs::write(&path, original).expect("write invalid config");

    let output = firma()
        .args([
            "config",
            "--yes",
            "--mode",
            "agent-local",
            "--agent-id",
            REGISTERED_AGENT_ID,
            "--output-dir",
        ])
        .arg(&config_dir)
        .output()
        .expect("spawn firma config");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a valid agent TypeID"));
    assert_eq!(
        std::fs::read_to_string(path).expect("read config"),
        original
    );
}

fn assert_unified_config_parses(firma_toml: &Path) {
    let text = std::fs::read_to_string(firma_toml)
        .unwrap_or_else(|e| panic!("read {}: {e}", firma_toml.display()));
    toml::from_str::<toml::Value>(&text)
        .unwrap_or_else(|e| panic!("parse {}: {e}\n---\n{text}", firma_toml.display()));
}

#[test]
#[expect(clippy::too_many_lines, reason = "linear scenario test")]
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
    let firma_toml_path = config_dir.join(CONFIG_FILE_NAME);
    // Add a custom env_set key inside [run.profiles.generic.env_set] so the
    // merge contract test can verify it survives subsequent firma config runs.
    let mut existing_firma_toml_text = std::fs::read_to_string(&firma_toml_path).unwrap();
    existing_firma_toml_text = existing_firma_toml_text.replace(
        "FIRMA_RUN_BWRAP_ROOTFS_MODE = \"readonly\"",
        "FIRMA_RUN_BWRAP_ROOTFS_MODE = \"readonly\"\nCUSTOM_WRAPPER_DEFAULT = \"kept\"",
    );
    let mut existing: toml::Value = toml::from_str(&existing_firma_toml_text).unwrap();
    existing["authority"]["mapping_rules_paths"] = toml::Value::Array(
        [
            "mappings/github.toml",
            "mapping-rules.toml",
            "custom/github.toml",
            "other.toml",
            "mappings/github.toml",
            "mapping-rules.toml",
            "./custom/github.toml",
            "./mappings/github.toml",
        ]
        .into_iter()
        .map(|path| toml::Value::String(path.into()))
        .collect(),
    );
    std::fs::write(&firma_toml_path, toml::to_string_pretty(&existing).unwrap()).unwrap();

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
    let firma_toml_out = extract_dry_run_file(&defaults.stdout, CONFIG_FILE_NAME);
    let value: toml::Value = toml::from_str(&firma_toml_out).unwrap();
    assert_eq!(
        value["authority"]["listen_addr"].as_str(),
        Some("127.0.0.1:9555"),
    );
    assert_eq!(
        value["authority"]["mapping_rules_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>(),
        vec![
            "mapping-rules.toml",
            "custom/github.toml",
            "other.toml",
            "mappings/github.toml"
        ],
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
    let firma_toml_out = extract_dry_run_file(&override_output.stdout, CONFIG_FILE_NAME);
    let value: toml::Value = toml::from_str(&firma_toml_out).unwrap();
    assert_eq!(
        value["authority"]["listen_addr"].as_str(),
        Some("127.0.0.1:9666"),
    );
    assert_eq!(
        value["authority"]["mapping_rules_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>(),
        vec![
            "mapping-rules.toml",
            "custom/github.toml",
            "other.toml",
            "mappings/openai.toml"
        ],
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
            "--agent-id",
            REGISTERED_AGENT_ID,
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

    let firma_toml = extract_dry_run_file(&output.stdout, CONFIG_FILE_NAME);
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
            "--agent-id",
            REGISTERED_AGENT_ID,
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
            "--agent-id",
            REGISTERED_AGENT_ID,
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
            "--agent-id",
            REGISTERED_AGENT_ID,
            "--output-dir",
        ])
        .arg(&config_dir)
        .args(["--authority-url", "https://authority.example.com:9443"])
        .output()
        .expect("spawn remote firma config without CA or public key");
    assert!(
        !output.status.success(),
        "agent-remote without public key material must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--authority-pub-key") && !stderr.contains("--authority-ca-cert"),
        "only the public key is required; the CA is optional:\n{stderr}"
    );
}

/// Run `firma config --yes --mode agent-remote` against `config_dir` with
/// `extra` arguments; returns stderr and the written `[sidecar.authority]`.
fn configure_remote(config_dir: &Path, state_dir: &Path, extra: &[&str]) -> (String, toml::Value) {
    let output = firma()
        .args([
            "config",
            "--yes",
            "--mode",
            "agent-remote",
            "--agent-id",
            REGISTERED_AGENT_ID,
            "--output-dir",
        ])
        .arg(config_dir)
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--authority-pub-key")
        .arg(state_dir.join("remote-authority.pub"))
        .args(extra)
        .output()
        .expect("spawn firma config");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "config failed: {stderr}");
    let body = std::fs::read_to_string(config_dir.join(CONFIG_FILE_NAME)).expect("read config");
    let config: toml::Value = toml::from_str(&body).expect("parse config");
    (stderr, config["sidecar"]["authority"].clone())
}

/// A publicly trusted Authority needs only its URL: no CA is written, so the
/// Sidecar verifies it against the platform's trusted roots.
#[test]
fn agent_remote_without_a_ca_writes_none() {
    let tmp = tempfile::tempdir().expect("tmpdir");

    let (_, authority) = configure_remote(
        &tmp.path().join("config"),
        &tmp.path().join("state"),
        &["--authority-url", "https://authority.example.com:9443"],
    );

    assert_eq!(
        authority["url"].as_str(),
        Some("https://authority.example.com:9443")
    );
    assert!(authority.get("ca_cert_paths").is_none(), "got: {authority}");
}

/// A configured CA belongs to its Authority endpoint, whatever the URL
/// spelling: a rerun for the same host and port keeps it, and one for another
/// port neither inherits it nor drops it silently.
#[test]
fn agent_remote_reuses_a_ca_only_for_the_same_authority() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");
    let ca = state_dir.join("remote-ca.crt");
    let ca = ca.to_str().expect("utf-8 path");
    configure_remote(
        &config_dir,
        &state_dir,
        &[
            "--authority-url",
            "https://authority.example.com:9443",
            "--authority-ca-cert",
            ca,
        ],
    );

    let (stderr, same) = configure_remote(
        &config_dir,
        &state_dir,
        &["--authority-url", "https://AUTHORITY.example.com:9443/"],
    );
    assert_eq!(same["ca_cert_paths"][0].as_str(), Some(ca));
    assert!(!stderr.contains("is not reused"), "{stderr}");

    // A blank flag is refused rather than read as "no CA", which would drop
    // the pin for the same Authority without a warning.
    let blank = firma()
        .args(["config", "--yes", "--mode", "agent-remote", "--output-dir"])
        .arg(&config_dir)
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--authority-ca-cert", " "])
        .output()
        .expect("spawn firma config");
    assert!(!blank.status.success());
    insta::assert_snapshot!(String::from_utf8_lossy(&blank.stderr).trim(), @"[ERR]  --authority-ca-cert must not be empty");

    let (stderr, other) = configure_remote(
        &config_dir,
        &state_dir,
        &["--authority-url", "https://AUTHORITY.example.com:9444/"],
    );
    assert!(other.get("ca_cert_paths").is_none(), "got: {other}");
    let warning = stderr.lines().next().expect("a warning");
    assert!(warning.contains(ca), "{stderr}");
    insta::assert_snapshot!(warning.replace(ca, "[CA]"), @"[WARN] the existing CA certificate [CA] is not reused for https://AUTHORITY.example.com:9444/: it was configured for another Authority; set a CA certificate if this one needs it");

    // Another Authority with its own CA: the new pin is written, and nothing
    // is said about the old one.
    let other_ca = state_dir.join("other-ca.crt");
    let other_ca = other_ca.to_str().expect("utf-8 path");
    let (stderr, pinned) = configure_remote(
        &config_dir,
        &state_dir,
        &[
            "--authority-url",
            "https://authority.example.com:9445",
            "--authority-ca-cert",
            other_ca,
        ],
    );
    assert_eq!(pinned["ca_cert_paths"][0].as_str(), Some(other_ca));
    assert!(!stderr.contains("is not reused"), "{stderr}");
}

#[test]
fn agent_remote_to_local_switch_persists_authority_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    // Bootstrap as agent-remote first.
    let remote = firma()
        .args([
            "config",
            "--yes",
            "--mode",
            "agent-remote",
            "--agent-id",
            REGISTERED_AGENT_ID,
            "--output-dir",
        ])
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

    let firma_toml_path = config_dir.join(CONFIG_FILE_NAME);
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
    let firma_toml = extract_dry_run_file(&output.stdout, CONFIG_FILE_NAME);
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

    let firma_toml = config_dir.join(CONFIG_FILE_NAME);
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

/// Pins the externally visible settings required for standalone Sidecar use.
/// `sidecar_start_scaffold` separately launches the generated configuration.
#[test]
fn scaffold_contains_standalone_sidecar_settings() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let firma_toml = config_dir.join(CONFIG_FILE_NAME);
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

    // The authority public key is adopted from the state directory, where this
    // same run generated it, so the scaffold must not name it.
    assert!(
        value["sidecar"]["authority"]
            .get("public_key_path")
            .is_none(),
        "scaffold must not emit [sidecar.authority].public_key_path:\n{text}"
    );

    // No [sidecar.preflight] section must be emitted; that concept is removed.
    assert!(
        value["sidecar"].get("preflight").is_none(),
        "scaffold must not emit [sidecar.preflight]:\n{text}"
    );
}

/// Nothing in the generated file points at a custom state dir, so scaffolding
/// into one without exporting `FIRMA_STATE_DIR` produces a config the processes
/// cannot start from. Say so at scaffold time.
#[test]
fn a_non_default_state_dir_warns_about_firma_state_dir() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    let output = firma()
        .args(["config", "--yes", "--output-dir"])
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .expect("spawn firma config");
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FIRMA_STATE_DIR") && stderr.contains(&state_dir.display().to_string()),
        "expected a state-dir warning naming the export, got: {stderr}"
    );
}

/// The warning is about reaching a directory the processes will not resolve,
/// not about the spelling of the flag. A relative `--state-dir` naming the very
/// directory `FIRMA_STATE_DIR` already points at is the default, so scaffolding
/// there must stay quiet.
#[test]
fn a_relative_state_dir_matching_the_default_stays_quiet() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let work = tmp.path();

    // Both spellings name the same directory; only the flag reaches the
    // warning unresolved. Keeping both relative also keeps the comparison off
    // the host's path conventions, which differ per platform once a path is
    // canonicalized.
    let output = firma()
        .args(["config", "--yes", "--output-dir"])
        .arg(work.join("config"))
        .args(["--state-dir", "state"])
        .current_dir(work)
        .env("FIRMA_STATE_DIR", "./state")
        .output()
        .expect("spawn firma config");
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("FIRMA_STATE_DIR"),
        "expected no state-dir warning, got: {stderr}"
    );
}

/// The generated config names no artifact path at all: every one of these has
/// a default that resolves to the position this same run generated the material
/// at. Writing them would pin the file to this machine.
#[test]
fn init_writes_no_artifact_paths() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let text = std::fs::read_to_string(config_dir.join(CONFIG_FILE_NAME)).unwrap();
    let value: toml::Value = toml::from_str(&text).unwrap();

    for (section, key) in [
        (vec!["authority"], "key_file"),
        (vec!["authority"], "revocation_file"),
        (vec!["authority"], "tls_cert_path"),
        (vec!["authority"], "tls_key_path"),
        (vec!["sidecar", "ca"], "dir"),
        (vec!["sidecar", "audit"], "file_path"),
        (vec!["sidecar", "audit"], "signing_key_path"),
        (vec!["sidecar", "authority"], "ca_cert_paths"),
        (vec!["sidecar", "authority"], "public_key_path"),
    ] {
        let mut node = Some(&value);
        for part in &section {
            node = node.and_then(|value| value.get(part));
        }
        let Some(node) = node else {
            continue;
        };
        assert!(
            node.get(key).is_none(),
            "[{}].{key} must not be written:\n{text}",
            section.join(".")
        );
    }
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

#[expect(
    clippy::too_many_lines,
    reason = "the table exhaustively exercises strict section rejection and no-write effects"
)]
#[test]
fn invalid_existing_sections_fail_without_writing() {
    let cases = [
        (
            "authority scalar removed in remote mode",
            "agent-remote",
            "[authority]\nmax_ttl_seconds = 3600\n",
            "max_ttl_seconds",
        ),
        (
            "sidecar scalar removed in authority mode",
            "authority",
            "[sidecar.interceptor]\nmax_request_body_size = 4194304\n",
            "max_request_body_size",
        ),
        (
            "run scalar overwritten in agent mode",
            "agent-local",
            "[run.profiles.generic.capability]\ngrace_seconds = 30\n",
            "grace_seconds",
        ),
        (
            "invalid user-driven authority field",
            "authority",
            "[authority]\nlisten_addr = 42\n",
            "listen_addr",
        ),
        (
            "unknown top-level section",
            "authority",
            "[project]\nagent = \"codex\"\n",
            "unknown top-level key `project`",
        ),
        (
            "flat capability source in defaults",
            "agent-local",
            "[run.defaults.capability]\nkind = \"file\"\npath = \"capability.toml\"\n",
            "unknown field `kind`",
        ),
        (
            "flat capability source in named profile",
            "agent-local",
            "[run.profiles.unselected.capability]\nkind = \"disabled\"\n",
            "unknown field `kind`",
        ),
        (
            "flat capability source in inline profile",
            "agent-local",
            "[run.profiles]\nunselected = { capability = { kind = \"file\", path = \"capability.toml\" } }\n",
            "unknown field `kind`",
        ),
        (
            "flat capability source beside tagged source",
            "agent-local",
            "[run.defaults.capability]\nkind = \"file\"\npath = \"discarded.toml\"\nsource = { kind = \"disabled\" }\n",
            "unknown field `kind`",
        ),
        (
            "malformed flat capability source",
            "agent-local",
            "[run.defaults.capability]\nkind = 42\n",
            "unknown field `kind`",
        ),
        (
            "Codex policy alias in defaults",
            "agent-local",
            "[run.defaults.codex_cli]\napproval_policy = \"never\"\n",
            "unknown field `codex_cli`",
        ),
        (
            "Codex policy alias in named profile",
            "agent-local",
            "[run.profiles.unselected.codex_cli]\napproval_policy = \"never\"\n",
            "unknown field `codex_cli`",
        ),
        (
            "Codex policy alias in inline profile",
            "agent-local",
            "[run.profiles]\nunselected = { codex_cli = { approval_policy = \"never\" } }\n",
            "unknown field `codex_cli`",
        ),
        (
            "Codex policy alias beside executable policy",
            "agent-local",
            "[run.defaults.codex_cli]\napproval_policy = \"never\"\n\n[run.defaults.executable_policies.codex]\napproval_policy = \"on-request\"\n",
            "unknown field `codex_cli`",
        ),
        (
            "malformed Codex policy alias",
            "agent-local",
            "[run.defaults]\ncodex_cli = 42\n",
            "unknown field `codex_cli`",
        ),
        (
            "removed capability action list in defaults",
            "agent-local",
            "[run.defaults.capability]\nrequested_actions = [\"filesystem.read\"]\n",
            "unknown field `requested_actions`",
        ),
        (
            "removed capability action list in inline profile",
            "agent-local",
            "[run.profiles]\nunselected = { capability = { requested_actions = [] } }\n",
            "unknown field `requested_actions`",
        ),
    ];

    for (name, mode, original, expected) in cases {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let config_dir = tmp.path().join("config");
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&config_dir).expect("create config dir");
        let config_path = config_dir.join(CONFIG_FILE_NAME);
        let sentinel_path = config_dir.join("sentinel");
        std::fs::write(&config_path, original).expect("write invalid config");
        std::fs::write(&sentinel_path, "unchanged").expect("write sentinel");

        let mut command = firma();
        command
            .args(["config", "--yes", "--mode", mode, "--output-dir"])
            .arg(&config_dir)
            .args(["--state-dir"])
            .arg(&state_dir);
        match mode {
            "agent-local" => {
                command.args(["--agent-id", REGISTERED_AGENT_ID]);
            }
            "agent-remote" => {
                command
                    .args(["--agent-id", REGISTERED_AGENT_ID])
                    .args(["--authority-url", "https://authority.example.com:9443"])
                    .args(["--authority-ca-cert"])
                    .arg(tmp.path().join("authority-ca.crt"))
                    .args(["--authority-pub-key"])
                    .arg(tmp.path().join("authority.pub"));
            }
            "authority" => {}
            other => panic!("unexpected test mode {other}"),
        }
        let output = command.output().expect("spawn firma config");

        assert!(!output.status.success(), "{name} unexpectedly succeeded");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "{name}: expected {expected:?} in stderr:\n{stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("read config"),
            original,
            "{name}: firma.toml changed"
        );
        assert_eq!(
            std::fs::read_to_string(&sentinel_path).expect("read sentinel"),
            "unchanged",
            "{name}: surrounding config state changed"
        );
        assert!(!state_dir.exists(), "{name}: state directory was created");
        let mut entries = std::fs::read_dir(&config_dir)
            .expect("read config dir")
            .map(|entry| entry.expect("read entry").file_name())
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(
            entries,
            [
                std::ffi::OsString::from(CONFIG_FILE_NAME),
                std::ffi::OsString::from("sentinel")
            ],
            "{name}: config directory contents changed"
        );
    }
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
/// not just the library validator.
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

/// The Authority is the only owner of mapping inputs, so a standalone
/// Authority scaffold must publish the mappings the operator selected. Dropping
/// them leaves every connected Sidecar denying that traffic as unclassified.
#[test]
fn authority_mode_publishes_selected_mappings() {
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
            "--mapping",
            "anthropic",
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

    let firma_toml = extract_dry_run_file(&output.stdout, CONFIG_FILE_NAME);
    let value: toml::Value = toml::from_str(&firma_toml).unwrap();
    let paths = value["authority"]["mapping_rules_paths"]
        .as_array()
        .unwrap_or_else(|| panic!("missing Authority mapping paths:\n{firma_toml}"));
    assert!(
        paths
            .iter()
            .any(|path| path.as_str() == Some("mappings/anthropic.toml")),
        "selected mapping is not published by the Authority:\n{firma_toml}"
    );
    let anthropic = extract_dry_run_file(&output.stdout, "mappings/anthropic.toml");
    assert!(anthropic.contains("anthropic.com"), "{anthropic}");
}

/// Without a local Authority nothing publishes generated mapping rules, so a
/// remote Sidecar scaffold must refuse inputs that only produce them instead of
/// writing files no configuration reads.
#[test]
fn agent_remote_rejects_extra_hosts_that_only_a_local_authority_publishes() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let output = firma()
        .args([
            "config",
            "--yes",
            "--dry-run",
            "--mode",
            "agent-remote",
            "--agent-id",
            REGISTERED_AGENT_ID,
            "--extra-hosts",
            "api.example.test",
            "--authority-url",
            "https://authority.example.com:9443",
            "--output-dir",
        ])
        .arg(tmp.path().join("config"))
        .args(["--state-dir"])
        .arg(tmp.path().join("state"))
        .args(["--authority-ca-cert"])
        .arg(tmp.path().join("remote-ca.crt"))
        .args(["--authority-pub-key"])
        .arg(tmp.path().join("remote-authority.pub"))
        .output()
        .expect("spawn remote firma config");

    assert!(
        !output.status.success(),
        "remote scaffold accepted extra hosts"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--mapping and --extra-hosts are local Authority options"),
        "{stderr}"
    );
}
