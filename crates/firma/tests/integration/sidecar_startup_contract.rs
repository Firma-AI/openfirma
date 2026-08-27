//! Locks the seven-line standalone-startup log contract.
//!
//! Boots the sidecar binary against a temp directory + a deny-all
//! Cedar bundle (so policy.dir resolves) and asserts that stderr
//! contains the contract's INFO lines in order with the documented
//! prefixes. A regression in any of `startup::log_contract`,
//! `startup::pipeline`, or `main::emit_ready_sequence` will fail this
//! test before reaching the demo path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code: panics are acceptable test failures"
)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::Command;
use std::time::{Duration, Instant};

use super::CONFIG_FILE_NAME;

const CONTRACT_PREFIXES: &[&str] = &[
    "config loaded",
    "mapping table loaded",
    "policy bundle loaded",
    "authority stream connected",
    "connector registry built",
    "interceptor listening",
    "ready",
];

const TEST_AUDIT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----
";

fn firma_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

struct StartupFixture {
    temp_dir: tempfile::TempDir,
    config_path: std::path::PathBuf,
}

fn startup_fixture(extra_config: &str) -> StartupFixture {
    let temp_dir = tempfile::tempdir().unwrap();
    let policies = temp_dir.path().join("policies");
    std::fs::create_dir_all(&policies).unwrap();
    std::fs::write(
        policies.join("default.cedar"),
        "permit(principal, action, resource);",
    )
    .unwrap();

    let mapping = temp_dir.path().join("mapping-rules.toml");
    std::fs::write(
        &mapping,
        r#"[[rules]]
method       = "GET"
host         = "example.test"
path         = "*"
action_class = "communication.external.send"
"#,
    )
    .unwrap();

    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();

    let audit_key = temp_dir.path().join("audit.key");
    std::fs::write(&audit_key, TEST_AUDIT_KEY_PEM).unwrap();

    let config_path = temp_dir.path().join(CONFIG_FILE_NAME);
    std::fs::write(
        &config_path,
        format!(
            // Paths embedded as TOML literal strings (single quotes) so Windows
            // backslashes pass through verbatim instead of being interpreted as
            // escape sequences. Unified sectioned config: every sidecar
            // table is nested under `[sidecar.*]`.
            r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:0"
drain_timeout = "30s"

[sidecar.policy]
dir = '{policies}'

[sidecar.ca]
dir = '{ca}'

[sidecar.mapping]
rules_path = '{mapping}'
default_protected = true

[sidecar.connector]
default_timeout_ms = 30000

[sidecar.audit]
sink = "stdout"
signing_key_path = '{audit_key}'

{extra_config}
"#,
            policies = policies.display(),
            ca = ca_dir.display(),
            mapping = mapping.display(),
            audit_key = audit_key.display(),
        ),
    )
    .unwrap();

    StartupFixture {
        temp_dir,
        config_path,
    }
}

#[test]
fn emits_ready_sequence_in_order() {
    let fixture = startup_fixture("");
    let health_bind_addr = "127.0.0.1:0";

    let stdout_file = File::create(fixture.temp_dir.path().join("sidecar.stdout.log")).unwrap();
    let stderr_log = fixture.temp_dir.path().join("sidecar.stderr.log");
    let stderr_file = File::create(&stderr_log).unwrap();

    let mut child = Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(&fixture.config_path)
        .args(["--health-bind-addr", health_bind_addr])
        .stdout(stdout_file)
        .stderr(stderr_file)
        .spawn()
        .expect("spawn firma sidecar");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut lines: Vec<String> = Vec::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
        let Ok(file) = File::open(&stderr_log) else {
            continue;
        };
        lines = BufReader::new(file).lines().map_while(Result::ok).collect();
        if lines.iter().any(|l| l.contains("sidecar ready")) {
            break;
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let mut idx = 0usize;
    for line in &lines {
        if idx >= CONTRACT_PREFIXES.len() {
            break;
        }
        if line.contains(CONTRACT_PREFIXES[idx]) {
            idx += 1;
        }
    }
    assert!(
        idx == CONTRACT_PREFIXES.len(),
        "contract sequence missing or out of order; matched {} of {}; captured stderr:\n{}",
        idx,
        CONTRACT_PREFIXES.len(),
        lines.join("\n"),
    );
}

#[test]
fn invalid_secret_provider_matcher_prevents_readiness() {
    let fixture = startup_fixture(
        r#"
[[sidecar.http_secret_providers]]
provider_id = "broken-vault"
host = "vault.example.test"

[[sidecar.http_secret_providers.matchers]]
type = "sensitive_command"
path = "/v1/secrets"

[sidecar.http_secret_providers.matchers.matcher]
type = "regex"
pattern = "no_named_groups_here"
"#,
    );

    let output = Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(&fixture.config_path)
        .args(["--health-bind-addr", "127.0.0.1:0"])
        .env("FIRMA_SECRET_GATEWAY_ADDR", "tcp://127.0.0.1:1")
        .output()
        .expect("spawn firma sidecar");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "an invalid sensitive-provider matcher must reject startup; stderr: {stderr}"
    );
    assert!(
        stderr.contains(
            "invalid secret provider config for \"broken-vault\": regex matcher must contain a \
             named `value` capture group, found"
        ),
        "startup diagnostic must identify the invalid provider and matcher: {stderr}"
    );
    assert!(
        !stderr.contains("sidecar ready"),
        "the Sidecar must not report readiness after rejecting its provider config: {stderr}"
    );
}
