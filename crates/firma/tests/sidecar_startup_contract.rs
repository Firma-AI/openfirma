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
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

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

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn firma_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

#[test]
fn emits_ready_sequence_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let policies = tmp.path().join("policies");
    std::fs::create_dir_all(&policies).unwrap();
    std::fs::write(
        policies.join("default.cedar"),
        "permit(principal, action, resource);",
    )
    .unwrap();

    let mapping = tmp.path().join("mapping-rules.toml");
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

    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();

    let audit_key = tmp.path().join("audit.key");
    std::fs::write(&audit_key, TEST_AUDIT_KEY_PEM).unwrap();

    let interceptor_port = pick_free_port();
    let health_port = pick_free_port();
    let sidecar_toml = tmp.path().join("firma.toml");
    std::fs::write(
        &sidecar_toml,
        format!(
            // Paths embedded as TOML literal strings (single quotes) so Windows
            // backslashes pass through verbatim instead of being interpreted as
            // escape sequences. Unified sectioned config: every sidecar
            // table is nested under `[sidecar.*]`.
            r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:{interceptor_port}"
drain_timeout_secs = 30

[sidecar.policy]
dir = '{policies}'

[sidecar.ca]
dir = '{ca}'

[sidecar.log]
level = "info"

[sidecar.mapping]
rules_path = '{mapping}'
default_protected = true

[sidecar.connector]
default_timeout_ms = 30000

[sidecar.audit]
sink = "stdout"
signing_key_path = '{audit_key}'
"#,
            policies = policies.display(),
            ca = ca_dir.display(),
            mapping = mapping.display(),
            audit_key = audit_key.display(),
        ),
    )
    .unwrap();

    let stdout_file = File::create(tmp.path().join("sidecar.stdout.log")).unwrap();
    let stderr_log = tmp.path().join("sidecar.stderr.log");
    let stderr_file = File::create(&stderr_log).unwrap();

    let mut child = Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(&sidecar_toml)
        .args(["--health-bind-addr", &format!("127.0.0.1:{health_port}")])
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
        if lines.iter().any(|l| l.contains("ready")) {
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
