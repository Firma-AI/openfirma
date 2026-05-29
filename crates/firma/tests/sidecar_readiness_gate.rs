//! FIR-183: the sidecar must hold the seven-line ready contract's final
//! `ready` log line until the Authority streams (policy bundle +
//! revocations) have hydrated. Boots the sidecar against an Authority
//! URL with no responsive listener and asserts that
//!
//! 1. lines 1-6 of the contract appear (config / mapping / policy bundle /
//!    authority stream / connector / interceptor), and
//! 2. line 7 (`ready`) does NOT appear within a quiet observation
//!    window, because the readiness flag never flips.
//!
//! Pairs with `sidecar_startup_contract.rs`, which exercises the
//! no-Authority happy path where readiness is pre-seeded as true.

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

const PRE_READY_PREFIXES: &[&str] = &[
    "config loaded",
    "mapping table loaded",
    "policy bundle loaded",
    "authority stream connected",
    "connector registry built",
    "interceptor listening",
];

/// Generate a fresh P-256 signing key as PKCS#8 PEM at test time. Keeps a
/// real key out of the source tree (secret scanners flag committed PEM
/// blocks) while still exercising the audit signer's real key loader.
fn generate_audit_key_pem() -> String {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use rand::RngCore;

    let mut rng = rand::rng();
    loop {
        let mut scalar = [0u8; 32];
        rng.fill_bytes(&mut scalar);
        // A uniform 32-byte string is a valid P-256 scalar with
        // overwhelming probability; reject the rare out-of-range draw.
        if let Ok(key) = SigningKey::from_slice(&scalar) {
            return key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode signing key as pkcs8 pem")
                .to_string();
        }
    }
}

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
fn ready_is_withheld_until_authority_streams_hydrate() {
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
    std::fs::write(&audit_key, generate_audit_key_pem()).unwrap();

    let interceptor_port = pick_free_port();
    let health_port = pick_free_port();
    // Authority URL points at a closed loopback port: tonic keeps
    // retrying without ever connecting, so neither stream flips
    // readiness — the only way the sidecar emits `ready` is via the
    // gate this test is meant to verify.
    let authority_port = pick_free_port();
    let authority_url = format!("http://127.0.0.1:{authority_port}");

    let sidecar_toml = tmp.path().join("firma.toml");
    std::fs::write(
        &sidecar_toml,
        format!(
            r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:{interceptor_port}"
drain_timeout_secs = 30

[sidecar.policy]
dir = '{policies}'

[sidecar.authority]
url = "{authority_url}"

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
        .env("NO_COLOR", "1")
        .stdout(stdout_file)
        .stderr(stderr_file)
        .spawn()
        .expect("spawn firma sidecar");

    // Wait for the pre-ready prefixes to appear. A 5 s deadline is well
    // above the wall-clock these emissions need on CI hardware.
    let prefixes_deadline = Instant::now() + Duration::from_secs(5);
    let mut seen_idx = 0usize;
    while Instant::now() < prefixes_deadline && seen_idx < PRE_READY_PREFIXES.len() {
        std::thread::sleep(Duration::from_millis(100));
        let Ok(file) = File::open(&stderr_log) else {
            continue;
        };
        let lines: Vec<String> = BufReader::new(file).lines().map_while(Result::ok).collect();
        seen_idx = 0;
        for line in &lines {
            if seen_idx >= PRE_READY_PREFIXES.len() {
                break;
            }
            if line.contains(PRE_READY_PREFIXES[seen_idx]) {
                seen_idx += 1;
            }
        }
    }
    if seen_idx != PRE_READY_PREFIXES.len() {
        let lines: Vec<String> = BufReader::new(File::open(&stderr_log).unwrap())
            .lines()
            .map_while(Result::ok)
            .collect();
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "pre-ready contract incomplete; matched {seen_idx} of {}; stderr:\n{}",
            PRE_READY_PREFIXES.len(),
            lines.join("\n"),
        );
    }

    // Observe a quiet window: `ready` must not appear while the
    // Authority remains unreachable.
    std::thread::sleep(Duration::from_secs(2));
    let lines: Vec<String> = BufReader::new(File::open(&stderr_log).unwrap())
        .lines()
        .map_while(Result::ok)
        .collect();
    let ready_visible = lines.iter().any(|line| {
        let trimmed = line.trim_end();
        trimmed.ends_with(": ready") || trimmed == "ready"
    });

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !ready_visible,
        "sidecar emitted 'ready' before Authority streams hydrated; captured stderr:\n{}",
        lines.join("\n"),
    );
}
