//! FIR-183: the sidecar must hold the seven-line ready contract's final
//! `ready` log line until the Authority streams (policy bundle +
//! revocations) have hydrated. Boots the sidecar against an Authority
//! URL whose TCP endpoint never completes gRPC stream setup and asserts that
//!
//! 1. lines 1-6 of the contract appear (config / mapping / policy bundle /
//!    authority stream / connector / interceptor), and
//! 2. neither the startup report nor line 7 (`ready`) appears within a quiet
//!    observation window, because the readiness flag never flips.
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

use super::CONFIG_FILE_NAME;
use wait_timeout::ChildExt as _;

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

    // Let the sidecar bind its own ephemeral ports. Pre-selecting a
    // "free" port here is racy once the listener is dropped.
    let interceptor_listen_addr = "127.0.0.1:0";
    let health_bind_addr = "127.0.0.1:0";
    // Keep a non-gRPC TCP listener bound for the whole test so the
    // Authority endpoint cannot be stolen by another concurrent test.
    // The sidecar can reach the TCP endpoint, but the gRPC streams
    // never hydrate, so readiness must remain withheld.
    let authority_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority_url = format!("http://{}", authority_listener.local_addr().unwrap());

    let sidecar_toml = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(
        &sidecar_toml,
        format!(
            r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "{interceptor_listen_addr}"
drain_timeout = "30s"

[sidecar.policy]
dir = '{policies}'

[sidecar.authority]
url = "{authority_url}"

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
"#,
            policies = policies.display(),
            ca = ca_dir.display(),
            mapping = mapping.display(),
            audit_key = audit_key.display(),
            interceptor_listen_addr = interceptor_listen_addr,
        ),
    )
    .unwrap();

    let stdout_file = File::create(tmp.path().join("sidecar.stdout.log")).unwrap();
    let stderr_log = tmp.path().join("sidecar.stderr.log");
    let stderr_file = File::create(&stderr_log).unwrap();
    let startup_report = tmp.path().join("sidecar.startup.toml");

    let mut child = Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(&sidecar_toml)
        .args(["--health-bind-addr", health_bind_addr])
        .arg("--startup-report")
        .arg(&startup_report)
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
        let status = child.try_wait().unwrap();
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "pre-ready contract incomplete; matched {seen_idx} of {}; child_status={status:?}; stderr:\n{}",
            PRE_READY_PREFIXES.len(),
            lines.join("\n"),
        );
    }

    // Observe a quiet window: `ready` must not appear while the
    // Authority streams never hydrate.
    std::thread::sleep(Duration::from_secs(2));
    #[cfg(unix)]
    {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("sidecar PID fits"));
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM)
            .expect("send termination signal to firma sidecar");
    }
    #[cfg(windows)]
    child.kill().expect("terminate firma sidecar");
    let status = child
        .wait_timeout(Duration::from_secs(10))
        .expect("wait for firma sidecar")
        .unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("firma sidecar did not exit after SIGTERM");
        });
    #[cfg(unix)]
    assert!(status.success(), "firma sidecar exited uncleanly: {status}");
    #[cfg(windows)]
    let _ = status;

    let lines: Vec<String> = BufReader::new(File::open(&stderr_log).unwrap())
        .lines()
        .map_while(Result::ok)
        .collect();
    let ready_visible = lines
        .iter()
        .any(|line| line.trim_end().contains("sidecar ready"));

    assert!(
        !ready_visible,
        "sidecar emitted 'ready' before exiting without Authority hydration; captured stderr:\n{}",
        lines.join("\n"),
    );
    assert!(
        !startup_report.exists(),
        "sidecar published its startup report before exiting without Authority hydration"
    );
}
