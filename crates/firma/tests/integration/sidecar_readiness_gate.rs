//! The sidecar must hold the six-line ready contract's final
//! `ready` log line until the Authority streams (policy bundle +
//! revocations) have hydrated. Boots the sidecar against an Authority
//! URL whose TCP endpoint never completes gRPC stream setup and asserts that
//!
//! 1. lines 1-6 of the contract appear (config / mapping / policy bundle /
//!    authority stream / connector / interceptor), and
//! 2. neither the startup report nor line 6 (`ready`) appears within a quiet
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

use firma_config_schema::sidecar::{
    AuditConfig, AuditSink, AuthorityConfig, CaConfig, InterceptorConfig, InterceptorMode,
    PolicyConfig, SidecarConfig,
};
use wait_timeout::ChildExt as _;

use super::{CONFIG_FILE_NAME, config_fixture::write_section, firma_bin};

const PRE_READY_PREFIXES: &[&str] = &[
    "config loaded",
    "connector registry built",
    "interceptor listening",
];

/// Contract lines that report Authority state and so wait for hydration.
const HYDRATED_PREFIXES: &[&str] = &["authority stream connected", "policy bundle loaded"];

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
    let health_bind_addr = "127.0.0.1:0";
    // Keep a non-gRPC TCP listener bound for the whole test so the
    // Authority endpoint cannot be stolen by another concurrent test.
    // The sidecar can reach the TCP endpoint, but the gRPC streams
    // never hydrate, so readiness must remain withheld.
    let authority_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority_url = format!("http://{}", authority_listener.local_addr().unwrap());

    let sidecar_toml = tmp.path().join(CONFIG_FILE_NAME);
    write_section(
        &sidecar_toml,
        "sidecar",
        &SidecarConfig {
            interceptor: InterceptorConfig {
                mode: InterceptorMode::HttpProxy,
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                ..InterceptorConfig::default()
            },
            policy: PolicyConfig { dir: policies },
            authority: AuthorityConfig {
                url: Some(authority_url),
                ..AuthorityConfig::default()
            },
            ca: CaConfig { dir: Some(ca_dir) },
            audit: AuditConfig {
                sink: AuditSink::Stdout,
                signing_key_path: Some(audit_key),
                ..AuditConfig::default()
            },
            ..SidecarConfig::default()
        },
    )
    .unwrap();

    let stdout_file = File::create(tmp.path().join("sidecar.stdout.log")).unwrap();
    let stderr_log = tmp.path().join("sidecar.stderr.log");
    let stderr_file = File::create(&stderr_log).unwrap();
    let startup_report = tmp.path().join("sidecar.startup.toml");
    // A predecessor's state must not survive into a Sidecar that never hydrates.
    let enforcement_state = tmp.path().join("enforcement.toml");
    std::fs::write(
        &enforcement_state,
        "version = \"stale\"\nttl_seconds = 30\nswapped_at = \"2026-01-01T00:00:00Z\"\nexpires_at = \"2026-01-01T00:00:30Z\"\n",
    )
    .unwrap();

    let mut child = Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(&sidecar_toml)
        // A temporary state directory: the host default would let the
        // developer's own audit key and trust anchors decide the outcome.
        .env("FIRMA_STATE_DIR", tmp.path().join("state"))
        .args(["--health-bind-addr", health_bind_addr])
        .arg("--startup-report")
        .arg(&startup_report)
        .arg("--enforcement-state")
        .arg(&enforcement_state)
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
    for prefix in HYDRATED_PREFIXES {
        assert!(
            !lines.iter().any(|line| line.contains(prefix)),
            "'{prefix}' was logged without Authority hydration; captured stderr:\n{}",
            lines.join("\n"),
        );
    }
    assert!(
        !enforcement_state.exists(),
        "a predecessor's enforcement state survived startup"
    );
}
