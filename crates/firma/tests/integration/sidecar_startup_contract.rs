//! Locks the six-line standalone-startup log contract.
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

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write as _};
use std::process::Command;
use std::time::{Duration, Instant};

use firma_config_schema::sidecar::{
    AuditConfig, AuditSink, CaConfig, InterceptorConfig, InterceptorMode, PolicyConfig,
    SidecarConfig,
};
use firma_secret_provider::gateway::client::GATEWAY_ADDR_ENV;

use super::{CONFIG_FILE_NAME, config_fixture::write_section, firma_bin};

const CONTRACT_PREFIXES: &[&str] = &[
    "config loaded",
    "connector registry built",
    "interceptor listening",
    "authority stream connected endpoint=",
    "policy bundle loaded",
    "ready",
];

const TEST_AUDIT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----
";

pub struct StartupFixture {
    authority: super::authority_fixture::LocalAuthority,
    pub temp_dir: tempfile::TempDir,
    pub config_path: std::path::PathBuf,
}

pub fn startup_fixture(configure: impl FnOnce(&mut SidecarConfig)) -> StartupFixture {
    startup_fixture_with_authority(|_| {}, configure)
}

fn startup_fixture_with_authority(
    configure_authority: impl FnOnce(&mut firma_config_schema::authority::AuthorityConfig),
    configure: impl FnOnce(&mut SidecarConfig),
) -> StartupFixture {
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
    let authority = super::authority_fixture::LocalAuthority::start_configured(
        temp_dir.path(),
        &policies,
        &mapping,
        configure_authority,
    )
    .unwrap();
    let mut config = SidecarConfig {
        interceptor: InterceptorConfig {
            mode: InterceptorMode::HttpProxy,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..InterceptorConfig::default()
        },
        policy: PolicyConfig { dir: policies },
        ca: CaConfig { dir: Some(ca_dir) },
        authority: firma_config_schema::sidecar::AuthorityConfig {
            url: Some(authority.url.clone()),
            public_key_path: Some(authority.public_key.clone()),
            ..Default::default()
        },
        audit: AuditConfig {
            sink: AuditSink::Stdout,
            signing_key_path: Some(audit_key),
            ..AuditConfig::default()
        },
        ..SidecarConfig::default()
    };
    configure(&mut config);
    write_section(&config_path, "sidecar", &config).unwrap();

    StartupFixture {
        authority,
        temp_dir,
        config_path,
    }
}

fn startup_fixture_with_invalid_extra(extra_config: &str) -> StartupFixture {
    let fixture = startup_fixture(|_| {});
    let mut document: toml::Table =
        toml::from_str(&std::fs::read_to_string(&fixture.config_path).expect("read typed config"))
            .expect("parse typed config");
    document["sidecar"]
        .as_table_mut()
        .expect("sidecar section")
        .remove("http_secret_providers");
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&fixture.config_path)
        .unwrap();
    write!(
        file,
        "{}\n{extra_config}\n",
        toml::to_string(&document).unwrap()
    )
    .unwrap();
    fixture
}

#[test]
fn emits_ready_sequence_in_order() {
    let fixture = startup_fixture(|_| {});
    let health_bind_addr = "127.0.0.1:0";

    let stdout_file = File::create(fixture.temp_dir.path().join("sidecar.stdout.log")).unwrap();
    let stderr_log = fixture.temp_dir.path().join("sidecar.stderr.log");
    let stderr_file = File::create(&stderr_log).unwrap();
    let enforcement_state = fixture.temp_dir.path().join("enforcement.toml");

    let mut child = Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(&fixture.config_path)
        // A temporary state directory: the host default would let the
        // developer's own audit key and trust anchors decide the outcome.
        .env("FIRMA_STATE_DIR", fixture.temp_dir.path().join("state"))
        .args(["--health-bind-addr", health_bind_addr])
        .arg("--enforcement-state")
        .arg(&enforcement_state)
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

    // The standalone Authority versions bundles by SHA-256 hex digest.
    let loaded = lines
        .iter()
        .find(|line| line.contains("policy bundle loaded"))
        .expect("policy bundle loaded line");
    let version = loaded
        .split("version=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("policy bundle loaded carries the enforced version: {loaded}"));
    assert_eq!(version.len(), 64, "{loaded}");
    assert!(version.chars().all(|c| c.is_ascii_hexdigit()), "{loaded}");

    let state: toml::Table =
        toml::from_str(&std::fs::read_to_string(&enforcement_state).unwrap()).unwrap();
    assert_eq!(state["version"].as_str(), Some(version));
    assert_eq!(state["ttl_seconds"].as_integer(), Some(30));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&enforcement_state)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn invalid_secret_provider_matcher_prevents_readiness() {
    let fixture = startup_fixture_with_invalid_extra(
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
        .env("FIRMA_STATE_DIR", fixture.temp_dir.path().join("state"))
        .env(GATEWAY_ADDR_ENV, "tcp://127.0.0.1:1")
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

#[tokio::test]
async fn terminal_audit_failure_stops_the_sidecar_before_authority_hydration() {
    // A bound non-gRPC endpoint holds readiness without relying on a timeout.
    let authority = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = startup_fixture(|config| {
        config.authority.url = Some(format!("http://{}", authority.local_addr().unwrap()));
    });
    let wal = fixture.temp_dir.path().join("legacy.jsonl");
    std::fs::write(&wal, b"retained legacy event\n").unwrap();
    let parsed = firma_config_loader::FirmaConfig::load(&fixture.config_path).unwrap();
    let mut config: SidecarConfig = parsed.section("sidecar").unwrap();
    config.audit.sink = AuditSink::Wal;
    config.audit.grpc_url = Some("http://127.0.0.1:1".to_owned());
    config.audit.wal_path = Some(wal.clone());
    write_section(&fixture.config_path, "sidecar", &config).unwrap();

    let child = tokio::process::Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(&fixture.config_path)
        .args(["--health-bind-addr", "127.0.0.1:0"])
        .current_dir(fixture.temp_dir.path())
        .env("FIRMA_STATE_DIR", fixture.temp_dir.path().join("state"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("terminal audit failure must finish shutdown")
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!output.status.success(), "{stderr}");
    assert!(!stderr.contains("sidecar ready"), "{stderr}");
    let diagnostics: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("audit sink stopped"))
        .collect();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        stderr
            .matches("nonempty legacy audit WAL has no scope")
            .count(),
        1
    );
    insta::assert_snapshot!(diagnostics[0], @"[ERR]  audit sink stopped recording events; shutting the sidecar down error=server error: nonempty legacy audit WAL has no scope; explicit migration is required");
    assert_eq!(std::fs::read(wal).unwrap(), b"retained legacy event\n");
}

fn read_lines(path: &std::path::Path) -> Vec<String> {
    File::open(path).map_or_else(
        |_| Vec::new(),
        |file| BufReader::new(file).lines().map_while(Result::ok).collect(),
    )
}

fn healthz_status(addr: &str) -> u16 {
    use std::io::Read as _;
    let mut stream = std::net::TcpStream::connect(addr).expect("connect to health endpoint");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .expect("HTTP status line")
}

#[test]
fn healthz_reports_not_ready_once_the_enforced_snapshot_expires() {
    // Revocation fail-closed would turn /healthz 503 on disconnect by itself,
    // hiding whether bundle expiry is what clears readiness.
    let mut fixture = startup_fixture_with_authority(
        |authority| authority.bundle_ttl = Duration::from_secs(4).try_into().unwrap(),
        |config| config.authority.revocation_fail_closed_on_disconnect = false,
    );
    let stderr_log = fixture.temp_dir.path().join("sidecar.stderr.log");
    let mut child = Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(&fixture.config_path)
        .env("FIRMA_STATE_DIR", fixture.temp_dir.path().join("state"))
        .args(["--health-bind-addr", "127.0.0.1:0"])
        .stdout(File::create(fixture.temp_dir.path().join("sidecar.stdout.log")).unwrap())
        .stderr(File::create(&stderr_log).unwrap())
        .spawn()
        .expect("spawn firma sidecar");

    let deadline = Instant::now() + Duration::from_secs(15);
    let health_addr = loop {
        let lines = read_lines(&stderr_log);
        let addr = lines
            .iter()
            .find(|line| line.contains("health endpoint listening"))
            .and_then(|line| line.split("addr=").nth(1))
            .map(|addr| addr.trim().to_owned());
        if let Some(addr) = addr
            && lines.iter().any(|line| line.contains("sidecar ready"))
        {
            break addr;
        }
        assert!(
            Instant::now() < deadline,
            "sidecar did not become ready:\n{}",
            lines.join("\n")
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(healthz_status(&health_addr), 200);

    // The Authority resends every TTL/2, so the cached snapshot stays fresh for
    // at least two more seconds after the Authority stops.
    fixture.authority.stop();
    assert_eq!(healthz_status(&health_addr), 200);

    let deadline = Instant::now() + Duration::from_secs(15);
    while healthz_status(&health_addr) != 503 {
        assert!(
            Instant::now() < deadline,
            "healthz stayed ready after the snapshot expired:\n{}",
            read_lines(&stderr_log).join("\n")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        read_lines(&stderr_log)
            .iter()
            .any(|line| line.contains("enforcement snapshot expired"))
    );
    let _ = child.kill();
    let _ = child.wait();
}
