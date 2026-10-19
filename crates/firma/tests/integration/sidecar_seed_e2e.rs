//! Verifies that `firma sidecar` accepts a valid seed in the runtime
//! capabilities directory, while refusing external or tampered seed files.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code: panics are acceptable test failures"
)]

use std::fs::File;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use firma_config_schema::authority::AuthorityConfig as AuthoritySchema;
use firma_config_schema::sidecar::{
    AuditConfig, AuditSink, CaConfig, CapabilitySeedConfig, InterceptorConfig, InterceptorMode,
    PolicyConfig, SidecarConfig,
};

use super::config_fixture::write_section;

const FIRMA_BIN: &str = env!("CARGO_BIN_EXE_firma");

#[test]
fn offline_issuance_requires_mapping_configuration_before_reading_keys() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("firma.toml");
    std::fs::write(&config, "[authority]\n").unwrap();
    let seed = root.path().join("seed.toml");
    let output = Command::new(FIRMA_BIN)
        .args(["authority", "--no-tls", "--config"])
        .arg(&config)
        .args([
            "issue",
            "--agent-id",
            "agt_01j0000000e008000000000001",
            "--session-id",
            "required-inputs",
            "--action",
            "code.read",
            "--resource-scope",
            "*",
            "--output",
        ])
        .arg(&seed)
        .env("FIRMA_STATE_DIR", root.path().join("state"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!seed.exists());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let diagnostic = stderr
        .lines()
        .find(|line| line.starts_with("[ERR]"))
        .expect("Authority diagnostic");
    let path = config.to_str().unwrap();
    assert!(diagnostic.contains(path));
    insta::assert_snapshot!(diagnostic.replace(path, "[CONFIG]"), @"[ERR]  failed to load authority configuration: failed to parse config file [CONFIG]: authority.mapping_rules_paths must contain at least one mapping file");
}

struct IssuedSeed {
    authority: std::cell::RefCell<Option<super::authority_fixture::LocalAuthority>>,
    tmp: tempfile::TempDir,
    seed_path: PathBuf,
    pub_key_path: PathBuf,
    policy_dir: PathBuf,
}

fn issue_seed() -> IssuedSeed {
    let tmp = tempfile::tempdir().unwrap();
    let policies = tmp.path().join("policies");
    std::fs::create_dir_all(&policies).unwrap();
    std::fs::write(
        policies.join("default.cedar"),
        "permit(principal, action, resource);",
    )
    .unwrap();

    let key_path = tmp.path().join("firma-authority.key");
    let pub_key_path = key_path.with_extension("pub");
    let status = Command::new(FIRMA_BIN)
        .args(["authority", "generate-key", "--output"])
        .arg(&key_path)
        .current_dir(&tmp)
        .status()
        .unwrap();
    assert!(status.success(), "generate-key failed");

    let auth_toml = tmp.path().join("authority.toml");
    let revocation_file = tmp.path().join("revocations.txt");
    write_section(
        &auth_toml,
        "authority",
        &AuthoritySchema {
            listen_addr: "127.0.0.1:0".to_owned(),
            policy_dir: policies.clone(),
            mapping_rules_paths: vec![tmp.path().join("not-read-by-offline-issuance.toml")],
            revocation_file: Some(revocation_file),
            key_file: Some(key_path),
            ..AuthoritySchema::default()
        },
    )
    .unwrap();

    let capabilities_dir = tmp.path().join("runtime/capabilities");
    std::fs::create_dir_all(&capabilities_dir).unwrap();
    let seed_path = capabilities_dir.join("capability.toml");
    let status = Command::new(FIRMA_BIN)
        .args(["authority", "--no-tls", "--config"])
        .arg(&auth_toml)
        .args([
            "issue",
            "--agent-id",
            "agt_01j0000000e008000000000001",
            "--session-id",
            "test-session",
            "--action",
            "communication.external.send",
            "--resource-scope",
            "*",
            "--ttl-seconds",
            "300",
            "--output",
        ])
        .arg(&seed_path)
        .status()
        .unwrap();
    assert!(status.success(), "issue subcommand failed");

    IssuedSeed {
        authority: std::cell::RefCell::new(None),
        tmp,
        seed_path,
        pub_key_path,
        policy_dir: policies,
    }
}

fn write_sidecar_config_with_seed(
    issued: &IssuedSeed,
    mapping_host: &str,
    seed_path: &Path,
) -> PathBuf {
    let mapping = issued.tmp.path().join("mapping-rules.toml");
    std::fs::write(
        &mapping,
        format!(
            r#"[[rules]]
method       = "GET"
host         = "{mapping_host}"
path         = "*"
action_class = "communication.external.send"
"#,
        ),
    )
    .unwrap();

    let ca_dir = issued.tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();

    let audit_key = issued.tmp.path().join("audit.key");
    std::fs::write(&audit_key, generate_audit_key_pem()).unwrap();

    let sidecar_toml = issued.tmp.path().join("sidecar.toml");
    std::fs::write(
        issued.policy_dir.join("default.cedar"),
        "forbid(principal, action, resource);",
    )
    .expect("deny at policy stage after offline issuance");
    let authority = super::authority_fixture::LocalAuthority::start_with_key(
        issued.tmp.path(),
        &issued.policy_dir,
        &mapping,
        &issued.pub_key_path.with_extension("key"),
    )
    .unwrap();
    let authority_url = authority.url.clone();
    *issued.authority.borrow_mut() = Some(authority);
    write_section(
        &sidecar_toml,
        "sidecar",
        &SidecarConfig {
            interceptor: InterceptorConfig {
                mode: InterceptorMode::HttpProxy,
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                ..InterceptorConfig::default()
            },
            policy: PolicyConfig {
                dir: issued.policy_dir.clone(),
            },
            ca: CaConfig { dir: Some(ca_dir) },
            authority: firma_config_schema::sidecar::AuthorityConfig {
                url: Some(authority_url),
                public_key_path: Some(issued.pub_key_path.clone()),
                ..firma_config_schema::sidecar::AuthorityConfig::default()
            },
            capability_seed: CapabilitySeedConfig {
                paths: vec![seed_path.to_path_buf()],
                ..CapabilitySeedConfig::default()
            },
            audit: AuditConfig {
                sink: AuditSink::Stdout,
                signing_key_path: Some(audit_key),
                ..AuditConfig::default()
            },
            ..SidecarConfig::default()
        },
    )
    .unwrap();
    sidecar_toml
}

fn write_sidecar_config(issued: &IssuedSeed, mapping_host: &str) -> PathBuf {
    write_sidecar_config_with_seed(issued, mapping_host, &issued.seed_path)
}

fn generate_audit_key_pem() -> String {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use rand::rngs::SmallRng;
    use rand::{RngCore, SeedableRng};

    let mut rng = SmallRng::seed_from_u64(1);
    let mut key_bytes = [0_u8; 32];
    rng.fill_bytes(&mut key_bytes);

    SigningKey::from_slice(&key_bytes)
        .unwrap()
        .to_pkcs8_pem(LineEnding::default())
        .unwrap()
        .to_string()
}

fn tamper_seed_action_set(seed_path: &Path, action: &str) {
    let body = std::fs::read_to_string(seed_path).unwrap();
    let mut seed: toml::Value = toml::from_str(&body).unwrap();
    let table = seed.as_table_mut().expect("seed file must be a TOML table");
    table.insert(
        "action_set".to_string(),
        toml::Value::Array(vec![toml::Value::String(action.to_string())]),
    );
    std::fs::write(seed_path, toml::to_string_pretty(&seed).unwrap()).unwrap();
}

/// Run a Sidecar to completion and report its exit code with captured output.
///
/// `FIRMA_STATE_DIR` points beside the config rather than at the host default,
/// which would let the developer's own audit key, trust anchors, and
/// capabilities directory decide the outcome.
fn run_sidecar_until_exit(config_path: &Path) -> (i32, String, String) {
    let mut child = Command::new(FIRMA_BIN)
        .args(["sidecar", "--config"])
        .arg(config_path)
        .args(["--health-bind-addr", "127.0.0.1:0"])
        .env(
            "FIRMA_STATE_DIR",
            config_path
                .parent()
                .expect("config path must have a parent")
                .join("runtime"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn firma sidecar");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            return (
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    panic!(
        "sidecar did not fail startup before timeout; status={:?}; stdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct ChildCleanup(Child);

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_sidecar_until_ready(config_path: &Path, target: SocketAddr) -> (String, String) {
    let stderr_path = config_path.with_extension("stderr.log");
    let stderr_file = File::create(&stderr_path).expect("create Sidecar stderr log");
    let child = Command::new(FIRMA_BIN)
        .args(["sidecar", "--config"])
        .arg(config_path)
        .args(["--health-bind-addr", "127.0.0.1:0"])
        .env(
            "FIRMA_STATE_DIR",
            config_path
                .parent()
                .expect("config path must have a parent")
                .join("runtime"),
        )
        .stdout(Stdio::null())
        .stderr(stderr_file)
        .spawn()
        .expect("spawn firma sidecar");
    let mut child = ChildCleanup(child);

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stderr = String::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        stderr = File::open(&stderr_path)
            .map(BufReader::new)
            .map(|reader| {
                reader
                    .lines()
                    .map_while(Result::ok)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        if stderr.contains("sidecar ready") {
            break;
        }
        if child.0.try_wait().expect("poll firma sidecar").is_some() {
            break;
        }
    }

    assert!(
        stderr.contains("sidecar ready"),
        "Sidecar did not accept the issued seed; stderr:\n{stderr}"
    );
    let interceptor = stderr
        .lines()
        .find(|line| line.contains("interceptor listening"))
        .and_then(|line| line.split("addr=").nth(1))
        .and_then(|value| value.split_whitespace().next())
        .map(|value| value.trim_matches('"').trim_end_matches(','))
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| panic!("missing interceptor address in stderr:\n{stderr}"));

    let mut proxy = TcpStream::connect(interceptor).expect("connect to Sidecar interceptor");
    proxy
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set proxy read timeout");
    write!(
        proxy,
        "GET http://{target}/allowed HTTP/1.1\r\n\
         Host: {target}\r\n\
         X-Firma-Session-Id: test-session\r\n\
         Connection: close\r\n\r\n"
    )
    .expect("send request through Sidecar");
    let mut reader = BufReader::new(proxy);
    let mut response = String::new();
    let mut content_length = None;
    loop {
        let mut line = String::new();
        assert_ne!(
            reader.read_line(&mut line).expect("read response header"),
            0,
            "Sidecar response ended before its headers"
        );
        response.push_str(&line);
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = Some(value.trim().parse::<usize>().expect("parse Content-Length"));
        }
        if line == "\r\n" {
            break;
        }
    }
    let mut body = vec![0_u8; content_length.expect("Sidecar response has Content-Length")];
    reader.read_exact(&mut body).expect("read response body");
    response.push_str(std::str::from_utf8(&body).expect("response body is UTF-8"));
    (stderr, response)
}

#[test]
fn issued_seed_admits_request_to_policy_stage() {
    let issued = issue_seed();
    let target = "127.0.0.1:1";
    let sidecar_toml = write_sidecar_config(&issued, target);

    let (stderr, response) =
        run_sidecar_until_ready(&sidecar_toml, target.parse().expect("parse request target"));

    assert_stage_one_admitted(&stderr, &response);
}

/// Assert the Sidecar came up and selected the seed for the request.
///
/// A fresh Authority forbid policy denies at Stage 2. Reaching that reason
/// proves the seed matched the session, action, and resource at Stage 1.
fn assert_stage_one_admitted(stderr: &str, response: &str) {
    assert!(
        stderr.contains("sidecar ready"),
        "expected ready contract; stderr:\n{stderr}"
    );
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden") && response.contains("PolicyDenied"),
        "seed did not admit the request through Stage 1; response:\n{response}\nstderr:\n{stderr}"
    );
}

/// A committed `firma.toml` cannot carry host-specific absolute paths, so the
/// shape operators actually share names its seed relative to the config. That
/// path is resolved against the config directory before confinement compares it
/// with the selected state directory, and both must agree for the Sidecar to
/// start.
#[test]
fn relative_seed_path_resolves_under_the_selected_state_dir() {
    let issued = issue_seed();
    let target = "127.0.0.1:1";
    let relative_seed = Path::new("runtime")
        .join("capabilities")
        .join("capability.toml");
    assert_eq!(
        issued.tmp.path().join(&relative_seed),
        issued.seed_path,
        "fixture seed must sit at the relative path under test"
    );
    let sidecar_toml = write_sidecar_config_with_seed(&issued, target, &relative_seed);

    let (stderr, response) =
        run_sidecar_until_ready(&sidecar_toml, target.parse().expect("parse request target"));

    assert_stage_one_admitted(&stderr, &response);
}

#[test]
fn seed_outside_runtime_capabilities_directory_fails_startup() {
    let issued = issue_seed();
    let external_seed = issued.tmp.path().join("external-capability.toml");
    std::fs::copy(&issued.seed_path, &external_seed).expect("copy seed outside runtime directory");
    let sidecar_toml = write_sidecar_config_with_seed(&issued, "example.test", &external_seed);

    let (code, _stdout, stderr) = run_sidecar_until_exit(&sidecar_toml);

    assert_ne!(code, 0, "expected non-zero exit; stderr:\n{stderr}");
    assert!(
        stderr.contains("must be under the runtime capabilities directory"),
        "stderr should identify the invalid seed location; got:\n{stderr}",
    );
}

#[test]
fn tampered_seed_action_set_makes_sidecar_startup_fail() {
    let issued = issue_seed();
    tamper_seed_action_set(&issued.seed_path, "github.repo.write");
    let sidecar_toml = write_sidecar_config(&issued, "example.test");

    let (code, _stdout, stderr) = run_sidecar_until_exit(&sidecar_toml);

    assert_ne!(code, 0, "expected non-zero exit; stderr:\n{stderr}");
    assert!(
        stderr.contains("raw_token claims do not match seed claims"),
        "stderr should mention mismatched claims; got:\n{stderr}",
    );
}
