//! Verifies that `firma sidecar` accepts a capability seed issued through
//! `firma authority`, while refusing a seed whose claims were tampered with.

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

const FIRMA_BIN: &str = env!("CARGO_BIN_EXE_firma");

struct IssuedSeed {
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
    std::fs::write(
        &auth_toml,
        format!(
            r#"
[authority]
listen_addr = "127.0.0.1:0"
policy_dir = {policy_dir}
revocation_file = {revocation}
max_ttl_seconds = 3600
key_file = {key_file}
bundle_ttl_seconds = 30
"#,
            policy_dir = toml::Value::String(policies.to_string_lossy().into_owned()),
            revocation = toml::Value::String(revocation_file.to_string_lossy().into_owned()),
            key_file = toml::Value::String(key_path.to_string_lossy().into_owned()),
        ),
    )
    .unwrap();

    let seed_path = tmp.path().join("capability.toml");
    let status = Command::new(FIRMA_BIN)
        .args(["authority", "--config"])
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
        tmp,
        seed_path,
        pub_key_path,
        policy_dir: policies,
    }
}

fn write_sidecar_config(issued: &IssuedSeed, mapping_host: &str) -> PathBuf {
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
        &sidecar_toml,
        format!(
            r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:0"
drain_timeout_secs = 30

[sidecar.policy]
dir = '{policy_dir}'

[sidecar.ca]
dir = '{ca_dir}'

[sidecar.mapping]
rules_path = '{mapping}'
default_protected = true

[sidecar.connector]
default_timeout_ms = 30000

[sidecar.authority]
public_key_path = '{pub_key}'

[sidecar.capability_seed]
paths = ['{seed_path}']

[sidecar.audit]
sink = "stdout"
signing_key_path = '{audit_key}'
"#,
            policy_dir = issued.policy_dir.display(),
            ca_dir = ca_dir.display(),
            mapping = mapping.display(),
            pub_key = issued.pub_key_path.display(),
            seed_path = issued.seed_path.display(),
            audit_key = audit_key.display(),
        ),
    )
    .unwrap();
    sidecar_toml
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

fn run_sidecar_until_exit(config_path: &Path) -> (i32, String, String) {
    let mut child = Command::new(FIRMA_BIN)
        .args(["sidecar", "--config"])
        .arg(config_path)
        .args(["--health-bind-addr", "127.0.0.1:0"])
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

    assert!(
        stderr.contains("sidecar ready"),
        "expected ready contract; stderr:\n{stderr}"
    );
    // Standalone Sidecars have no Authority policy stream, so Stage 2 fails
    // closed as stale. Reaching that reason proves the CLI-issued seed matched
    // the session, action, and resource at Stage 1.
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden") && response.contains("PolicyBundleStale"),
        "CLI-issued seed did not admit the request through Stage 1; response:\n{response}\nstderr:\n{stderr}"
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
