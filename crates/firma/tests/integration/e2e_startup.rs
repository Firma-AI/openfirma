//! End-to-end test: boot `firma authority` from the unified binary against a
//! fixture config, assert it reaches its ready log line, then SIGTERM and
//! assert clean exit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::CONFIG_FILE_NAME;

const READY_TIMEOUT: Duration = Duration::from_secs(15);

fn firma_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

fn wait_for_line<R: std::io::BufRead>(reader: &mut R, needle: &str) -> bool {
    let start = Instant::now();
    let mut line = String::new();
    while start.elapsed() < READY_TIMEOUT {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {
                if line.contains(needle) {
                    return true;
                }
            }
        }
    }
    false
}

fn write_authority_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    // Minimal authority TOML: relies on AuthorityConfig defaults where
    // possible. Fields below MUST exist — adjust if AuthorityConfig
    // schema diverges.
    let policy_dir = dir.join("policies");
    std::fs::create_dir_all(&policy_dir).unwrap();
    let issuance_policy_dir = dir.join("issuance-policies");
    std::fs::create_dir_all(&issuance_policy_dir).unwrap();
    let key_file = dir.join("auth.key");
    // Generate a key first via the binary itself.
    let status = Command::new(firma_bin())
        .args(["authority", "generate-key", "-o"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(status.success(), "generate-key failed");

    let revocation_file = dir.join("revocations.txt");
    std::fs::write(&revocation_file, "").unwrap();

    // Unified sectioned config: `firma authority` resolves the
    // `[authority]` section out of one `firma.toml` via the strict
    // section loader.
    let config_path = dir.join(CONFIG_FILE_NAME);
    let toml = format!(
        r#"
[authority]
listen_addr = "127.0.0.1:0"
policy_dir = "{policy_dir}"
issuance_policy_dir = "{issuance_policy_dir}"
revocation_file = "{revocation_file}"
max_ttl_seconds = 3600
key_file = "{key_file}"
log_level = "info"
bundle_ttl_seconds = 30
"#,
        policy_dir = policy_dir.display(),
        issuance_policy_dir = issuance_policy_dir.display(),
        revocation_file = revocation_file.display(),
        key_file = key_file.display(),
    );
    std::fs::write(&config_path, toml).unwrap();
    config_path
}

#[test]
#[cfg_attr(not(unix), ignore = "SIGTERM only on unix")]
fn authority_starts_then_terminates_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_authority_fixture(tmp.path());

    let mut child = Command::new(firma_bin())
        .args(["authority", "-c"])
        .arg(&cfg)
        .env("FIRMA_LOG_FILTER", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn firma authority");

    // tracing writes to stderr by default; read there.
    // The ready needle "listening" matches the log line:
    // `tracing::info!(port = %self.port, "gRPC server listening");`
    // emitted from `firma_authority::server::Server::run`.
    let stderr = child.stderr.take().expect("stderr pipe");
    let mut reader = std::io::BufReader::new(stderr);
    let ready = wait_for_line(&mut reader, "listening");
    assert!(ready, "authority did not log ready line within timeout");

    // Send SIGTERM (unix-only, gated above).
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        let raw_pid = i32::try_from(child.id()).expect("PID fits i32");
        let pid = nix::unistd::Pid::from_raw(raw_pid);
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).unwrap();
        let status = child.wait().expect("wait child");
        assert!(
            status.success() || status.signal() == Some(15),
            "unexpected exit: {status:?}"
        );
    }
    child.wait().unwrap();
}
