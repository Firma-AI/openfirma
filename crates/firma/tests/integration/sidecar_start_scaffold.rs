//! Exercises the detached sidecar lifecycle from the default Anthropic-only
//! `firma config` scaffold, where HTTPS MITM and CA material are absent.
//!
//! The scenarios cover startup readiness and JSON status, a rejected duplicate
//! startup with missing lock state, stop and restart, and supervisor-owned
//! component teardown.

#![allow(
    clippy::expect_used,
    reason = "test code: panics acceptable on test failure"
)]

use std::fs::File;
use std::io::{Read, Seek};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::CONFIG_FILE_NAME;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

#[cfg(windows)]
fn hard_terminate_process(pid: u32) -> std::io::Result<()> {
    let output = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "taskkill failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn start_detached(cfg_path: &Path, state_dir: &Path) -> std::process::Output {
    // A detached supervisor may retain inherited handles after the launcher
    // exits. File-backed capture lets `status` return without waiting for pipe
    // EOF, which would otherwise hang indefinitely on Windows.
    let mut stderr = tempfile::tempfile_in(state_dir).expect("create start stderr log");
    let status = firma()
        .args(["sidecar", "start", "--detach", "--config"])
        .arg(cfg_path)
        .args(["--state-dir"])
        .arg(state_dir)
        .env("FIRMA_SIDECAR_HEALTH_BIND_ADDR", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            stderr.try_clone().expect("clone start stderr log"),
        ))
        .status()
        .expect("run firma sidecar start");
    stderr.rewind().expect("rewind start stderr log");
    let mut diagnostics = Vec::new();
    stderr
        .read_to_end(&mut diagnostics)
        .expect("read start stderr log");
    std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: diagnostics,
    }
}

fn daemon_status(state_dir: &Path) -> (std::process::ExitStatus, serde_json::Value) {
    let output = firma()
        .args(["sidecar", "status", "--daemon", "--json"])
        .env("FIRMA_STATE_DIR", state_dir)
        .output()
        .expect("run firma sidecar status");
    let rows = serde_json::from_slice(&output.stdout).expect("status returns JSON");
    (output.status, rows)
}

struct StackCleanup<'a>(&'a Path);

impl Drop for StackCleanup<'_> {
    fn drop(&mut self) {
        let _ = firma()
            .args(["sidecar", "stop", "--state-dir"])
            .arg(self.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct Scaffold {
    _tmp: tempfile::TempDir,
    cfg_path: std::path::PathBuf,
    state_dir: std::path::PathBuf,
}

impl Scaffold {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tmp");
        let config_dir = tmp.path().join("cfg");
        let state_dir = tmp.path().join("state");

        let init = firma()
            .args(["config", "--yes", "--mode", "agent-local", "--output-dir"])
            .arg(&config_dir)
            .args(["--state-dir"])
            .arg(&state_dir)
            .args(["--authority-listen"])
            .arg("127.0.0.1:0")
            .output()
            .expect("run firma config");
        assert!(init.status.success(), "config scaffold failed: {init:?}");

        let cfg_path = config_dir.join(CONFIG_FILE_NAME);
        let text = std::fs::read_to_string(&cfg_path).expect("read firma.toml");
        let mut config: toml::Value = toml::from_str(&text).expect("parse firma.toml");
        config["sidecar"]["interceptor"]["listen_addr"] =
            toml::Value::String("127.0.0.1:0".to_string());
        config["sidecar"]["authority"]
            .as_table_mut()
            .expect("sidecar Authority config")
            .insert(
                "connect_addr".to_string(),
                toml::Value::String("127.0.0.1:1".to_string()),
            );
        std::fs::write(
            &cfg_path,
            toml::to_string_pretty(&config).expect("serialize firma.toml"),
        )
        .expect("write firma.toml");

        std::fs::create_dir_all(&state_dir).expect("state dir");

        Self {
            _tmp: tmp,
            cfg_path,
            state_dir,
        }
    }

    fn start(&self) -> std::process::Output {
        start_detached(&self.cfg_path, &self.state_dir)
    }

    fn cleanup(&self) -> StackCleanup<'_> {
        StackCleanup(&self.state_dir)
    }

    fn stack_pid_path(&self) -> std::path::PathBuf {
        self.state_dir.join("stack.pid")
    }

    fn endpoint(&self, component: &str) -> SocketAddr {
        let endpoint = std::fs::read_to_string(self.state_dir.join(format!("{component}.listen")))
            .expect("read canonical component endpoint")
            .trim()
            .parse::<SocketAddr>()
            .expect("parse canonical component endpoint");
        assert_ne!(endpoint.port(), 0, "{component} retained port zero");
        TcpStream::connect(endpoint).expect("connect to canonical component endpoint");
        endpoint
    }

    fn assert_sidecar_connected_to(&self, authority_addr: SocketAddr) {
        let text = std::fs::read_to_string(&self.cfg_path).expect("read scaffold config");
        let config: toml::Value = toml::from_str(&text).expect("parse scaffold config");
        let expected_url = config["sidecar"]["authority"]["url"]
            .as_str()
            .expect("configured logical Authority URL");
        let expected_endpoint = format!("endpoint={expected_url}");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let log = read_log(&self.state_dir.join("sidecar.log")).unwrap_or_default();
            let reports_endpoint = log.lines().any(|line| {
                line.contains("authority stream connected") && line.contains(&expected_endpoint)
            });
            let connected_streams = log
                .lines()
                .filter(|line| line.contains("authority stream connected"))
                .filter(|line| {
                    line.contains("stream=policy_bundle") || line.contains("stream=revocations")
                })
                .count();
            if reports_endpoint && connected_streams == 2 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Sidecar did not connect both streams to {authority_addr}:\n{log}"
            );
            std::thread::yield_now();
        }
    }

    fn start_failure_diagnostics(&self, output: &std::process::Output) -> StartDiagnostics {
        StartDiagnostics {
            launcher_stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            supervisor_log: read_log(&self.state_dir.join("supervisor.log")),
            authority_log: read_log(&self.state_dir.join("authority.log")),
            sidecar_log: read_log(&self.state_dir.join("sidecar.log")),
        }
    }

    fn format_start_failure(&self, output: &std::process::Output) -> String {
        let diagnostics = self.start_failure_diagnostics(output);
        let state_files = [
            "stack.lock",
            "stack.pid",
            "authority.pid",
            "authority.listen",
            "sidecar.pid",
            "sidecar.listen",
        ]
        .map(|name| {
            let state = if self.state_dir.join(name).exists() {
                "present"
            } else {
                "missing"
            };
            format!("{name}={state}")
        })
        .join(", ");

        format!(
            "exit status: {}\nconfig path: {}\nstate dir: {}\nconfigured addresses: authority=127.0.0.1:0, interceptor=127.0.0.1:0, health=127.0.0.1:0\nstate files: {state_files}\n{diagnostics}",
            output.status,
            self.cfg_path.display(),
            self.state_dir.display(),
        )
    }
}

struct StartDiagnostics {
    launcher_stderr: String,
    supervisor_log: Option<String>,
    authority_log: Option<String>,
    sidecar_log: Option<String>,
}

impl std::fmt::Display for StartDiagnostics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "launcher stderr:\n{}", self.launcher_stderr)?;
        for (name, contents) in [
            ("supervisor.log", self.supervisor_log.as_deref()),
            ("authority.log", self.authority_log.as_deref()),
            ("sidecar.log", self.sidecar_log.as_deref()),
        ] {
            match contents {
                Some(contents) => writeln!(f, "{name}:\n{contents}")?,
                None => writeln!(f, "{name}: <unavailable>")?,
            }
        }
        Ok(())
    }
}

fn read_log(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|contents| String::from_utf8_lossy(&contents).into_owned())
}

fn assert_stack_pid_published(stack_pid: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !stack_pid.exists() {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        stack_pid.exists(),
        "stack did not come up: stack.pid missing"
    );
}

#[test]
fn scaffold_start_reaches_readiness_and_reports_running_json_status() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();

    let start = scaffold.start();
    assert!(
        start.status.success(),
        "sidecar start failed (MITM-inactive scaffold must not block on CA material):\n{}",
        scaffold.format_start_failure(&start)
    );
    assert_stack_pid_published(&scaffold.stack_pid_path());
    let authority_addr = scaffold.endpoint("authority");
    let sidecar_addr = scaffold.endpoint("sidecar");
    scaffold.assert_sidecar_connected_to(authority_addr);

    let (status, rows) = daemon_status(&scaffold.state_dir);
    assert!(status.success(), "running daemon status was {status}");
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["sandbox_id"], "daemon");
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["listen"], sidecar_addr.to_string());
}

#[test]
fn failed_second_start_does_not_claim_or_terminate_existing_stack() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();
    let start = scaffold.start();
    assert!(
        start.status.success(),
        "initial start failed:\n{}",
        scaffold.format_start_failure(&start)
    );

    let state_dir = &scaffold.state_dir;
    let authority_pid = firma_runtime_state::pidfile::read(&state_dir.join("authority.pid"))
        .expect("read authority pidfile")
        .expect("authority pid");
    let sidecar_pid = firma_runtime_state::pidfile::read(&state_dir.join("sidecar.pid"))
        .expect("read sidecar pidfile")
        .expect("sidecar pid");

    std::fs::remove_file(state_dir.join("stack.lock")).expect("remove stack lock");
    let restart_stderr = state_dir.join("restart.stderr.log");
    let restart_status = firma()
        .args(["sidecar", "start", "--detach", "--config"])
        .arg(&scaffold.cfg_path)
        .args(["--state-dir"])
        .arg(state_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            File::create(&restart_stderr).expect("create restart log"),
        ))
        .status()
        .expect("run second firma sidecar start");
    assert!(
        !restart_status.success(),
        "second start unexpectedly succeeded"
    );
    let restart_diagnostics = std::fs::read_to_string(&restart_stderr).unwrap_or_default();
    assert_eq!(restart_status.code(), Some(2));
    assert!(
        authority_pid.process_exists().expect("probe authority"),
        "failed startup rollback terminated the existing authority: {restart_diagnostics}"
    );
    assert!(
        sidecar_pid.process_exists().expect("probe sidecar"),
        "failed startup rollback terminated the existing sidecar: {restart_diagnostics}"
    );
    assert!(
        !state_dir.join("stack.lock").exists(),
        "blocked startup published a generation it does not own"
    );
}

#[test]
fn stopped_stack_reports_stopped_and_can_restart() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();
    let start = scaffold.start();
    assert!(
        start.status.success(),
        "initial start failed:\n{}",
        scaffold.format_start_failure(&start)
    );

    let stop = firma()
        .args(["sidecar", "stop", "--state-dir"])
        .arg(&scaffold.state_dir)
        .output()
        .expect("stop running daemon");
    assert!(
        stop.status.success(),
        "sidecar stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let (status, rows) = daemon_status(&scaffold.state_dir);
    assert_eq!(status.code(), Some(1));
    assert_eq!(rows[0]["state"], "stopped");
    assert!(!scaffold.state_dir.join("authority.listen").exists());
    assert!(!scaffold.state_dir.join("sidecar.listen").exists());

    let restart = scaffold.start();
    assert!(
        restart.status.success(),
        "sidecar restart failed:\n{}",
        scaffold.format_start_failure(&restart)
    );
    assert_stack_pid_published(&scaffold.stack_pid_path());
    let authority_addr = scaffold.endpoint("authority");
    let _sidecar_addr = scaffold.endpoint("sidecar");
    scaffold.assert_sidecar_connected_to(authority_addr);
}

#[test]
fn concurrent_starts_publish_exactly_one_stack() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();
    let barrier = std::sync::Barrier::new(3);

    let outputs = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            scaffold.start()
        });
        let second = scope.spawn(|| {
            barrier.wait();
            scaffold.start()
        });
        // The test thread is the third participant, releasing both launcher
        // threads from the same in-process barrier before either spawns `firma`.
        barrier.wait();
        [
            first.join().expect("first start thread"),
            second.join().expect("second start thread"),
        ]
    });

    let successes = outputs
        .iter()
        .filter(|output| output.status.success())
        .count();
    let output_diagnostics = outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            format!(
                "start {}:\n{}",
                index + 1,
                scaffold.format_start_failure(output)
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    assert_eq!(
        successes, 1,
        "concurrent starts did not produce exactly one winner:\n{output_diagnostics}"
    );
    let failure = outputs
        .iter()
        .find(|output| !output.status.success())
        .expect("one start must lose the race");
    assert_eq!(failure.status.code(), Some(2));

    let (status, rows) = daemon_status(&scaffold.state_dir);
    assert!(status.success(), "winning stack status was {status}");
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["listen"], scaffold.endpoint("sidecar").to_string());
}

#[test]
fn supervisor_owner_teardown_terminates_components() {
    let scaffold = Scaffold::new();
    let _cleanup = scaffold.cleanup();
    let start = scaffold.start();
    assert!(
        start.status.success(),
        "initial start failed:\n{}",
        scaffold.format_start_failure(&start)
    );

    let state_dir = &scaffold.state_dir;
    let stack_pid = scaffold.stack_pid_path();
    let authority_pid = firma_runtime_state::pidfile::read(&state_dir.join("authority.pid"))
        .expect("read authority pidfile")
        .expect("authority pid");
    let sidecar_pid = firma_runtime_state::pidfile::read(&state_dir.join("sidecar.pid"))
        .expect("read sidecar pidfile")
        .expect("sidecar pid");
    let supervisor_pid = firma_runtime_state::pidfile::read(&stack_pid)
        .expect("read supervisor pidfile")
        .expect("supervisor pid");

    #[cfg(unix)]
    {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(
                i32::try_from(supervisor_pid.get()).expect("supervisor PID fits pid_t"),
            ),
            nix::sys::signal::Signal::SIGTERM,
        )
        .expect("SIGTERM detached supervisor");
    }
    #[cfg(windows)]
    hard_terminate_process(supervisor_pid.get()).expect("terminate detached supervisor");

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline
        && (supervisor_pid.process_exists().expect("probe supervisor")
            || authority_pid.process_exists().expect("probe authority")
            || sidecar_pid.process_exists().expect("probe sidecar"))
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !supervisor_pid.process_exists().expect("probe supervisor"),
        "detached supervisor still exists after termination"
    );
    assert!(
        !authority_pid.process_exists().expect("probe authority"),
        "authority still exists after supervisor teardown"
    );
    assert!(
        !sidecar_pid.process_exists().expect("probe sidecar"),
        "sidecar still exists after supervisor teardown"
    );

    let stop_status = firma()
        .args(["sidecar", "stop", "--state-dir"])
        .arg(state_dir)
        .status()
        .expect("clean retained state");
    assert!(stop_status.success(), "could not clean retained state");
    assert!(!state_dir.join("stack.pid").exists());
}
