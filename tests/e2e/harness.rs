use std::ffi::OsStr;
use std::fmt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use wait_timeout::ChildExt;

use crate::audit::{AuditEvent, correlated_event};

pub(crate) struct TestWorld {
    root: tempfile::TempDir,
    session_id: String,
}

impl TestWorld {
    pub(crate) fn new() -> Self {
        let root = tempfile::tempdir().expect("create isolated test world");
        for directory in [
            "config",
            "state",
            "workspace",
            "home",
            "xdg/cache",
            "xdg/config",
            "xdg/data",
            "xdg/runtime",
            "xdg/state",
            "tmp",
        ] {
            std::fs::create_dir_all(root.path().join(directory))
                .expect("create isolated directory");
        }
        let world = Self {
            root,
            session_id: format!("sess_e2e_{}", uuid::Uuid::new_v4().simple()),
        };
        world.scaffold();
        world
    }

    fn scaffold(&self) {
        let mut command = isolated_command(env!("CARGO_BIN_EXE_firma"), self);
        command
            .args([
                "config",
                "--yes",
                "--mode",
                "agent-local",
                "--profile",
                "generic",
                "--posture",
                "dev",
                "--output-dir",
            ])
            .arg(self.root.path().join("config"))
            .arg("--state-dir")
            .arg(self.root.path().join("state"))
            .args(["--authority-listen", "127.0.0.1:0", "--workspace"])
            .arg(self.root.path().join("workspace"));
        let output = run_bounded(&mut command, Duration::from_secs(30));
        assert!(output.success(), "firma config failed:\n{output}");

        let path = self.config_path();
        let config = std::fs::read_to_string(&path).expect("read scaffolded config");
        let patched = config.replace(
            r#"FIRMA_RUN_BWRAP_MASK_HOME_PATHS = ".ssh,.gnupg,.aws,.config/gcloud,.env""#,
            r#"FIRMA_RUN_BWRAP_MASK_HOME_PATHS = """#,
        );
        assert_ne!(patched, config, "expected generated home-mask setting");
        std::fs::write(path, patched).expect("write deterministic config");
    }

    fn config_path(&self) -> PathBuf {
        self.root.path().join("config/firma.toml")
    }

    fn audit_path(&self) -> PathBuf {
        self.root.path().join("state/audit.jsonl")
    }

    pub(crate) fn add_policy(&self, name: &str, policy: &str) {
        std::fs::write(self.root.path().join("config/policies").join(name), policy)
            .expect("write scenario policy");
    }

    pub(crate) fn run_governed<I, S>(
        &self,
        nonce: &str,
        program: impl AsRef<OsStr>,
        args: I,
    ) -> GovernedRun
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = isolated_command(env!("CARGO_BIN_EXE_firma"), self);
        command
            .args([
                "run",
                "--profile",
                "generic",
                "--authority",
                "local",
                "--sidecar",
                "local",
                "--config",
            ])
            .arg(self.config_path())
            .arg("--")
            .arg(program)
            .args(args)
            .env("FIRMA_RUN_SESSION_ID", &self.session_id);
        GovernedRun {
            output: run_bounded(&mut command, Duration::from_mins(2)),
            audit_path: self.audit_path(),
            session_id: self.session_id.clone(),
            nonce: nonce.to_string(),
        }
    }
}

pub(crate) struct GovernedRun {
    pub(crate) output: ProcessOutput,
    audit_path: PathBuf,
    session_id: String,
    nonce: String,
}

impl GovernedRun {
    pub(crate) fn audit_event(&self) -> AuditEvent {
        correlated_event(&self.audit_path, &self.session_id, &self.nonce)
    }
}

pub(crate) fn isolated_command(program: impl AsRef<OsStr>, world: &TestWorld) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", world.root.path().join("home"))
        .env("XDG_CACHE_HOME", world.root.path().join("xdg/cache"))
        .env("XDG_CONFIG_HOME", world.root.path().join("xdg/config"))
        .env("XDG_DATA_HOME", world.root.path().join("xdg/data"))
        .env("XDG_RUNTIME_DIR", world.root.path().join("xdg/runtime"))
        .env("XDG_STATE_HOME", world.root.path().join("xdg/state"))
        .env("TMPDIR", world.root.path().join("tmp"))
        .env("FIRMA_STATE_DIR", world.root.path().join("state"))
        .env("NO_COLOR", "1")
        .current_dir(world.root.path().join("workspace"));
    command
}

pub(crate) struct ProcessOutput {
    status: ExitStatus,
    pub(crate) stdout: String,
    stderr: String,
    timed_out: bool,
}

impl ProcessOutput {
    pub(crate) fn success(&self) -> bool {
        self.status.success() && !self.timed_out
    }
}

impl fmt::Display for ProcessOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "status={} timed_out={}\nstdout:\n{}\nstderr:\n{}",
            self.status, self.timed_out, self.stdout, self.stderr
        )
    }
}

pub(crate) fn run_bounded(command: &mut Command, timeout: Duration) -> ProcessOutput {
    let stdout = tempfile::NamedTempFile::new().expect("stdout capture");
    let stderr = tempfile::NamedTempFile::new().expect("stderr capture");
    command
        .stdout(Stdio::from(stdout.reopen().expect("stdout handle")))
        .stderr(Stdio::from(stderr.reopen().expect("stderr handle")));
    command.process_group(0);
    let mut child = command.spawn().expect("spawn bounded process");
    let status = child
        .wait_timeout(timeout)
        .expect("wait for bounded process");
    let timed_out = status.is_none();
    let status = status.unwrap_or_else(|| {
        let group = Pid::from_raw(child.id().try_into().expect("pid fits i32"));
        let _ = killpg(group, Signal::SIGTERM);
        let grace_period = Duration::from_secs(2);
        let grace_deadline = Instant::now() + grace_period;
        let status = child
            .wait_timeout(grace_period)
            .expect("wait after SIGTERM");
        if status.is_some() {
            std::thread::sleep(grace_deadline.saturating_duration_since(Instant::now()));
        }
        let _ = killpg(group, Signal::SIGKILL);
        status.unwrap_or_else(|| child.wait().expect("reap timed-out process"))
    });
    ProcessOutput {
        status,
        stdout: read_capture(stdout.path()),
        stderr: read_capture(stderr.path()),
        timed_out,
    }
}

fn read_capture(path: &Path) -> String {
    String::from_utf8_lossy(&std::fs::read(path).unwrap_or_default()).into_owned()
}
