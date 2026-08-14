use std::ffi::OsStr;
use std::fmt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
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
        let world = Self::isolated();
        world.scaffold_config(
            "generic",
            &world.path("config"),
            &world.state_path(),
            Some(&world.workspace_path()),
            &world.workspace_path(),
        );
        Self::disable_host_home_masks(&world.config_path());
        world
    }

    pub(crate) fn isolated() -> Self {
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
        Self {
            root,
            session_id: format!("sess_e2e_{}", uuid::Uuid::new_v4().simple()),
        }
    }

    pub(crate) fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        let relative = relative.as_ref();
        assert!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_) | Component::CurDir)),
            "world path must be contained and relative"
        );
        self.root.path().join(relative)
    }

    pub(crate) fn workspace_path(&self) -> PathBuf {
        self.path("workspace")
    }

    pub(crate) fn state_path(&self) -> PathBuf {
        self.path("state")
    }

    pub(crate) fn config_path(&self) -> PathBuf {
        self.path("config/firma.toml")
    }

    pub(crate) fn scaffold_config(
        &self,
        profile: &str,
        config_dir: &Path,
        state_dir: &Path,
        workspace: Option<&Path>,
        cwd: &Path,
    ) {
        let mut command = self.isolated_command_in(env!("CARGO_BIN_EXE_firma"), cwd);
        command
            .args([
                "config",
                "--yes",
                "--mode",
                "agent-local",
                "--profile",
                profile,
                "--posture",
                "dev",
                "--output-dir",
            ])
            .arg(config_dir)
            .arg("--state-dir")
            .arg(state_dir)
            .args(["--authority-listen", "127.0.0.1:0"]);
        if let Some(workspace) = workspace {
            command.arg("--workspace").arg(workspace);
        }
        let output = run_bounded(&mut command, Duration::from_secs(30));
        assert!(output.success(), "firma config failed:\n{output}");
    }

    pub(crate) fn disable_host_home_masks(config_path: &Path) {
        let config = std::fs::read_to_string(config_path).expect("read scaffolded config");
        let patched = config.replace(
            r#"FIRMA_RUN_BWRAP_MASK_HOME_PATHS = ".ssh,.gnupg,.aws,.config/gcloud,.env""#,
            r#"FIRMA_RUN_BWRAP_MASK_HOME_PATHS = """#,
        );
        assert_ne!(patched, config, "expected generated home-mask setting");
        std::fs::write(config_path, patched).expect("write deterministic config");
    }

    fn audit_path(&self) -> PathBuf {
        self.path("state/audit.jsonl")
    }

    pub(crate) fn audit_event(&self, nonce: &str) -> AuditEvent {
        correlated_event(&self.audit_path(), &self.session_id, nonce)
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
        GovernedRun {
            output: self.run_firma(
                "generic",
                Some(&self.config_path()),
                &self.workspace_path(),
                &["--authority", "local", "--sidecar", "local"],
                program,
                args,
            ),
            audit_path: self.audit_path(),
            session_id: self.session_id.clone(),
            nonce: nonce.to_string(),
        }
    }

    pub(crate) fn run_firma<I, S>(
        &self,
        profile: &str,
        config_path: Option<&Path>,
        cwd: &Path,
        run_args: &[&str],
        program: impl AsRef<OsStr>,
        args: I,
    ) -> ProcessOutput
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = self.isolated_command_in(env!("CARGO_BIN_EXE_firma"), cwd);
        command.args(["run", "--profile", profile]);
        if let Some(config_path) = config_path {
            command.arg("--config").arg(config_path);
        }
        command
            .args(run_args)
            .arg("--")
            .arg(program)
            .args(args)
            .env("FIRMA_RUN_SESSION_ID", &self.session_id);
        run_bounded(&mut command, Duration::from_mins(2))
    }

    pub(crate) fn isolated_command_in(&self, program: impl AsRef<OsStr>, cwd: &Path) -> Command {
        let canonical_cwd = cwd
            .canonicalize()
            .expect("canonicalize isolated command cwd");
        assert!(
            canonical_cwd.starts_with(self.root.path()),
            "isolated command cwd must stay inside the test world"
        );
        let mut command = isolated_command(program, self);
        command.current_dir(cwd);
        command
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
    pub(crate) stderr: String,
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
