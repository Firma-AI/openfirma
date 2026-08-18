use std::ffi::OsStr;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use firma_test_helpers::process_fixture;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt;

use crate::audit::{AuditEvent, correlated_event};
use crate::poll::wait_for;

/// An isolated filesystem and environment for one E2E test phase.
///
/// Dropping the world removes its temporary root. Commands created through the world inherit only
/// the explicitly configured environment and must run from a directory beneath that root.
pub(crate) struct TestWorld {
    root: tempfile::TempDir,
    session_id: String,
}

impl TestWorld {
    /// Creates a world with the default `generic` agent-local configuration.
    ///
    /// Host-home masks are disabled because [`Self::isolated`] already supplies an empty home;
    /// this keeps scenarios independent of files on the machine running the tests.
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

    /// Creates an empty world with isolated home, XDG, state, workspace, and temporary directories.
    ///
    /// Unlike [`Self::new`], this does not scaffold a Firma configuration.
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

    /// Resolves a contained relative path beneath the world's temporary root.
    ///
    /// Absolute paths and paths containing parent or platform-prefix components are rejected.
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

    /// Returns the world's isolated workspace directory.
    pub(crate) fn workspace_path(&self) -> PathBuf {
        self.path("workspace")
    }

    /// Returns the world's isolated Firma state directory.
    pub(crate) fn state_path(&self) -> PathBuf {
        self.path("state")
    }

    /// Returns the default scaffolded configuration path.
    pub(crate) fn config_path(&self) -> PathBuf {
        self.path("config/firma.toml")
    }

    /// Runs `firma config` to scaffold an agent-local development configuration.
    ///
    /// The command runs with the world's isolated environment and a 30-second deadline. The test
    /// fails if scaffolding times out or exits unsuccessfully.
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

    /// Removes generated masks for host-home secrets from a scaffolded configuration.
    ///
    /// Tests use an empty isolated home, so retaining these masks would test host-specific paths
    /// rather than the scenario. The test fails if the expected generated setting is absent.
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

    /// Returns the unique audit event whose resource contains `nonce` in this world's session.
    pub(crate) fn audit_event(&self, nonce: &str) -> AuditEvent {
        correlated_event(&self.audit_path(), &self.session_id, nonce)
    }

    /// Writes a Cedar policy into the default scaffolded policy directory.
    pub(crate) fn add_policy(&self, name: &str, policy: &str) {
        std::fs::write(self.root.path().join("config/policies").join(name), policy)
            .expect("write scenario policy");
    }

    /// Runs a command through local Firma authority and sidecar processes using the default profile.
    ///
    /// The returned run retains the session and nonce needed to retrieve its correlated audit
    /// event with [`GovernedRun::audit_event`].
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

    /// Runs a program through `firma run` in this world and returns its captured output.
    ///
    /// The Firma process receives a two-minute deadline; if it is still running then, its entire
    /// process group is terminated. `run_args` are Firma arguments placed before `--`; `args` are
    /// arguments for `program`.
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

    /// Starts one governed Rust fixture that accepts multiple HTTP requests over standard input.
    ///
    /// The returned run owns the full local Authority, Sidecar, sandbox, and wrapped-process group.
    /// Startup waits for both the fixture's readiness event and one complete Sidecar marker.
    pub(crate) fn start_live_governed(&self) -> LiveGovernedRun {
        let stderr = tempfile::NamedTempFile::new().expect("live stderr capture");
        let mut fixture = live_http_client_fixture();
        fixture.arg("--nocapture");
        let mut command =
            self.isolated_command_in(env!("CARGO_BIN_EXE_firma"), &self.workspace_path());
        command
            .args(["run", "--profile", "generic", "--config"])
            .arg(self.config_path())
            .args(["--authority", "local", "--sidecar", "local", "--"])
            .arg(fixture.get_program())
            .args(fixture.get_args())
            .env("FIRMA_RUN_SESSION_ID", &self.session_id)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr.reopen().expect("live stderr handle")));
        for (name, value) in fixture.get_envs() {
            if let Some(value) = value {
                command.env(name, value);
            } else {
                command.env_remove(name);
            }
        }
        command.process_group(0);
        let mut child = command.spawn().expect("spawn live governed process");
        let stdin = child.stdin.take().expect("live governed stdin");
        let stdout = child.stdout.take().expect("live governed stdout");
        let (events, stdout_reader) = start_live_stdout_reader(stdout);
        let mut run = LiveGovernedRun {
            child: Some(child),
            stdin: Some(stdin),
            events,
            stdout_reader: Some(stdout_reader),
            stderr,
            state_path: self.state_path(),
            audit_path: self.audit_path(),
            session_id: self.session_id.clone(),
            identity: None,
        };
        let LiveHttpEvent::Ready {
            process_id,
            mount_namespace,
        } = run.receive_event("fixture readiness", Duration::from_secs(30))
        else {
            panic!("live governed fixture did not send readiness first");
        };
        let marker = wait_for_sidecar_marker(&self.state_path(), Duration::from_secs(5));
        assert_eq!(marker.session_id, self.session_id);
        run.identity = Some(LiveIdentity {
            process_id,
            mount_namespace,
            sandbox_id: marker.sandbox_id,
            sidecar_id: marker.sidecar_id,
            agent_id: marker.agent_id,
            session_id: marker.session_id,
            sidecar_started_at: marker.started_at,
        });
        run
    }

    /// Creates an isolated command whose working directory is contained by this world.
    ///
    /// The test fails if `cwd` does not exist or resolves outside the world's temporary root.
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

const LIVE_HTTP_PREFIX: &str = "FIRMA_E2E_HTTP ";

#[derive(Deserialize, Serialize)]
struct LiveHttpRequest {
    nonce: String,
    url: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LiveHttpEvent {
    Ready {
        process_id: u32,
        mount_namespace: String,
    },
    Attempt {
        nonce: String,
    },
    Response {
        nonce: String,
        status: u16,
        body: Vec<u8>,
    },
    Error {
        nonce: String,
        message: String,
    },
}

/// The HTTP response returned to a request made inside a live governed sandbox.
pub(crate) struct LiveHttpResponse {
    /// HTTP status returned by the Sidecar or upstream destination.
    pub(crate) status: u16,
    /// Response body returned by the Sidecar or upstream destination.
    pub(crate) body: Vec<u8>,
}

process_fixture! {
    fn live_http_client_fixture() {
        let proxy = std::env::var("HTTP_PROXY").expect("live HTTP proxy URL");
        let client = reqwest::blocking::Client::builder()
            .use_preconfigured_tls(build_live_http_tls_config())
            .proxy(reqwest::Proxy::all(proxy).expect("configure live HTTP proxy"))
            .timeout(Duration::from_secs(3))
            .build()
            .expect("build live HTTP client");
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        write_live_http_event(
            &mut stdout,
            &LiveHttpEvent::Ready {
                process_id: std::process::id(),
                mount_namespace: std::fs::read_link("/proc/self/ns/mnt")
                    .expect("read fixture mount namespace")
                    .to_string_lossy()
                    .into_owned(),
            },
        );

        for line in stdin.lock().lines() {
            let line = line.expect("read live HTTP request");
            let request: LiveHttpRequest =
                serde_json::from_str(&line).expect("deserialize live HTTP request");
            write_live_http_event(
                &mut stdout,
                &LiveHttpEvent::Attempt {
                    nonce: request.nonce.clone(),
                },
            );
            let event = match client.get(&request.url).send() {
                Ok(response) => {
                    let status = response.status().as_u16();
                    match response.bytes() {
                        Ok(body) => LiveHttpEvent::Response {
                            nonce: request.nonce,
                            status,
                            body: body.to_vec(),
                        },
                        Err(error) => LiveHttpEvent::Error {
                            nonce: request.nonce,
                            message: format!("read HTTP response body: {error}"),
                        },
                    }
                }
                Err(error) => LiveHttpEvent::Error {
                    nonce: request.nonce,
                    message: format!("send HTTP request: {error}"),
                },
            };
            write_live_http_event(&mut stdout, &event);
        }
    }
}

fn build_live_http_tls_config() -> rustls::ClientConfig {
    use rustls_platform_verifier::BuilderVerifierExt as _;

    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("configure live HTTP TLS protocol versions")
        .with_platform_verifier()
        .expect("configure live HTTP platform verifier")
        .with_no_client_auth()
}

fn write_live_http_event(writer: &mut impl Write, event: &LiveHttpEvent) {
    write!(writer, "{LIVE_HTTP_PREFIX}").expect("write live HTTP protocol prefix");
    serde_json::to_writer(&mut *writer, event).expect("serialize live HTTP event");
    writeln!(writer).expect("terminate live HTTP event");
    writer.flush().expect("flush live HTTP event");
}

fn start_live_stdout_reader(
    stdout: ChildStdout,
) -> (Receiver<Result<LiveHttpEvent, String>>, JoinHandle<String>) {
    let (sender, receiver) = channel();
    let reader = std::thread::spawn(move || {
        let mut capture = String::new();
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    capture.push_str(&line);
                    capture.push('\n');
                    if let Some((_, encoded)) = line.split_once(LIVE_HTTP_PREFIX) {
                        let event = serde_json::from_str(encoded).map_err(|error| {
                            format!("deserialize live HTTP event {encoded:?}: {error}")
                        });
                        let _ = sender.send(event);
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(format!("read live governed stdout: {error}")));
                    break;
                }
            }
        }
        capture
    });
    (receiver, reader)
}

/// Stable process, sandbox, Sidecar, agent, and session identity for a live governed run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveIdentity {
    /// PID of the wrapped fixture inside the structural sandbox.
    pub(crate) process_id: u32,
    /// Initial mount-namespace link target for the wrapped fixture.
    pub(crate) mount_namespace: String,
    /// Per-run sandbox marker directory name.
    pub(crate) sandbox_id: String,
    /// PID recorded for the owned Sidecar.
    pub(crate) sidecar_id: u32,
    /// Agent identity recorded in the Sidecar marker metadata.
    pub(crate) agent_id: String,
    /// Session identity recorded in the Sidecar marker metadata.
    pub(crate) session_id: String,
    /// Sidecar start timestamp recorded in marker metadata.
    pub(crate) sidecar_started_at: String,
}

/// A long-lived governed HTTP fixture plus its owned local Authority, Sidecar, and process group.
///
/// Dropping an unfinished run performs bounded process-group cleanup. Call [`Self::finish`] to
/// assert and inspect its final status and captured output.
pub(crate) struct LiveGovernedRun {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    events: Receiver<Result<LiveHttpEvent, String>>,
    stdout_reader: Option<JoinHandle<String>>,
    stderr: tempfile::NamedTempFile,
    state_path: PathBuf,
    audit_path: PathBuf,
    session_id: String,
    identity: Option<LiveIdentity>,
}

impl LiveGovernedRun {
    /// Returns the original identity after verifying every process and marker remains unchanged.
    pub(crate) fn identity(&self) -> LiveIdentity {
        let identity = self.identity.clone().expect("live identity ready");
        assert!(
            Path::new(&format!("/proc/{}", identity.process_id)).exists(),
            "wrapped process {} exited",
            identity.process_id
        );
        assert_eq!(
            std::fs::read_link(format!("/proc/{}/ns/mnt", identity.process_id))
                .expect("read wrapped process mount namespace")
                .to_string_lossy(),
            identity.mount_namespace,
            "wrapped process mount namespace changed"
        );
        let marker_path = self.state_path.join("run").join(&identity.sandbox_id);
        let marker = read_sidecar_marker(&marker_path, &identity.sandbox_id)
            .expect("read stable Sidecar marker");
        assert_eq!(
            marker,
            SidecarMarker {
                sandbox_id: identity.sandbox_id.clone(),
                sidecar_id: identity.sidecar_id,
                agent_id: identity.agent_id.clone(),
                session_id: identity.session_id.clone(),
                started_at: identity.sidecar_started_at.clone(),
            },
            "Sidecar marker identity changed"
        );
        assert!(
            Path::new(&format!("/proc/{}", identity.sidecar_id)).exists(),
            "Sidecar {} exited",
            identity.sidecar_id
        );
        identity
    }

    /// Sends one request through the existing governed fixture and returns its HTTP response.
    ///
    /// The method waits for an explicit attempt event and matching response, proving that the
    /// requested stimulus ran inside the sandbox.
    pub(crate) fn request(&mut self, nonce: &str, url: &str) -> LiveHttpResponse {
        let stdin = self.stdin.as_mut().expect("live governed stdin open");
        serde_json::to_writer(
            &mut *stdin,
            &LiveHttpRequest {
                nonce: nonce.to_string(),
                url: url.to_string(),
            },
        )
        .expect("serialize request to live governed process");
        writeln!(stdin).expect("terminate live governed request");
        stdin.flush().expect("flush live governed request");
        match self.receive_event("request attempt", Duration::from_secs(5)) {
            LiveHttpEvent::Attempt {
                nonce: attempted_nonce,
            } => assert_eq!(attempted_nonce, nonce),
            event => panic!("expected request attempt for {nonce}, got {event:?}"),
        }
        match self.receive_event("request response", Duration::from_secs(10)) {
            LiveHttpEvent::Response {
                nonce: response_nonce,
                status,
                body,
            } => {
                assert_eq!(response_nonce, nonce);
                LiveHttpResponse { status, body }
            }
            LiveHttpEvent::Error {
                nonce: response_nonce,
                message,
            } => {
                assert_eq!(response_nonce, nonce);
                panic!("live HTTP request {nonce} failed: {message}");
            }
            event => panic!("expected request response for {nonce}, got {event:?}"),
        }
    }

    /// Waits up to `timeout` for this run's unique audit event containing `nonce`.
    pub(crate) fn audit_event(&self, nonce: &str, timeout: Duration) -> AuditEvent {
        crate::audit::wait_for_correlated_event(&self.audit_path, &self.session_id, nonce, timeout)
    }

    /// Closes the request stream and waits up to 30 seconds for clean process-group completion.
    pub(crate) fn finish(mut self) -> ProcessOutput {
        self.finish_inner(Duration::from_secs(30))
    }

    fn receive_event(&mut self, expected: &str, timeout: Duration) -> LiveHttpEvent {
        match self.events.recv_timeout(timeout) {
            Ok(Ok(event)) => event,
            Ok(Err(error)) => {
                panic!("invalid live HTTP protocol while waiting for {expected}: {error}")
            }
            Err(RecvTimeoutError::Timeout) => {
                let status = self
                    .child
                    .as_mut()
                    .expect("live governed child")
                    .try_wait()
                    .expect("poll live governed child");
                panic!(
                    "timed out waiting for {expected}: status={status:?}\nstderr:\n{}",
                    read_capture(self.stderr.path())
                );
            }
            Err(RecvTimeoutError::Disconnected) => panic!(
                "live HTTP protocol closed while waiting for {expected}\nstderr:\n{}",
                read_capture(self.stderr.path())
            ),
        }
    }

    fn finish_inner(&mut self, timeout: Duration) -> ProcessOutput {
        self.stdin.take();
        let Some(mut child) = self.child.take() else {
            panic!("live governed process already finished");
        };
        let status = child
            .wait_timeout(timeout)
            .expect("wait for live governed process");
        let timed_out = status.is_none();
        let status = status.unwrap_or_else(|| terminate_process_group(&mut child));
        let stdout = self
            .stdout_reader
            .take()
            .expect("live stdout reader")
            .join()
            .expect("join live stdout reader");
        ProcessOutput {
            status,
            stdout,
            stderr: read_capture(self.stderr.path()),
            timed_out,
        }
    }
}

impl Drop for LiveGovernedRun {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.finish_inner(Duration::from_secs(10));
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SidecarMarker {
    sandbox_id: String,
    sidecar_id: u32,
    agent_id: String,
    session_id: String,
    started_at: String,
}

#[derive(Deserialize)]
struct SidecarMarkerMetadata {
    sandbox_id: String,
    agent_id: String,
    session_id: String,
    pid: u32,
    started_at: String,
}

fn wait_for_sidecar_marker(state_path: &Path, timeout: Duration) -> SidecarMarker {
    wait_for("one complete live Sidecar marker", timeout, || {
        let run_path = state_path.join("run");
        let markers = std::fs::read_dir(&run_path)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let sandbox_id = entry.file_name().into_string().ok()?;
                read_sidecar_marker(&entry.path(), &sandbox_id)
            })
            .collect::<Vec<_>>();
        match markers.as_slice() {
            [marker] => Some(marker.clone()),
            [] => None,
            _ => panic!("expected one live Sidecar marker, found {markers:?}"),
        }
    })
}

fn read_sidecar_marker(path: &Path, sandbox_id: &str) -> Option<SidecarMarker> {
    let sidecar_id = read_pid_file(&path.join("sidecar.pid"))?;
    let metadata = std::fs::read_to_string(path.join("metadata.toml")).ok()?;
    let metadata = toml::from_str::<SidecarMarkerMetadata>(&metadata).ok()?;
    assert_eq!(metadata.sandbox_id, sandbox_id);
    assert_eq!(metadata.pid, sidecar_id);
    Some(SidecarMarker {
        sandbox_id: sandbox_id.to_string(),
        sidecar_id,
        agent_id: metadata.agent_id,
        session_id: metadata.session_id,
        started_at: metadata.started_at,
    })
}

fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// The output and audit correlation data from [`TestWorld::run_governed`].
pub(crate) struct GovernedRun {
    /// Captured process status and output.
    pub(crate) output: ProcessOutput,
    audit_path: PathBuf,
    session_id: String,
    nonce: String,
}

impl GovernedRun {
    /// Returns the unique audit event correlated with this run's session and nonce.
    pub(crate) fn audit_event(&self) -> AuditEvent {
        correlated_event(&self.audit_path, &self.session_id, &self.nonce)
    }
}

/// Creates a command with only the environment needed to run inside `world`.
///
/// The command defaults to the world's workspace directory. Callers may add scenario-specific
/// environment variables and arguments before passing it to [`run_bounded`].
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

/// Captured UTF-8-lossy output and completion state for a bounded child process.
pub(crate) struct ProcessOutput {
    status: ExitStatus,
    /// Standard output captured when the process-group leader was reaped.
    pub(crate) stdout: String,
    /// Standard error captured when the process-group leader was reaped.
    pub(crate) stderr: String,
    timed_out: bool,
}

impl ProcessOutput {
    /// Reports success only when the process exited successfully before its deadline.
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

/// Runs `command` with a deadline for its process-group leader while capturing stdout and stderr.
///
/// The command starts a new process group. If its leader is still running at the deadline, the
/// entire group receives `SIGTERM`, then receives `SIGKILL` after a two-second grace period even if
/// the leader exited during that grace period. The returned output records the timeout independently
/// of the eventual exit status. If the leader exits before the deadline, descendants are not
/// explicitly reaped and the captures are read immediately.
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
    let status = status.unwrap_or_else(|| terminate_process_group(&mut child));
    ProcessOutput {
        status,
        stdout: read_capture(stdout.path()),
        stderr: read_capture(stderr.path()),
        timed_out,
    }
}

fn terminate_process_group(child: &mut Child) -> ExitStatus {
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
}

fn read_capture(path: &Path) -> String {
    String::from_utf8_lossy(&std::fs::read(path).unwrap_or_default()).into_owned()
}
