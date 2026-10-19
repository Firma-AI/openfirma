use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::audit::{AuditDecision, AuditEvent};
use crate::harness::{LiveGovernedRun, ProcessOutput, TestWorld};
use crate::upstream::{HttpProbe, ProbeBehavior};

/// Requests each URL argument through the configured proxy, labelling every attempt and status.
const HTTP_ATTEMPTS: &str = r#"for url in "$@"; do
printf 'ATTEMPT %s\n' "$url"
status=$(curl --silent --output /dev/null --max-time 10 --write-out '%{http_code}' "$url")
printf 'STATUS %s %s\n' "$status" "$url"
done"#;

/// Question shown by `firma run` before it persists a local Mini Authority configuration.
const BOOTSTRAP_PROMPT: &str = "Start a local Mini Authority?";

const AUTHORITY_REUSED: &str = "authority reused: existing local authority on plaintext loopback";

/// A host-owned mapping rule that classifies loopback `/reload-*` requests once enforced.
const RELOAD_RULE: &str = "\n[[rules]]\nmethod = 'GET'\nhost = '127.0.0.1:*'\npath = '/reload-*'\naction_class = 'communication.internal.send'\n";

#[test]
fn persisted_authority_classifies_using_custom_mapping_inputs() {
    for mapping_sources in [&["custom.toml"][..], &["mapping-rules.toml", "custom.toml"]] {
        let world = TestWorld::new();
        let nonce = format!("authority-mapping-{}", uuid::Uuid::new_v4().simple());
        let upstream = HttpProbe::start(&nonce, ProbeBehavior::Respond("custom-mapping-ok\n"));
        let mut config = read_config(&world.config_path());
        config["authority"]["mapping_rules_paths"] = toml::Value::from(mapping_sources.to_vec());
        write_config(&world.config_path(), &config);
        std::fs::write(
            world.path("config/custom.toml"),
            format!(
                "[[rules]]\nmethod = 'GET'\nhost = '{}'\npath = '/{nonce}'\naction_class = 'code.read'\n",
                upstream.authority()
            ),
        )
        .expect("write distinct custom mapping");
        let run = world.run_governed(
            &nonce,
            "curl",
            [
                "--fail-with-body",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                &upstream.url(),
            ],
        );
        assert!(
            run.output.success(),
            "custom Authority mapping run with {mapping_sources:?} failed:\n{}",
            run.output
        );
        assert!(run.output.stdout.ends_with("custom-mapping-ok\n"));
        let resource = upstream.resource();
        let capture = upstream
            .finish()
            .expect("classified request reached upstream");
        assert_eq!(capture.method, "GET");
        assert_eq!(capture.path, format!("/{nonce}"));
        let event = run.audit_event();
        assert_eq!(event.action, "code.read");
        assert_eq!(event.resource, resource);
        assert_eq!(event.decision, AuditDecision::Allow);
        assert_eq!(event.deny_reason, "");
        assert_ne!(event.bundle_version, "");
    }
}

#[test]
fn protection_only_template_starts_with_generated_authority_mappings() {
    let world = TestWorld::new();
    let config_path = world.config_path();
    let mut config = read_config(&config_path);
    config
        .as_table_mut()
        .expect("config table")
        .remove("authority");
    write_config(&config_path, &config);
    std::fs::remove_file(world.path("config/mapping-rules.toml"))
        .expect("no implicit mapping file");

    // The generated rules classify AI-provider hosts only. The Sidecar's upstream client honours
    // the host's `HTTP_PROXY`, so the classified provider request reaches this loopback probe
    // instead of the real provider. The wrapped command always receives the Sidecar as its proxy.
    let provider_nonce = format!("generated-provider-{}", uuid::Uuid::new_v4().simple());
    let provider_proxy = HttpProbe::start(
        &provider_nonce,
        ProbeBehavior::Respond("generated-mapping-ok\n"),
    );
    let provider_url = format!("http://claude.ai/{provider_nonce}");
    let upstream_proxy = format!("http://{}", provider_proxy.authority());
    let denied_nonce = format!("generated-unmapped-{}", uuid::Uuid::new_v4().simple());
    let denied = HttpProbe::start(&denied_nonce, ProbeBehavior::MustNotConnect);
    let output = world.run_firma_with_host_env(
        "generic",
        Some(&config_path),
        &world.workspace_path(),
        &["--authority", "local", "--sidecar", "local"],
        "sh",
        ["-c", HTTP_ATTEMPTS, "sh", &provider_url, &denied.url()],
        &[("HTTP_PROXY", Path::new(&upstream_proxy))],
    );
    assert!(
        output.success(),
        "path-less Authority bootstrap failed:\n{output}"
    );
    assert_attempted(&output, &provider_url, 200);
    assert_attempted(&output, &denied.url(), 403);

    let capture = provider_proxy
        .finish()
        .expect("generated provider mapping allowed dispatch");
    assert_eq!(capture.method, "GET");
    assert_eq!(capture.path, provider_url);
    let allowed = world.audit_event(&provider_nonce);
    assert_eq!(allowed.decision, AuditDecision::Allow);
    assert_eq!(allowed.action, "communication.external.send");
    assert_eq!(allowed.resource, format!("claude.ai/{provider_nonce}"));
    assert_ne!(allowed.bundle_version, "");

    let denied_resource = denied.resource();
    assert!(
        denied.finish().is_none(),
        "unmapped request reached upstream"
    );
    let blocked = world.audit_event(&denied_nonce);
    assert_unclassified(&blocked, &denied_resource);
    assert_eq!(blocked.bundle_version, allowed.bundle_version);
}

#[test]
fn agent_mapping_rewrites_cannot_change_owned_authority_governance() {
    let world = TestWorld::new();
    let control_nonce = format!("mapping-control-{}", uuid::Uuid::new_v4().simple());
    let control = HttpProbe::start(&control_nonce, ProbeBehavior::Respond("control-ok\n"));
    let agent_mapping = world.path("workspace/agent-mapping.toml");
    std::fs::write(
        &agent_mapping,
        format!(
            "[[rules]]\nhost = '{}'\naction_class = 'communication.external.send'\n",
            control.authority()
        ),
    )
    .expect("write agent-writable mapping");
    let host_mapping = write_host_owned_mapping(
        &world,
        "[[rules]]\nhost = 'host-owned.invalid'\naction_class = 'communication.internal.send'\n",
    );
    let mut config = read_config(&world.config_path());
    config["authority"]["mapping_rules_paths"] = toml::Value::from(vec![
        agent_mapping.display().to_string(),
        "host-mapping.toml".to_string(),
    ]);
    write_config(&world.config_path(), &config);

    let mut run = world.start_live_governed();
    let frozen_host_mapping = frozen_copy(&world, &mut run, &host_mapping);
    let control_resource = control.resource();
    let response = run.request(&control_nonce, &control.url());
    assert_eq!(response.status, 200, "agent-writable mapping was not used");
    assert_eq!(response.body, b"control-ok\n");
    let capture = control.finish().expect("control request reached upstream");
    assert_eq!(capture.path, format!("/{control_nonce}"));
    let allowed = run.audit_event(&control_nonce, Duration::from_secs(5));
    assert_eq!(allowed.decision, AuditDecision::Allow);
    assert_eq!(allowed.action, "communication.external.send");
    assert_eq!(allowed.resource, control_resource);

    let before_nonce = format!("mapping-before-{}", uuid::Uuid::new_v4().simple());
    assert_unclassified_request(&mut run, &before_nonce, &allowed.bundle_version);

    let widened = "[[rules]]\nhost = '*'\naction_class = 'communication.external.send'\n";
    run.write_file("agent-mapping-rewrite", &agent_mapping, widened);
    assert_eq!(
        std::fs::read_to_string(&agent_mapping).expect("agent-rewritten mapping"),
        widened
    );
    let reloaded = reload_host_owned_mapping(&mut run, &frozen_host_mapping);
    assert_ne!(reloaded, allowed.bundle_version);

    let after_nonce = format!("mapping-after-{}", uuid::Uuid::new_v4().simple());
    assert_unclassified_request(&mut run, &after_nonce, &reloaded);
    let output = run.finish();
    assert!(output.success(), "live governed run failed:\n{output}");
}

/// Writes `rules` to `config/host-mapping.toml`, which the sandboxed agent cannot write, and
/// returns the file contents. A unique comment lets the test identify the run's frozen copy.
fn write_host_owned_mapping(world: &TestWorld, rules: &str) -> String {
    let contents = format!(
        "# host-owned mapping {}\n{rules}",
        uuid::Uuid::new_v4().simple()
    );
    std::fs::write(world.path("config/host-mapping.toml"), &contents)
        .expect("write host-owned mapping");
    contents
}

/// Returns the single regular file below the live run's marker directory holding `contents`.
///
/// `firma run` freezes Authority inputs into this host-only directory before the agent starts.
fn frozen_copy(world: &TestWorld, run: &mut LiveGovernedRun, contents: &str) -> PathBuf {
    let run_directory = world
        .state_path()
        .join("run")
        .join(run.identity().sandbox_id);
    let mut pending = vec![run_directory.clone()];
    let mut copies = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("read run marker directory") {
            let entry = entry.expect("run marker entry");
            let file_type = entry.file_type().expect("run marker entry type");
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file()
                && std::fs::read_to_string(entry.path()).is_ok_and(|text| text == contents)
            {
                copies.push(entry.path());
            }
        }
    }
    match <[PathBuf; 1]>::try_from(copies) {
        Ok([copy]) => copy,
        Err(copies) => panic!(
            "expected one frozen host-owned mapping below {}, found {copies:?}",
            run_directory.display()
        ),
    }
}

/// Appends [`RELOAD_RULE`] to the frozen host-owned mapping and waits until the Sidecar enforces
/// the reloaded bundle, returning its version.
///
/// The frozen copy is not agent-writable, so this proves that the Authority recompiled its inputs
/// and the Sidecar adopted the result after any earlier agent rewrite.
fn reload_host_owned_mapping(run: &mut LiveGovernedRun, frozen: &Path) -> String {
    let mut contents = std::fs::read_to_string(frozen).expect("read frozen host-owned mapping");
    contents.push_str(RELOAD_RULE);
    std::fs::write(frozen, contents).expect("update frozen host-owned mapping");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let nonce = format!("reload-{}", uuid::Uuid::new_v4().simple());
        let probe = HttpProbe::start(&nonce, ProbeBehavior::OptionalResponse("reload-ok\n"));
        let resource = probe.resource();
        let response = run.request(&nonce, &probe.url());
        let capture = probe.finish();
        let event = run.audit_event(&nonce, Duration::from_secs(5));
        if response.status == 403 {
            assert!(
                capture.is_none(),
                "unclassified reload probe reached upstream"
            );
            assert_unclassified(&event, &resource);
            assert!(
                Instant::now() < deadline,
                "host-owned mapping update was not enforced within 30 seconds"
            );
            continue;
        }
        assert_eq!(response.status, 200, "unexpected reload probe status");
        assert_eq!(response.body, b"reload-ok\n");
        let capture = capture.expect("reload probe reached upstream");
        assert_eq!(capture.path, format!("/{nonce}"));
        assert_eq!(event.decision, AuditDecision::Allow);
        assert_eq!(
            event.action, "communication.internal.send",
            "reload probe was classified by a rule other than the host-owned update"
        );
        assert_eq!(event.resource, resource);
        return event.bundle_version;
    }
}

/// Requests an unmapped loopback URL and asserts it is denied as unclassified under `version`.
fn assert_unclassified_request(run: &mut LiveGovernedRun, nonce: &str, version: &str) {
    let probe = HttpProbe::start(nonce, ProbeBehavior::MustNotConnect);
    let resource = probe.resource();
    let response = run.request(nonce, &probe.url());
    assert_eq!(
        response.status, 403,
        "unmapped request was not denied; an agent mapping rewrite may have taken effect"
    );
    assert!(
        probe.finish().is_none(),
        "unmapped request reached upstream"
    );
    let event = run.audit_event(nonce, Duration::from_secs(5));
    assert_unclassified(&event, &resource);
    assert_eq!(event.bundle_version, version);
}

#[test]
fn missing_authority_mapping_inputs_fail_before_the_wrapped_command() {
    let world = TestWorld::new();
    let path = world.config_path();
    let mut config = read_config(&path);
    config["authority"]
        .as_table_mut()
        .expect("Authority")
        .remove("mapping_rules_paths");
    write_config(&path, &config);
    let run = world.run_governed("missing-mappings", "echo", ["WRAPPED_COMMAND_STARTED"]);
    assert!(
        !run.output.success(),
        "missing sources started: {}",
        run.output
    );
    assert!(!run.output.stdout.contains("WRAPPED_COMMAND_STARTED"));
    assert!(
        run.output
            .stderr
            .contains("authority.mapping_rules_paths must contain at least one mapping file"),
        "{}",
        run.output
    );
}

#[test]
fn an_explicit_empty_mapping_file_denies_protected_transport() {
    let control_world = TestWorld::new();
    let control_nonce = format!("empty-control-{}", uuid::Uuid::new_v4().simple());
    let control = HttpProbe::start(&control_nonce, ProbeBehavior::Respond("control-ok\n"));
    let run = control_world.run_governed(
        &control_nonce,
        "sh",
        ["-c", HTTP_ATTEMPTS, "sh", &control.url()],
    );
    assert!(run.output.success(), "{}", run.output);
    assert_attempted(&run.output, &control.url(), 200);
    assert!(control.finish().is_some());
    assert_eq!(run.audit_event().decision, AuditDecision::Allow);

    let world = TestWorld::new();
    let path = world.config_path();
    std::fs::write(world.path("config/empty.toml"), "rules = []\n")
        .expect("write explicit deny-all");
    let mut config = read_config(&path);
    config["authority"]["mapping_rules_paths"] = toml::Value::from(vec!["empty.toml".to_string()]);
    write_config(&path, &config);
    let nonce = format!("empty-deny-{}", uuid::Uuid::new_v4().simple());
    let denied = HttpProbe::start(&nonce, ProbeBehavior::MustNotConnect);
    let resource = denied.resource();
    let run = world.run_governed(&nonce, "sh", ["-c", HTTP_ATTEMPTS, "sh", &denied.url()]);
    assert!(run.output.success(), "{}", run.output);
    assert_attempted(&run.output, &denied.url(), 403);
    assert!(denied.finish().is_none());
    let event = run.audit_event();
    assert_unclassified(&event, &resource);
    assert_ne!(event.bundle_version, "");
}

#[test]
fn implicit_initialization_preserves_authored_mapping_sources_on_first_and_second_runs() {
    let control_world = TestWorld::new();
    let control_nonce = format!("init-control-{}", uuid::Uuid::new_v4().simple());
    let control = HttpProbe::start(&control_nonce, ProbeBehavior::Respond("control-ok\n"));
    let control_run = control_world.run_governed(
        &control_nonce,
        "sh",
        ["-c", HTTP_ATTEMPTS, "sh", &control.url()],
    );
    assert!(control_run.output.success(), "{}", control_run.output);
    assert_attempted(&control_run.output, &control.url(), 200);
    assert!(control.finish().is_some());

    let world = TestWorld::new();
    let directory = world.path("workspace/.firma");
    std::fs::create_dir_all(&directory).expect("create implicit init target");
    std::fs::write(directory.join("mapping-rules.toml"), "rules = []\n")
        .expect("write authored mapping");
    let mut identity = None;
    let mut version = None;
    for _ in 0..2 {
        let nonce = format!("init-preserved-{}", uuid::Uuid::new_v4().simple());
        let denied = HttpProbe::start(&nonce, ProbeBehavior::MustNotConnect);
        let resource = denied.resource();
        let output = world.run_firma(
            "generic",
            None,
            &world.workspace_path(),
            &["--authority", "local", "--sidecar", "local"],
            "sh",
            ["-c", HTTP_ATTEMPTS, "sh", &denied.url()],
        );
        assert!(output.success(), "{output}");
        assert_attempted(&output, &denied.url(), 403);
        assert!(denied.finish().is_none());
        let config = read_config(&directory.join("firma.toml"));
        assert_eq!(
            mapping_sources(&config),
            ["mapping-rules.toml", "mappings/anthropic.toml"]
        );
        let current_id = config["sidecar"]["authority"]["agent_id"]
            .as_str()
            .expect("agent identity")
            .to_string();
        assert_eq!(
            identity.get_or_insert_with(|| current_id.clone()),
            &current_id
        );
        assert_eq!(
            std::fs::read_to_string(directory.join("mapping-rules.toml"))
                .expect("authored mapping"),
            "rules = []\n"
        );
        let event = world.audit_event(&nonce);
        assert_unclassified(&event, &resource);
        assert_ne!(event.bundle_version, "");
        assert_eq!(
            version.get_or_insert_with(|| event.bundle_version.clone()),
            &event.bundle_version
        );
    }
}

#[test]
fn local_daemon_reuse_cannot_bypass_required_mapping_configuration() {
    let world = TestWorld::new();
    let report = world.path("authority.startup.toml");
    let stderr = world.path("authority.stderr.log");
    let child = world
        .isolated_command_in(env!("CARGO_BIN_EXE_firma"), &world.workspace_path())
        .args(["authority", "--no-tls", "--config"])
        .arg(world.config_path())
        .arg("--startup-report")
        .arg(&report)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr).expect("Authority log"))
        .spawn()
        .expect("start existing Authority");
    let mut daemon = AuthorityDaemon(child);
    let address =
        crate::poll::wait_for("Authority startup report", Duration::from_secs(10), || {
            assert!(
                daemon.0.try_wait().expect("Authority status").is_none(),
                "{}",
                std::fs::read_to_string(&stderr).expect("log")
            );
            let text = std::fs::read_to_string(&report).ok()?;
            let report: toml::Value = toml::from_str(&text).expect("startup report");
            Some(
                report["endpoint"]
                    .as_str()
                    .expect("published Authority endpoint")
                    .to_string(),
            )
        });
    let path = world.config_path();
    let mut config = read_config(&path);
    config["authority"]["listen_addr"] = toml::Value::String(address.clone());
    config["sidecar"]["authority"]["url"] = toml::Value::String(format!("http://{address}"));
    write_config(&path, &config);
    let control = world.run_governed("reuse-control", "echo", ["WRAPPED_COMMAND_STARTED"]);
    assert!(control.output.success(), "{}", control.output);
    assert!(control.output.stdout.contains("WRAPPED_COMMAND_STARTED"));
    assert!(
        control.output.stderr.contains(AUTHORITY_REUSED),
        "control run did not reuse the existing Authority:\n{}",
        control.output
    );
    config["authority"]
        .as_table_mut()
        .expect("Authority")
        .remove("mapping_rules_paths");
    write_config(&path, &config);
    let blocked = world.run_governed("reuse-invalid", "echo", ["WRAPPED_COMMAND_STARTED"]);
    assert!(!blocked.output.success(), "{}", blocked.output);
    assert!(!blocked.output.stdout.contains("WRAPPED_COMMAND_STARTED"));
    assert!(
        blocked
            .output
            .stderr
            .contains("authority.mapping_rules_paths must contain at least one mapping file"),
        "{}",
        blocked.output
    );
    assert!(
        daemon
            .0
            .try_wait()
            .expect("Authority still running")
            .is_none()
    );
}

struct AuthorityDaemon(std::process::Child);

impl Drop for AuthorityDaemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn prompted_bootstrap_preserves_authored_sources_across_two_governed_launches() {
    let world = TestWorld::new();
    let config_path = world.config_path();
    let mut config = read_config(&config_path);
    config
        .as_table_mut()
        .expect("config table")
        .remove("authority");
    config["sidecar"]["authority"]
        .as_table_mut()
        .expect("connect fields")
        .remove("url");
    write_config(&config_path, &config);
    let authored_mapping = world.path("config/mapping-rules.toml");
    let authored = "[[rules]]\nmethod = 'GET'\nhost = '127.0.0.1:*'\npath = '/allowed-*'\naction_class = 'communication.external.send'\n";
    std::fs::write(&authored_mapping, authored).expect("write authored mapping");
    let session = format!("sess_prompted_{}", uuid::Uuid::new_v4().simple());
    let mut version = None;
    for launch in 0..2 {
        let allowed_nonce = format!("allowed-{}", uuid::Uuid::new_v4().simple());
        let denied_nonce = format!("denied-{}", uuid::Uuid::new_v4().simple());
        let control = HttpProbe::start(&allowed_nonce, ProbeBehavior::Respond("control-ok\n"));
        let denied = HttpProbe::start(&denied_nonce, ProbeBehavior::MustNotConnect);
        let (allowed_resource, denied_resource) = (control.resource(), denied.resource());
        let mut command =
            world.isolated_command_in(env!("CARGO_BIN_EXE_firma"), &world.workspace_path());
        command
            .args(["run", "--config"])
            .arg(&config_path)
            .args(["--profile", "generic", "--sidecar", "local", "--"])
            .args([
                "sh",
                "-c",
                HTTP_ATTEMPTS,
                "sh",
                &control.url(),
                &denied.url(),
            ])
            .env("FIRMA_RUN_SESSION_ID", &session);
        let run = run_answering_bootstrap_prompt(command, Duration::from_secs(90));
        assert!(run.status.success(), "{run}");
        assert_eq!(
            run.terminal.contains(BOOTSTRAP_PROMPT),
            launch == 0,
            "the bootstrap prompt must appear only before its answer is persisted:\n{run}"
        );
        for (url, status) in [(control.url(), 200), (denied.url(), 403)] {
            assert!(
                run.stdout.contains(&format!("ATTEMPT {url}\n"))
                    && run.stdout.contains(&format!("STATUS {status} {url}\n")),
                "expected status {status} for {url}:\n{run}"
            );
        }
        assert!(control.finish().is_some());
        assert!(denied.finish().is_none());
        assert_eq!(
            mapping_sources(&read_config(&config_path)),
            ["mapping-rules.toml"]
        );
        assert_eq!(
            std::fs::read_to_string(&authored_mapping).expect("authored mapping retained"),
            authored
        );
        let audit = world.path("state/audit.jsonl");
        let allowed = crate::audit::correlated_event(&audit, &session, &allowed_nonce);
        let blocked = crate::audit::correlated_event(&audit, &session, &denied_nonce);
        assert_eq!(allowed.decision, AuditDecision::Allow);
        assert_eq!(allowed.action, "communication.external.send");
        assert_eq!(allowed.resource, allowed_resource);
        assert_unclassified(&blocked, &denied_resource);
        assert_eq!(allowed.bundle_version, blocked.bundle_version);
        assert_eq!(
            version.get_or_insert_with(|| allowed.bundle_version.clone()),
            &allowed.bundle_version
        );
    }
}

/// Completion state of a command whose standard input and error were a pseudo-terminal.
struct TerminalRun {
    status: ExitStatus,
    stdout: String,
    terminal: String,
}

impl fmt::Display for TerminalRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "status={}\nstdout:\n{}\nterminal:\n{}",
            self.status, self.stdout, self.terminal
        )
    }
}

/// Runs `command` with standard input and error on a new pseudo-terminal, answering `y` once
/// when [`BOOTSTRAP_PROMPT`] appears, and captures standard output separately.
///
/// The command runs in its own process group, which is killed if it is still running after
/// `timeout`.
fn run_answering_bootstrap_prompt(mut command: Command, timeout: Duration) -> TerminalRun {
    use std::io::Write as _;
    use std::os::unix::process::CommandExt as _;

    use wait_timeout::ChildExt as _;

    let pty = nix::pty::openpty(None, None).expect("open pseudo-terminal");
    let stdout = tempfile::NamedTempFile::new().expect("stdout capture");
    command
        .stdin(Stdio::from(
            pty.slave.try_clone().expect("terminal input handle"),
        ))
        .stderr(Stdio::from(pty.slave))
        .stdout(Stdio::from(stdout.reopen().expect("stdout handle")))
        .process_group(0);
    let mut child = command.spawn().expect("spawn terminal command");
    // Release the parent's terminal handles so reads observe hang-up once the command exits.
    drop(command);
    let mut terminal = std::fs::File::from(pty.master);
    let mut transcript = Vec::new();
    let mut answered = false;
    let deadline = Instant::now() + timeout;
    let status = loop {
        let progressed = read_terminal(&mut terminal, &mut transcript, 100);
        if !answered && String::from_utf8_lossy(&transcript).contains(BOOTSTRAP_PROMPT) {
            terminal.write_all(b"y\n").expect("answer bootstrap prompt");
            answered = true;
        }
        if let Some(status) = child.try_wait().expect("poll terminal command") {
            break status;
        }
        if Instant::now() >= deadline {
            let group = nix::unistd::Pid::from_raw(
                i32::try_from(child.id()).expect("process id fits a process group id"),
            );
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
            let status = child
                .wait_timeout(Duration::from_secs(10))
                .expect("reap timed-out terminal command");
            panic!(
                "terminal command did not finish within {timeout:?} (status after kill: {status:?})\nterminal:\n{}",
                String::from_utf8_lossy(&transcript)
            );
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    while read_terminal(&mut terminal, &mut transcript, 100) {}
    TerminalRun {
        status,
        stdout: String::from_utf8_lossy(&std::fs::read(stdout.path()).unwrap_or_default())
            .into_owned(),
        terminal: String::from_utf8_lossy(&transcript).into_owned(),
    }
}

/// Appends terminal output that becomes readable within `timeout_ms` to `transcript`.
///
/// Returns `false` when nothing was read, including the hang-up Linux reports as `EIO` once every
/// terminal handle held by the command is closed.
fn read_terminal(terminal: &mut std::fs::File, transcript: &mut Vec<u8>, timeout_ms: u16) -> bool {
    use std::io::Read as _;
    use std::os::fd::AsFd as _;

    use nix::poll::{PollFd, PollFlags, poll};

    let mut descriptors = [PollFd::new(terminal.as_fd(), PollFlags::POLLIN)];
    if poll(&mut descriptors, timeout_ms).expect("poll terminal") == 0 {
        return false;
    }
    let mut chunk = [0_u8; 4096];
    match terminal.read(&mut chunk) {
        Ok(read) if read > 0 => {
            transcript.extend_from_slice(&chunk[..read]);
            true
        }
        _ => false,
    }
}

fn read_config(path: &Path) -> toml::Value {
    toml::from_str(&std::fs::read_to_string(path).expect("read config")).expect("parse config")
}

fn write_config(path: &Path, config: &toml::Value) {
    std::fs::write(path, toml::to_string(config).expect("serialize config")).expect("write config");
}

fn mapping_sources(config: &toml::Value) -> Vec<&str> {
    config["authority"]["mapping_rules_paths"]
        .as_array()
        .expect("mapping sources")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect()
}

/// Asserts that the [`HTTP_ATTEMPTS`] stimulus attempted `url` and observed `status`.
fn assert_attempted(output: &ProcessOutput, url: &str, status: u16) {
    assert!(
        output.stdout.contains(&format!("ATTEMPT {url}\n")),
        "missing attempt for {url}:\n{output}"
    );
    assert!(
        output.stdout.contains(&format!("STATUS {status} {url}\n")),
        "expected status {status} for {url}:\n{output}"
    );
}

fn assert_unclassified(event: &AuditEvent, resource: &str) {
    assert_eq!(event.decision, AuditDecision::Deny);
    assert_eq!(event.action, "raw.http.GET");
    assert_eq!(event.resource, resource);
    assert!(
        event.deny_reason.starts_with("unclassified intent:"),
        "unexpected deny reason: {}",
        event.deny_reason
    );
}
