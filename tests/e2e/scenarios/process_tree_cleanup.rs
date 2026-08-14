use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use wait_timeout::ChildExt as _;

use crate::harness::TestWorld;

const READY_TIMEOUT: Duration = Duration::from_secs(30);
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn termination_reaps_the_sandbox_process_tree_and_helpers() {
    let world = TestWorld::new();
    let workspace = world.workspace_path();
    let root_pid_path = workspace.join("root.pid");
    let child_pid_path = workspace.join("child.pid");
    let grandchild_pid_path = workspace.join("grandchild.pid");
    let ready_path = workspace.join("process-tree.ready");
    let script = workspace.join("process-tree.sh");
    write_process_tree_script(
        &script,
        &root_pid_path,
        &child_pid_path,
        &grandchild_pid_path,
        &ready_path,
    );

    let stdout = tempfile::NamedTempFile::new().expect("create stdout capture");
    let stderr = tempfile::NamedTempFile::new().expect("create stderr capture");
    let mut command = world.isolated_command_in(env!("CARGO_BIN_EXE_firma"), &workspace);
    command
        .args(["run", "--profile", "generic"])
        .arg("--config")
        .arg(world.config_path())
        .args(["--authority", "local", "--sidecar", "local", "--"])
        .arg("/usr/bin/bash")
        .arg(&script)
        .env("FIRMA_RUN_SESSION_ID", "sess_process_tree_cleanup")
        .stdout(Stdio::from(stdout.reopen().expect("reopen stdout capture")))
        .stderr(Stdio::from(stderr.reopen().expect("reopen stderr capture")));

    // Intentionally do not put `firma run` in a harness-owned process group.
    // The only stimulus below is SIGTERM to the user-facing CLI PID. The guard
    // kills individual recorded processes only if an assertion fails.
    let child = command.spawn().expect("spawn firma run");
    let mut guard = FailureCleanup::new(child);
    wait_for_path(&ready_path, READY_TIMEOUT, &mut guard);

    let root = process_identity(read_pid(&root_pid_path));
    let child = process_identity(read_pid(&child_pid_path));
    let grandchild = process_identity(read_pid(&grandchild_pid_path));
    let firma_pid = guard.firma_pid();
    let descendants = descendant_identities(firma_pid);
    assert!(
        descendants.values().any(|identity| identity == &root),
        "sandbox root was not a descendant of firma run: {descendants:?}"
    );
    assert!(
        descendants.values().any(|identity| identity == &child),
        "sandbox child was not a descendant of firma run: {descendants:?}"
    );
    assert!(
        descendants.values().any(|identity| identity == &grandchild),
        "sandbox grandchild was not a descendant of firma run: {descendants:?}"
    );
    guard.record(descendants.values().cloned());

    kill(pid(firma_pid), Signal::SIGTERM).expect("terminate firma run through its CLI PID");
    let status = guard
        .wait_timeout(EXIT_TIMEOUT)
        .expect("wait for firma run")
        .unwrap_or_else(|| panic!("firma run did not complete within {EXIT_TIMEOUT:?}"));
    assert!(
        status.success(),
        "the TERM-handling root exited cleanly, but firma run reported {status}"
    );

    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        let survivors = descendants
            .values()
            .filter(|identity| identity.exists())
            .cloned()
            .collect::<Vec<_>>();
        if survivors.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "firma run exited but left sandbox descendants or helpers alive: {survivors:?}\nstdout:\n{}\nstderr:\n{}",
            read_capture(stdout.path()),
            read_capture(stderr.path()),
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    guard.disarm();
}

fn write_process_tree_script(
    script: &Path,
    root_pid: &Path,
    child_pid: &Path,
    grandchild_pid: &Path,
    ready: &Path,
) {
    let contents = format!(
        r#"#!/usr/bin/bash
set -eu
printf '%s\n' "$BASHPID" > {root_pid}
trap 'exit 0' TERM INT
(
  printf '%s\n' "$BASHPID" > {child_pid}
  trap 'exit 0' TERM INT
  (
    trap '' TERM INT
    printf '%s\n' "$BASHPID" > {grandchild_pid}
    : > {ready}
    while :; do sleep 1; done
  ) &
  while :; do sleep 1; done
) &
while :; do sleep 1; done
"#,
        root_pid = shell_quote(root_pid),
        child_pid = shell_quote(child_pid),
        grandchild_pid = shell_quote(grandchild_pid),
        ready = shell_quote(ready),
    );
    std::fs::write(script, contents).expect("write process-tree fixture");
}

fn wait_for_path(path: &Path, timeout: Duration, guard: &mut FailureCleanup) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if let Some(status) = guard.try_wait().expect("poll firma run readiness") {
            panic!("firma run exited before process-tree readiness: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "process tree was not ready within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn descendant_identities(root: u32) -> BTreeMap<u32, ProcessIdentity> {
    let mut pending = vec![root];
    let mut seen = BTreeSet::new();
    let mut identities = BTreeMap::new();
    while let Some(parent) = pending.pop() {
        for child in process_children(parent) {
            if seen.insert(child) {
                pending.push(child);
                if let Some(identity) = try_process_identity(child) {
                    identities.insert(child, identity);
                }
            }
        }
    }
    identities
}

fn process_children(parent: u32) -> Vec<u32> {
    let path = format!("/proc/{parent}/task/{parent}/children");
    std::fs::read_to_string(path).map_or_else(
        |_| Vec::new(),
        |contents| {
            contents
                .split_whitespace()
                .filter_map(|value| value.parse().ok())
                .collect()
        },
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    start_time: String,
}

impl ProcessIdentity {
    fn exists(&self) -> bool {
        read_start_time(self.pid).is_some_and(|start_time| start_time == self.start_time)
    }
}

fn process_identity(raw_pid: u32) -> ProcessIdentity {
    try_process_identity(raw_pid)
        .unwrap_or_else(|| panic!("process {raw_pid} disappeared before identity capture"))
}

fn try_process_identity(raw_pid: u32) -> Option<ProcessIdentity> {
    Some(ProcessIdentity {
        pid: raw_pid,
        start_time: read_start_time(raw_pid)?,
    })
}

fn read_start_time(raw_pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{raw_pid}/stat")).ok()?;
    // The comm field can contain spaces and parentheses. Fields after its final
    // ')' start at field 3; starttime is field 22, offset 19 in this suffix.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)
        .map(ToOwned::to_owned)
}

fn read_pid(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("parse PID from {}: {error}", path.display()))
}

fn pid(raw: u32) -> Pid {
    Pid::from_raw(i32::try_from(raw).expect("PID fits pid_t"))
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn read_capture(path: &Path) -> String {
    String::from_utf8_lossy(&std::fs::read(path).unwrap_or_default()).into_owned()
}

struct FailureCleanup {
    firma: Child,
    recorded: Vec<ProcessIdentity>,
    armed: bool,
}

impl FailureCleanup {
    fn new(firma: Child) -> Self {
        Self {
            firma,
            recorded: Vec::new(),
            armed: true,
        }
    }

    fn firma_pid(&self) -> u32 {
        self.firma.id()
    }

    fn record(&mut self, identities: impl IntoIterator<Item = ProcessIdentity>) {
        self.recorded.extend(identities);
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.firma.try_wait()
    }

    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.firma.wait_timeout(timeout)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FailureCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.firma.kill();
        for identity in &self.recorded {
            if identity.exists() {
                let _ = kill(pid(identity.pid), Signal::SIGKILL);
            }
        }
        let _ = self.firma.wait();
    }
}
