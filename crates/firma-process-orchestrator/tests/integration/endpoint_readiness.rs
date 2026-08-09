//! Child-published TCP readiness and startup transaction coverage.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use firma_process_orchestrator::{
    ComponentSpec, OrchestratorError, Readiness, RunningStack, StackTopology, StartError,
    publish_tcp_endpoint, spawn_stack_from_plan,
};

const CHILD_MODE: &str = "FIRMA_ENDPOINT_CHILD_MODE";
const CHILD_BIND_ADDR: &str = "FIRMA_ENDPOINT_CHILD_BIND_ADDR";
const CHILD_RECORD: &str = "FIRMA_ENDPOINT_CHILD_RECORD";
const CHILD_MARKER: &str = "FIRMA_ENDPOINT_CHILD_MARKER";
const CHILD_PUBLICATION_PATH: &str = "FIRMA_ENDPOINT_CHILD_PUBLICATION_PATH";

#[test]
fn dynamic_publication_replaces_stale_canonical_only_after_validation() {
    let fixture = Fixture::new("publish", "127.0.0.1:0", None);
    std::fs::create_dir_all(&fixture.state_dir).expect("create state dir");
    std::fs::write(fixture.state_dir.join("worker.listen"), "127.0.0.1:1\n")
        .expect("write stale canonical endpoint");
    let stale_publication = fixture.state_dir.join(".startup-stale/0.listen");
    std::fs::create_dir_all(stale_publication.parent().expect("stale parent"))
        .expect("create stale generation");
    publish_tcp_endpoint(
        &stale_publication,
        "127.0.0.1:2".parse().expect("stale endpoint"),
    )
    .expect("write stale publication");

    let mut stack = fixture
        .spawn("127.0.0.1:0".parse().expect("requested endpoint"))
        .expect("dynamic child-published readiness");

    let effective: SocketAddr = std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
        .expect("read canonical endpoint")
        .trim()
        .parse()
        .expect("parse canonical endpoint");
    assert_eq!(effective.ip().to_string(), "127.0.0.1");
    assert_ne!(effective.port(), 0);
    assert!(
        stale_publication.exists(),
        "new generation touched stale state"
    );
    assert_current_publications_absent(&fixture.state_dir);

    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[test]
fn fixed_publication_requires_the_exact_requested_endpoint() {
    let requested = reserve_endpoint();
    let fixture = Fixture::new("publish", &requested.to_string(), None);
    let mut stack = fixture
        .spawn(requested)
        .expect("fixed endpoint attestation");
    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read canonical endpoint"),
        format!("{requested}\n")
    );
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");

    let requested = reserve_endpoint();
    let mismatch = Fixture::new("publish", "127.0.0.1:0", None);
    let Err(error) = mismatch.spawn(requested) else {
        panic!("different effective port must fail fixed readiness");
    };
    assert!(matches!(
        error,
        StartError::Orchestrator(OrchestratorError::Platform(_))
    ));
    assert!(
        error.to_string().contains("does not match requested"),
        "unexpected error: {error}"
    );
    assert_rollback_clean(&mismatch.state_dir);
}

#[test]
fn configured_tcp_readiness_preserves_fixed_endpoint_behavior() {
    let requested = reserve_endpoint();
    let fixture = Fixture::new("configured", &requested.to_string(), None);
    let mut stack = fixture
        .spawn_with_readiness(Readiness::ConfiguredTcp(requested))
        .expect("configured TCP readiness");

    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read configured canonical endpoint"),
        format!("{requested}\n")
    );
    assert_current_publications_absent(&fixture.state_dir);
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[test]
fn malformed_and_invalid_publications_fail_closed() {
    let cases = [
        (
            "malformed",
            "not = valid = toml",
            "invalid endpoint publication",
        ),
        (
            "wrong version",
            "protocol_version = 2\neffective_addr = \"127.0.0.1:41000\"\n",
            "unsupported protocol version 2",
        ),
        (
            "wrong IP",
            "protocol_version = 1\neffective_addr = \"127.0.0.2:41000\"\n",
            "does not match requested IP",
        ),
        (
            "zero port",
            "protocol_version = 1\neffective_addr = \"127.0.0.1:0\"\n",
            "effective port is zero",
        ),
    ];
    for (label, record, expected) in cases {
        let fixture = Fixture::new("raw", "127.0.0.1:0", Some(record));
        let Err(error) = fixture.spawn("127.0.0.1:0".parse().expect("requested endpoint")) else {
            panic!("{label} publication unexpectedly succeeded");
        };
        assert!(
            error.to_string().contains(expected),
            "{label} returned unexpected error: {error}"
        );
        assert_rollback_clean(&fixture.state_dir);
    }
}

#[test]
fn child_exit_before_or_after_publication_fails_and_rolls_back() {
    let before = Fixture::new("exit-before", "127.0.0.1:0", None);
    let Err(before_error) = before.spawn("127.0.0.1:0".parse().expect("requested endpoint")) else {
        panic!("exit before publication must fail");
    };
    assert!(matches!(
        before_error,
        StartError::Orchestrator(OrchestratorError::ReadinessProcessExited { .. })
    ));
    assert_rollback_clean(&before.state_dir);

    let after = Fixture::new("publish-without-listener", "127.0.0.1:0", None);
    let Err(after_error) = after.spawn("127.0.0.1:0".parse().expect("requested endpoint")) else {
        panic!("publication without a live listener must fail");
    };
    assert!(matches!(
        after_error,
        StartError::Orchestrator(OrchestratorError::ReadinessProcessExited { .. })
    ));
    assert_rollback_clean(&after.state_dir);
}

#[test]
fn canonical_endpoint_remains_absent_while_probe_is_unvalidated() {
    let fixture = Fixture::new("publish-without-listener", "127.0.0.1:0", None);
    let marker = fixture.marker.clone();
    let state_dir = fixture.state_dir.clone();
    let startup = std::thread::spawn(move || {
        fixture.spawn("127.0.0.1:0".parse().expect("requested endpoint"))
    });

    wait_for_file(&marker);
    assert!(
        !state_dir.join("worker.listen").exists(),
        "canonical endpoint appeared before a successful TCP probe"
    );
    let startup_result = startup.join().expect("join startup");
    assert!(
        startup_result.is_err(),
        "listener-free publication must fail"
    );
    assert_rollback_clean(&state_dir);
}

#[test]
fn publication_is_atomic_and_no_clobber() {
    let dir = tempfile::tempdir().expect("publication dir");
    let path = dir.path().join("endpoint.toml");
    let first = "127.0.0.1:41000".parse().expect("first endpoint");
    publish_tcp_endpoint(&path, first).expect("initial publication");
    let original = std::fs::read_to_string(&path).expect("read initial publication");

    let error = publish_tcp_endpoint(&path, "127.0.0.1:42000".parse().expect("second endpoint"))
        .expect_err("publication must not replace an existing path");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read_to_string(path).expect("read retained publication"),
        original
    );
}

struct Fixture {
    _dir: tempfile::TempDir,
    state_dir: PathBuf,
    executable: PathBuf,
    marker: PathBuf,
}

impl Fixture {
    fn new(mode: &str, bind_addr: &str, record: Option<&str>) -> Self {
        let dir = tempfile::tempdir().expect("fixture dir");
        let state_dir = dir.path().join("state");
        let executable = dir.path().join("fixture.sh");
        let marker = dir.path().join("child.published");
        let test_binary = std::env::current_exe().expect("test executable");
        let record = record.unwrap_or("");
        let publication = format!("{CHILD_PUBLICATION_PATH}=\"$2\"");
        let expected_args = usize::from(mode != "configured") + 1;
        let script = format!(
            "#!/bin/sh\n[ \"$#\" -eq {expected_args} ] || exit 64\n{mode} {bind_addr} {record} {marker} {publication} {test_binary} --exact endpoint_readiness::child_fixture --ignored\n",
            mode = shell_env(CHILD_MODE, mode),
            bind_addr = shell_env(CHILD_BIND_ADDR, bind_addr),
            record = shell_env(CHILD_RECORD, record),
            marker = shell_env(CHILD_MARKER, &marker.to_string_lossy()),
            publication = publication,
            test_binary = shell_quote(&test_binary.to_string_lossy()),
        );
        std::fs::write(&executable, script).expect("write fixture executable");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("make fixture executable");
        Self {
            _dir: dir,
            state_dir,
            executable,
            marker,
        }
    }

    fn spawn(
        &self,
        requested_addr: SocketAddr,
    ) -> Result<RunningStack, StartError<std::convert::Infallible>> {
        spawn_stack_from_plan(
            &StackTopology::new(["worker"]).expect("valid topology"),
            |contexts| {
                assert_eq!(contexts[0].name(), "worker");
                let publication = contexts[0].child_published_tcp(requested_addr);
                assert_eq!(
                    publication
                        .publication_path()
                        .file_name()
                        .and_then(std::ffi::OsStr::to_str),
                    Some("0.listen")
                );
                assert!(
                    publication
                        .publication_path()
                        .parent()
                        .and_then(Path::file_name)
                        .is_some_and(|name| name.to_string_lossy().starts_with(".startup-"))
                );
                let mut command = std::process::Command::new(&self.executable);
                command.arg("fixture").arg(publication.publication_path());
                Ok(vec![ComponentSpec {
                    command,
                    readiness: publication.into_readiness(),
                }])
            },
            &self.state_dir,
        )
    }

    fn spawn_with_readiness(
        &self,
        readiness: Readiness,
    ) -> Result<RunningStack, StartError<std::convert::Infallible>> {
        spawn_stack_from_plan(
            &StackTopology::new(["worker"]).expect("valid topology"),
            |_| {
                let mut command = std::process::Command::new(&self.executable);
                command.arg("fixture");
                Ok(vec![ComponentSpec { command, readiness }])
            },
            &self.state_dir,
        )
    }
}

#[test]
fn publication_contexts_cannot_be_reassigned_before_spawn() {
    let dir = tempfile::tempdir().expect("state dir");
    let topology = StackTopology::new(["first", "second"]).expect("valid topology");
    let requested_addr = "127.0.0.1:0".parse().expect("requested endpoint");
    let result = spawn_stack_from_plan(
        &topology,
        |contexts| {
            let [_, second] = contexts else {
                panic!("unexpected context count");
            };
            Ok::<_, std::convert::Infallible>(vec![
                ComponentSpec {
                    command: std::process::Command::new("must-not-spawn"),
                    readiness: second.child_published_tcp(requested_addr).into_readiness(),
                },
                ComponentSpec {
                    command: std::process::Command::new("must-not-spawn"),
                    readiness: Readiness::ConfiguredTcp(
                        "127.0.0.1:1".parse().expect("configured endpoint"),
                    ),
                },
            ])
        },
        dir.path(),
    );

    let Err(StartError::Orchestrator(OrchestratorError::Platform(message))) = result else {
        panic!("misaligned publication context was accepted");
    };
    assert_eq!(
        message,
        "first readiness used a publication path from another component context"
    );
    assert!(!dir.path().join("first.pid").exists());
    assert!(!dir.path().join("second.pid").exists());
}

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn child_fixture() {
    let mode = std::env::var(CHILD_MODE).expect("child mode");
    let publication_path =
        PathBuf::from(std::env::var_os(CHILD_PUBLICATION_PATH).expect("child publication path"));
    if mode == "exit-before" {
        return;
    }
    if mode == "raw" {
        publish_raw(
            &publication_path,
            &std::env::var(CHILD_RECORD).expect("raw child record"),
        );
        std::thread::sleep(Duration::from_mins(1));
        return;
    }

    let listener = TcpListener::bind(
        std::env::var(CHILD_BIND_ADDR)
            .expect("child bind address")
            .parse::<SocketAddr>()
            .expect("parse child bind address"),
    )
    .expect("bind child listener");
    let effective_addr = listener.local_addr().expect("effective child address");
    if mode == "configured" {
        std::fs::write(std::env::var_os(CHILD_MARKER).expect("child marker"), [])
            .expect("write child marker");
        loop {
            std::thread::sleep(Duration::from_mins(1));
        }
    }
    if mode == "publish-without-listener" {
        drop(listener);
    }
    publish_tcp_endpoint(&publication_path, effective_addr).expect("publish child endpoint");
    std::fs::write(std::env::var_os(CHILD_MARKER).expect("child marker"), [])
        .expect("write child marker");
    if mode == "publish-without-listener" {
        std::thread::sleep(Duration::from_millis(500));
        return;
    }
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}

fn publish_raw(path: &Path, record: &str) {
    let parent = path.parent().expect("publication parent");
    let mut temp = tempfile::NamedTempFile::new_in(parent).expect("publication temp file");
    temp.write_all(record.as_bytes()).expect("write raw record");
    temp.as_file().sync_all().expect("flush raw record");
    temp.persist_noclobber(path)
        .map_err(|error| error.error)
        .expect("publish raw record");
}

fn reserve_endpoint() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve endpoint");
    listener.local_addr().expect("reserved endpoint")
}

fn assert_rollback_clean(state_dir: &Path) {
    for name in ["worker.pid", "worker.listen", "stack.lock"] {
        assert!(!state_dir.join(name).exists(), "rollback left {name}");
    }
    assert_current_publications_absent(state_dir);
}

fn assert_current_publications_absent(state_dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(state_dir) {
        let current: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| {
                name.to_string_lossy().starts_with(".startup-") && name != ".startup-stale"
            })
            .collect();
        assert!(
            current.is_empty(),
            "publication state remained: {current:?}"
        );
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn shell_env(name: &str, value: &str) -> String {
    format!("{name}={}", shell_quote(value))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
