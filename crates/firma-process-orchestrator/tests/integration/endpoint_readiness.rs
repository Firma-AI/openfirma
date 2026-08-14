//! Child-published TCP readiness and startup transaction coverage.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use camino::Utf8PathBuf;
#[cfg(unix)]
use firma_process_orchestrator::UnixEndpoint;
use firma_process_orchestrator::{
    ComponentEndpoint, ComponentSpec, LifecycleTimeouts, OrchestratorError, Readiness,
    RunningStack, StackTopology, StartError, publish_startup_report, spawn_stack_from_plan,
};

use crate::support::wait_for_file;

#[test]
fn endpoint_state_representation_round_trips_and_preserves_tcp_bytes() {
    let tcp = ComponentEndpoint::Tcp("127.0.0.1:41000".parse().expect("TCP endpoint"));
    assert_eq!(tcp.to_string(), "127.0.0.1:41000");
    assert_eq!(tcp.to_string().parse::<ComponentEndpoint>(), Ok(tcp));
    let decoded: OwnedEndpointRecord =
        toml::from_str("endpoint = \"127.0.0.1:41000\"\n").expect("deserialize TCP endpoint");
    assert_eq!(
        decoded.endpoint,
        ComponentEndpoint::Tcp("127.0.0.1:41000".parse().expect("TCP endpoint"))
    );

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;

        let unix = unix_endpoint("/tmp/firma socket.sock");
        assert_eq!(unix.to_string(), "unix:/tmp/firma socket.sock");
        assert_eq!(
            unix.to_string().parse::<ComponentEndpoint>(),
            Ok(unix.clone())
        );
        assert_eq!(
            toml::to_string(&EndpointRecord { endpoint: &unix }).expect("serialize Unix endpoint"),
            "endpoint = \"unix:/tmp/firma socket.sock\"\n"
        );
        assert!(UnixEndpoint::new("/tmp/firma\n.sock").is_err());
        assert!(UnixEndpoint::new("/tmp/firma\0.sock").is_err());
        assert!(
            UnixEndpoint::new(PathBuf::from(std::ffi::OsString::from_vec(
                b"/tmp/firma-\xff.sock".to_vec()
            )))
            .is_err()
        );
    }
}

#[cfg(unix)]
#[derive(serde::Serialize)]
struct EndpointRecord<'a> {
    endpoint: &'a ComponentEndpoint,
}

#[cfg(unix)]
fn unix_endpoint(path: impl Into<PathBuf>) -> ComponentEndpoint {
    ComponentEndpoint::Unix(UnixEndpoint::new(path).expect("UTF-8 Unix endpoint path"))
}

#[derive(serde::Deserialize)]
struct OwnedEndpointRecord {
    endpoint: ComponentEndpoint,
}

#[test]
fn dynamic_publication_replaces_stale_canonical_only_after_validation() {
    let fixture = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    std::fs::create_dir_all(&fixture.state_dir).expect("create state dir");
    std::fs::write(fixture.state_dir.join("worker.listen"), "127.0.0.1:1\n")
        .expect("write stale canonical endpoint");
    let stale_publication = fixture.state_dir.join(".startup-stale/0.toml");
    std::fs::create_dir_all(stale_publication.parent().expect("stale parent"))
        .expect("create stale generation");
    publish_startup_report(
        &stale_publication,
        &ComponentEndpoint::Tcp("127.0.0.1:2".parse().expect("stale endpoint")),
    )
    .expect("write stale publication");

    let mut stack = fixture
        .spawn("127.0.0.1:0".parse().expect("requested endpoint"))
        .expect("dynamic child-published readiness");

    let effective = fixture.canonical_endpoint("worker");
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
fn wildcard_bind_publications_are_probed_and_published_as_family_matching_loopback() {
    for (bind_ip, dial_ip) in [("0.0.0.0", "127.0.0.1"), ("::", "::1")] {
        for fixed_port in [false, true] {
            let requested = if fixed_port {
                reserve_endpoint_for_ip(bind_ip)
            } else {
                format_endpoint(bind_ip, 0)
            };
            let fixture = Fixture::new(ChildBehavior::Publish(requested));
            let mut stack = fixture.spawn(requested).expect("wildcard readiness");
            let canonical = fixture.canonical_endpoint("worker");

            assert_eq!(canonical.ip().to_string(), dial_ip);
            assert_ne!(canonical.port(), 0);
            if fixed_port {
                assert_eq!(canonical.port(), requested.port());
            }
            std::net::TcpStream::connect(canonical).expect("dial canonical wildcard endpoint");
            stack.shutdown(Duration::ZERO).expect("shutdown fixture");
        }
    }
}

#[test]
fn wildcard_publication_is_validated_before_dial_normalization() {
    let fixture = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    fixture.assert_platform_rejection(
        "0.0.0.0:0".parse().expect("wildcard request"),
        "does not match requested IP",
    );
}

#[test]
fn non_wildcard_publication_is_unchanged() {
    let fixture = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    let mut stack = fixture
        .spawn("127.0.0.1:0".parse().expect("loopback request"))
        .expect("loopback readiness");
    let canonical = std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
        .expect("read loopback canonical endpoint");
    assert!(canonical.starts_with("127.0.0.1:"));
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[test]
fn fixed_publication_requires_the_exact_requested_endpoint() {
    let requested = reserve_endpoint();
    let fixture = Fixture::new(ChildBehavior::Publish(requested));
    let mut stack = fixture
        .spawn(requested)
        .expect("fixed endpoint attestation");
    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read canonical endpoint"),
        format!("{requested}\n")
    );
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");

    let requested_listener = TcpListener::bind(loopback_ephemeral()).expect("reserve endpoint");
    let requested = requested_listener.local_addr().expect("reserved endpoint");
    let mismatch = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    mismatch.assert_platform_rejection(requested, "does not match requested");
    drop(requested_listener);
}

#[test]
fn configured_tcp_readiness_preserves_fixed_endpoint_behavior() {
    let requested = reserve_endpoint();
    let fixture = Fixture::new(ChildBehavior::Configured(requested));
    let mut stack = fixture
        .spawn_with_readiness(Readiness::Configured(ComponentEndpoint::Tcp(requested)))
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
fn configured_ipv4_wildcard_publishes_and_retains_connectable_endpoint() {
    let requested = reserve_endpoint_for_ip("0.0.0.0");
    let fixture = Fixture::new(ChildBehavior::Configured(requested));
    let mut stack = fixture
        .spawn_with_readiness(Readiness::Configured(ComponentEndpoint::Tcp(requested)))
        .expect("configured wildcard readiness");
    let effective = ComponentEndpoint::Tcp(SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        requested.port(),
    )));

    assert_eq!(
        stack
            .handle()
            .component("worker")
            .expect("worker handle")
            .endpoint(),
        &effective
    );
    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read configured canonical endpoint"),
        format!("{effective}\n")
    );
    let ComponentEndpoint::Tcp(effective) = effective else {
        unreachable!("effective endpoint is TCP");
    };
    std::net::TcpStream::connect(effective).expect("dial configured wildcard endpoint");
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[cfg(unix)]
#[test]
fn configured_unix_readiness_publishes_canonical_endpoint() {
    let relative = Utf8PathBuf::from("worker% socket.sock");
    let fixture = Fixture::new(ChildBehavior::ConfiguredUnix(relative.clone()));
    let socket = fixture.dir.path().join(relative.as_std_path());
    let mut stack = fixture
        .spawn_with_readiness(Readiness::Configured(unix_endpoint(socket.clone())))
        .expect("configured Unix readiness");

    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read configured canonical endpoint"),
        format!("{}\n", unix_endpoint(socket.clone()))
    );
    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read canonical endpoint")
            .strip_suffix('\n')
            .expect("writer newline")
            .parse::<ComponentEndpoint>(),
        Ok(unix_endpoint(socket))
    );
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[cfg(unix)]
#[test]
fn child_published_unix_readiness_publishes_connectable_canonical_endpoint() {
    let fixture = Fixture::new(ChildBehavior::PublishUnix);
    let socket = fixture.socket_path();
    let expected = unix_endpoint(socket.clone());
    let mut stack = fixture
        .spawn_endpoint(&expected)
        .expect("child-published Unix readiness");

    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read canonical Unix endpoint"),
        format!("{expected}\n")
    );
    assert_eq!(
        stack
            .handle()
            .component("worker")
            .expect("worker handle")
            .endpoint(),
        &expected
    );
    std::os::unix::net::UnixStream::connect(socket).expect("connect published Unix endpoint");
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[cfg(unix)]
#[test]
fn configured_unix_readiness_fails_closed_when_socket_is_unreachable() {
    let fixture = Fixture::new(ChildBehavior::ConfiguredUnixUnavailable);
    let endpoint = unix_endpoint(fixture.socket_path());
    let timeouts = LifecycleTimeouts {
        component_readiness: Duration::from_millis(150),
        ..LifecycleTimeouts::default()
    };
    let started = std::time::Instant::now();
    let Err(error) =
        fixture.spawn_with_readiness_and_timeouts(Readiness::Configured(endpoint), timeouts)
    else {
        panic!("unreachable Unix socket must fail readiness");
    };
    assert!(matches!(
        error,
        StartError::Orchestrator(OrchestratorError::Readiness { .. })
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_rollback_clean(&fixture.state_dir);
}

#[cfg(unix)]
#[test]
fn zero_timeout_does_not_attempt_unavailable_unix_readiness() {
    let fixture = Fixture::new(ChildBehavior::ConfiguredUnixUnavailable);
    let endpoint = unix_endpoint(fixture.socket_path());
    let timeouts = LifecycleTimeouts {
        component_readiness: Duration::ZERO,
        ..LifecycleTimeouts::default()
    };
    let started = std::time::Instant::now();
    let result =
        fixture.spawn_with_readiness_and_timeouts(Readiness::Configured(endpoint), timeouts);

    assert!(matches!(
        result,
        Err(StartError::Orchestrator(
            OrchestratorError::Readiness { .. }
        ))
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_rollback_clean(&fixture.state_dir);
}

#[test]
fn malformed_and_invalid_publications_fail_closed() {
    let cases = [
        ("not = valid = toml", "invalid startup report"),
        (
            "protocol_version = 1\nendpoint = \"127.0.0.1:41000\"\n",
            "unsupported protocol version 1",
        ),
        (
            "protocol_version = 3\nendpoint = \"127.0.0.1:41000\"\n",
            "unsupported protocol version 3",
        ),
        (
            "protocol_version = 2\nendpoint = \"127.0.0.2:41000\"\n",
            "does not match requested IP",
        ),
        (
            "protocol_version = 2\nendpoint = \"127.0.0.1:0\"\n",
            "effective port is zero",
        ),
    ];
    for (record, expected) in cases {
        let fixture = Fixture::new(ChildBehavior::Raw(record.to_string()));
        fixture.assert_platform_rejection(loopback_ephemeral(), expected);
    }

    let symlink = Fixture::new(ChildBehavior::Symlink);
    symlink.assert_platform_rejection(loopback_ephemeral(), "invalid startup report");

    for (behavior, expected) in [
        (ChildBehavior::Directory, "not a regular file"),
        (
            ChildBehavior::Raw("x".repeat(4_097)),
            "exceeds the size limit",
        ),
    ] {
        let fixture = Fixture::new(behavior);
        fixture.assert_platform_rejection(loopback_ephemeral(), expected);
    }
}

#[cfg(unix)]
#[test]
fn unrepresentable_unix_publications_fail_as_invalid_reports() {
    let endpoint = unix_endpoint(PathBuf::from(format!("/tmp/{}", "x".repeat(200))));
    let record = format!("protocol_version = 2\nendpoint = \"{endpoint}\"\n");

    let invalid_expected = Fixture::new(ChildBehavior::Raw(record.clone()));
    invalid_expected
        .assert_endpoint_platform_rejection(&endpoint, "invalid expected Unix endpoint");

    let invalid_published = Fixture::new(ChildBehavior::Raw(record));
    invalid_published.assert_endpoint_platform_rejection(
        &unix_endpoint(invalid_published.socket_path()),
        "invalid published Unix endpoint",
    );
}

#[test]
fn child_exit_before_or_after_publication_fails_and_rolls_back() {
    let before = Fixture::new(ChildBehavior::ExitBeforePublication);
    before.assert_process_exit(loopback_ephemeral());

    let after = Fixture::new(ChildBehavior::PublishWithoutListener(loopback_ephemeral()));
    after.assert_process_exit(loopback_ephemeral());
}

#[test]
fn publication_and_probe_share_the_configured_timeout_budget() {
    let fixture = Fixture::new(ChildBehavior::DelayedPublishWithoutListener(
        loopback_ephemeral(),
    ));
    let marker = fixture.marker.clone();
    let state_dir = fixture.state_dir.clone();
    let startup = std::thread::spawn(move || {
        fixture.spawn_endpoint_with_timeouts(
            &ComponentEndpoint::Tcp(loopback_ephemeral()),
            LifecycleTimeouts {
                component_readiness: Duration::from_secs(3),
                ..LifecycleTimeouts::default()
            },
        )
    });

    wait_for_file(&marker);
    let published = std::time::Instant::now();
    let result = startup.join().expect("join startup");
    let elapsed_after_publication = published.elapsed();

    assert!(matches!(
        result,
        Err(StartError::Orchestrator(OrchestratorError::Readiness {
            timeout_secs: 3,
            ..
        }))
    ));
    assert!(
        elapsed_after_publication < Duration::from_secs(2),
        "elapsed after publication: {elapsed_after_publication:?}"
    );
    assert_rollback_clean(&state_dir);
}

#[test]
fn canonical_endpoint_remains_absent_while_probe_is_unvalidated() {
    let fixture = Fixture::new(ChildBehavior::PublishWithoutListener(loopback_ephemeral()));
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
    let Err(error) = startup_result else {
        panic!("listener-free publication must fail");
    };
    assert!(matches!(
        error,
        StartError::Orchestrator(OrchestratorError::ReadinessProcessExited { .. })
    ));
    assert_rollback_clean(&state_dir);
}

#[test]
fn publication_is_atomic_and_no_clobber() {
    let dir = tempfile::tempdir().expect("publication dir");
    let path = dir.path().join("endpoint.toml");
    let first = "127.0.0.1:41000".parse().expect("first endpoint");
    publish_startup_report(&path, &ComponentEndpoint::Tcp(first)).expect("initial publication");
    let original = std::fs::read_to_string(&path).expect("read initial publication");

    let error = publish_startup_report(
        &path,
        &ComponentEndpoint::Tcp("127.0.0.1:42000".parse().expect("second endpoint")),
    )
    .expect_err("publication must not replace an existing path");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read_to_string(path).expect("read retained publication"),
        original
    );
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
enum ChildBehavior {
    Publish(SocketAddr),
    Configured(SocketAddr),
    #[cfg(unix)]
    ConfiguredUnix(Utf8PathBuf),
    #[cfg(unix)]
    ConfiguredUnixUnavailable,
    #[cfg(unix)]
    PublishUnix,
    Raw(String),
    Symlink,
    Directory,
    ExitBeforePublication,
    PublishWithoutListener(SocketAddr),
    DelayedPublishWithoutListener(SocketAddr),
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ChildProcess {
    behavior: ChildBehavior,
    marker: Utf8PathBuf,
    bind_path: Option<Utf8PathBuf>,
    startup_report_path: Option<Utf8PathBuf>,
}

struct Fixture {
    dir: tempfile::TempDir,
    state_dir: PathBuf,
    marker: PathBuf,
    behavior: ChildBehavior,
}

impl Fixture {
    fn new(behavior: ChildBehavior) -> Self {
        let dir = tempfile::tempdir().expect("fixture dir");
        let state_dir = dir.path().join("state");
        let marker = dir.path().join("child.published");
        Self {
            dir,
            state_dir,
            marker,
            behavior,
        }
    }

    fn command(&self, startup_report_path: Option<&Path>) -> std::process::Command {
        let bind_path = match &self.behavior {
            ChildBehavior::ConfiguredUnix(path) => Some(self.dir.path().join(path.as_std_path())),
            ChildBehavior::PublishUnix => Some(self.socket_path()),
            _ => None,
        };
        child_fixture(ChildProcess {
            behavior: self.behavior.clone(),
            marker: utf8_fixture_path(self.marker.clone()),
            bind_path: bind_path.map(utf8_fixture_path),
            startup_report_path: startup_report_path
                .map(Path::to_path_buf)
                .map(utf8_fixture_path),
        })
    }

    fn canonical_endpoint(&self, component: &str) -> SocketAddr {
        std::fs::read_to_string(self.state_dir.join(format!("{component}.listen")))
            .expect("read canonical endpoint")
            .trim()
            .parse()
            .expect("parse canonical endpoint")
    }

    fn assert_platform_rejection(&self, requested_addr: SocketAddr, expected: &str) {
        self.assert_endpoint_platform_rejection(&ComponentEndpoint::Tcp(requested_addr), expected);
    }

    fn assert_endpoint_platform_rejection(&self, endpoint: &ComponentEndpoint, expected: &str) {
        let Err(error) = self.spawn_endpoint(endpoint) else {
            panic!("{:?} unexpectedly succeeded", self.behavior);
        };
        assert!(matches!(
            &error,
            StartError::Orchestrator(OrchestratorError::Platform(_))
        ));
        assert!(
            error.to_string().contains(expected),
            "{:?} returned unexpected error: {error}",
            self.behavior
        );
        assert_rollback_clean(&self.state_dir);
    }

    fn assert_process_exit(&self, requested_addr: SocketAddr) {
        let Err(error) = self.spawn(requested_addr) else {
            panic!("{:?} unexpectedly succeeded", self.behavior);
        };
        assert!(
            matches!(
                &error,
                StartError::Orchestrator(OrchestratorError::ReadinessProcessExited { .. })
            ),
            "{:?} returned unexpected error: {error:?}",
            self.behavior
        );
        assert_rollback_clean(&self.state_dir);
    }

    fn spawn(
        &self,
        requested_addr: SocketAddr,
    ) -> Result<RunningStack, StartError<std::convert::Infallible>> {
        self.spawn_endpoint(&ComponentEndpoint::Tcp(requested_addr))
    }

    fn spawn_endpoint(
        &self,
        expected_endpoint: &ComponentEndpoint,
    ) -> Result<RunningStack, StartError<std::convert::Infallible>> {
        self.spawn_endpoint_with_timeouts(expected_endpoint, LifecycleTimeouts::default())
    }

    fn spawn_endpoint_with_timeouts(
        &self,
        expected_endpoint: &ComponentEndpoint,
        timeouts: LifecycleTimeouts,
    ) -> Result<RunningStack, StartError<std::convert::Infallible>> {
        spawn_stack_from_plan(
            &StackTopology::new(["worker"]).expect("valid topology"),
            |context| {
                assert_eq!(context.name(), "worker");
                assert!(context.ready_endpoint("worker").is_none());
                let publication = context.child_published(expected_endpoint.clone());
                assert_eq!(
                    publication
                        .startup_report_path()
                        .file_name()
                        .and_then(std::ffi::OsStr::to_str),
                    Some("0.toml")
                );
                assert!(
                    publication
                        .startup_report_path()
                        .parent()
                        .and_then(Path::file_name)
                        .is_some_and(|name| name.to_string_lossy().starts_with(".startup-"))
                );
                let command = self.command(Some(publication.startup_report_path()));
                Ok(ComponentSpec {
                    command,
                    readiness: publication.into_readiness(),
                })
            },
            &self.state_dir,
            timeouts,
        )
    }

    fn spawn_with_readiness(
        &self,
        readiness: Readiness,
    ) -> Result<RunningStack, StartError<std::convert::Infallible>> {
        self.spawn_with_readiness_and_timeouts(readiness, LifecycleTimeouts::default())
    }

    fn spawn_with_readiness_and_timeouts(
        &self,
        readiness: Readiness,
        timeouts: LifecycleTimeouts,
    ) -> Result<RunningStack, StartError<std::convert::Infallible>> {
        let mut readiness = Some(readiness);
        spawn_stack_from_plan(
            &StackTopology::new(["worker"]).expect("valid topology"),
            |_| {
                let command = self.command(None);
                Ok(ComponentSpec {
                    command,
                    readiness: readiness.take().expect("single component planned once"),
                })
            },
            &self.state_dir,
            timeouts,
        )
    }

    #[cfg(unix)]
    fn socket_path(&self) -> PathBuf {
        self.dir.path().join("worker.sock")
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SecondPlanFailure;

#[test]
fn later_plan_failure_sees_prior_endpoint_and_rolls_it_back() {
    let fixture = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    let topology = StackTopology::new(["first", "second"]).expect("valid topology");
    let requested_addr = "127.0.0.1:0".parse().expect("requested endpoint");
    let result = spawn_stack_from_plan(
        &topology,
        |context| {
            if context.name() == "first" {
                let publication = context.child_published(ComponentEndpoint::Tcp(requested_addr));
                let command = fixture.command(Some(publication.startup_report_path()));
                return Ok(ComponentSpec {
                    command,
                    readiness: publication.into_readiness(),
                });
            }
            let ready = context
                .ready_endpoint("first")
                .expect("first endpoint must be available to second planner");
            let ready = match ready {
                ComponentEndpoint::Tcp(ready) => ready,
                #[cfg(unix)]
                ComponentEndpoint::Unix(_) => {
                    panic!("dynamic child publication must remain TCP");
                }
            };
            assert_ne!(ready.port(), 0);
            assert_eq!(
                std::fs::read_to_string(fixture.state_dir.join("first.listen"))
                    .expect("canonical first endpoint")
                    .trim(),
                ready.to_string()
            );
            Err(SecondPlanFailure)
        },
        &fixture.state_dir,
        LifecycleTimeouts::default(),
    );

    assert!(matches!(result, Err(StartError::Plan(SecondPlanFailure))));
    assert_rollback_clean_named(&fixture.state_dir, &["first", "second"]);
}

process_fixture! {
    fn child_fixture(child: ChildProcess) {
        child.run();
    }
}

impl ChildProcess {
    fn run(self) {
        let Self {
            behavior,
            marker,
            bind_path,
            startup_report_path,
        } = self;
        let marker = marker.into_std_path_buf();
        let bind_path = bind_path.map(Utf8PathBuf::into_std_path_buf);
        let startup_report_path = startup_report_path.map(Utf8PathBuf::into_std_path_buf);
        match behavior {
            ChildBehavior::ExitBeforePublication => {}
            ChildBehavior::Raw(record) => {
                publish_raw(
                    required_report_path(startup_report_path.as_deref()),
                    &record,
                );
                sleep_forever();
            }
            ChildBehavior::Symlink => {
                let publication_path = required_report_path(startup_report_path.as_deref());
                let outside = publication_path
                    .parent()
                    .and_then(Path::parent)
                    .expect("state dir")
                    .join("outside-endpoint.toml");
                publish_raw(
                    &outside,
                    "protocol_version = 2\nendpoint = \"127.0.0.1:41000\"\n",
                );
                std::os::unix::fs::symlink(outside, publication_path)
                    .expect("publish endpoint symlink");
                sleep_forever();
            }
            ChildBehavior::Directory => {
                std::fs::create_dir(required_report_path(startup_report_path.as_deref()))
                    .expect("publish endpoint directory");
                sleep_forever();
            }
            ChildBehavior::ConfiguredUnix(_) => {
                let _listener = std::os::unix::net::UnixListener::bind(
                    bind_path.expect("configured Unix child bind path"),
                )
                .expect("bind Unix child listener");
                sleep_forever();
            }
            ChildBehavior::ConfiguredUnixUnavailable => sleep_forever(),
            ChildBehavior::PublishUnix => {
                let socket = bind_path.expect("published Unix child bind path");
                let _listener = std::os::unix::net::UnixListener::bind(&socket)
                    .expect("bind published Unix child listener");
                publish_startup_report(
                    required_report_path(startup_report_path.as_deref()),
                    &unix_endpoint(socket),
                )
                .expect("publish Unix startup report");
                sleep_forever();
            }
            ChildBehavior::Configured(bind_addr) => {
                let _listener = TcpListener::bind(bind_addr).expect("bind child listener");
                std::fs::write(marker, []).expect("write child marker");
                sleep_forever();
            }
            ChildBehavior::Publish(bind_addr) => {
                let listener = TcpListener::bind(bind_addr).expect("bind child listener");
                let effective_addr = listener.local_addr().expect("effective child address");
                publish_child_endpoint(
                    required_report_path(startup_report_path.as_deref()),
                    &marker,
                    effective_addr,
                );
                sleep_forever();
            }
            ChildBehavior::PublishWithoutListener(bind_addr) => publish_without_listener(
                bind_addr,
                false,
                required_report_path(startup_report_path.as_deref()),
                &marker,
            ),
            ChildBehavior::DelayedPublishWithoutListener(bind_addr) => publish_without_listener(
                bind_addr,
                true,
                required_report_path(startup_report_path.as_deref()),
                &marker,
            ),
        }
    }
}

fn publish_without_listener(
    bind_addr: SocketAddr,
    delayed: bool,
    startup_report_path: &Path,
    marker: &Path,
) {
    // Keep the published port reserved without making it connectable.
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind_addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .expect("create child socket");
    socket
        .bind(&socket2::SockAddr::from(bind_addr))
        .expect("bind child socket");
    let effective_addr = socket
        .local_addr()
        .expect("effective child socket address")
        .as_socket()
        .expect("TCP child socket address");
    if delayed {
        std::thread::sleep(Duration::from_secs(2));
    }
    publish_child_endpoint(startup_report_path, marker, effective_addr);
    std::thread::sleep(Duration::from_secs(5));
}

fn publish_child_endpoint(startup_report_path: &Path, marker: &Path, effective_addr: SocketAddr) {
    publish_startup_report(startup_report_path, &ComponentEndpoint::Tcp(effective_addr))
        .expect("publish startup report");
    std::fs::write(marker, []).expect("write child marker");
}

fn required_report_path(path: Option<&Path>) -> &Path {
    path.expect("child startup report path")
}

fn utf8_fixture_path(path: PathBuf) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(path).expect("process fixture paths must be valid UTF-8")
}

fn sleep_forever() -> ! {
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

fn loopback_ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback endpoint")
}

fn reserve_endpoint_for_ip(ip: &str) -> SocketAddr {
    TcpListener::bind(format_endpoint(ip, 0))
        .expect("reserve endpoint for IP family")
        .local_addr()
        .expect("reserved endpoint")
}

fn format_endpoint(ip: &str, port: u16) -> SocketAddr {
    format!("{ip}:{port}")
        .parse()
        .or_else(|_| format!("[{ip}]:{port}").parse())
        .expect("format endpoint")
}

fn assert_rollback_clean(state_dir: &Path) {
    assert_rollback_clean_named(state_dir, &["worker"]);
}

fn assert_rollback_clean_named(state_dir: &Path, components: &[&str]) {
    for name in components
        .iter()
        .flat_map(|component| [format!("{component}.pid"), format!("{component}.listen")])
        .chain(["stack.lock".to_string()])
    {
        assert!(!state_dir.join(&name).exists(), "rollback left {name}");
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
