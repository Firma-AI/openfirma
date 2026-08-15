//! Endpoint readiness and startup transaction coverage.

mod failures_transactions;
mod representation;
mod tcp;
#[cfg(unix)]
mod unix;

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
use firma_test_helpers::process_fixture;

use crate::helper::wait_for_file;

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
