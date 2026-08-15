//! Windows dependency-sequential teardown regression.

#![cfg(windows)]
#![expect(
    unsafe_code,
    reason = "the fixture installs and waits on the production Win32 shutdown event contract"
)]

use std::ffi::OsStr;
use std::io::Write as _;
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use firma_process_orchestrator::{
    ComponentEndpoint, ComponentSpec, LifecycleTimeouts, Readiness, RunningStack, StackTopology,
    spawn_stack_from_plan,
};
use firma_test_helpers::process_fixture;
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

const COMPONENT: &str = "FIRMA_TEST_WINDOWS_STOP_COMPONENT";
const READY: &str = "FIRMA_TEST_WINDOWS_STOP_READY";
const SIDECAR_STOPPING: &str = "FIRMA_TEST_WINDOWS_SIDECAR_STOPPING";
const SIDECAR_RELEASE: &str = "FIRMA_TEST_WINDOWS_SIDECAR_RELEASE";
const SIDECAR_EXITED: &str = "FIRMA_TEST_WINDOWS_SIDECAR_EXITED";
const SIDECAR_STUCK: &str = "FIRMA_TEST_WINDOWS_SIDECAR_STUCK";
const SIDECAR_DESCENDANT: &str = "FIRMA_TEST_WINDOWS_SIDECAR_DESCENDANT";
const AUTHORITY_SIGNAL: &str = "FIRMA_TEST_WINDOWS_AUTHORITY_SIGNAL";

#[test]
fn authority_is_not_signalled_until_sidecar_is_collected() {
    let dir = tempfile::tempdir().expect("state dir");
    let sidecar_stopping = dir.path().join("sidecar-stopping");
    let sidecar_release = dir.path().join("release-sidecar");
    let sidecar_exited = dir.path().join("sidecar-exited");
    let sidecar_descendant = dir.path().join("sidecar-descendant");
    let authority_signal = dir.path().join("authority-signal");
    let mut stack = spawn_ordered_stack(
        dir.path(),
        &sidecar_stopping,
        &sidecar_release,
        &sidecar_exited,
        &sidecar_descendant,
        &authority_signal,
        false,
    );

    let release_thread = std::thread::spawn({
        let authority_signal = authority_signal.clone();
        move || {
            wait_for_file(&sidecar_stopping);
            assert!(
                !authority_signal.exists(),
                "authority was signalled while sidecar teardown was blocked"
            );
            std::fs::write(sidecar_release, []).expect("release sidecar shutdown");
        }
    });

    let outcome = stack
        .shutdown(Duration::from_secs(2))
        .expect("ordered shutdown");
    release_thread.join().expect("join release thread");

    assert_eq!(
        std::fs::read_to_string(authority_signal).expect("read Authority signal marker"),
        "ordered"
    );
    assert!(!outcome.forced, "graceful shutdown escalated unexpectedly");
}

#[test]
fn forced_sidecar_job_termination_kills_its_descendants() {
    let dir = tempfile::tempdir().expect("state dir");
    let sidecar_stopping = dir.path().join("sidecar-stopping");
    let sidecar_release = dir.path().join("unused-sidecar-release");
    let sidecar_exited = dir.path().join("sidecar-exited");
    let sidecar_descendant = dir.path().join("sidecar-descendant");
    let authority_signal = dir.path().join("authority-signal");
    let mut stack = spawn_ordered_stack(
        dir.path(),
        &sidecar_stopping,
        &sidecar_release,
        &sidecar_exited,
        &sidecar_descendant,
        &authority_signal,
        true,
    );

    wait_for_file(&sidecar_descendant);
    let descendant_pid = std::fs::read_to_string(&sidecar_descendant)
        .expect("read Sidecar descendant PID")
        .trim()
        .parse()
        .expect("parse Sidecar descendant PID");
    let descendant = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, descendant_pid) };
    assert!(!descendant.is_null(), "open Sidecar descendant process");
    assert_eq!(
        unsafe { WaitForSingleObject(descendant, 0) },
        WAIT_TIMEOUT,
        "Sidecar descendant exited before shutdown"
    );

    let observation_thread = std::thread::spawn({
        move || {
            wait_for_file(&sidecar_stopping);
            assert!(
                !authority_signal.exists(),
                "authority was signalled while the stuck Sidecar remained alive"
            );
        }
    });

    let outcome = stack
        .shutdown(Duration::from_secs(1))
        .expect("forced ordered shutdown");
    observation_thread.join().expect("join observation thread");
    let descendant_wait = unsafe { WaitForSingleObject(descendant, 2_000) };
    unsafe { CloseHandle(descendant) };

    assert!(outcome.forced, "stuck Sidecar did not require escalation");
    assert_eq!(
        descendant_wait, WAIT_OBJECT_0,
        "Sidecar Job termination left its descendant alive"
    );
    assert!(
        !sidecar_exited.exists(),
        "stuck Sidecar unexpectedly completed graceful shutdown"
    );
}

fn spawn_ordered_stack(
    state_dir: &Path,
    sidecar_stopping: &Path,
    sidecar_release: &Path,
    sidecar_exited: &Path,
    sidecar_descendant: &Path,
    authority_signal: &Path,
    stuck_sidecar: bool,
) -> RunningStack {
    let topology = StackTopology::new(["authority", "sidecar"]).expect("fixture topology");
    let listeners = [reserve_listener(), reserve_listener()];
    let addresses = listeners
        .each_ref()
        .map(|listener| listener.local_addr().expect("readiness address"));
    let ready = [
        state_dir.join("authority-ready"),
        state_dir.join("sidecar-ready"),
    ];
    let mut index = 0;

    let stack = spawn_stack_from_plan(
        &topology,
        |context| {
            let component = context.name();
            let mut command = fixture_command();
            command.env(COMPONENT, component).env(READY, &ready[index]);
            if component == "sidecar" {
                command
                    .env(SIDECAR_STOPPING, sidecar_stopping)
                    .env(SIDECAR_RELEASE, sidecar_release)
                    .env(SIDECAR_EXITED, sidecar_exited)
                    .env(SIDECAR_DESCENDANT, sidecar_descendant);
            } else {
                command
                    .env(SIDECAR_EXITED, sidecar_exited)
                    .env(AUTHORITY_SIGNAL, authority_signal);
            }
            if stuck_sidecar {
                command.env(SIDECAR_STUCK, "1");
            }
            let spec = ComponentSpec {
                command,
                readiness: Readiness::Configured(ComponentEndpoint::Tcp(addresses[index])),
            };
            index += 1;
            Ok::<_, std::convert::Infallible>(spec)
        },
        state_dir,
        LifecycleTimeouts::default(),
    )
    .expect("spawn ordered stack");
    for marker in &ready {
        wait_for_file(marker);
    }
    drop(listeners);
    stack
}

process_fixture! {
    fn managed_component_fixture() {
        if std::env::var(COMPONENT).as_deref() == Ok("sidecar-descendant") {
            loop {
                std::thread::park();
            }
        }

        let _descendant = if std::env::var(COMPONENT).as_deref() == Ok("sidecar")
            && std::env::var_os(SIDECAR_STUCK).is_some()
        {
            let child = fixture_command()
                .env(COMPONENT, "sidecar-descendant")
                .spawn()
                .expect("spawn Sidecar descendant");
            publish_marker(&required_path(SIDECAR_DESCENDANT), &child.id().to_string());
            Some(child)
        } else {
            None
        };

        let event_name = firma_process_orchestrator::shutdown_event::windows_shutdown_event_name(
            std::process::id(),
        );
        let wide: Vec<u16> = OsStr::new(&event_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
        assert!(!event.is_null(), "create shutdown event");
        std::fs::write(required_path(READY), []).expect("publish fixture readiness");

        let wait = unsafe { WaitForSingleObject(event, INFINITE) };
        unsafe { CloseHandle(event) };
        assert_eq!(wait, WAIT_OBJECT_0, "wait for shutdown event");

        match std::env::var(COMPONENT).as_deref() {
            Ok("sidecar") => {
                std::fs::write(required_path(SIDECAR_STOPPING), [])
                    .expect("mark Sidecar stopping");
                if std::env::var_os(SIDECAR_STUCK).is_some() {
                    loop {
                        std::thread::park();
                    }
                }
                wait_for_file(&required_path(SIDECAR_RELEASE));
                std::fs::write(required_path(SIDECAR_EXITED), [])
                    .expect("mark Sidecar exited");
            }
            Ok("authority") => {
                if std::env::var_os(SIDECAR_STUCK).is_some() {
                    return;
                }
                let ordering = if required_path(SIDECAR_EXITED).exists() {
                    "ordered"
                } else {
                    "overlap"
                };
                publish_marker(&required_path(AUTHORITY_SIGNAL), ordering);
            }
            other => panic!("unexpected fixture component: {other:?}"),
        }
    }
}

fn fixture_command() -> Command {
    managed_component_fixture()
}

fn reserve_listener() -> std::net::TcpListener {
    std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve readiness address")
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} must be set")))
}

fn publish_marker(path: &Path, contents: &str) {
    let parent = path.parent().expect("marker parent");
    let mut temporary = tempfile::NamedTempFile::new_in(parent).expect("temporary marker");
    temporary
        .write_all(contents.as_bytes())
        .expect("write temporary marker");
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .expect("publish marker");
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}
