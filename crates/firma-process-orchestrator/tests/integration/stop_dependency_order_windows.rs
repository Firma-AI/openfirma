//! Windows dependency-sequential teardown regression.

#![cfg(windows)]
#![expect(
    unsafe_code,
    reason = "the fixture installs and waits on the production Win32 shutdown event contract"
)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use firma_process_orchestrator::{
    ComponentEndpoint, ComponentSpec, LifecycleTimeouts, Readiness, RunningStack, StackTopology,
    spawn_stack_from_plan,
};
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

const COMPONENT: &str = "FIRMA_TEST_WINDOWS_STOP_COMPONENT";
const READY: &str = "FIRMA_TEST_WINDOWS_STOP_READY";
const SIDECAR_STOPPING: &str = "FIRMA_TEST_WINDOWS_SIDECAR_STOPPING";
const SIDECAR_RELEASE: &str = "FIRMA_TEST_WINDOWS_SIDECAR_RELEASE";
const SIDECAR_EXITED: &str = "FIRMA_TEST_WINDOWS_SIDECAR_EXITED";
const AUTHORITY_SIGNAL: &str = "FIRMA_TEST_WINDOWS_AUTHORITY_SIGNAL";

#[test]
fn authority_is_not_signalled_until_sidecar_is_collected() {
    let dir = tempfile::tempdir().expect("state dir");
    let sidecar_stopping = dir.path().join("sidecar-stopping");
    let sidecar_release = dir.path().join("release-sidecar");
    let sidecar_exited = dir.path().join("sidecar-exited");
    let authority_signal = dir.path().join("authority-signal");
    let mut stack = spawn_ordered_stack(
        dir.path(),
        &sidecar_stopping,
        &sidecar_release,
        &sidecar_exited,
        &authority_signal,
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

fn spawn_ordered_stack(
    state_dir: &Path,
    sidecar_stopping: &Path,
    sidecar_release: &Path,
    sidecar_exited: &Path,
    authority_signal: &Path,
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
                    .env(SIDECAR_EXITED, sidecar_exited);
            } else {
                command
                    .env(SIDECAR_EXITED, sidecar_exited)
                    .env(AUTHORITY_SIGNAL, authority_signal);
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

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn managed_component_fixture() {
    let event_name =
        firma_process_orchestrator::shutdown_event::windows_shutdown_event_name(std::process::id());
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
            std::fs::write(required_path(SIDECAR_STOPPING), []).expect("mark Sidecar stopping");
            wait_for_file(&required_path(SIDECAR_RELEASE));
            std::fs::write(required_path(SIDECAR_EXITED), []).expect("mark Sidecar exited");
        }
        Ok("authority") => {
            let ordering = if required_path(SIDECAR_EXITED).exists() {
                "ordered"
            } else {
                "overlap"
            };
            std::fs::write(required_path(AUTHORITY_SIGNAL), ordering)
                .expect("record Authority signal order");
        }
        other => panic!("unexpected fixture component: {other:?}"),
    }
}

fn fixture_command() -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command.args([
        "--exact",
        "stop_dependency_order_windows::managed_component_fixture",
        "--ignored",
    ]);
    command
}

fn reserve_listener() -> std::net::TcpListener {
    std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve readiness address")
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} must be set")))
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}
