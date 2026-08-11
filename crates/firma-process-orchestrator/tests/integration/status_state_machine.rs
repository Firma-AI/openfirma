//! Status cases that do not require a running stack.

#[cfg(unix)]
use firma_process_orchestrator::UnixEndpoint;
use firma_process_orchestrator::{ComponentEndpoint, OrchestratorError, State, status_components};
use tempfile::tempdir;

use crate::topology;

#[test]
fn no_pidfiles_yields_stopped() {
    let dir = tempdir().expect("dir");
    let stack_status = status_components(dir.path(), &topology()).expect("status");
    assert_eq!(stack_status.components.len(), 2);
    for component in &stack_status.components {
        assert_eq!(component.state, State::Stopped);
    }
}

#[test]
fn dead_pid_yields_stopped() {
    let dir = tempdir().expect("dir");
    std::fs::write(dir.path().join("authority.pid"), "999998\n").expect("write authority");
    std::fs::write(dir.path().join("sidecar.pid"), "999999\n").expect("write sidecar");
    let stack_status = status_components(dir.path(), &topology()).expect("status");
    let authority = stack_status
        .components
        .iter()
        .find(|component| component.name == "authority")
        .expect("authority");
    let sidecar = stack_status
        .components
        .iter()
        .find(|component| component.name == "sidecar")
        .expect("sidecar");
    assert_eq!(authority.state, State::Stopped);
    assert_eq!(sidecar.state, State::Stopped);
}

#[test]
fn malformed_pidfile_is_reported() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("sidecar.pid");
    std::fs::write(&path, "not-a-pid\n").expect("write sidecar pidfile");

    let error =
        status_components(dir.path(), &topology()).expect_err("malformed status state must fail");
    let OrchestratorError::RuntimeState(firma_runtime_state::RuntimeStateError::PidfileParse {
        path: error_path,
        value,
    }) = &error
    else {
        panic!("expected pidfile parse error, got {error:?}");
    };
    assert_eq!(error_path, &path);
    assert_eq!(value, "not-a-pid");
}

#[test]
fn legacy_tcp_listen_state_remains_a_string_and_reports_running() {
    let dir = tempdir().expect("dir");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("TCP listener");
    let addr = listener.local_addr().expect("TCP address");
    std::fs::write(
        dir.path().join("authority.pid"),
        format!("{}\n", std::process::id()),
    )
    .expect("write live pid");
    std::fs::write(dir.path().join("authority.listen"), format!("{addr}\n"))
        .expect("write legacy TCP endpoint");

    let status = status_components(dir.path(), &topology()).expect("status");
    let authority = &status.components[0];
    assert_eq!(authority.state, State::Running);
    assert_eq!(authority.listen, Some(ComponentEndpoint::Tcp(addr)));
    let serialized = toml::to_string(authority).expect("serialize status");
    assert!(
        serialized
            .lines()
            .any(|line| line == format!("listen = \"{addr}\"")),
        "TCP listen status changed shape: {serialized}"
    );
}

#[cfg(unix)]
#[test]
fn unix_listen_state_distinguishes_running_and_unhealthy() {
    let dir = tempdir().expect("dir");
    let socket = dir.path().join("authority.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("Unix listener");
    std::fs::write(
        dir.path().join("authority.pid"),
        format!("{}\n", std::process::id()),
    )
    .expect("write live pid");
    std::fs::write(
        dir.path().join("authority.listen"),
        format!("unix:{}\n", socket.display()),
    )
    .expect("write Unix endpoint");

    let running = status_components(dir.path(), &topology()).expect("running status");
    assert_eq!(running.components[0].state, State::Running);
    assert_eq!(
        running.components[0].listen,
        Some(ComponentEndpoint::Unix(
            UnixEndpoint::new(socket.clone()).expect("UTF-8 socket path")
        ))
    );

    drop(listener);
    std::fs::remove_file(&socket).expect("remove Unix socket");
    let unhealthy = status_components(dir.path(), &topology()).expect("unhealthy status");
    assert_eq!(unhealthy.components[0].state, State::Unhealthy);
    assert_eq!(
        unhealthy.components[0].listen,
        Some(ComponentEndpoint::Unix(
            UnixEndpoint::new(socket).expect("UTF-8 socket path")
        ))
    );
}

#[cfg(unix)]
#[test]
fn noncanonical_unix_listen_state_is_not_accepted() {
    let dir = tempdir().expect("dir");
    std::fs::write(
        dir.path().join("authority.pid"),
        format!("{}\n", std::process::id()),
    )
    .expect("write live pid");

    for record in ["unix:\n", "unix:/tmp/a\njunk\n"] {
        std::fs::write(dir.path().join("authority.listen"), record)
            .expect("write malformed Unix endpoint");
        let status = status_components(dir.path(), &topology()).expect("status");
        assert_eq!(status.components[0].state, State::Unhealthy);
        assert_eq!(status.components[0].listen, None);
    }
}
