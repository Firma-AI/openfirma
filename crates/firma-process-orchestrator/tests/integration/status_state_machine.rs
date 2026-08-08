//! Status cases that do not require a running stack.

use firma_process_orchestrator::{OrchestratorError, State, status_components};
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
