//! Status cases that do not require a running stack.

use firma_stack::{State, status};
use tempfile::tempdir;

#[test]
fn no_pidfiles_yields_stopped() {
    let dir = tempdir().expect("dir");
    let stack_status = status(dir.path()).expect("status");
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
    let stack_status = status(dir.path()).expect("status");
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
