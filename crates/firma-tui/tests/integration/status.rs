use std::path::PathBuf;

use crate::support::audit_row;
use firma_tui::control::{App, AuditDecision, ControlRuntimeState};

#[test]
fn initial_status_with_no_policy_dir() {
    let app = App::new(None, false);

    let status = app.status();

    assert_eq!(status.policy_dir, None);
    assert_eq!(status.runtime_state, ControlRuntimeState::Starting);
    assert_eq!(status.policy_count, 0);
    assert!(!status.audit_connected);
    assert_eq!(status.audit_rows, 0);
    assert_eq!(status.last_error, None);
}

#[test]
fn status_tracks_policy_dir() {
    let policy_dir = PathBuf::from("/tmp/openfirma-policy-dir");
    let app = App::new(Some(policy_dir.clone()), false);

    assert_eq!(app.status().policy_dir.as_ref(), Some(&policy_dir));
}

#[test]
fn status_tracks_audit_connected_true_and_false() {
    let disconnected = App::new(None, false);
    let connected = App::new(None, true);

    assert!(!disconnected.status().audit_connected);
    assert!(connected.status().audit_connected);
}

#[test]
fn status_tracks_audit_row_count_changes() {
    let mut app = App::new(None, true);

    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    app.push_audit_row(audit_row(AuditDecision::Deny, 1));

    assert_eq!(app.status().audit_rows, 2);
}

#[test]
fn runtime_state_labels_are_stable() {
    assert_eq!(ControlRuntimeState::Starting.label(), "starting");
    assert_eq!(ControlRuntimeState::Running.label(), "running");
    assert_eq!(ControlRuntimeState::ShuttingDown.label(), "stopping");
    assert_eq!(ControlRuntimeState::Error.label(), "error");
    assert!(ControlRuntimeState::ShuttingDown.is_shutting_down());
    assert!(!ControlRuntimeState::Running.is_shutting_down());
}
