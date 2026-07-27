use std::path::PathBuf;

use crate::support::{audit_row, status_snapshot};
use firma_tui::control::{App, AuditDecision, ControlError, ControlRuntimeState};

#[test]
fn initial_status_with_no_policy_dir() {
    let app = App::new(None, false);

    let status = app.status();

    assert_eq!(status.policy_dir, None);
    assert_eq!(status.policy_count, 0);
    assert!(!status.audit_connected);
    assert_eq!(status.audit_rows, 0);
    assert_eq!(status.rewrite_queue_len, 0);
    assert_eq!(status.pending_rewrites, 0);
    assert_eq!(status.last_policy_error, None);
    insta::assert_snapshot!(status_snapshot(&status, None), @"
runtime_state: running
policy_dir: <none>
policy_count: 0
audit_connected: false
audit_rows: 0
rewrite_queue_len: 0
pending_rewrites: 0
last_policy_error: none
");
}

#[test]
fn status_tracks_policy_dir() {
    let policy_dir = PathBuf::from("/tmp/openfirma-policy-dir");
    let app = App::new(Some(policy_dir.clone()), false);

    assert_eq!(app.status().policy_dir.as_ref(), Some(&policy_dir));
    insta::assert_snapshot!(status_snapshot(&app.status(), Some(&policy_dir)), @"
runtime_state: running
policy_dir: <policy-dir>
policy_count: 0
audit_connected: false
audit_rows: 0
rewrite_queue_len: 0
pending_rewrites: 0
last_policy_error: none
");
}

#[test]
fn status_tracks_audit_connected_true_and_false() {
    let disconnected = App::new(None, false);
    let connected = App::new(None, true);

    assert!(!disconnected.status().audit_connected);
    assert!(connected.status().audit_connected);
    insta::assert_snapshot!(status_snapshot(&connected.status(), None), @"
runtime_state: running
policy_dir: <none>
policy_count: 0
audit_connected: true
audit_rows: 0
rewrite_queue_len: 0
pending_rewrites: 0
last_policy_error: none
");
}

#[test]
fn status_tracks_audit_row_count_changes() {
    let mut app = App::new(None, true);

    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    app.push_audit_row(audit_row(AuditDecision::Deny, 1));

    assert_eq!(app.status().audit_rows, 2);
    insta::assert_snapshot!(status_snapshot(&app.status(), None), @"
runtime_state: running
policy_dir: <none>
policy_count: 0
audit_connected: true
audit_rows: 2
rewrite_queue_len: 0
pending_rewrites: 0
last_policy_error: none
");
}

#[test]
fn status_tracks_rewrite_queue_length_changes() {
    let mut app = App::new(None, false);

    app.sync_rewrite_queue(3, false);

    let status = app.status();
    assert_eq!(status.runtime_state, ControlRuntimeState::Rewriting);
    assert_eq!(status.rewrite_queue_len, 3);
    assert_eq!(status.pending_rewrites, 0);
    insta::assert_snapshot!(status_snapshot(&status, None), @"
runtime_state: rewriting
policy_dir: <none>
policy_count: 0
audit_connected: false
audit_rows: 0
rewrite_queue_len: 3
pending_rewrites: 0
last_policy_error: none
");
}

#[test]
fn status_records_last_policy_error() {
    let mut app = App::new(None, false);

    app.set_policy_error(ControlError::runtime("terminal failed"));
    let error_status = app.status();

    assert_eq!(error_status.runtime_state, ControlRuntimeState::Error);
    assert!(error_status.last_policy_error.is_some());
    insta::assert_snapshot!(status_snapshot(&error_status, None), @"
runtime_state: error
policy_dir: <none>
policy_count: 0
audit_connected: false
audit_rows: 0
rewrite_queue_len: 0
pending_rewrites: 0
last_policy_error: present
");
}

#[test]
fn runtime_state_labels_are_stable() {
    assert_eq!(ControlRuntimeState::Starting.label(), "starting");
    assert_eq!(ControlRuntimeState::Running.label(), "running");
    assert_eq!(ControlRuntimeState::EditingPolicy.label(), "editing");
    assert_eq!(ControlRuntimeState::Rewriting.label(), "rewriting");
    assert_eq!(ControlRuntimeState::ShuttingDown.label(), "stopping");
    assert_eq!(ControlRuntimeState::Error.label(), "error");
    assert!(ControlRuntimeState::ShuttingDown.is_shutting_down());
    assert!(!ControlRuntimeState::Running.is_shutting_down());
}
