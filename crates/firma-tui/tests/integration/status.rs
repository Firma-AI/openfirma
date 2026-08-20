use crate::support::{
    BlockingRewriteHandler, DEFAULT_POLICY_SOURCE, OTHER_POLICY_SOURCE, REWRITE_TEST_TIMEOUT,
    RewriteRelease, app_with_default_policies, app_with_policy_files, audit_row,
    blocking_first_rewrite_handler, permit_policy, status_snapshot, successful_editor,
    write_named_policy_file,
};
use firma_tui::control::{
    App, AuditDecision, ControlEffect, ControlError, ControlRuntimeState, PolicyRewriteRequest,
    PolicyState, set_policy_states, testing::HeadlessRunner,
};

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
    assert_eq!(status.policy_error, None);
    insta::assert_snapshot!(status_snapshot(&status, None), @"
    runtime_state: running
    policy_dir: <none>
    policy_count: 0
    audit_connected: false
    audit_rows: 0
    rewrite_queue_len: 0
    pending_rewrites: 0
    policy_error: none
    ");
}

#[test]
fn status_with_policy_dir_and_policy_count() -> anyhow::Result<()> {
    let (temp, app) = app_with_policy_files(&[
        ("default.cedar", DEFAULT_POLICY_SOURCE),
        ("other.cedar", OTHER_POLICY_SOURCE),
    ])?;

    let status = app.status();

    assert_eq!(status.policy_dir.as_deref(), Some(temp.path()));
    assert_eq!(status.policy_count, 4);
    insta::assert_snapshot!(status_snapshot(&status, Some(temp.path())), @"
    runtime_state: running
    policy_dir: <policy-dir>
    policy_count: 4
    audit_connected: false
    audit_rows: 0
    rewrite_queue_len: 0
    pending_rewrites: 0
    policy_error: none
    ");

    Ok(())
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
    policy_error: none
    ");
}

#[test]
fn status_tracks_audit_row_count_changes() {
    let mut app = App::new(None, true);
    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    app.push_audit_row(audit_row(AuditDecision::Deny, 1));

    let status = app.status();

    assert_eq!(status.audit_rows, 2);
    insta::assert_snapshot!(status_snapshot(&status, None), @"
    runtime_state: running
    policy_dir: <none>
    policy_count: 0
    audit_connected: true
    audit_rows: 2
    rewrite_queue_len: 0
    pending_rewrites: 0
    policy_error: none
    ");
}

#[test]
fn status_tracks_rewrite_queue_length_changes() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let active_path =
        write_named_policy_file(temp.path(), "active.cedar", &permit_policy("active_policy"))?;
    let queued_path =
        write_named_policy_file(temp.path(), "queued.cedar", &permit_policy("queued_policy"))?;
    let BlockingRewriteHandler { handler, release } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let (mut runner, rewrite_probe) = HeadlessRunner::with_observed_policy_rewrite_handler(
        Some(temp.path().to_path_buf()),
        None,
        handler,
    );

    runner.execute_effects_with_editor(
        vec![ControlEffect::EnqueuePolicyRewrite(PolicyRewriteRequest {
            file: active_path,
            ids: vec!["active_policy".to_string()],
            requested: PolicyState::Disabled,
        })],
        successful_editor(),
    )?;

    rewrite_probe.wait_for_started(REWRITE_TEST_TIMEOUT)?;
    runner.execute_effects_with_editor(
        vec![ControlEffect::EnqueuePolicyRewrite(PolicyRewriteRequest {
            file: queued_path,
            ids: vec!["queued_policy".to_string()],
            requested: PolicyState::Disabled,
        })],
        successful_editor(),
    )?;

    let status = runner.app().status();

    assert_eq!(status.rewrite_queue_len, 1);
    insta::assert_snapshot!(status_snapshot(&status, Some(temp.path())), @"
    runtime_state: rewriting
    policy_dir: <policy-dir>
    policy_count: 2
    audit_connected: false
    audit_rows: 0
    rewrite_queue_len: 1
    pending_rewrites: 0
    policy_error: none
    ");

    release_rewrite.release()?;
    drop(runner);

    Ok(())
}

#[test]
fn status_tracks_pending_rewrite_count_changes() -> anyhow::Result<()> {
    let (temp, mut app) = app_with_default_policies()?;

    let request = app
        .request_selected_policy_toggle()
        .ok_or_else(|| anyhow::anyhow!("selected policy did not produce a rewrite request"))?;

    let queued_status = app.status();
    assert_eq!(queued_status.pending_rewrites, 1);
    insta::assert_snapshot!(status_snapshot(&queued_status, Some(temp.path())), @"
    runtime_state: rewriting
    policy_dir: <policy-dir>
    policy_count: 3
    audit_connected: false
    audit_rows: 0
    rewrite_queue_len: 0
    pending_rewrites: 1
    policy_error: none
    ");

    set_policy_states(&request.file, &request.ids, request.requested)?;
    app.finish_policy_rewrite(&firma_tui::control::PolicyRewriteCompletion {
        file: request.file,
        ids: request.ids,
        requested: request.requested,
        result: Ok(()),
    });

    let completed_status = app.status();

    assert_eq!(completed_status.pending_rewrites, 0);
    insta::assert_snapshot!(status_snapshot(&completed_status, Some(temp.path())), @"
    runtime_state: running
    policy_dir: <policy-dir>
    policy_count: 3
    audit_connected: false
    audit_rows: 0
    rewrite_queue_len: 0
    pending_rewrites: 0
    policy_error: none
    ");

    Ok(())
}

#[test]
fn status_tracks_policy_editing_state() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;

    assert!(app.request_policy_edit());
    assert_eq!(
        app.status().runtime_state,
        ControlRuntimeState::EditingPolicy
    );

    app.finish_policy_edit();

    assert_eq!(app.status().runtime_state, ControlRuntimeState::Running);

    Ok(())
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

#[test]
fn status_preserves_and_clears_policy_error() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path =
        write_named_policy_file(temp.path(), "policies.cedar", &permit_policy("one"))?;
    let mut app = App::new(Some(temp.path().to_path_buf()), false);
    assert_eq!(app.status().policy_error, None);

    std::fs::write(&policy_path, "@id(\"broken\")\npermit (")?;
    app.reload_policies();
    let error_status = app.status();
    let reload_error = error_status
        .policy_error
        .clone()
        .ok_or_else(|| anyhow::anyhow!("policy reload error was not recorded"))?;
    let ControlError::PolicyDiscovery { path, error } = &reload_error else {
        anyhow::bail!("reload did not produce a policy discovery error");
    };
    assert_eq!(path, temp.path());
    let policy_path_text = policy_path.display().to_string();
    let message = error.to_string();
    assert!(message.contains(&policy_path_text));
    insta::assert_snapshot!(message.replace(&policy_path_text, "<policy-file>"), @"failed to parse `<policy-file>`: unexpected end of input");

    assert_eq!(error_status.policy_count, 1);
    insta::assert_snapshot!(status_snapshot(&error_status, Some(temp.path())), @"
    runtime_state: error
    policy_dir: <policy-dir>
    policy_count: 1
    audit_connected: false
    audit_rows: 0
    rewrite_queue_len: 0
    pending_rewrites: 0
    policy_error: present
    ");

    app.push_audit_row(audit_row(AuditDecision::Deny, 3));
    assert_eq!(app.status().policy_error.as_ref(), Some(&reload_error));

    std::fs::write(
        &policy_path,
        format!("{}\n{}", permit_policy("one"), permit_policy("two")),
    )?;
    app.reload_policies();
    let recovered_status = app.status();

    assert_eq!(recovered_status.policy_error, None);
    assert_eq!(recovered_status.policy_count, 2);
    insta::assert_snapshot!(status_snapshot(&recovered_status, Some(temp.path())), @"
    runtime_state: running
    policy_dir: <policy-dir>
    policy_count: 2
    audit_connected: false
    audit_rows: 1
    rewrite_queue_len: 0
    pending_rewrites: 0
    policy_error: none
    ");

    Ok(())
}
