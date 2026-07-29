use std::{path::PathBuf, time::Duration};

use crate::support::{
    BlockingRewriteHandler, CRANK_TEST_TIMEOUT, FakeTerminal, REWRITE_TEST_TIMEOUT, RewriteRelease,
    audit_channel, audit_channel_with_rows, blocking_first_rewrite_handler, crank_until,
    crank_until_with_terminal, generated_policy_ids, generated_policy_source,
    headless_runner_with_policy_source, permit_policy, policy_status, replace_policy_source_editor,
    send_audit_rows, successful_editor, write_named_policy_file, write_policy_file,
};
use crossterm::event::KeyCode;
use firma_tui::control::{
    AuditSourceError, ControlAnnouncement, ControlEffect, ControlError, ControlRuntimeState,
    EditorError, Event, PolicyRewriteRequest, PolicyRowStatus, PolicyState, read_policy_state,
    testing::{ControlCrankOutcome, EventKind, HeadlessRunner},
};

const LARGE_REWRITE_BACKLOG_COUNT: usize = 1_000;

#[test]
fn input_beats_audit() -> anyhow::Result<()> {
    let (_audit_tx, audit_rx) = audit_channel_with_rows(128)?;
    let mut runner = HeadlessRunner::new(None, Some(&audit_rx));
    let event_probe = runner.observe_processed_events();

    let outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('j')),
        successful_editor(),
    )?;

    assert_eq!(outcome, ControlCrankOutcome::Processed(EventKind::Input));
    assert!(!event_probe.observed_any(|event| event == EventKind::Audit)?);
    assert_eq!(runner.app().audit_rows_len(), 0);

    Ok(())
}

#[test]
fn input_beats_rewrite() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &permit_policy("policy_one"))?;
    let BlockingRewriteHandler { handler, release } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let (mut runner, rewrite_probe) = HeadlessRunner::with_observed_policy_rewrite_handler(
        Some(temp.path().to_path_buf()),
        None,
        handler,
    );

    let event_probe = runner.observe_processed_events();

    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: policy_path,
                ids: vec!["policy_one".to_string()],
                requested: PolicyState::Disabled,
            })
    );

    rewrite_probe.wait_for_started(REWRITE_TEST_TIMEOUT)?;

    let input_outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('h')),
        successful_editor(),
    )?;
    assert_eq!(
        input_outcome,
        ControlCrankOutcome::Processed(EventKind::Input)
    );
    assert!(!event_probe.observed_any(|event| event == EventKind::Rewrite)?);
    assert!(runner.app().help_visible());

    let rewrite_outcome = runner.try_crank(&FakeTerminal::default(), successful_editor())?;
    assert_eq!(
        rewrite_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );
    assert_eq!(
        policy_status(runner.app(), "policy_one"),
        Some(PolicyRowStatus::Writing)
    );

    release_rewrite.release()?;
    rewrite_probe.wait_for_completed(REWRITE_TEST_TIMEOUT)?;
    let completion_outcome = crank_until(
        &mut runner,
        |app| {
            policy_status(app, "policy_one") == Some(PolicyRowStatus::State(PolicyState::Disabled))
        },
        REWRITE_TEST_TIMEOUT,
    )?;
    assert_eq!(
        completion_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );
    assert_eq!(
        event_probe.observed_count(|event| event == EventKind::Rewrite)?,
        2
    );

    Ok(())
}

#[test]
fn rewrite_beats_audit() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &permit_policy("policy_one"))?;
    let (audit_tx, audit_rx) = audit_channel();
    let BlockingRewriteHandler { handler, release } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let (mut runner, rewrite_probe) = HeadlessRunner::with_observed_policy_rewrite_handler(
        Some(temp.path().to_path_buf()),
        Some(&audit_rx),
        handler,
    );

    let event_probe = runner.observe_processed_events();

    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: policy_path,
                ids: vec!["policy_one".to_string()],
                requested: PolicyState::Disabled,
            })
    );

    rewrite_probe.wait_for_started(REWRITE_TEST_TIMEOUT)?;

    send_audit_rows(&audit_tx, 128)?;
    let start_outcome = runner.try_crank(&FakeTerminal::default(), successful_editor())?;
    assert_eq!(
        start_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );
    assert!(!event_probe.observed_any(|event| event == EventKind::Audit)?);
    assert_eq!(runner.app().audit_rows_len(), 0);

    release_rewrite.release()?;
    rewrite_probe.wait_for_completed(REWRITE_TEST_TIMEOUT)?;
    let completion_outcome = runner.try_crank(&FakeTerminal::default(), successful_editor())?;

    assert_eq!(
        completion_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );
    assert_eq!(
        event_probe.observed_count(|event| event == EventKind::Rewrite)?,
        2
    );
    assert!(!event_probe.observed_any(|event| event == EventKind::Audit)?);
    assert_eq!(runner.app().audit_rows_len(), 0);
    assert_eq!(
        policy_status(runner.app(), "policy_one"),
        Some(PolicyRowStatus::State(PolicyState::Disabled))
    );

    Ok(())
}

#[test]
fn input_remains_responsive_while_rewrite_backlog_exists() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(
        temp.path(),
        &generated_policy_source("backlog_policy", LARGE_REWRITE_BACKLOG_COUNT, |_| true),
    )?;
    let BlockingRewriteHandler { handler, release } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let (mut runner, rewrite_probe) = HeadlessRunner::with_observed_policy_rewrite_handler(
        Some(temp.path().to_path_buf()),
        None,
        handler,
    );

    for id in generated_policy_ids("backlog_policy", LARGE_REWRITE_BACKLOG_COUNT) {
        assert!(
            runner
                .sources()
                .enqueue_policy_rewrite(PolicyRewriteRequest {
                    file: policy_path.clone(),
                    ids: vec![id],
                    requested: PolicyState::Enabled,
                })
        );
    }

    rewrite_probe.wait_for_started(REWRITE_TEST_TIMEOUT)?;
    assert!(runner.sources().rewrite_queue_len() > 0);

    let outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('j')),
        successful_editor(),
    )?;

    assert_eq!(outcome, ControlCrankOutcome::Processed(EventKind::Input));
    assert_eq!(runner.app().selected_policy_index(), 1);

    release_rewrite.release()?;
    drop(runner);

    Ok(())
}

#[test]
fn audit_drains_only_64_rows_per_crank() -> anyhow::Result<()> {
    let (_audit_tx, audit_rx) = audit_channel_with_rows(65)?;
    let mut runner = HeadlessRunner::new(None, Some(&audit_rx));

    let first_outcome = crank_until(
        &mut runner,
        |app| app.audit_rows_len() == 64,
        CRANK_TEST_TIMEOUT,
    )?;
    assert_eq!(
        first_outcome,
        ControlCrankOutcome::Processed(EventKind::Audit)
    );
    assert_eq!(runner.app().audit_rows_len(), 64);

    let second_outcome = crank_until(
        &mut runner,
        |app| app.audit_rows_len() == 65,
        CRANK_TEST_TIMEOUT,
    )?;
    assert_eq!(
        second_outcome,
        ControlCrankOutcome::Processed(EventKind::Audit)
    );
    assert_eq!(runner.app().audit_rows_len(), 65);

    Ok(())
}

#[test]
fn crank_until_waits_for_rewrite_start_and_completion() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &permit_policy("policy_one"))?;
    let BlockingRewriteHandler { handler, release } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let (mut runner, rewrite_probe) = HeadlessRunner::with_observed_policy_rewrite_handler(
        Some(temp.path().to_path_buf()),
        None,
        handler,
    );

    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: policy_path,
                ids: vec!["policy_one".to_string()],
                requested: PolicyState::Disabled,
            })
    );

    rewrite_probe.wait_for_started(REWRITE_TEST_TIMEOUT)?;

    let start_outcome = crank_until(
        &mut runner,
        |app| policy_status(app, "policy_one") == Some(PolicyRowStatus::Writing),
        REWRITE_TEST_TIMEOUT,
    )?;
    assert_eq!(
        start_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    release_rewrite.release()?;
    rewrite_probe.wait_for_completed(REWRITE_TEST_TIMEOUT)?;
    let completion_outcome = crank_until(
        &mut runner,
        |app| {
            policy_status(app, "policy_one") == Some(PolicyRowStatus::State(PolicyState::Disabled))
        },
        REWRITE_TEST_TIMEOUT,
    )?;
    assert_eq!(
        completion_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    Ok(())
}

#[test]
fn crank_until_errors_when_runner_quits_before_condition() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None, None);

    let error = runner
        .crank_until(
            &FakeTerminal::with_key(KeyCode::Char('q')),
            successful_editor(),
            |_app| false,
            CRANK_TEST_TIMEOUT,
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("crank_until unexpectedly succeeded"))?;

    assert_eq!(error.to_string(), "runner quit before condition was met");
    assert!(runner.app().should_quit());

    Ok(())
}

#[test]
fn crank_until_reports_timeout_with_last_outcome() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None, None);

    let error = runner
        .crank_until(
            &FakeTerminal::default(),
            successful_editor(),
            |_app| false,
            Duration::from_millis(1),
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("crank_until unexpectedly succeeded"))?;

    assert_eq!(
        error.to_string(),
        "condition was not met within 1ms; last outcome: NoEvent"
    );

    Ok(())
}

#[test]
fn tick_reports_no_event_when_nothing_else_is_ready() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None, None);
    let event_probe = runner.observe_processed_events();

    let outcome = runner.try_crank(&FakeTerminal::default(), successful_editor())?;

    assert_eq!(outcome, ControlCrankOutcome::NoEvent);
    assert_eq!(event_probe.observed_events()?, Vec::<EventKind>::new());

    Ok(())
}

#[test]
fn resize_and_mouse_events_are_reported() -> anyhow::Result<()> {
    let mut resize_runner = HeadlessRunner::new(None, None);
    let resize_outcome = resize_runner.try_crank(
        &FakeTerminal::with_events([Event::Resize]),
        successful_editor(),
    )?;
    assert_eq!(
        resize_outcome,
        ControlCrankOutcome::Processed(EventKind::Resize)
    );

    let mut mouse_runner = HeadlessRunner::new(None, None);
    let mouse_outcome = mouse_runner.try_crank(
        &FakeTerminal::with_events([Event::Mouse]),
        successful_editor(),
    )?;
    assert_eq!(
        mouse_outcome,
        ControlCrankOutcome::Processed(EventKind::Mouse)
    );

    Ok(())
}

#[test]
fn quit_seals_rewrite_enqueueing_and_updates_status() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None, None);

    let outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('q')),
        successful_editor(),
    )?;

    assert_eq!(outcome, ControlCrankOutcome::Quit);
    assert!(runner.app().should_quit());
    assert_eq!(
        runner.app().status().runtime_state,
        ControlRuntimeState::ShuttingDown
    );
    assert!(
        !runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: PathBuf::from("unused.cedar"),
                ids: vec!["unused_policy".to_string()],
                requested: PolicyState::Disabled,
            })
    );

    Ok(())
}

#[test]
fn active_rewrite_is_allowed_to_finish_after_shutdown() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let active_path =
        write_named_policy_file(temp.path(), "active.cedar", &permit_policy("active_policy"))?;
    let BlockingRewriteHandler { handler, release } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let (mut runner, rewrite_probe) = HeadlessRunner::with_observed_policy_rewrite_handler(
        Some(temp.path().to_path_buf()),
        None,
        handler,
    );

    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: active_path.clone(),
                ids: vec!["active_policy".to_string()],
                requested: PolicyState::Disabled,
            })
    );

    rewrite_probe.wait_for_started(REWRITE_TEST_TIMEOUT)?;

    let start_outcome = crank_until(
        &mut runner,
        |app| policy_status(app, "active_policy") == Some(PolicyRowStatus::Writing),
        REWRITE_TEST_TIMEOUT,
    )?;
    assert_eq!(
        start_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    let quit_outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('q')),
        successful_editor(),
    )?;
    assert_eq!(quit_outcome, ControlCrankOutcome::Quit);

    release_rewrite.release()?;
    drop(runner);

    assert_eq!(
        read_policy_state(&active_path, "active_policy"),
        PolicyState::Disabled
    );

    Ok(())
}

#[test]
fn queued_but_not_started_rewrites_are_discarded_after_shutdown() -> anyhow::Result<()> {
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

    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: active_path.clone(),
                ids: vec!["active_policy".to_string()],
                requested: PolicyState::Disabled,
            })
    );
    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: queued_path.clone(),
                ids: vec!["queued_policy".to_string()],
                requested: PolicyState::Disabled,
            })
    );

    rewrite_probe.wait_for_started(REWRITE_TEST_TIMEOUT)?;

    let start_outcome = crank_until(
        &mut runner,
        |app| policy_status(app, "active_policy") == Some(PolicyRowStatus::Writing),
        REWRITE_TEST_TIMEOUT,
    )?;
    assert_eq!(
        start_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    let quit_outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('q')),
        successful_editor(),
    )?;
    assert_eq!(quit_outcome, ControlCrankOutcome::Quit);

    release_rewrite.release()?;
    drop(runner);

    assert_eq!(
        read_policy_state(&active_path, "active_policy"),
        PolicyState::Disabled
    );
    assert_eq!(
        read_policy_state(&queued_path, "queued_policy"),
        PolicyState::Enabled
    );
    Ok(())
}

#[test]
fn quit_short_circuits_future_enqueue_effects() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &permit_policy("post_quit_policy"))?;
    let mut runner = HeadlessRunner::new(None, None);

    runner.execute_effects_with_editor(
        vec![
            ControlEffect::Announce(ControlAnnouncement::ShutdownRequested),
            ControlEffect::EnqueuePolicyRewrite(PolicyRewriteRequest {
                file: policy_path.clone(),
                ids: vec!["post_quit_policy".to_string()],
                requested: PolicyState::Disabled,
            }),
        ],
        successful_editor(),
    )?;

    assert!(runner.app().should_quit());
    assert_eq!(
        runner.app().status().runtime_state,
        ControlRuntimeState::ShuttingDown
    );
    assert_eq!(runner.app().status().rewrite_queue_len, 0);
    assert_eq!(
        read_policy_state(&policy_path, "post_quit_policy"),
        PolicyState::Enabled
    );

    Ok(())
}

#[test]
fn policy_reload_announcement_reloads_policies() -> anyhow::Result<()> {
    let policy_one = permit_policy("policy_one");
    let policy_two = permit_policy("policy_two");
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &policy_one)?;
    let mut runner = HeadlessRunner::new(Some(temp.path().to_path_buf()), None);

    assert_eq!(runner.app().policies().len(), 1);

    std::fs::write(policy_path, format!("{policy_one}\n{policy_two}"))?;
    runner.execute_effects_with_editor(
        vec![ControlEffect::Announce(
            ControlAnnouncement::PolicyReloadRequested,
        )],
        successful_editor(),
    )?;

    assert_eq!(runner.app().policy_error(), None);
    assert_eq!(runner.app().policies().len(), 2);

    Ok(())
}

#[test]
fn fatal_announcement_records_error_and_shuts_down() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &permit_policy("fatal_policy"))?;
    let mut runner = HeadlessRunner::new(Some(temp.path().to_path_buf()), None);
    let fatal_error = ControlError::audit_source(AuditSourceError::operation("fatal failure"));

    runner.execute_effects_with_editor(
        vec![
            ControlEffect::Announce(ControlAnnouncement::FatalError(fatal_error.clone())),
            ControlEffect::EnqueuePolicyRewrite(PolicyRewriteRequest {
                file: policy_path.clone(),
                ids: vec!["fatal_policy".to_string()],
                requested: PolicyState::Disabled,
            }),
        ],
        successful_editor(),
    )?;

    assert!(runner.app().should_quit());
    assert_eq!(runner.app().policy_error(), Some(&fatal_error));
    assert_eq!(
        runner.app().status().runtime_state,
        ControlRuntimeState::ShuttingDown
    );
    assert_eq!(
        read_policy_state(&policy_path, "fatal_policy"),
        PolicyState::Enabled
    );

    Ok(())
}

#[test]
fn queue_dump_announcement_is_non_disruptive() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None, None);

    runner.execute_effects_with_editor(
        vec![ControlEffect::Announce(
            ControlAnnouncement::QueueDumpRequested,
        )],
        successful_editor(),
    )?;

    assert!(!runner.app().should_quit());
    assert_eq!(runner.app().policy_error(), None);
    assert_eq!(
        runner.app().status().runtime_state,
        ControlRuntimeState::Running
    );

    Ok(())
}

#[test]
fn open_policy_source_success_produces_reload() -> anyhow::Result<()> {
    let policy_one = permit_policy("policy_one");
    let policy_two = permit_policy("policy_two");
    let (_temp, policy_path, mut runner) = headless_runner_with_policy_source(&policy_one)?;

    assert_eq!(runner.app().policies().len(), 1);

    let outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('e')),
        replace_policy_source_editor(policy_path, format!("{policy_one}\n{policy_two}")),
    )?;

    assert_eq!(outcome, ControlCrankOutcome::Processed(EventKind::Input));
    assert_eq!(runner.app().policy_error(), None);
    assert_eq!(runner.app().policies().len(), 2);

    Ok(())
}

#[test]
fn reload_preserves_audit_buffer() -> anyhow::Result<()> {
    let policy_one = permit_policy("policy_one");
    let policy_two = permit_policy("policy_two");
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &policy_one)?;
    let (_audit_tx, audit_rx) = audit_channel_with_rows(2)?;
    let mut runner = HeadlessRunner::new(Some(temp.path().to_path_buf()), Some(&audit_rx));

    let audit_outcome = crank_until(
        &mut runner,
        |app| app.audit_rows_len() == 2,
        CRANK_TEST_TIMEOUT,
    )?;
    assert_eq!(
        audit_outcome,
        ControlCrankOutcome::Processed(EventKind::Audit)
    );
    assert_eq!(runner.app().policies().len(), 1);

    let edit_outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('e')),
        replace_policy_source_editor(policy_path, format!("{policy_one}\n{policy_two}")),
    )?;

    assert_eq!(
        edit_outcome,
        ControlCrankOutcome::Processed(EventKind::Input)
    );
    assert_eq!(runner.app().policy_error(), None);
    assert_eq!(runner.app().policies().len(), 2);
    assert_eq!(runner.app().audit_rows_len(), 2);

    Ok(())
}

#[test]
fn reload_clamps_selected_policy_index() -> anyhow::Result<()> {
    let policy_one = permit_policy("policy_one");
    let policy_two = permit_policy("policy_two");
    let policy_three = permit_policy("policy_three");
    let (_temp, policy_path, mut runner) =
        headless_runner_with_policy_source(&format!("{policy_one}\n{policy_two}\n{policy_three}"))?;

    assert_eq!(runner.app().policies().len(), 3);
    assert_eq!(
        runner.try_crank(
            &FakeTerminal::with_key(KeyCode::Char('j')),
            successful_editor()
        )?,
        ControlCrankOutcome::Processed(EventKind::Input)
    );
    assert_eq!(
        runner.try_crank(
            &FakeTerminal::with_key(KeyCode::Char('j')),
            successful_editor()
        )?,
        ControlCrankOutcome::Processed(EventKind::Input)
    );
    assert_eq!(runner.app().selected_policy_index(), 2);

    let edit_outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('e')),
        replace_policy_source_editor(policy_path, policy_one),
    )?;

    assert_eq!(
        edit_outcome,
        ControlCrankOutcome::Processed(EventKind::Input)
    );
    assert_eq!(runner.app().policy_error(), None);
    assert_eq!(runner.app().policies().len(), 1);
    assert_eq!(runner.app().selected_policy_index(), 0);

    Ok(())
}

#[test]
fn crank_until_waits_for_policy_reload_error() -> anyhow::Result<()> {
    let (_temp, policy_path, mut runner) =
        headless_runner_with_policy_source(&permit_policy("policy_one"))?;

    let terminal = FakeTerminal::with_key(KeyCode::Char('e'));
    let outcome = crank_until_with_terminal(
        &mut runner,
        &terminal,
        replace_policy_source_editor(policy_path, "@id(\"broken\")\npermit (".to_string()),
        |app| app.status().last_policy_error.is_some(),
        CRANK_TEST_TIMEOUT,
    )?;

    assert_eq!(outcome, ControlCrankOutcome::Processed(EventKind::Input));
    assert_eq!(runner.app().policies().len(), 1);
    assert_eq!(
        runner.app().status().last_policy_error.as_ref(),
        runner.app().policy_error()
    );

    Ok(())
}

#[test]
fn editor_failure_does_not_reload_policies() -> anyhow::Result<()> {
    let policy_one = permit_policy("policy_one");
    let policy_two = permit_policy("policy_two");
    let (_temp, policy_path, mut runner) = headless_runner_with_policy_source(&policy_one)?;
    let edited_source = format!("{policy_one}\n{policy_two}");
    let edited_path = policy_path.clone();

    assert_eq!(runner.app().policies().len(), 1);

    let outcome = runner.try_crank(
        &FakeTerminal::with_key(KeyCode::Char('e')),
        move |path: &std::path::Path| {
            assert_eq!(path, edited_path.as_path());
            std::fs::write(path, &edited_source)?;
            Ok(Err(EditorError::operation("editor failed")))
        },
    )?;

    assert_eq!(outcome, ControlCrankOutcome::Processed(EventKind::Input));
    assert_eq!(runner.app().policies().len(), 1);
    let Some(ControlError::Editor { path, error }) = runner.app().policy_error() else {
        anyhow::bail!("editor failure did not produce an editor error");
    };
    assert_eq!(path, &policy_path);
    assert_eq!(error.as_ref(), &EditorError::operation("editor failed"));

    Ok(())
}
