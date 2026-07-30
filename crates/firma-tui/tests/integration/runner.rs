use std::{path::PathBuf, sync::mpsc};

use crate::support::{
    BlockingRewriteHandler, FakeTerminal, REWRITE_TEST_TIMEOUT, RewriteRelease, audit_channel,
    audit_channel_with_rows, blocking_first_rewrite_handler, crank_until, generated_policy_ids,
    generated_policy_source, permit_policy, policy_status, send_audit_rows,
    wait_for_rewrite_event_dispatch, write_named_policy_file, write_policy_file,
};
use crossterm::event::KeyCode;
use firma_tui::control::{
    ControlAnnouncement, ControlCrankOutcome, ControlEffect, ControlRuntimeState, Event, EventKind,
    HeadlessRunner, PolicyRewriteRequest, PolicyRowStatus, PolicyState, read_policy_state,
};

const LARGE_REWRITE_BACKLOG_COUNT: usize = 1_000;

#[test]
fn input_beats_audit() -> anyhow::Result<()> {
    let (_audit_tx, audit_rx) = audit_channel_with_rows(128)?;
    let mut runner = HeadlessRunner::with_audit_rows(None, Some(&audit_rx));

    let outcome = runner.try_crank(&FakeTerminal::with_key(KeyCode::Char('j')))?;

    assert_eq!(outcome, ControlCrankOutcome::Processed(EventKind::Input));
    assert_eq!(runner.app().audit_rows_len(), 0);

    Ok(())
}

#[test]
fn input_beats_rewrite() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &permit_policy("policy_one"))?;
    let BlockingRewriteHandler {
        handler,
        release,
        started,
        completed,
    } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let mut runner =
        HeadlessRunner::with_policy_rewrite_handler(Some(temp.path().to_path_buf()), None, handler);

    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: policy_path,
                ids: vec!["policy_one".to_string()],
                requested: PolicyState::Disabled,
            })
    );
    assert_eq!(
        started.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["policy_one".to_string()]
    );

    let input_outcome = runner.try_crank(&FakeTerminal::with_key(KeyCode::Char('h')))?;
    assert_eq!(
        input_outcome,
        ControlCrankOutcome::Processed(EventKind::Input)
    );
    assert!(runner.app().help_visible());

    let rewrite_outcome = runner.try_crank(&FakeTerminal::default())?;
    assert_eq!(
        rewrite_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );
    assert_eq!(
        policy_status(runner.app(), "policy_one"),
        Some(PolicyRowStatus::Writing)
    );

    release_rewrite.release()?;
    assert_eq!(
        completed.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["policy_one".to_string()]
    );
    let completion_outcome = crank_until(
        &mut runner,
        |app| {
            policy_status(app, "policy_one") == Some(PolicyRowStatus::State(PolicyState::Disabled))
        },
        64,
    )?;
    assert_eq!(
        completion_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    Ok(())
}

#[test]
fn rewrite_beats_audit() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &permit_policy("policy_one"))?;
    let (audit_tx, audit_rx) = audit_channel();
    let BlockingRewriteHandler {
        handler,
        release,
        started,
        completed,
    } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let mut runner = HeadlessRunner::with_policy_rewrite_handler(
        Some(temp.path().to_path_buf()),
        Some(&audit_rx),
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
    assert_eq!(
        started.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["policy_one".to_string()]
    );

    send_audit_rows(&audit_tx, 128)?;
    let start_outcome = runner.try_crank(&FakeTerminal::default())?;
    assert_eq!(
        start_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );
    assert_eq!(runner.app().audit_rows_len(), 0);

    release_rewrite.release()?;
    assert_eq!(
        completed.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["policy_one".to_string()]
    );
    // The completion signal above fires from inside the test handler, which
    // runs before the queue's worker thread pushes the real
    // `PolicyRewriteEvent::Completed` onto its own channel: there is an
    // unavoidable gap between "handler returned" and "event enqueued". A
    // `try_crank` sampled inside that gap would find no rewrite event yet
    // and drain the pending audit rows instead, so give the worker thread a
    // moment to finish its dispatch before taking the one decisive crank
    // this test asserts on.
    wait_for_rewrite_event_dispatch();
    let completion_outcome = runner.try_crank(&FakeTerminal::default())?;

    assert_eq!(
        completion_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );
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
    let BlockingRewriteHandler {
        handler,
        release,
        started,
        completed: _completed,
    } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let mut runner =
        HeadlessRunner::with_policy_rewrite_handler(Some(temp.path().to_path_buf()), None, handler);

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
    assert_eq!(
        started.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["backlog_policy_0000".to_string()]
    );
    assert!(runner.sources().rewrite_queue_len() > 0);

    let outcome = runner.try_crank(&FakeTerminal::with_key(KeyCode::Char('j')))?;

    assert_eq!(outcome, ControlCrankOutcome::Processed(EventKind::Input));
    assert_eq!(runner.app().selected_policy_index(), 1);

    release_rewrite.release()?;
    drop(runner);

    Ok(())
}

#[test]
fn audit_drains_only_64_rows_per_crank() -> anyhow::Result<()> {
    let (_audit_tx, audit_rx) = audit_channel_with_rows(65)?;
    let mut runner = HeadlessRunner::with_audit_rows(None, Some(&audit_rx));

    let first_outcome = runner.try_crank(&FakeTerminal::default())?;
    assert_eq!(
        first_outcome,
        ControlCrankOutcome::Processed(EventKind::Audit)
    );
    assert_eq!(runner.app().audit_rows_len(), 64);

    let second_outcome = runner.try_crank(&FakeTerminal::default())?;
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
    let BlockingRewriteHandler {
        handler,
        release,
        started,
        completed,
    } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let mut runner =
        HeadlessRunner::with_policy_rewrite_handler(Some(temp.path().to_path_buf()), None, handler);

    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: policy_path,
                ids: vec!["policy_one".to_string()],
                requested: PolicyState::Disabled,
            })
    );
    assert_eq!(
        started.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["policy_one".to_string()]
    );

    let start_outcome = crank_until(
        &mut runner,
        |app| policy_status(app, "policy_one") == Some(PolicyRowStatus::Writing),
        64,
    )?;
    assert_eq!(
        start_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    release_rewrite.release()?;
    assert_eq!(
        completed.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["policy_one".to_string()]
    );
    let completion_outcome = crank_until(
        &mut runner,
        |app| {
            policy_status(app, "policy_one") == Some(PolicyRowStatus::State(PolicyState::Disabled))
        },
        64,
    )?;
    assert_eq!(
        completion_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    Ok(())
}

#[test]
fn tick_reports_no_event_when_nothing_else_is_ready() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None);

    let outcome = runner.try_crank(&FakeTerminal::default())?;

    assert_eq!(outcome, ControlCrankOutcome::NoEvent);

    Ok(())
}

#[test]
fn quit_requests_shutdown() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None);

    let outcome = runner.try_crank(&FakeTerminal::with_key(KeyCode::Char('q')))?;

    assert_eq!(outcome, ControlCrankOutcome::Quit);
    assert!(runner.app().should_quit());
    assert_eq!(
        runner.app().status().runtime_state,
        ControlRuntimeState::ShuttingDown
    );

    Ok(())
}

#[test]
fn quit_seals_rewrite_enqueueing_and_updates_status() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None);

    let outcome = runner.try_crank(&FakeTerminal::with_key(KeyCode::Char('q')))?;

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
    let BlockingRewriteHandler {
        handler,
        release,
        started,
        completed: _completed,
    } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let mut runner =
        HeadlessRunner::with_policy_rewrite_handler(Some(temp.path().to_path_buf()), None, handler);

    assert!(
        runner
            .sources()
            .enqueue_policy_rewrite(PolicyRewriteRequest {
                file: active_path.clone(),
                ids: vec!["active_policy".to_string()],
                requested: PolicyState::Disabled,
            })
    );
    assert_eq!(
        started.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["active_policy".to_string()]
    );

    let start_outcome = crank_until(
        &mut runner,
        |app| policy_status(app, "active_policy") == Some(PolicyRowStatus::Writing),
        64,
    )?;
    assert_eq!(
        start_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    let quit_outcome = runner.try_crank(&FakeTerminal::with_key(KeyCode::Char('q')))?;
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
    let BlockingRewriteHandler {
        handler,
        release,
        started,
        completed: _completed,
    } = blocking_first_rewrite_handler();
    let mut release_rewrite = RewriteRelease::new(release);
    let mut runner =
        HeadlessRunner::with_policy_rewrite_handler(Some(temp.path().to_path_buf()), None, handler);

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
    assert_eq!(
        started.recv_timeout(REWRITE_TEST_TIMEOUT)?,
        vec!["active_policy".to_string()]
    );

    let start_outcome = crank_until(
        &mut runner,
        |app| policy_status(app, "active_policy") == Some(PolicyRowStatus::Writing),
        64,
    )?;
    assert_eq!(
        start_outcome,
        ControlCrankOutcome::Processed(EventKind::Rewrite)
    );

    let quit_outcome = runner.try_crank(&FakeTerminal::with_key(KeyCode::Char('q')))?;
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
    assert!(matches!(
        started.try_recv(),
        Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected)
    ));

    Ok(())
}

#[test]
fn quit_short_circuits_future_enqueue_effects() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), &permit_policy("post_quit_policy"))?;
    let mut runner = HeadlessRunner::new(None);

    runner.execute_effects(vec![
        ControlEffect::Announce(ControlAnnouncement::ShutdownRequested),
        ControlEffect::EnqueuePolicyRewrite(PolicyRewriteRequest {
            file: policy_path.clone(),
            ids: vec!["post_quit_policy".to_string()],
            requested: PolicyState::Disabled,
        }),
    ]);

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
fn help_input_is_applied_by_runner() -> anyhow::Result<()> {
    let mut runner = HeadlessRunner::new(None);

    let outcome = runner.try_crank(&FakeTerminal::with_key(KeyCode::Char('h')))?;

    assert_eq!(outcome, ControlCrankOutcome::Processed(EventKind::Input));
    assert!(runner.app().help_visible());

    Ok(())
}

#[test]
fn resize_and_mouse_events_are_reported() -> anyhow::Result<()> {
    let mut resize_runner = HeadlessRunner::new(None);
    let resize_outcome = resize_runner.try_crank(&FakeTerminal::with_events([Event::Resize]))?;
    assert_eq!(
        resize_outcome,
        ControlCrankOutcome::Processed(EventKind::Resize)
    );

    let mut mouse_runner = HeadlessRunner::new(None);
    let mouse_outcome = mouse_runner.try_crank(&FakeTerminal::with_events([Event::Mouse]))?;
    assert_eq!(
        mouse_outcome,
        ControlCrankOutcome::Processed(EventKind::Mouse)
    );

    Ok(())
}
