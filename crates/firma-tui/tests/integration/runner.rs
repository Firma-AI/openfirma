use crate::support::{FakeTerminal, audit_channel_with_rows};
use crossterm::event::KeyCode;
use firma_tui::control::{
    ControlCrankOutcome, ControlRuntimeState, Event, EventKind, HeadlessRunner,
};

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
