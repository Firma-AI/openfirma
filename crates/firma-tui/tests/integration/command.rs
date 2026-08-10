use crate::support::{app_with_default_policies, audit_row, policy_status};
use crossterm::event::KeyCode;
use firma_tui::control::{
    App, AuditDecision, AuditFilter, ControlAnnouncement, ControlEffect, PolicyRowStatus,
    PolicyState, handle_key,
};

#[test]
fn quit_key_returns_shutdown_announcement() -> anyhow::Result<()> {
    let mut app = App::default();
    let effect = single_effect(handle_key(&mut app, KeyCode::Char('q')))?;

    let ControlEffect::Announce(announcement) = effect else {
        anyhow::bail!("quit did not return an announcement effect");
    };

    assert_eq!(announcement, ControlAnnouncement::ShutdownRequested);
    assert!(!app.should_quit());

    Ok(())
}

#[test]
fn edit_key_returns_no_effect_without_selected_file() {
    let mut app = App::default();

    let effects = handle_key(&mut app, KeyCode::Char('e'));

    assert!(effects.is_empty());
    assert_eq!(app.policy_error(), None);
}

#[test]
fn space_key_returns_one_effect_until_row_is_pending() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;
    let selected_id = app.policies()[app.selected_policy_index()].id.clone();

    let effect = single_effect(handle_key(&mut app, KeyCode::Char(' ')))?;
    let ControlEffect::EnqueuePolicyRewrite(request) = effect else {
        anyhow::bail!("selected toggle did not enqueue a policy rewrite");
    };

    assert_eq!(request.ids, vec![selected_id.clone()]);
    assert_eq!(
        policy_status(&app, &selected_id),
        Some(PolicyRowStatus::Queued)
    );

    let effects = handle_key(&mut app, KeyCode::Char(' '));
    assert!(effects.is_empty());
    assert_eq!(
        policy_status(&app, &selected_id),
        Some(PolicyRowStatus::Queued)
    );

    Ok(())
}

#[test]
fn toggle_all_key_returns_grouped_effects_until_rows_are_pending() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;

    let effects = handle_key(&mut app, KeyCode::Char('t'));

    assert_eq!(effects.len(), 1);
    let Some(ControlEffect::EnqueuePolicyRewrite(request)) = effects.first() else {
        anyhow::bail!("toggle all did not enqueue a policy rewrite");
    };

    assert_eq!(request.ids, vec!["second_policy".to_string()]);
    assert_eq!(request.requested, PolicyState::Enabled);

    let effects = handle_key(&mut app, KeyCode::Char('t'));
    assert!(effects.is_empty());

    Ok(())
}

#[test]
fn audit_filter_key_mutates_state_without_effects() {
    let mut app = App::new(None, true);
    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    app.push_audit_row(audit_row(AuditDecision::Deny, 1));

    let effects = handle_key(&mut app, KeyCode::Char('d'));

    assert!(effects.is_empty());
    assert_eq!(app.audit_filter(), AuditFilter::Deny);
    assert_eq!(app.visible_audit_rows_len(), 1);
    assert_eq!(
        app.visible_audit_rows()
            .next()
            .map(|row| row.resource.as_str()),
        Some("resource-1")
    );
}

fn single_effect(effects: Vec<ControlEffect>) -> anyhow::Result<ControlEffect> {
    let mut effects = effects.into_iter();
    let Some(effect) = effects.next() else {
        anyhow::bail!("command did not return an effect");
    };

    if effects.next().is_some() {
        anyhow::bail!("command returned more than one effect");
    }

    Ok(effect)
}
