use crate::support::{
    app_with_audit_rows, app_with_default_policies, app_with_policy_files, audit_row, handle_key,
    last_visible_audit_index, policy_status, selected_audit_resource,
};
use crossterm::event::KeyCode;
use firma_tui::control::{
    App, AuditDecision, AuditFilter, AuditViewportMode, ControlError, Pane, PolicyDiscoveryError,
    PolicyRowStatus, PolicyState,
};

#[test]
fn tab_switches_panes() {
    let mut app = app_with_audit_rows();

    assert_eq!(app.selected_pane(), Pane::Policies);

    handle_key(&mut app, KeyCode::Tab);
    assert_eq!(app.selected_pane(), Pane::Audit);

    handle_key(&mut app, KeyCode::Tab);
    assert_eq!(app.selected_pane(), Pane::Policies);
}

#[test]
fn j_k_and_arrows_clamp_policy_selection() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;

    assert_eq!(app.selected_policy_index(), 0);

    handle_key(&mut app, KeyCode::Char('k'));
    handle_key(&mut app, KeyCode::Up);
    assert_eq!(app.selected_policy_index(), 0);

    handle_key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.selected_policy_index(), 1);

    handle_key(&mut app, KeyCode::Down);
    handle_key(&mut app, KeyCode::Down);
    handle_key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.selected_policy_index(), 2);

    handle_key(&mut app, KeyCode::Char('k'));
    handle_key(&mut app, KeyCode::Up);
    assert_eq!(app.selected_policy_index(), 0);

    Ok(())
}

#[test]
fn gg_jumps_to_first_policy_row() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;

    app.move_selection_last();
    assert_eq!(app.selected_policy_index(), 2);

    handle_key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected_policy_index(), 2);

    handle_key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected_policy_index(), 0);

    Ok(())
}

#[test]
fn policy_rows_reflect_cedar_disabled_state() -> anyhow::Result<()> {
    let (_temp, app) = app_with_default_policies()?;

    assert_eq!(
        policy_status(&app, "first_policy"),
        Some(PolicyRowStatus::State(PolicyState::Enabled))
    );
    assert_eq!(
        policy_status(&app, "second_policy"),
        Some(PolicyRowStatus::State(PolicyState::Disabled))
    );

    Ok(())
}

#[test]
fn policy_discovery_ignores_unannotated_cedar_policies() -> anyhow::Result<()> {
    let source = format!(
        r"
permit (
    principal,
    action,
    resource
);
{}
",
        crate::support::permit_policy("visible_policy")
    );
    let (_temp, app) = app_with_policy_files(&[("policies.cedar", &source)])?;

    assert_eq!(app.policies().len(), 1);
    assert_eq!(
        app.policies().first().map(|policy| policy.id.as_str()),
        Some("visible_policy")
    );

    Ok(())
}

#[test]
fn policy_discovery_reports_duplicate_ids() -> anyhow::Result<()> {
    let source = format!(
        "{}{}",
        crate::support::permit_policy("duplicate_policy"),
        crate::support::permit_policy("duplicate_policy")
    );
    let temp = tempfile::tempdir()?;
    crate::support::write_named_policy_file(temp.path(), "policies.cedar", &source)?;
    let app = App::new(Some(temp.path().to_path_buf()), false);

    let Some(ControlError::PolicyDiscovery { error, .. }) = app.policy_error() else {
        anyhow::bail!("duplicate policy id did not produce a discovery error");
    };
    assert_eq!(
        error.as_ref(),
        &PolicyDiscoveryError::DuplicateId {
            id: "duplicate_policy".to_string()
        }
    );

    Ok(())
}

#[test]
fn gg_jumps_to_first_audit_row() {
    let mut app = app_with_audit_rows();
    app.switch_pane();

    app.move_selection_last();
    assert_eq!(app.selected_audit_index(), last_visible_audit_index(&app));

    handle_key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected_audit_index(), last_visible_audit_index(&app));

    handle_key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected_audit_index(), 0);
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);
}

#[test]
fn capital_g_jumps_last_and_resumes_audit_follow_tail() {
    let mut app = app_with_audit_rows();

    app.switch_pane();
    app.move_selection_first();
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);

    handle_key(&mut app, KeyCode::Char('G'));

    assert_eq!(app.selected_audit_index(), last_visible_audit_index(&app));
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::FollowTail);
}

#[test]
fn j_to_last_audit_row_resumes_follow_tail() {
    let mut app = app_with_audit_rows();

    app.switch_pane();
    app.move_selection_first();

    handle_key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.selected_audit_index(), 1);
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);

    handle_key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.selected_audit_index(), last_visible_audit_index(&app));
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::FollowTail);
}

#[test]
fn audit_filters_preserve_and_clamp_selected_row() {
    let mut app = app_with_audit_rows();

    app.switch_pane();
    app.move_selection_first();
    app.move_selection_down();
    assert_eq!(app.selected_audit_index(), 1);

    handle_key(&mut app, KeyCode::Char('l'));
    assert_eq!(app.audit_filter(), AuditFilter::Allow);
    assert_eq!(app.selected_audit_index(), 1);
    assert_eq!(selected_audit_resource(&app), Some("resource-2"));

    handle_key(&mut app, KeyCode::Char('d'));
    assert_eq!(app.audit_filter(), AuditFilter::Deny);
    assert_eq!(app.selected_audit_index(), 0);
    assert_eq!(selected_audit_resource(&app), Some("resource-1"));
}

#[test]
fn help_overlay_changes_key_context() {
    let mut app = app_with_audit_rows();

    handle_key(&mut app, KeyCode::Char('h'));
    assert!(app.help_visible());

    handle_key(&mut app, KeyCode::Char('j'));
    assert!(app.help_visible());
    assert_eq!(app.selected_pane(), Pane::Policies);

    handle_key(&mut app, KeyCode::Esc);
    assert!(!app.help_visible());
    assert!(!app.should_quit());
}

#[test]
fn audit_buffer_drops_oldest_row_at_capacity() {
    let mut app = App::new(None, true);
    for index in 0..=1_000 {
        app.push_audit_row(audit_row(AuditDecision::Allow, index));
    }

    assert_eq!(app.audit_rows_len(), 1_000);
    assert_eq!(
        app.visible_audit_rows()
            .next()
            .map(|row| row.resource.as_str()),
        Some("resource-1")
    );
}

#[test]
fn empty_audit_navigation_stays_clamped() {
    let mut app = App::default();
    app.switch_pane();

    app.move_selection_up();
    app.move_selection_down();
    app.move_selection_first();
    app.move_selection_last();

    assert_eq!(app.selected_audit_index(), 0);
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::FollowTail);
}
