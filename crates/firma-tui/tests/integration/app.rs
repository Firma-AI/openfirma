use crate::support::{
    app_with_audit_rows, audit_row, handle_key, last_visible_audit_index, selected_audit_resource,
};
use crossterm::event::KeyCode;
use firma_tui::control::{App, AuditDecision, AuditFilter, AuditViewportMode, Pane};

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
