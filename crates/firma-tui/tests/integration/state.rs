use crate::support::{audit_row, handle_key, render_text, selected_audit_resource};
use crossterm::event::KeyCode;
use firma_tui::control::{App, AuditDecision, AuditFilter, AuditViewportMode};

#[test]
fn audit_follow_tail_tracks_latest_visible_row() {
    let mut app = App::new(None, true);
    app.set_audit_filter(AuditFilter::Deny);

    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    assert_eq!(app.visible_audit_rows_len(), 0);
    assert_eq!(selected_audit_resource(&app), None);
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::FollowTail);

    app.push_audit_row(audit_row(AuditDecision::Deny, 1));
    app.push_audit_row(audit_row(AuditDecision::Deny, 2));

    assert_eq!(app.selected_audit_index(), 1);
    assert_eq!(selected_audit_resource(&app), Some("resource-2"));
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::FollowTail);
}

#[test]
fn audit_manual_selection_survives_non_matching_append() {
    let mut app = App::new(None, true);
    app.set_audit_filter(AuditFilter::Deny);
    app.push_audit_row(audit_row(AuditDecision::Deny, 0));
    app.push_audit_row(audit_row(AuditDecision::Deny, 1));
    app.switch_pane();
    app.move_selection_first();

    app.push_audit_row(audit_row(AuditDecision::Allow, 2));

    assert_eq!(app.selected_audit_index(), 0);
    assert_eq!(selected_audit_resource(&app), Some("resource-0"));
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);
}

#[test]
fn audit_manual_selection_is_adjusted_when_oldest_row_is_dropped() {
    let mut app = App::new(None, true);
    for index in 0..1_000 {
        app.push_audit_row(audit_row(AuditDecision::Allow, index));
    }
    app.switch_pane();
    app.move_selection_first();
    app.move_selection_down();

    app.push_audit_row(audit_row(AuditDecision::Allow, 1_000));

    assert_eq!(app.audit_rows_len(), 1_000);
    assert_eq!(app.selected_audit_index(), 0);
    assert_eq!(selected_audit_resource(&app), Some("resource-1"));
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);
}

#[test]
fn audit_manual_selection_survives_non_matching_eviction() -> anyhow::Result<()> {
    let mut app = App::new(None, true);
    app.set_audit_filter(AuditFilter::Deny);
    for index in 0..1_000 {
        let decision = if index % 2 == 0 {
            AuditDecision::Allow
        } else {
            AuditDecision::Deny
        };
        app.push_audit_row(audit_row(decision, index));
    }
    app.switch_pane();
    app.move_selection_first();
    app.move_selection_down();

    assert_eq!(app.selected_audit_index(), 1);
    assert_eq!(selected_audit_resource(&app), Some("resource-3"));

    handle_key(&mut app, KeyCode::Char('i'));
    app.push_audit_row(audit_row(AuditDecision::Allow, 1_000));

    assert_eq!(app.audit_rows_len(), 1_000);
    assert_eq!(app.selected_audit_index(), 1);
    assert_eq!(selected_audit_resource(&app), Some("resource-3"));
    assert_eq!(app.audit_viewport_mode(), AuditViewportMode::Manual);
    assert!(render_text(&app, 120, 24)?.contains("resource-3"));

    Ok(())
}

#[test]
fn overlay_state_has_one_visible_overlay_slot() -> anyhow::Result<()> {
    let mut app = App::new(None, true);
    app.push_audit_row(audit_row(AuditDecision::Deny, 0));
    app.switch_pane();

    handle_key(&mut app, KeyCode::Char('i'));
    let inspect_text = render_text(&app, 120, 24)?;
    assert!(inspect_text.contains("Inspect"));
    assert!(inspect_text.contains("resource-0"));

    app.toggle_help();
    let help_text = render_text(&app, 120, 24)?;
    assert!(help_text.contains("Help"));
    assert!(app.help_visible());

    handle_key(&mut app, KeyCode::Esc);
    let main_text = render_text(&app, 120, 24)?;
    assert!(!main_text.contains("Help"));
    assert!(!main_text.contains("Inspect"));
    assert!(!app.help_visible());

    handle_key(&mut app, KeyCode::Char('o'));
    let about_text = render_text(&app, 120, 24)?;
    assert!(about_text.contains("About"));
    assert!(about_text.contains("Version"));

    app.toggle_help();
    let help_text = render_text(&app, 120, 24)?;
    assert!(help_text.contains("Help"));
    assert!(app.help_visible());

    handle_key(&mut app, KeyCode::Esc);
    let main_text = render_text(&app, 120, 24)?;
    assert!(!main_text.contains("Version"));
    assert!(!main_text.contains("Help"));
    assert!(!app.help_visible());

    Ok(())
}
