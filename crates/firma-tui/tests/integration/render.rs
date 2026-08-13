use crate::support::{
    app_with_audit_rows, app_with_default_policies, audit_row, handle_key, render_text,
};
use crossterm::event::KeyCode;
use firma_tui::control::{
    App, AuditDecision, AuditFilter, ControlError, PolicyRewriteCompletion, PolicyRewriteError,
    PolicyRewriteStart,
};

#[test]
fn empty_state_renders_policy_and_audit_messages() -> anyhow::Result<()> {
    let app = App::new(None, false);

    let text = render_text(&app, 180, 24)?;

    assert!(text.contains("OPENFIRMA"));
    assert!(text.contains("Policies"));
    assert!(text.contains("Audit"));
    assert!(text.contains("No policies configured."));
    assert!(text.contains("Add @id(...) Cedar policies to the policy directory."));
    assert!(text.contains("No audit events buffered."));

    Ok(())
}

#[test]
fn audit_table_renders_filter_and_rows() -> anyhow::Result<()> {
    let app = app_with_audit_rows();

    let text = render_text(&app, 120, 24)?;

    assert!(text.contains("Filter:"));
    assert!(text.contains("all"));
    assert!(text.contains("deny"));
    assert!(text.contains("allow"));
    assert!(text.contains("time"));
    assert!(text.contains("dec"));
    assert!(text.contains("class"));
    assert!(text.contains("resource"));
    assert!(text.contains("00:00:02"));
    assert!(text.contains("class-2"));
    assert!(text.contains("resource-2"));

    Ok(())
}

#[test]
fn audit_panel_renders_no_match_message() -> anyhow::Result<()> {
    let mut app = App::new(None, true);
    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    app.set_audit_filter(AuditFilter::Deny);

    let text = render_text(&app, 100, 24)?;

    assert!(text.contains("No audit events match this filter."));

    Ok(())
}

#[test]
fn help_overlay_renders_bindings_and_footer() -> anyhow::Result<()> {
    let mut app = app_with_audit_rows();
    app.toggle_help();

    let text = render_text(&app, 100, 24)?;

    assert!(text.contains("Help"));
    assert!(text.contains("First row"));
    assert!(text.contains("Last row"));
    assert!(text.contains("Close"));
    assert!(text.contains("Quit"));

    Ok(())
}

#[test]
fn about_overlay_renders_project_metadata() -> anyhow::Result<()> {
    let mut app = App::default();
    handle_key(&mut app, KeyCode::Char('o'));

    let text = render_text(&app, 100, 24)?;

    assert!(text.contains("About"));
    assert!(text.contains("OPENFIRMA"));
    assert!(text.contains("Policy Control"));
    assert!(text.contains("firma-tui"));
    assert!(text.contains("GPL-3.0-only"));

    Ok(())
}

#[test]
fn audit_inspect_overlay_renders_selected_row() -> anyhow::Result<()> {
    let mut app = app_with_audit_rows();
    app.switch_pane();
    app.move_selection_up();
    handle_key(&mut app, KeyCode::Char('i'));

    let text = render_text(&app, 120, 24)?;

    assert!(text.contains("Inspect"));
    assert!(text.contains("decision"));
    assert!(text.contains("deny"));
    assert!(text.contains("action"));
    assert!(text.contains("class-1"));
    assert!(text.contains("resource-1"));
    assert!(text.contains("esc/enter/i"));

    Ok(())
}

#[test]
fn audit_inspect_overlay_renders_empty_selection_message() -> anyhow::Result<()> {
    let mut app = App::new(None, true);
    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    app.switch_pane();
    handle_key(&mut app, KeyCode::Char('i'));
    app.set_audit_filter(AuditFilter::Deny);

    let text = render_text(&app, 120, 24)?;

    assert!(text.contains("Inspect"));
    assert!(text.contains("No audit row selected."));

    Ok(())
}

#[test]
fn overlays_do_not_render_main_footer_hints() -> anyhow::Result<()> {
    let mut about_app = App::default();
    handle_key(&mut about_app, KeyCode::Char('o'));
    let about_text = render_text(&about_app, 120, 24)?;
    assert!(about_text.contains("About"));
    assert_main_footer_hints_absent(&about_text);

    let mut inspect_app = app_with_audit_rows();
    inspect_app.switch_pane();
    handle_key(&mut inspect_app, KeyCode::Char('i'));
    let inspect_text = render_text(&inspect_app, 120, 24)?;
    assert!(inspect_text.contains("Inspect"));
    assert_main_footer_hints_absent(&inspect_text);

    Ok(())
}

#[test]
fn policy_table_renders_queued_and_writing_statuses() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;
    let writing = app
        .request_selected_policy_toggle()
        .ok_or_else(|| anyhow::anyhow!("first policy did not produce a rewrite request"))?;

    app.start_policy_rewrite(&PolicyRewriteStart {
        file: writing.file,
        ids: writing.ids,
    });

    app.move_selection_down();
    let _ = app
        .request_selected_policy_toggle()
        .ok_or_else(|| anyhow::anyhow!("second policy did not produce a rewrite request"))?;

    let text = render_text(&app, 120, 24)?;

    assert!(text.contains("writing"));
    assert!(text.contains("queued"));

    Ok(())
}

fn assert_main_footer_hints_absent(text: &str) {
    assert!(!text.contains("tab"));
    assert!(!text.contains("space"));
    assert!(!text.contains("toggle"));
}

#[test]
fn policy_error_renders_in_policy_pane() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;
    let error_request = app
        .request_selected_policy_toggle()
        .ok_or_else(|| anyhow::anyhow!("policy did not produce a rewrite request"))?;

    let rewrite_error = ControlError::policy_rewrite(
        error_request.file.clone(),
        error_request.ids.clone(),
        PolicyRewriteError::operation("write failed"),
    );

    app.finish_policy_rewrite(&PolicyRewriteCompletion {
        file: error_request.file,
        ids: error_request.ids,
        requested: error_request.requested,
        result: Err(rewrite_error),
    });

    let text = render_text(&app, 120, 24)?;

    assert!(text.contains("Policy error"));
    assert!(text.contains("failed to rewrite"));

    Ok(())
}

#[test]
fn help_overlay_hides_edit_without_policy_source() -> anyhow::Result<()> {
    let mut app = App::default();
    app.toggle_help();

    let text = render_text(&app, 100, 24)?;

    assert!(!text.contains("Edit policy"));

    Ok(())
}

#[test]
fn help_overlay_shows_edit_with_policy_source() -> anyhow::Result<()> {
    let (_temp, mut app) = app_with_default_policies()?;
    app.toggle_help();

    let text = render_text(&app, 100, 24)?;

    assert!(text.contains("Edit policy"));

    Ok(())
}

#[test]
fn footer_hides_edit_hint_without_policy_source() -> anyhow::Result<()> {
    let app = App::default();

    let text = render_text(&app, 100, 24)?;

    assert!(!text.contains("edit policy"));

    Ok(())
}

#[test]
fn small_terminal_renders_without_error() -> anyhow::Result<()> {
    let app = app_with_audit_rows();

    let text = render_text(&app, 24, 8)?;

    assert!(!text.is_empty());

    Ok(())
}

#[test]
fn non_running_status_is_rendered_in_outer_frame() -> anyhow::Result<()> {
    let mut app = App::default();
    app.request_quit();

    let text = render_text(&app, 80, 20)?;

    assert!(text.contains("stopping"));

    Ok(())
}
