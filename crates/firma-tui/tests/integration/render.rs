use std::path::PathBuf;

use crate::support::{app_with_audit_rows, audit_row, render_text};
use firma_tui::control::{App, AuditDecision, AuditFilter};

#[test]
fn empty_state_renders_policy_context_and_empty_audit() -> anyhow::Result<()> {
    let app = App::new(Some(PathBuf::from("/tmp/policies")), false);

    let text = render_text(&app, 100, 24)?;

    assert!(text.contains("OPENFIRMA"));
    assert!(text.contains("Policies"));
    assert!(text.contains("Audit"));
    assert!(text.contains("policy dir: /tmp/policies"));
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
fn non_running_status_is_rendered_in_outer_frame() -> anyhow::Result<()> {
    let mut app = App::default();
    app.request_quit();

    let text = render_text(&app, 80, 20)?;

    assert!(text.contains("stopping"));

    Ok(())
}
