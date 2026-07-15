//! Rendering for the control surface.

mod about;
mod audit;
mod help;
mod inspect;
mod policies;
mod theme;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders},
};

use crate::control::{app::App, state::ControlRuntimeState};

use self::{
    about::render_about,
    audit::render_audit,
    help::{key_hints, render_help},
    inspect::render_audit_inspect,
    policies::render_policies,
    theme::{accent_style, dim_style, error_style, warning_style},
};

/// Draws one full Policy Control frame.
///
/// The outer frame owns global status and key hints. Panes are drawn first,
/// then modal overlays are rendered from lowest to highest priority.
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let status = app.status();
    let outer = Block::default()
        .title_top(Line::from(title_spans(status.runtime_state)))
        .title_bottom(key_hints(app).right_aligned())
        .border_style(dim_style())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(inner);

    render_policies(frame, panes[0], app);
    render_audit(frame, panes[1], app);

    if app.audit_inspect_visible() {
        render_audit_inspect(frame, area, app);
    }

    if app.about_visible() {
        render_about(frame, area);
    }

    if app.help_visible() {
        render_help(frame, area, app);
    }
}

fn title_spans(runtime_state: ControlRuntimeState) -> Vec<Span<'static>> {
    let mut spans = vec![
        Span::styled(" OPENFIRMA ", accent_style()),
        Span::styled("local ", dim_style()),
    ];

    if let Some(span) = runtime_state_span(runtime_state) {
        spans.push(span);
    }

    spans
}

fn runtime_state_span(runtime_state: ControlRuntimeState) -> Option<Span<'static>> {
    match runtime_state {
        ControlRuntimeState::Running => None,
        ControlRuntimeState::Error => Some(Span::styled(
            format!("{} ", runtime_state.label()),
            error_style(),
        )),
        ControlRuntimeState::Starting
        | ControlRuntimeState::EditingPolicy
        | ControlRuntimeState::Rewriting
        | ControlRuntimeState::ShuttingDown => Some(Span::styled(
            format!("{} ", runtime_state.label()),
            warning_style(),
        )),
    }
}
