//! Rendering for the control surface.

mod audit;
mod help;
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
    audit::render_audit,
    help::{key_hints, render_help},
    policies::render_policies,
    theme::{accent_style, dim_style, warning_style},
};

/// Renders the full Policy Control frame.
pub fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let outer = Block::default()
        .title_top(Line::from(title_spans(app.status().runtime_state)))
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

    if app.help_visible() {
        render_help(frame, area, app);
    }
}

fn title_spans(runtime_state: ControlRuntimeState) -> Vec<Span<'static>> {
    let mut spans = vec![
        Span::styled(" OPENFIRMA ", accent_style()),
        Span::styled("local ", dim_style()),
    ];

    if runtime_state != ControlRuntimeState::Running {
        spans.push(Span::styled(
            format!("{} ", runtime_state.label()),
            warning_style(),
        ));
    }

    spans
}
