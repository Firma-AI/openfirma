//! Rendering for the control surface.

mod audit;
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
    policies::render_policies,
    theme::{accent_style, dim_style, warning_style},
};

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
}

fn key_hints(app: &App) -> Line<'static> {
    let entries = crate::control::bindings::footer_entries(app);
    let mut spans = Vec::with_capacity(entries.len().saturating_mul(4).saturating_add(1));
    spans.push(Span::styled(" ", dim_style()));

    for entry in entries {
        spans.push(Span::styled("[", dim_style()));
        spans.push(Span::styled(entry.key, accent_style()));
        spans.push(Span::styled("] ", dim_style()));
        spans.push(Span::styled(
            format!("{} ", entry.label.to_lowercase()),
            dim_style(),
        ));
    }

    Line::from(spans)
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
