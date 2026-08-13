//! Audit row inspector for the focused log entry.
//!
//! The inspector gives one audit row enough room to be read without changing
//! the audit buffer itself. Navigation and filtering still belong to the app
//! state; this renderer only formats the selected row, sizes the popup and
//! keeps the close and movement hints visible.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
};

use crate::control::{app::App, state::AuditRow};

use super::theme::{accent_style, base_style, decision_style, dim_style, panel};

pub fn render_audit_inspect(frame: &mut Frame, area: Rect, app: &App) {
    let lines = app.selected_audit_row().map_or_else(
        || vec![Line::styled("No audit row selected.", dim_style())],
        audit_inspect_lines,
    );
    let area = inspect_area(area, lines.len());

    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel("Inspect"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn inspect_area(area: Rect, line_count: usize) -> Rect {
    let width = if area.width > 4 {
        76.min(area.width - 4)
    } else {
        area.width
    };
    let height = if area.height > 4 {
        u16::try_from(line_count)
            .unwrap_or(u16::MAX)
            .saturating_add(2)
            .min(area.height - 2)
    } else {
        area.height
    };

    Rect {
        x: area.x.saturating_add(area.width.saturating_sub(width) / 2),
        y: area
            .y
            .saturating_add(area.height.saturating_sub(height) / 2),
        width,
        height,
    }
}

fn audit_inspect_lines(row: &AuditRow) -> Vec<Line<'static>> {
    vec![
        inspect_row("time", row.time.clone(), base_style()),
        inspect_row(
            "decision",
            row.decision.label(),
            decision_style(row.decision),
        ),
        inspect_row("action", row.action_class.clone(), base_style()),
        inspect_row("resource", row.resource.clone(), base_style()),
        inspect_row("detail", audit_detail(row), base_style()),
        Line::default(),
        Line::from(vec![
            Span::styled(" [", dim_style()),
            Span::styled("j/k", accent_style()),
            Span::styled("] move  [", dim_style()),
            Span::styled("a/d/l", accent_style()),
            Span::styled("] filter  [", dim_style()),
            Span::styled("esc/enter/i", accent_style()),
            Span::styled("] close ", dim_style()),
        ]),
    ]
}

fn inspect_row(label: &'static str, value: impl Into<String>, value_style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(" ", dim_style()),
        Span::styled(format!("{label:<9}"), dim_style()),
        Span::styled(value.into(), value_style),
    ])
}

fn audit_detail(row: &AuditRow) -> String {
    if row.policy.is_empty() {
        "-".to_string()
    } else {
        row.policy.clone()
    }
}
