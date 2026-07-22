//! Audit pane rendering.

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table},
};

use crate::control::{
    app::App,
    state::{AuditFilter, AuditRow, AuditViewportMode, Pane},
};

use super::theme::{
    accent_style, base_style, decision_style, dim_style, focused_panel, header_style,
    selected_style,
};

/// Renders the audit pane using the current filter and viewport mode.
pub fn render_audit(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let block = audit_panel(app);
    let visible_count = app.visible_audit_rows_len();

    if app.audit_rows_len() == 0 {
        render_audit_message(
            frame,
            area,
            block,
            vec![Line::styled("No audit events buffered.", dim_style())],
        );
        return;
    }

    if visible_count == 0 {
        render_audit_message(
            frame,
            area,
            block,
            vec![Line::styled(
                "No audit events match this filter.",
                dim_style(),
            )],
        );
        return;
    }

    let visible_rows = area.height.saturating_sub(3) as usize;
    let skip = match app.audit_viewport_mode() {
        AuditViewportMode::FollowTail => visible_count.saturating_sub(visible_rows),
        AuditViewportMode::Manual => app
            .selected_audit_index()
            .saturating_sub(visible_rows.saturating_sub(1)),
    };

    let rows = app
        .visible_audit_rows()
        .skip(skip)
        .take(visible_rows)
        .enumerate()
        .map(|(offset, row)| audit_table_row(app, skip + offset, row));

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(30),
            Constraint::Min(8),
        ],
    )
    .header(
        Row::new([
            Cell::from("time"),
            Cell::from("dec"),
            Cell::from("class"),
            Cell::from("resource"),
        ])
        .style(header_style()),
    )
    .block(block)
    .column_spacing(1);

    frame.render_widget(table, area);
}

fn filter_line(selected: AuditFilter) -> Line<'static> {
    let mut spans = Vec::new();
    spans.push(Span::styled(" Filter:", dim_style()));
    for filter in AuditFilter::ALL {
        let style = if filter == selected {
            accent_style()
        } else {
            dim_style()
        };
        spans.push(Span::styled(format!(" {} ", filter.label()), style));
    }

    Line::from(spans)
}

fn audit_panel(app: &App) -> ratatui::widgets::Block<'static> {
    let focused = app.selected_pane() == Pane::Audit;
    let audit_detail = format!(" {} shown ", app.visible_audit_rows_len());

    focused_panel("Audit", focused)
        .title_top(filter_line(app.audit_filter()).right_aligned())
        .title_bottom(Line::styled(audit_detail, dim_style()))
}

fn render_audit_message(
    frame: &mut Frame<'_>,
    area: Rect,
    block: ratatui::widgets::Block<'static>,
    lines: Vec<Line<'static>>,
) {
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn audit_table_row(app: &App, index: usize, row: &AuditRow) -> Row<'static> {
    let selected = index == app.selected_audit_index();
    let focused = app.selected_pane() == Pane::Audit;
    let row = Row::new([
        Cell::from(row.time.clone()).style(dim_style()),
        Cell::from(row.decision.label()).style(decision_style(row.decision)),
        Cell::from(row.action_class.clone()).style(base_style()),
        Cell::from(row.resource.clone()).style(dim_style()),
    ]);

    if selected && focused {
        row.style(selected_style())
    } else {
        row
    }
}
