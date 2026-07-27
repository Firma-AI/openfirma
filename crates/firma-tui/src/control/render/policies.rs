//! Policy pane rendering.

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    text::Line,
    widgets::{Cell, Paragraph, Row, Table},
};

use crate::control::{
    app::App,
    state::{Pane, PolicyRow},
};

use super::theme::{
    base_style, dim_style, error_style, focused_panel, header_style, selected_policy_style,
    status_label, status_style,
};

pub fn render_policies(frame: &mut Frame, area: Rect, app: &App) {
    let block = policy_panel(app);

    if let Some(error) = app.policy_error() {
        render_policy_message(
            frame,
            area,
            block,
            vec![
                Line::styled("Policy error", error_style()),
                Line::default(),
                Line::styled(error.to_string(), base_style()),
            ],
        );
        return;
    }

    if app.policies().is_empty() {
        render_policy_message(
            frame,
            area,
            block,
            vec![
                Line::styled("No policies configured.", dim_style()),
                Line::default(),
                Line::styled(
                    "Add @id(...) Cedar policies to the policy directory.",
                    dim_style(),
                ),
            ],
        );
        return;
    }

    let visible_rows = area.height.saturating_sub(3) as usize;
    let skip = app
        .selected_policy_index()
        .saturating_sub(visible_rows.saturating_sub(1));
    let rows = app
        .policies()
        .iter()
        .skip(skip)
        .take(visible_rows)
        .enumerate()
        .map(|(offset, policy)| policy_table_row(app, skip + offset, policy));

    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new([
            Cell::from(""),
            Cell::from("#"),
            Cell::from("status"),
            Cell::from("policy"),
        ])
        .style(header_style()),
    )
    .block(block)
    .column_spacing(1);

    frame.render_widget(table, area);
}

fn policy_panel(app: &App) -> ratatui::widgets::Block<'static> {
    let focused = app.selected_pane() == Pane::Policies;
    let policy_detail = format!(" {} policies ", app.policies().len());

    focused_panel("Policies", focused).title_bottom(Line::styled(policy_detail, dim_style()))
}

fn render_policy_message(
    frame: &mut Frame,
    area: Rect,
    block: ratatui::widgets::Block<'static>,
    lines: Vec<Line<'static>>,
) {
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn policy_table_row(app: &App, index: usize, policy: &PolicyRow) -> Row<'static> {
    let selected = index == app.selected_policy_index();
    let focused = app.selected_pane() == Pane::Policies;
    let indicator = if selected && focused { ">" } else { "" };
    let status = status_label(policy.status);

    let status_cell = Cell::from(status).style(status_style(policy.status));

    let row = Row::new([
        Cell::from(indicator),
        Cell::from((index + 1).to_string()).style(dim_style()),
        status_cell,
        Cell::from(policy_display_label(&policy.id)).style(base_style()),
    ]);

    if selected {
        row.style(selected_policy_style())
    } else {
        row
    }
}

fn policy_display_label(id: &str) -> String {
    id.replace('_', "-")
}
