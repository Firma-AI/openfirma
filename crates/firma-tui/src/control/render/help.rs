//! Help overlay and footer key hint rendering.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
};

use crate::control::{
    app::App,
    bindings::{self, BindingHint},
};

use super::theme::{accent_style, base_style, centered_popup, dim_style, panel};

/// Renders the key binding help overlay.
pub fn render_help(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let entries = bindings::help_entries(app);
    let footer = bindings::help_footer_entries(app);
    let key_width = help_key_width(&entries);
    let label_width = help_label_width(&entries);
    let cell_width = help_cell_width(key_width, label_width);
    let columns = help_columns(area, cell_width, entries.len());
    let rows = entries.len().div_ceil(columns);

    let mut body = Vec::with_capacity(rows.saturating_add(2));
    for row in 0..rows {
        let mut spans = Vec::new();
        for column in 0..columns {
            let index = row * columns + column;
            if let Some(entry) = entries.get(index) {
                spans.extend(help_cell(entry, key_width, label_width));
            }
        }
        body.push(Line::from(spans));
    }
    body.push(Line::default());
    body.push(help_footer(&footer));

    let width = help_width(cell_width, columns, &footer);
    let area = centered_popup(area, width, body.len().saturating_add(2));

    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(body)
            .block(panel("Help"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Renders compact key hints for the outer frame footer.
pub fn key_hints(app: &App) -> Line<'static> {
    let entries = bindings::footer_entries(app);
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

fn help_columns(area: Rect, cell_width: usize, count: usize) -> usize {
    let available = usize::from(area.width.saturating_sub(4));
    (available / cell_width.max(1))
        .clamp(1, 3)
        .min(count.max(1))
}

fn help_width(cell_width: usize, columns: usize, footer: &[BindingHint]) -> usize {
    let grid_width = 2 + cell_width.saturating_mul(columns);
    grid_width.max(help_footer_width(footer))
}

fn help_key_width(entries: &[BindingHint]) -> usize {
    entries
        .iter()
        .map(|entry| entry.key.chars().count())
        .max()
        .unwrap_or(0)
        .max(3)
}

fn help_label_width(entries: &[BindingHint]) -> usize {
    entries
        .iter()
        .map(|entry| entry.label.chars().count())
        .max()
        .unwrap_or(0)
}

fn help_cell_width(key_width: usize, label_width: usize) -> usize {
    1 + key_width + 1 + label_width + 2
}

fn help_cell(entry: &BindingHint, key_width: usize, label_width: usize) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {:<key_width$} ", entry.key, key_width = key_width),
            accent_style(),
        ),
        Span::styled(
            format!("{:<label_width$}  ", entry.label, label_width = label_width),
            base_style(),
        ),
    ]
}

fn help_footer(entries: &[BindingHint]) -> Line<'static> {
    let mut spans = Vec::with_capacity(entries.len().saturating_mul(5).saturating_add(2));
    spans.push(Span::styled(" ", dim_style()));
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" ", dim_style()));
        }
        spans.push(Span::styled("[", dim_style()));
        spans.push(Span::styled(entry.key, accent_style()));
        spans.push(Span::styled("] ", dim_style()));
        spans.push(Span::styled(entry.label, dim_style()));
    }
    spans.push(Span::styled(" ", dim_style()));
    Line::from(spans)
}

fn help_footer_width(entries: &[BindingHint]) -> usize {
    let item_width: usize = entries
        .iter()
        .map(|entry| 1 + entry.key.chars().count() + 2 + entry.label.chars().count())
        .sum();
    item_width
        .saturating_add(entries.len().saturating_sub(1))
        .saturating_add(2)
}
