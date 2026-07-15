//! About overlay for Policy Control metadata.
//!
//! The about view is intentionally static. It reports build and project
//! metadata that is useful while the TUI is running, while runtime state stays
//! in the main frame and status model.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
};

use super::theme::{accent_style, base_style, dim_style, panel};

pub fn render_about(frame: &mut Frame, area: Rect) {
    let lines = about_lines();
    let area = about_area(area, &lines);

    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel("About"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn about_area(area: Rect, lines: &[Line<'static>]) -> Rect {
    let content_width = lines.iter().map(Line::width).max().unwrap_or(0);
    let width = u16::try_from(content_width)
        .unwrap_or(u16::MAX)
        .saturating_add(3)
        .min(area.width);
    let height = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2)
        .min(area.height);

    Rect {
        x: area.x.saturating_add(area.width.saturating_sub(width) / 2),
        y: area
            .y
            .saturating_add(area.height.saturating_sub(height) / 2),
        width,
        height,
    }
}

fn about_lines() -> Vec<Line<'static>> {
    vec![
        about_field("", "OPENFIRMA", accent_style()),
        Line::styled(" Policy Control", dim_style()),
        Line::default(),
        about_field("Version", env!("CARGO_PKG_VERSION"), base_style()),
        about_field("Crate", env!("CARGO_PKG_NAME"), base_style()),
        about_field("License", env!("CARGO_PKG_LICENSE"), base_style()),
        about_field("Repo", env!("CARGO_PKG_REPOSITORY"), base_style()),
        Line::default(),
        Line::from(vec![
            Span::styled(" [", dim_style()),
            Span::styled("o", accent_style()),
            Span::styled("] close  [", dim_style()),
            Span::styled("esc", accent_style()),
            Span::styled("] close ", dim_style()),
        ]),
    ]
}

fn about_field(label: &'static str, value: &'static str, value_style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {label:<8}"), dim_style()),
        Span::styled(value, value_style),
    ])
}
