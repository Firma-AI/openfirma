//! Shared render styles and panel helpers.

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, BorderType, Borders},
};

/// Returns a centered rectangle capped to the available area.
pub fn centered_popup(area: Rect, width: usize, height: usize) -> Rect {
    let width = u16::try_from(width).unwrap_or(u16::MAX).min(area.width);
    let height = u16::try_from(height).unwrap_or(u16::MAX).min(area.height);

    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

/// Standard unfocused panel block.
pub fn panel(title: &'static str) -> Block<'static> {
    Block::default()
        .title_top(Line::styled(format!(" {title} "), accent_style()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(dim_style())
}

/// Panel block whose border reflects focus.
pub fn focused_panel(title: &'static str, focused: bool) -> Block<'static> {
    let style = if focused { accent_style() } else { dim_style() };

    Block::default()
        .title_top(Line::styled(format!(" {title} "), style))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style)
}

/// Low-emphasis text and border style.
pub fn dim_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// Normal table text style.
pub fn base_style() -> Style {
    Style::default().fg(Color::Gray)
}

/// Accent style used for focused labels and active controls.
pub fn accent_style() -> Style {
    Style::default()
        .fg(Color::LightGreen)
        .add_modifier(Modifier::BOLD)
}

/// Header text style.
pub fn header_style() -> Style {
    Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

/// Style for an audit decision label.
pub fn decision_style(decision: crate::control::AuditDecision) -> Style {
    match decision {
        crate::control::AuditDecision::Allow => Style::default().fg(Color::LightGreen),
        crate::control::AuditDecision::Deny => Style::default().fg(Color::LightRed),
    }
}

/// Style applied to a selected row while its pane is focused.
pub fn selected_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::LightGreen)
        .add_modifier(Modifier::BOLD)
}

/// Warning style used for non-running runtime labels.
pub fn warning_style() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}
