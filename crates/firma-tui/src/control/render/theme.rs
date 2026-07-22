//! Shared render styles and panel helpers.

use ratatui::{
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, BorderType, Borders},
};

pub fn focused_panel(title: &'static str, focused: bool) -> Block<'static> {
    let style = if focused { accent_style() } else { dim_style() };

    Block::default()
        .title_top(Line::styled(format!(" {title} "), style))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style)
}

pub fn dim_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn accent_style() -> Style {
    Style::default()
        .fg(Color::LightGreen)
        .add_modifier(Modifier::BOLD)
}

pub fn warning_style() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}
