//! Shared render styles and panel helpers.

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, BorderType, Borders},
};

use crate::control::{
    state::{AuditDecision, PolicyRowStatus},
    toggle::PolicyState,
};

/// Returns a centered rectangle constrained to the available area.
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

/// Builds a standard rounded panel block.
pub fn panel(title: &'static str) -> Block<'static> {
    Block::default()
        .title_top(Line::styled(format!(" {title} "), accent_style()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(dim_style())
}

/// Builds a panel whose border reflects focus.
pub fn focused_panel(title: &'static str, focused: bool) -> Block<'static> {
    let style = if focused { accent_style() } else { dim_style() };

    Block::default()
        .title_top(Line::styled(format!(" {title} "), style))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style)
}

/// Normal foreground style for table values.
pub fn base_style() -> Style {
    Style::default().fg(Color::White)
}

/// Muted style for secondary text and borders.
pub fn dim_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// Accent style for active labels and controls.
pub fn accent_style() -> Style {
    Style::default()
        .fg(Color::LightGreen)
        .add_modifier(Modifier::BOLD)
}

/// Selected audit-row style.
pub fn selected_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::LightGreen)
        .add_modifier(Modifier::BOLD)
}

/// Selected policy-row style.
pub fn selected_policy_style() -> Style {
    Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

/// Header style for table labels.
pub fn header_style() -> Style {
    dim_style().add_modifier(Modifier::BOLD)
}

/// Error style for failed policy and runtime states.
pub fn error_style() -> Style {
    Style::default()
        .fg(Color::LightRed)
        .add_modifier(Modifier::BOLD)
}

/// Warning style for transitional runtime states.
pub fn warning_style() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

/// Returns the terminal style for a policy row status.
pub fn status_style(status: PolicyRowStatus) -> Style {
    match status {
        PolicyRowStatus::State(state) => match state {
            PolicyState::Enabled => Style::default().fg(Color::LightGreen),
            PolicyState::Disabled => dim_style(),
            PolicyState::MissingFile
            | PolicyState::MissingId
            | PolicyState::InvalidPolicy
            | PolicyState::ReadError => error_style(),
        },
        PolicyRowStatus::Queued | PolicyRowStatus::Writing => Style::default().fg(Color::Yellow),
        PolicyRowStatus::Error => error_style(),
    }
}

/// Returns the compact terminal label for a policy row status.
pub const fn status_label(status: PolicyRowStatus) -> &'static str {
    match status {
        PolicyRowStatus::State(PolicyState::Enabled) => "[ on ]",
        PolicyRowStatus::State(PolicyState::Disabled) => "[ off ]",
        PolicyRowStatus::State(PolicyState::MissingFile) => "[ missing ]",
        PolicyRowStatus::State(PolicyState::MissingId) => "[ id? ]",
        PolicyRowStatus::State(PolicyState::InvalidPolicy) => "[ invalid ]",
        PolicyRowStatus::State(PolicyState::ReadError) => "[ readerr ]",
        PolicyRowStatus::Queued => "[ queued ]",
        PolicyRowStatus::Writing => "[ writing ]",
        PolicyRowStatus::Error => "[ error ]",
    }
}

/// Returns the terminal style for an audit decision.
pub fn decision_style(decision: AuditDecision) -> Style {
    match decision {
        AuditDecision::Allow => Style::default().fg(Color::LightGreen),
        AuditDecision::Deny => Style::default().fg(Color::LightRed),
    }
}
