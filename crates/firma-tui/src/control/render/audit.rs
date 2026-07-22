//! Audit pane rendering.

use ratatui::{Frame, layout::Rect, widgets::Paragraph};

use crate::control::{app::App, state::Pane};

use super::theme::focused_panel;

pub fn render_audit(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let block = focused_panel("Audit", app.selected_pane() == Pane::Audit);
    frame.render_widget(Paragraph::new("").block(block), area);
}
