//! Policies pane rendering.

use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Paragraph, Wrap},
};

use crate::control::{app::App, state::Pane};

use super::theme::focused_panel;

pub fn render_policies(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let text = app.policy_dir().map_or_else(String::new, |path| {
        format!("policy dir: {}", path.display())
    });
    let block = focused_panel("Policies", app.selected_pane() == Pane::Policies);
    frame.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: true }),
        area,
    );
}
