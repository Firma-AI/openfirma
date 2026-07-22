//! Key handling for Policy Control.

use crossterm::event::KeyCode;

use crate::control::{
    app::App,
    bindings,
    command::{ControlCommand, ControlEffect},
};

#[must_use]
pub fn command_for_key(app: &App, key: KeyCode) -> Option<ControlCommand> {
    bindings::command_for_key(app, key)
}

#[must_use]
pub fn handle_key(app: &mut App, key: KeyCode) -> Vec<ControlEffect> {
    command_for_key(app, key)
        .map(|command| command.apply(app))
        .unwrap_or_default()
}
