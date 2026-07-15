//! Key handling for Policy Control.

use crossterm::event::KeyCode;

use crate::control::{
    app::App,
    bindings,
    command::{ControlCommand, ControlEffect},
};

/// Applies the command represented by a key press.
///
/// Keys that do not map to a command in the current UI context leave the app
/// unchanged and return no effects.
#[must_use]
pub fn handle_key(app: &mut App, key: KeyCode) -> Vec<ControlEffect> {
    command_for_key(app, key).map_or_else(Vec::new, |command| command.apply(app))
}

/// Converts a key press into a command for the current application state.
#[must_use]
pub fn command_for_key(app: &mut App, key: KeyCode) -> Option<ControlCommand> {
    bindings::command_for_key(app, key)
}
