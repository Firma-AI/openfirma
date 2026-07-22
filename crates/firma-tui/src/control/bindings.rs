//! Key binding registry for the control surface.

use crossterm::event::KeyCode;

use crate::control::{app::App, command::ControlCommand};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingHint {
    pub key: &'static str,
    pub label: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    key: KeyCode,
    hint: BindingHint,
    action: ControlCommand,
    show_in_footer: bool,
}

impl Binding {
    const fn new(
        key: KeyCode,
        hint_key: &'static str,
        label: &'static str,
        action: ControlCommand,
    ) -> Self {
        Self {
            key,
            hint: BindingHint {
                key: hint_key,
                label,
            },
            action,
            show_in_footer: false,
        }
    }

    const fn footer(mut self) -> Self {
        self.show_in_footer = true;
        self
    }

    fn command(self, key: KeyCode) -> Option<ControlCommand> {
        if key == self.key {
            Some(self.action)
        } else {
            None
        }
    }
}

const BINDINGS: &[Binding] = &[
    Binding::new(KeyCode::Char('q'), "q", "Quit", ControlCommand::Quit).footer(),
    Binding::new(KeyCode::Esc, "esc", "Quit", ControlCommand::Quit),
];

#[must_use]
pub fn command_for_key(_app: &App, key: KeyCode) -> Option<ControlCommand> {
    BINDINGS.iter().find_map(|binding| binding.command(key))
}

#[must_use]
pub fn footer_entries(_app: &App) -> Vec<BindingHint> {
    BINDINGS
        .iter()
        .filter(|binding| binding.show_in_footer)
        .map(|binding| binding.hint)
        .collect()
}
