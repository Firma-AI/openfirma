//! Key binding registry for the control surface.

use crossterm::event::KeyCode;

use crate::control::{
    app::App,
    command::{ControlCommand, SelectionMovement},
    state::AuditFilter,
};

/// Text shown for one key binding in the footer or help overlay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingHint {
    /// Key label as rendered in the UI.
    pub key: &'static str,
    /// Short action label paired with the key.
    pub label: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    key: BindingKey,
    hint: BindingHint,
    action: ControlCommand,
    show_in_help: bool,
    show_in_footer: bool,
}

impl Binding {
    const fn new(
        key: BindingKey,
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
            show_in_help: true,
            show_in_footer: false,
        }
    }

    const fn hidden(mut self) -> Self {
        self.show_in_help = false;
        self
    }

    const fn footer(mut self) -> Self {
        self.show_in_footer = true;
        self
    }

    fn single_command(self, key: KeyCode) -> Option<ControlCommand> {
        match self.key {
            BindingKey::Single(binding_key) if binding_key == key => Some(self.action),
            BindingKey::Single(_) | BindingKey::Sequence(_, _) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingKey {
    Single(KeyCode),
    Sequence(KeyCode, KeyCode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SequenceCommand {
    Pending,
    Complete(ControlCommand),
}

const BINDINGS: &[Binding] = &[
    Binding::new(
        BindingKey::Single(KeyCode::Tab),
        "tab",
        "Pane",
        ControlCommand::SwitchPane,
    )
    .footer(),
    Binding::new(
        BindingKey::Single(KeyCode::Up),
        "up/down",
        "Move",
        ControlCommand::MoveSelection(SelectionMovement::Up),
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Down),
        "up/down",
        "Move",
        ControlCommand::MoveSelection(SelectionMovement::Down),
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Char('j')),
        "j/k",
        "Move",
        ControlCommand::MoveSelection(SelectionMovement::Down),
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Char('k')),
        "j/k",
        "Move",
        ControlCommand::MoveSelection(SelectionMovement::Up),
    ),
    Binding::new(
        BindingKey::Sequence(KeyCode::Char('g'), KeyCode::Char('g')),
        "gg",
        "First row",
        ControlCommand::MoveSelection(SelectionMovement::First),
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Char('G')),
        "G",
        "Last row",
        ControlCommand::MoveSelection(SelectionMovement::Last),
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Char('a')),
        "a",
        "All",
        ControlCommand::SetAuditFilter(AuditFilter::All),
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Char('d')),
        "d",
        "Deny",
        ControlCommand::SetAuditFilter(AuditFilter::Deny),
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Char('l')),
        "l",
        "Allow",
        ControlCommand::SetAuditFilter(AuditFilter::Allow),
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Char('h')),
        "h",
        "Help",
        ControlCommand::ToggleHelp,
    )
    .hidden()
    .footer(),
    Binding::new(
        BindingKey::Single(KeyCode::Char('?')),
        "?",
        "Help",
        ControlCommand::ToggleHelp,
    )
    .hidden(),
    Binding::new(
        BindingKey::Single(KeyCode::Char('q')),
        "q",
        "Quit",
        ControlCommand::Quit,
    ),
    Binding::new(
        BindingKey::Single(KeyCode::Esc),
        "esc",
        "Quit",
        ControlCommand::Quit,
    ),
];

/// Resolves a key into a command for the current app context.
///
/// Multi-key prefixes are tracked on the app so `gg` can be recognized without
/// making the event pump aware of binding state.
#[must_use]
pub fn command_for_key(app: &mut App, key: KeyCode) -> Option<ControlCommand> {
    if app.help_visible() {
        app.clear_g_prefix();
        return help_command_for_key(key);
    }

    if let Some(command) = sequence_command(app, key) {
        return match command {
            SequenceCommand::Pending => None,
            SequenceCommand::Complete(command) => Some(command),
        };
    }

    let command = BINDINGS
        .iter()
        .find_map(|binding| binding.single_command(key));
    if key != KeyCode::Char('g') {
        app.clear_g_prefix();
    }

    command
}

/// Bindings rendered in the help overlay.
#[must_use]
pub fn help_entries(_app: &App) -> Vec<BindingHint> {
    BINDINGS
        .iter()
        .filter(|binding| binding.show_in_help)
        .map(|binding| binding.hint)
        .collect()
}

/// Bindings rendered in the bottom footer.
#[must_use]
pub fn footer_entries(_app: &App) -> Vec<BindingHint> {
    BINDINGS
        .iter()
        .filter(|binding| binding.show_in_footer)
        .map(|binding| binding.hint)
        .collect()
}

/// Footer bindings shown while the help overlay is open.
#[must_use]
pub fn help_footer_entries(_app: &App) -> Vec<BindingHint> {
    vec![
        BindingHint {
            key: "h/?",
            label: "Close",
        },
        BindingHint {
            key: "esc",
            label: "Close",
        },
        BindingHint {
            key: "q",
            label: "Quit",
        },
    ]
}

fn help_command_for_key(key: KeyCode) -> Option<ControlCommand> {
    match key {
        KeyCode::Char('h' | '?') | KeyCode::Esc => Some(ControlCommand::CloseHelp),
        KeyCode::Char('q') => Some(ControlCommand::Quit),
        _ => None,
    }
}

fn sequence_command(app: &mut App, key: KeyCode) -> Option<SequenceCommand> {
    let binding = BINDINGS
        .iter()
        .copied()
        .find(|binding| binding.matches_sequence_prefix(key))?;
    let BindingKey::Sequence(_, second_key) = binding.key else {
        return None;
    };

    if app.take_g_prefix() && second_key == key {
        Some(SequenceCommand::Complete(binding.action))
    } else {
        app.start_g_prefix();
        Some(SequenceCommand::Pending)
    }
}

impl Binding {
    fn matches_sequence_prefix(self, key: KeyCode) -> bool {
        matches!(self.key, BindingKey::Sequence(first, _) if first == key)
    }
}
