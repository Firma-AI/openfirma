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
    context: BindingContext,
    key: BindingKey,
    hint: BindingHint,
    action: BindingAction,
    visible: BindingVisibility,
    show_in_help: bool,
    show_in_footer: bool,
    show_in_help_footer: bool,
}

impl Binding {
    const fn new(
        context: BindingContext,
        key: BindingKey,
        hint_key: &'static str,
        label: &'static str,
        action: BindingAction,
    ) -> Self {
        Self {
            context,
            key,
            hint: BindingHint {
                key: hint_key,
                label,
            },
            action,
            visible: BindingVisibility::Always,
            show_in_help: true,
            show_in_footer: false,
            show_in_help_footer: false,
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

    const fn help_footer(mut self) -> Self {
        self.show_in_help = false;
        self.show_in_help_footer = true;
        self
    }

    const fn visible_when(mut self, visible: BindingVisibility) -> Self {
        self.visible = visible;
        self
    }

    fn is_visible(self, app: &App) -> bool {
        match self.visible {
            BindingVisibility::Always => true,
            BindingVisibility::SelectedPolicyFile => app.selected_policy_file().is_some(),
        }
    }

    fn single_command(self, app: &App, key: KeyCode) -> Option<ControlCommand> {
        match self.key {
            BindingKey::Single(binding_key) if binding_key == key => Some(self.action.command(app)),
            BindingKey::Single(_) | BindingKey::Sequence(_, _) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingContext {
    Main,
    Navigation,
    Help,
    About,
    AuditInspect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingKey {
    Single(KeyCode),
    Sequence(KeyCode, KeyCode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingAction {
    Static(ControlCommand),
    Enter,
}

impl BindingAction {
    fn command(self, app: &App) -> ControlCommand {
        match self {
            Self::Static(command) => command,
            Self::Enter => enter_command(app),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingVisibility {
    Always,
    SelectedPolicyFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SequenceCommand {
    Pending,
    Complete(ControlCommand),
}

// Context lists define both scope and search order for a key press. Navigation
// is searched before view-specific actions, so shared motions such as j, k,
// gg and G keep the same meaning when the main view and the audit
// inspector add their own local bindings.
const MAIN_CONTEXTS: &[BindingContext] = &[BindingContext::Navigation, BindingContext::Main];
const HELP_CONTEXTS: &[BindingContext] = &[BindingContext::Help];
const ABOUT_CONTEXTS: &[BindingContext] = &[BindingContext::About];
const AUDIT_INSPECT_CONTEXTS: &[BindingContext] =
    &[BindingContext::Navigation, BindingContext::AuditInspect];

// This registry is the single source for key handling and key labels. Keeping
// commands, help text, and footer hints together prevents the usual TUI drift
// where a shortcut works but the help overlay describes an older binding.
const BINDINGS: &[Binding] = &[
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Tab),
        "tab",
        "Pane",
        BindingAction::Static(ControlCommand::SwitchPane),
    )
    .footer(),
    Binding::new(
        BindingContext::Navigation,
        BindingKey::Single(KeyCode::Up),
        "up/down",
        "Move",
        BindingAction::Static(ControlCommand::MoveSelection(SelectionMovement::Up)),
    ),
    Binding::new(
        BindingContext::Navigation,
        BindingKey::Single(KeyCode::Down),
        "up/down",
        "Move",
        BindingAction::Static(ControlCommand::MoveSelection(SelectionMovement::Down)),
    ),
    Binding::new(
        BindingContext::Navigation,
        BindingKey::Single(KeyCode::Char('j')),
        "j/k",
        "Move",
        BindingAction::Static(ControlCommand::MoveSelection(SelectionMovement::Down)),
    ),
    Binding::new(
        BindingContext::Navigation,
        BindingKey::Single(KeyCode::Char('k')),
        "j/k",
        "Move",
        BindingAction::Static(ControlCommand::MoveSelection(SelectionMovement::Up)),
    ),
    Binding::new(
        BindingContext::Navigation,
        BindingKey::Sequence(KeyCode::Char('g'), KeyCode::Char('g')),
        "gg",
        "First row",
        BindingAction::Static(ControlCommand::MoveSelection(SelectionMovement::First)),
    ),
    Binding::new(
        BindingContext::Navigation,
        BindingKey::Single(KeyCode::Char('G')),
        "G",
        "Last row",
        BindingAction::Static(ControlCommand::MoveSelection(SelectionMovement::Last)),
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char(' ')),
        "space",
        "Toggle",
        BindingAction::Static(ControlCommand::ToggleSelectedPolicy),
    )
    .footer(),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Enter),
        "enter",
        "Toggle/Inspect",
        BindingAction::Enter,
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('t')),
        "t",
        "Toggle all",
        BindingAction::Static(ControlCommand::ToggleAllPolicies),
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('e')),
        "e",
        "Edit policy",
        BindingAction::Static(ControlCommand::OpenPolicySource),
    )
    .visible_when(BindingVisibility::SelectedPolicyFile),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('i')),
        "i",
        "Inspect",
        BindingAction::Static(ControlCommand::InspectAuditRow),
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('a')),
        "a",
        "All decisions",
        BindingAction::Static(ControlCommand::SetAuditFilter(AuditFilter::All)),
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('d')),
        "d",
        "Denied only",
        BindingAction::Static(ControlCommand::SetAuditFilter(AuditFilter::Deny)),
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('l')),
        "l",
        "Allowed only",
        BindingAction::Static(ControlCommand::SetAuditFilter(AuditFilter::Allow)),
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('o')),
        "o",
        "About",
        BindingAction::Static(ControlCommand::ToggleAbout),
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('h')),
        "h",
        "Help",
        BindingAction::Static(ControlCommand::ToggleHelp),
    )
    .hidden()
    .footer(),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('?')),
        "?",
        "Help",
        BindingAction::Static(ControlCommand::ToggleHelp),
    )
    .hidden(),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Char('q')),
        "q",
        "Quit",
        BindingAction::Static(ControlCommand::Quit),
    ),
    Binding::new(
        BindingContext::Main,
        BindingKey::Single(KeyCode::Esc),
        "esc",
        "Quit",
        BindingAction::Static(ControlCommand::Quit),
    )
    .hidden(),
    Binding::new(
        BindingContext::Help,
        BindingKey::Single(KeyCode::Char('h')),
        "h/?",
        "Close",
        BindingAction::Static(ControlCommand::CloseHelp),
    )
    .help_footer(),
    Binding::new(
        BindingContext::Help,
        BindingKey::Single(KeyCode::Char('?')),
        "h/?",
        "Close",
        BindingAction::Static(ControlCommand::CloseHelp),
    )
    .help_footer(),
    Binding::new(
        BindingContext::Help,
        BindingKey::Single(KeyCode::Esc),
        "esc",
        "Close",
        BindingAction::Static(ControlCommand::CloseHelp),
    )
    .help_footer(),
    Binding::new(
        BindingContext::Help,
        BindingKey::Single(KeyCode::Char('q')),
        "q",
        "Quit",
        BindingAction::Static(ControlCommand::Quit),
    )
    .help_footer(),
    Binding::new(
        BindingContext::About,
        BindingKey::Single(KeyCode::Char('o')),
        "o",
        "Close",
        BindingAction::Static(ControlCommand::CloseAbout),
    )
    .hidden(),
    Binding::new(
        BindingContext::About,
        BindingKey::Single(KeyCode::Esc),
        "esc",
        "Close",
        BindingAction::Static(ControlCommand::CloseAbout),
    )
    .hidden(),
    Binding::new(
        BindingContext::About,
        BindingKey::Single(KeyCode::Char('q')),
        "q",
        "Quit",
        BindingAction::Static(ControlCommand::Quit),
    )
    .hidden(),
    Binding::new(
        BindingContext::AuditInspect,
        BindingKey::Single(KeyCode::Esc),
        "esc",
        "Close",
        BindingAction::Static(ControlCommand::CloseAuditInspect),
    )
    .hidden(),
    Binding::new(
        BindingContext::AuditInspect,
        BindingKey::Single(KeyCode::Enter),
        "enter",
        "Close",
        BindingAction::Static(ControlCommand::CloseAuditInspect),
    )
    .hidden(),
    Binding::new(
        BindingContext::AuditInspect,
        BindingKey::Single(KeyCode::Char('i')),
        "i",
        "Close",
        BindingAction::Static(ControlCommand::CloseAuditInspect),
    )
    .hidden(),
    Binding::new(
        BindingContext::AuditInspect,
        BindingKey::Single(KeyCode::Char('q')),
        "q",
        "Quit",
        BindingAction::Static(ControlCommand::Quit),
    )
    .hidden(),
    Binding::new(
        BindingContext::AuditInspect,
        BindingKey::Single(KeyCode::Char('a')),
        "a",
        "All decisions",
        BindingAction::Static(ControlCommand::SetAuditFilter(AuditFilter::All)),
    )
    .hidden(),
    Binding::new(
        BindingContext::AuditInspect,
        BindingKey::Single(KeyCode::Char('d')),
        "d",
        "Denied only",
        BindingAction::Static(ControlCommand::SetAuditFilter(AuditFilter::Deny)),
    )
    .hidden(),
    Binding::new(
        BindingContext::AuditInspect,
        BindingKey::Single(KeyCode::Char('l')),
        "l",
        "Allowed only",
        BindingAction::Static(ControlCommand::SetAuditFilter(AuditFilter::Allow)),
    )
    .hidden(),
];

/// Converts a key press into the command for the active UI context.
///
/// The active overlay decides which bindings are valid. A pending `g` prefix
/// is only kept when it can still become `gg`; unrelated keys clear it.
#[must_use]
pub fn command_for_key(app: &mut App, key: KeyCode) -> Option<ControlCommand> {
    let contexts = active_contexts(app);
    if let Some(command) = sequence_command(app, contexts, key) {
        return match command {
            SequenceCommand::Pending => None,
            SequenceCommand::Complete(command) => Some(command),
        };
    }

    let command = contexts
        .iter()
        .find_map(|context| single_command(app, *context, key));
    if key != KeyCode::Char('g') {
        app.clear_g_prefix();
    }

    command
}

/// Returns the binding rows shown in the help overlay.
#[must_use]
pub fn help_entries(app: &App) -> Vec<BindingHint> {
    visible_hints(app, |binding| binding.show_in_help)
}

/// Returns the compact binding rows shown in the bottom footer.
#[must_use]
pub fn footer_entries(app: &App) -> Vec<BindingHint> {
    visible_hints(app, |binding| binding.show_in_footer)
}

/// Returns the footer rows used while the help overlay is open.
#[must_use]
pub fn help_footer_entries(app: &App) -> Vec<BindingHint> {
    visible_hints(app, |binding| binding.show_in_help_footer)
}

fn active_contexts(app: &App) -> &'static [BindingContext] {
    if app.about_visible() {
        ABOUT_CONTEXTS
    } else if app.help_visible() {
        HELP_CONTEXTS
    } else if app.audit_inspect_visible() {
        AUDIT_INSPECT_CONTEXTS
    } else {
        MAIN_CONTEXTS
    }
}

fn single_command(app: &App, context: BindingContext, key: KeyCode) -> Option<ControlCommand> {
    BINDINGS
        .iter()
        .copied()
        .filter(|binding| binding.context == context && binding.is_visible(app))
        .find_map(|binding| binding.single_command(app, key))
}

fn sequence_command(
    app: &mut App,
    contexts: &[BindingContext],
    key: KeyCode,
) -> Option<SequenceCommand> {
    let binding = BINDINGS
        .iter()
        .copied()
        .find(|binding| binding.matches_sequence_prefix(contexts, key))?;
    let BindingKey::Sequence(_, second_key) = binding.key else {
        return None;
    };

    if app.take_g_prefix() && second_key == key {
        Some(SequenceCommand::Complete(binding.action.command(app)))
    } else {
        app.start_g_prefix();
        Some(SequenceCommand::Pending)
    }
}

impl Binding {
    fn matches_sequence_prefix(self, contexts: &[BindingContext], key: KeyCode) -> bool {
        contexts.contains(&self.context)
            && matches!(self.key, BindingKey::Sequence(first, _) if first == key)
    }
}

fn enter_command(app: &App) -> ControlCommand {
    match app.selected_pane() {
        crate::control::state::Pane::Policies => ControlCommand::ToggleSelectedPolicy,
        crate::control::state::Pane::Audit => ControlCommand::InspectAuditRow,
    }
}

fn visible_hints(app: &App, include: fn(Binding) -> bool) -> Vec<BindingHint> {
    let mut hints = Vec::new();
    for binding in BINDINGS.iter().copied() {
        if include(binding) && binding.is_visible(app) && !hints.contains(&binding.hint) {
            hints.push(binding.hint);
        }
    }
    hints
}
