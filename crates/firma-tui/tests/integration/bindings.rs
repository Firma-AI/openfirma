use crate::support::{app_with_audit_rows, handle_key};
use crossterm::event::KeyCode;
use firma_tui::control::{
    App, AuditFilter, BindingHint, ControlCommand, SelectionMovement, command_for_key,
    footer_entries,
};

#[test]
fn keys_map_to_commands() {
    let mut app = App::default();

    assert_eq!(
        command_for_key(&mut app, KeyCode::Tab),
        Some(ControlCommand::SwitchPane)
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Up),
        Some(ControlCommand::MoveSelection(SelectionMovement::Up))
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Down),
        Some(ControlCommand::MoveSelection(SelectionMovement::Down))
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('j')),
        Some(ControlCommand::MoveSelection(SelectionMovement::Down))
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('k')),
        Some(ControlCommand::MoveSelection(SelectionMovement::Up))
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('G')),
        Some(ControlCommand::MoveSelection(SelectionMovement::Last))
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char(' ')),
        Some(ControlCommand::ToggleSelectedPolicy)
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('t')),
        Some(ControlCommand::ToggleAllPolicies)
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('a')),
        Some(ControlCommand::SetAuditFilter(AuditFilter::All))
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('d')),
        Some(ControlCommand::SetAuditFilter(AuditFilter::Deny))
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('l')),
        Some(ControlCommand::SetAuditFilter(AuditFilter::Allow))
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('q')),
        Some(ControlCommand::Quit)
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Esc),
        Some(ControlCommand::Quit)
    );
}

#[test]
fn gg_is_a_two_key_sequence() {
    let mut app = App::default();

    assert_eq!(command_for_key(&mut app, KeyCode::Char('g')), None);
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('g')),
        Some(ControlCommand::MoveSelection(SelectionMovement::First))
    );
}

#[test]
fn unrelated_key_clears_pending_sequence() {
    let mut app = App::default();

    assert_eq!(command_for_key(&mut app, KeyCode::Char('g')), None);
    assert_eq!(command_for_key(&mut app, KeyCode::Char('x')), None);
    assert_eq!(command_for_key(&mut app, KeyCode::Char('g')), None);
}

#[test]
fn help_context_uses_close_bindings() {
    let mut app = App::default();
    app.toggle_help();

    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('h')),
        Some(ControlCommand::CloseHelp)
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('?')),
        Some(ControlCommand::CloseHelp)
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Esc),
        Some(ControlCommand::CloseHelp)
    );
    assert_eq!(
        command_for_key(&mut app, KeyCode::Char('q')),
        Some(ControlCommand::Quit)
    );
    assert_eq!(command_for_key(&mut app, KeyCode::Char('j')), None);
}

#[test]
fn footer_entries_stay_small() {
    let app = App::default();

    assert_eq!(
        footer_entries(&app),
        vec![
            BindingHint {
                key: "tab",
                label: "Pane",
            },
            BindingHint {
                key: "space",
                label: "Toggle",
            },
            BindingHint {
                key: "h",
                label: "Help",
            },
        ]
    );
}

#[test]
fn footer_entries_follow_active_context() {
    let mut help_app = App::default();
    help_app.toggle_help();
    assert_eq!(footer_entries(&help_app), Vec::<BindingHint>::new());

    let mut about_app = App::default();
    handle_key(&mut about_app, KeyCode::Char('o'));
    assert_eq!(footer_entries(&about_app), Vec::<BindingHint>::new());

    let mut inspect_app = app_with_audit_rows();
    inspect_app.switch_pane();
    handle_key(&mut inspect_app, KeyCode::Char('i'));
    assert_eq!(footer_entries(&inspect_app), Vec::<BindingHint>::new());
}
