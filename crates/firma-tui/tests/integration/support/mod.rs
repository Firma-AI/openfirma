use std::{
    cell::RefCell,
    collections::VecDeque,
    path::Path,
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};

use crossterm::event::KeyCode;
use firma_tui::control::{
    App, AuditDecision, AuditRow, ControlEffect, ControlError, ControlStatus, Event,
    TerminalEventSource,
};
use ratatui::{Terminal, backend::TestBackend};

#[derive(Debug, Default)]
pub struct FakeTerminal {
    events: RefCell<VecDeque<Event>>,
}

impl FakeTerminal {
    pub fn with_key(key: KeyCode) -> Self {
        Self::with_events([Event::Key(key)])
    }

    pub fn with_events(events: impl IntoIterator<Item = Event>) -> Self {
        Self {
            events: RefCell::new(events.into_iter().collect()),
        }
    }
}

impl TerminalEventSource for FakeTerminal {
    fn poll(&self, _timeout: Duration) -> anyhow::Result<bool> {
        Ok(!self.events.borrow().is_empty())
    }

    fn read(&self) -> anyhow::Result<Event> {
        Ok(self.events.borrow_mut().pop_front().unwrap_or(Event::Tick))
    }
}

pub fn audit_row(decision: AuditDecision, index: usize) -> AuditRow {
    AuditRow {
        time: format!("00:00:{index:02}"),
        decision,
        action_class: format!("class-{index}"),
        resource: format!("resource-{index}"),
        policy: format!("policy-{index}"),
    }
}

pub fn app_with_audit_rows() -> App {
    let mut app = App::new(None, true);
    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    app.push_audit_row(audit_row(AuditDecision::Deny, 1));
    app.push_audit_row(audit_row(AuditDecision::Allow, 2));
    app
}

pub fn audit_channel_with_rows(
    count: usize,
) -> anyhow::Result<(Sender<AuditRow>, Receiver<AuditRow>)> {
    let (tx, rx) = mpsc::channel();
    send_audit_rows(&tx, count)?;
    Ok((tx, rx))
}

pub fn send_audit_rows(tx: &Sender<AuditRow>, count: usize) -> anyhow::Result<()> {
    for index in 0..count {
        let decision = if index.is_multiple_of(2) {
            AuditDecision::Allow
        } else {
            AuditDecision::Deny
        };
        tx.send(audit_row(decision, index))?;
    }
    Ok(())
}

pub fn handle_key(app: &mut App, key: KeyCode) -> Vec<ControlEffect> {
    firma_tui::control::handle_key(app, key)
}

pub fn last_visible_audit_index(app: &App) -> usize {
    app.visible_audit_rows_len().saturating_sub(1)
}

pub fn selected_audit_resource(app: &App) -> Option<&str> {
    app.visible_audit_rows()
        .nth(app.selected_audit_index())
        .map(|row| row.resource.as_str())
}

pub fn render_text(app: &App, width: u16, height: u16) -> anyhow::Result<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend)?;
    terminal.draw(|frame| firma_tui::control::render(frame, app))?;
    Ok(terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect())
}

pub fn status_snapshot(status: &ControlStatus, expected_policy_dir: Option<&Path>) -> String {
    let policy_dir = policy_dir_snapshot(status.policy_dir.as_deref(), expected_policy_dir);
    let last_policy_error = policy_error_snapshot(status.last_policy_error.as_ref());

    format!(
        "runtime_state: {}\n\
         policy_dir: {policy_dir}\n\
         policy_count: {}\n\
         audit_connected: {}\n\
         audit_rows: {}\n\
         rewrite_queue_len: {}\n\
         pending_rewrites: {}\n\
         last_policy_error: {last_policy_error}",
        status.runtime_state.label(),
        status.policy_count,
        status.audit_connected,
        status.audit_rows,
        status.rewrite_queue_len,
        status.pending_rewrites,
    )
}

fn policy_dir_snapshot(actual: Option<&Path>, expected: Option<&Path>) -> &'static str {
    match (actual, expected) {
        (None, None) => "<none>",
        (Some(actual), Some(expected)) => {
            assert_eq!(actual, expected);
            "<policy-dir>"
        }
        (None, Some(_)) => "<missing>",
        (Some(_), None) => "<policy-dir>",
    }
}

fn policy_error_snapshot(error: Option<&ControlError>) -> &'static str {
    if error.is_some() { "present" } else { "none" }
}
