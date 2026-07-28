use std::{
    cell::RefCell,
    collections::VecDeque,
    fs,
    path::Path,
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};

use crossterm::event::KeyCode;
use firma_tui::control::{
    App, AuditDecision, AuditRow, ControlError, ControlStatus, Event, PolicyRowStatus,
    TerminalEventSource,
};
use ratatui::{Terminal, backend::TestBackend};

pub const DEFAULT_POLICY_SOURCE: &str = r#"
@id("first_policy")
permit (
    principal,
    action,
    resource
);

@id("second_policy")
permit (
    principal,
    action,
    resource
) when { false }; // openfirma-control:disabled

@id("third_policy")
permit (
    principal,
    action,
    resource
);
"#;

pub const OTHER_POLICY_SOURCE: &str = r#"
@id("fourth_policy")
permit (
    principal,
    action,
    resource
) when { false }; // openfirma-control:disabled
"#;

pub fn permit_policy(id: &str) -> String {
    format!(
        r#"
@id("{id}")
permit (
    principal,
    action,
    resource
);
"#
    )
}

#[derive(Default)]
pub struct FakeTerminal {
    events: RefCell<VecDeque<Event>>,
}

impl FakeTerminal {
    pub fn new(events: impl IntoIterator<Item = Event>) -> Self {
        Self {
            events: RefCell::new(events.into_iter().collect()),
        }
    }

    pub fn with_events(events: impl IntoIterator<Item = Event>) -> Self {
        Self::new(events)
    }

    pub fn with_key(key: KeyCode) -> Self {
        Self::new([Event::Key(key)])
    }
}

impl TerminalEventSource for FakeTerminal {
    fn poll(&self, _timeout: Duration) -> anyhow::Result<bool> {
        Ok(!self.events.borrow().is_empty())
    }

    fn read(&self) -> anyhow::Result<Event> {
        self.events
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("terminal event queue is empty"))
    }
}

pub fn audit_row(decision: AuditDecision, index: usize) -> AuditRow {
    AuditRow {
        time: format!("00:00:{index:02}"),
        decision,
        action_class: format!("class-{index}"),
        resource: format!("resource-{index}"),
        policy: String::new(),
    }
}

pub fn app_with_audit_rows() -> App {
    let mut app = App::default();
    app.push_audit_row(audit_row(AuditDecision::Allow, 0));
    app.push_audit_row(audit_row(AuditDecision::Deny, 1));
    app.push_audit_row(audit_row(AuditDecision::Allow, 2));
    app
}

pub fn audit_channel() -> (mpsc::Sender<AuditRow>, mpsc::Receiver<AuditRow>) {
    mpsc::channel()
}

pub fn app_with_default_policies() -> anyhow::Result<(tempfile::TempDir, App)> {
    app_with_policy_files(&[("policies.cedar", DEFAULT_POLICY_SOURCE)])
}

pub fn app_with_policy_files(files: &[(&str, &str)]) -> anyhow::Result<(tempfile::TempDir, App)> {
    let temp = tempfile::tempdir()?;
    for (name, source) in files {
        fs::write(temp.path().join(name), source)?;
    }
    let app = App::new(Some(temp.path().to_path_buf()), false);

    assert_eq!(app.policy_error(), None);
    assert_eq!(
        app.policies().len(),
        files
            .iter()
            .map(|(_, source)| source.matches("@id(").count())
            .sum::<usize>()
    );

    Ok((temp, app))
}

pub fn audit_channel_with_rows(
    count: usize,
) -> anyhow::Result<(Sender<AuditRow>, Receiver<AuditRow>)> {
    let (tx, rx) = audit_channel();
    send_audit_rows(&tx, count)?;
    Ok((tx, rx))
}

pub fn send_audit_rows(tx: &Sender<AuditRow>, count: usize) -> anyhow::Result<()> {
    for index in 0..count {
        tx.send(indexed_audit_row(index))?;
    }
    Ok(())
}

pub fn indexed_audit_row(index: usize) -> AuditRow {
    let decision = if index.is_multiple_of(2) {
        AuditDecision::Allow
    } else {
        AuditDecision::Deny
    };
    audit_row(decision, index)
}

pub fn handle_key(app: &mut App, key: KeyCode) {
    let _outcome = firma_tui::control::handle_key(app, key);
}

pub fn last_visible_audit_index(app: &App) -> usize {
    app.visible_audit_rows_len().saturating_sub(1)
}

pub fn selected_audit_resource(app: &App) -> Option<&str> {
    app.visible_audit_rows()
        .nth(app.selected_audit_index())
        .map(|row| row.resource.as_str())
}

pub fn policy_status(app: &App, id: &str) -> Option<PolicyRowStatus> {
    app.policies()
        .iter()
        .find(|policy| policy.id == id)
        .map(|policy| policy.status)
}

pub fn write_named_policy_file(
    dir: &Path,
    name: &str,
    source: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let policy_path = dir.join(name);
    fs::write(&policy_path, source)?;
    Ok(policy_path)
}

pub fn write_policy_file(dir: &Path, source: &str) -> anyhow::Result<std::path::PathBuf> {
    write_named_policy_file(dir, "policies.cedar", source)
}

pub fn temp_policy_file(source: &str) -> anyhow::Result<(tempfile::TempDir, std::path::PathBuf)> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), source)?;
    Ok((temp, policy_path))
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
