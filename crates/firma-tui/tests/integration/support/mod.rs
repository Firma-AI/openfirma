use std::{
    cell::RefCell,
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
    },
    time::Duration,
};

use crossterm::event::KeyCode;
use firma_tui::control::{
    App, AuditDecision, AuditRow, ControlError, ControlStatus, EditorError, Event,
    PolicyRewriteError, PolicyRewriteHandler, PolicyRewriteRequest, PolicyRowStatus,
    PolicyStateReader, TerminalEventSource, read_policy_states, set_policy_states,
    testing::{ControlCrankOutcome, HeadlessRunner},
};
use ratatui::{Terminal, backend::TestBackend};

pub const CRANK_TEST_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(unix)]
pub const REWRITE_TEST_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(windows)]
// We give Windows more room because the test waits at the real rewrite worker
// boundary. Once the blocked handler is released, the worker still needs CPU
// time to resume, rewrite Cedar, and publish `Completed`. A throttled CI runner
// can exceed one second here without the queue being broken.
//
// This is not a synchronization delay. The event still decides progress; the
// timeout only decides when we stop waiting and fail.
pub const REWRITE_TEST_TIMEOUT: Duration = Duration::from_secs(5);

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

pub const DISABLED_POLICY_SOURCE: &str = r#"
@id("first_policy")
permit (
    principal,
    action,
    resource
) when { false }; // openfirma-control:disabled

@id("second_policy")
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

pub fn generated_policy_id(prefix: &str, index: usize) -> String {
    format!("{prefix}_{index:04}")
}

pub fn generated_policy_ids(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| generated_policy_id(prefix, index))
        .collect()
}

pub fn generated_policy_source(
    prefix: &str,
    count: usize,
    disabled: impl Fn(usize) -> bool,
) -> String {
    let mut source = String::new();
    for index in 0..count {
        source.push_str(&generated_policy(
            &generated_policy_id(prefix, index),
            disabled(index),
        ));
    }

    source
}

fn generated_policy(id: &str, disabled: bool) -> String {
    let suffix = if disabled {
        " when { false }; // openfirma-control:disabled"
    } else {
        ";"
    };

    format!(
        r#"
@id("{id}")
permit (
    principal,
    action,
    resource
){suffix}
"#
    )
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

#[derive(Clone, Default)]
pub struct PolicyStateReadCounts {
    counts: Arc<Mutex<std::collections::HashMap<PathBuf, usize>>>,
}

impl PolicyStateReadCounts {
    pub fn reader(&self) -> PolicyStateReader {
        let counts = Arc::clone(&self.counts);
        PolicyStateReader::new(move |file, ids| {
            if let Ok(mut counts) = counts.lock() {
                *counts.entry(file.to_path_buf()).or_default() += 1;
            }
            read_policy_states(file, ids)
        })
    }

    pub fn clear(&self) -> anyhow::Result<()> {
        self.counts
            .lock()
            .map_err(|error| anyhow::anyhow!("policy state read count mutex poisoned: {error}"))?
            .clear();
        Ok(())
    }

    pub fn count_for(&self, file: &Path) -> anyhow::Result<usize> {
        Ok(*self
            .counts
            .lock()
            .map_err(|error| anyhow::anyhow!("policy state read count mutex poisoned: {error}"))?
            .get(file)
            .unwrap_or(&0))
    }
}

pub fn headless_runner_with_policy_source(
    source: &str,
) -> anyhow::Result<(tempfile::TempDir, PathBuf, HeadlessRunner<'static>)> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), source)?;
    let runner = HeadlessRunner::new(Some(temp.path().to_path_buf()), None);
    Ok((temp, policy_path, runner))
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

pub fn audit_channel_with_rows(
    count: usize,
) -> anyhow::Result<(mpsc::Sender<AuditRow>, mpsc::Receiver<AuditRow>)> {
    let (audit_tx, audit_rx) = audit_channel();
    send_audit_rows(&audit_tx, count)?;
    Ok((audit_tx, audit_rx))
}

pub fn send_audit_rows(audit_tx: &mpsc::Sender<AuditRow>, count: usize) -> anyhow::Result<()> {
    for index in 0..count {
        audit_tx.send(indexed_audit_row(index))?;
    }
    Ok(())
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

pub fn indexed_audit_row(index: usize) -> AuditRow {
    let decision = if index.is_multiple_of(2) {
        AuditDecision::Allow
    } else {
        AuditDecision::Deny
    };
    audit_row(decision, index)
}

pub struct BlockingRewriteHandler {
    pub handler: PolicyRewriteHandler,
    pub release: Sender<()>,
}

pub fn blocking_first_rewrite_handler() -> BlockingRewriteHandler {
    let (release_rewrite_tx, release_rewrite_rx) = mpsc::channel();
    let first_rewrite = Arc::new(AtomicBool::new(true));
    let handler = Box::new(move |request: &PolicyRewriteRequest| {
        if first_rewrite.swap(false, Ordering::SeqCst) {
            release_rewrite_rx.recv().map_err(|error| {
                ControlError::policy_rewrite(
                    &request.file,
                    request.ids.clone(),
                    PolicyRewriteError::operation(error.to_string()),
                )
            })?;
        }

        set_policy_states(&request.file, &request.ids, request.requested).map_err(|error| {
            ControlError::policy_rewrite(&request.file, request.ids.clone(), error)
        })?;
        Ok(())
    });

    BlockingRewriteHandler {
        handler,
        release: release_rewrite_tx,
    }
}

pub struct RewriteRelease {
    release: Option<Sender<()>>,
}

impl RewriteRelease {
    pub fn new(release: Sender<()>) -> Self {
        Self {
            release: Some(release),
        }
    }

    pub fn release(&mut self) -> anyhow::Result<()> {
        if let Some(release) = self.release.take() {
            release.send(())?;
        }

        Ok(())
    }
}

impl Drop for RewriteRelease {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _sent = release.send(()).is_ok();
        }
    }
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

pub fn replace_policy_source_editor(
    policy_path: PathBuf,
    source: String,
) -> impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>> {
    move |path| {
        if path != policy_path.as_path() {
            return Ok(Err(EditorError::operation(format!(
                "expected editor path `{}`, got `{}`",
                policy_path.display(),
                path.display()
            ))));
        }

        Ok(
            fs::write(&policy_path, &source).map_err(|error| EditorError::Operation {
                message: error.to_string(),
            }),
        )
    }
}

pub fn successful_editor() -> impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>> {
    |_path| Ok(Ok(()))
}

pub fn crank_until(
    runner: &mut HeadlessRunner<'_>,
    condition: impl FnMut(&App) -> bool,
    timeout: Duration,
) -> anyhow::Result<ControlCrankOutcome> {
    let terminal = FakeTerminal::default();
    crank_until_with_terminal(runner, &terminal, successful_editor(), condition, timeout)
}

pub fn crank_until_with_terminal(
    runner: &mut HeadlessRunner<'_>,
    terminal: &impl TerminalEventSource,
    mut open_policy_source: impl FnMut(&Path) -> anyhow::Result<Result<(), EditorError>>,
    condition: impl FnMut(&App) -> bool,
    timeout: Duration,
) -> anyhow::Result<ControlCrankOutcome> {
    runner.crank_until(terminal, &mut open_policy_source, condition, timeout)
}

pub fn write_policy_file(dir: &Path, source: &str) -> anyhow::Result<PathBuf> {
    write_named_policy_file(dir, "policies.cedar", source)
}

pub fn write_named_policy_file(dir: &Path, name: &str, source: &str) -> anyhow::Result<PathBuf> {
    let policy_path = dir.join(name);
    fs::write(&policy_path, source)?;
    Ok(policy_path)
}

pub fn temp_policy_file(source: &str) -> anyhow::Result<(tempfile::TempDir, PathBuf)> {
    let temp = tempfile::tempdir()?;
    let policy_path = write_policy_file(temp.path(), source)?;
    Ok((temp, policy_path))
}

pub fn handle_key(app: &mut App, key: KeyCode) {
    let _outcome = firma_tui::control::handle_key(app, key);
}

pub fn last_visible_audit_index(app: &App) -> usize {
    app.visible_audit_rows_len().saturating_sub(1)
}

pub fn policy_status(app: &App, id: &str) -> Option<PolicyRowStatus> {
    app.policies()
        .iter()
        .find(|policy| policy.id == id)
        .map(|policy| policy.status)
}

pub fn rewrite_ids_for_file(
    rewrites: &[PolicyRewriteRequest],
    file_name: &str,
) -> Option<Vec<String>> {
    rewrites
        .iter()
        .find(|request| {
            request
                .file
                .file_name()
                .is_some_and(|name| name == file_name)
        })
        .map(|request| request.ids.clone())
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
    let policy_error = policy_error_snapshot(status.policy_error.as_ref());

    format!(
        "runtime_state: {}\n\
         policy_dir: {policy_dir}\n\
         policy_count: {}\n\
         audit_connected: {}\n\
         audit_rows: {}\n\
         rewrite_queue_len: {}\n\
         pending_rewrites: {}\n\
         policy_error: {policy_error}",
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
