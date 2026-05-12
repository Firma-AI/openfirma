mod layout;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, BufRead as _, Seek as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::agent_bridge::{AgentBridge, spawn_agent};
use crate::demo_loader::{
    ConfigItem, DemoEntry, DemoManifest, discover, load, load_config_template,
};
use crate::runtime::{DemoRuntime, boot};

pub enum Phase {
    Config,
    Menu,
    Running,
}

pub struct App {
    pub phase: Phase,
    // Config
    pub config_items: Vec<ConfigItem>,
    pub config_selected: usize,
    // Menu
    pub menu_entries: Vec<DemoEntry>,
    pub menu_selected: usize,
    // Populated after demo selection
    pub manifest: Option<DemoManifest>,
    pub runtime: Option<DemoRuntime>,
    pub agent: Option<AgentBridge>,
    // Log panes
    pub authority_logs: Vec<String>,
    pub sidecar_logs: Vec<String>,
    pub audit_logs: Vec<String>,
    pub audit_log_offset: u64,
    pub agent_logs: Vec<String>,
    pub should_quit: bool,
    // Stored for lazy boot on menu selection
    demos_dir: PathBuf,
}

impl App {
    fn new(menu_entries: Vec<DemoEntry>, demos_dir: &Path) -> Self {
        let config_items = load_config_template(demos_dir);
        Self {
            phase: Phase::Menu,
            config_items,
            config_selected: 0,
            menu_entries,
            menu_selected: 0,
            manifest: None,
            runtime: None,
            agent: None,
            authority_logs: Vec::new(),
            sidecar_logs: Vec::new(),
            audit_logs: Vec::new(),
            audit_log_offset: 0,
            agent_logs: Vec::new(),
            should_quit: false,
            demos_dir: demos_dir.to_path_buf(),
        }
    }

    fn save_config(&self) -> Result<()> {
        let mut content = String::new();
        for item in &self.config_items {
            if !item.description.is_empty() {
                let _ = writeln!(content, "# {}", item.description);
            }
            let _ = write!(content, "{}={}\n\n", item.key, item.value);
        }
        std::fs::write(self.demos_dir.join(".env"), content)?;
        Ok(())
    }

    /// Spawn the Python demo script for the currently loaded manifest +
    /// runtime. Caller is expected to have set `manifest` and `runtime`
    /// already and to have transitioned to `Phase::Running`.
    fn start_script(&mut self) -> Result<()> {
        let Some(manifest) = self.manifest.as_ref() else {
            return Ok(());
        };
        let Some(rt) = self.runtime.as_ref() else {
            return Ok(());
        };

        let mut extra_env = HashMap::new();
        for item in &self.config_items {
            if !item.value.is_empty() {
                extra_env.insert(item.key.clone(), item.value.clone());
            }
        }
        let ca_cert = rt.ca_cert_path.to_string_lossy().into_owned();
        extra_env.insert("SSL_CERT_FILE".to_string(), ca_cert.clone());
        extra_env.insert("REQUESTS_CA_BUNDLE".to_string(), ca_cert);
        if !manifest.session_id.is_empty() {
            extra_env.insert("FIRMA_SESSION_ID".to_string(), manifest.session_id.clone());
        }

        let ag = spawn_agent(&manifest.agent_script, "http://127.0.0.1:8080", &extra_env)?;
        self.agent = Some(ag);
        self.agent_logs
            .push("Demo running. ESC to quit.".to_string());
        self.agent_logs.push(String::new());
        Ok(())
    }
}

pub fn run(demos_dir: &Path, initial_demo: Option<&Path>) -> Result<()> {
    let menu_entries = discover(demos_dir)?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(menu_entries, demos_dir);

    // If .env is missing in demos_dir, start in Config phase
    if !demos_dir.join(".env").exists() {
        app.phase = Phase::Config;
    }

    if let Some(demo_path) = initial_demo {
        let manifest = load(demo_path)?;
        let rt = boot(&manifest)?;
        note_process_log_paths(&mut app, &rt);
        app.manifest = Some(manifest);
        app.runtime = Some(rt);
        push_ready_banner(&mut app);
        app.phase = Phase::Running;
    }

    let result = event_loop(&mut terminal, &mut app);

    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    if let Some(mut rt) = app.runtime.take() {
        rt.shutdown();
    }
    if let Some(mut ag) = app.agent.take() {
        ag.shutdown();
    }

    result
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        if matches!(app.phase, Phase::Running) {
            drain_channels(app);
        }

        terminal.draw(|f| layout::render(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                handle_key(app, key)?;
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn drain_channels(app: &mut App) {
    if let Some(rt) = app.runtime.as_mut() {
        while let Ok(line) = rt.authority.output_rx.try_recv() {
            app.authority_logs.push(line);
        }
        while let Ok(line) = rt.sidecar.output_rx.try_recv() {
            app.sidecar_logs.push(line);
        }
        drain_audit_log(app);
    }
    if let Some(ag) = app.agent.as_ref() {
        while let Ok(line) = ag.output_rx.try_recv() {
            app.agent_logs.push(line);
        }
    }
}

fn drain_audit_log(app: &mut App) {
    let Some(rt) = app.runtime.as_ref() else {
        return;
    };

    let Ok(mut file) = std::fs::File::open(&rt.audit_log_path) else {
        return;
    };

    let Ok(metadata) = file.metadata() else {
        return;
    };
    if metadata.len() < app.audit_log_offset {
        app.audit_log_offset = 0;
    }

    if file
        .seek(std::io::SeekFrom::Start(app.audit_log_offset))
        .is_err()
    {
        return;
    }

    let mut reader = std::io::BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let Ok(bytes) = reader.read_line(&mut line) else {
            break;
        };
        if bytes == 0 {
            break;
        }
        while line.ends_with(['\n', '\r']) {
            line.pop();
        }
        if !line.is_empty() {
            app.audit_logs.push(line.clone());
        }
    }

    if let Ok(pos) = reader.stream_position() {
        app.audit_log_offset = pos;
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match app.phase {
        Phase::Config => handle_config_key(app, key),
        Phase::Menu => handle_menu_key(app, key)?,
        Phase::Running => handle_running_key(app, key)?,
    }
    Ok(())
}

fn handle_config_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Up | KeyCode::BackTab => {
            app.config_selected = app.config_selected.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Tab if app.config_selected + 1 < app.config_items.len() => {
            app.config_selected += 1;
        }
        KeyCode::Char(c) => {
            if let Some(item) = app.config_items.get_mut(app.config_selected) {
                item.value.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Some(item) = app.config_items.get_mut(app.config_selected) {
                item.value.pop();
            }
        }
        KeyCode::Enter => {
            if app.config_selected + 1 < app.config_items.len() {
                app.config_selected += 1;
            } else {
                let _ = app.save_config();
                app.phase = Phase::Menu;
            }
        }
        _ => {}
    }
}

fn handle_menu_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Char('c') => {
            app.phase = Phase::Config;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.menu_selected = app.menu_selected.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if app.menu_selected + 1 < app.menu_entries.len() => {
            app.menu_selected += 1;
        }
        KeyCode::Enter => {
            let path = app.menu_entries[app.menu_selected].path.clone();
            let manifest = load(&path)?;
            let rt = boot(&manifest)?;
            note_process_log_paths(app, &rt);
            app.manifest = Some(manifest);
            app.runtime = Some(rt);
            push_ready_banner(app);
            app.phase = Phase::Running;
        }
        _ => {}
    }
    Ok(())
}

fn note_process_log_paths(app: &mut App, rt: &DemoRuntime) {
    app.authority_logs.push(format!(
        "Writing authority process log to {}",
        rt.authority_log_path.display()
    ));
    app.sidecar_logs.push(format!(
        "Writing sidecar process log to {}",
        rt.sidecar_log_path.display()
    ));
}

fn push_ready_banner(app: &mut App) {
    let prompt = app
        .manifest
        .as_ref()
        .map(|m| m.prompt.clone())
        .unwrap_or_default();
    if !prompt.trim().is_empty() {
        for line in prompt.lines() {
            app.agent_logs.push(line.to_string());
        }
        app.agent_logs.push(String::new());
    }
    app.agent_logs.push("─".repeat(40));
    app.agent_logs
        .push("Authority + sidecar booted.".to_string());
    app.agent_logs
        .push("Press Enter to start the demo. ESC to quit.".to_string());
    app.agent_logs.push(String::new());
}

fn handle_running_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Enter if app.agent.is_none() => {
            app.start_script()?;
        }
        _ => {}
    }
    Ok(())
}
