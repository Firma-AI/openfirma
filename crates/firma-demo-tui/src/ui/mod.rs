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
use std::io;
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
    pub agent_logs: Vec<String>,
    pub input: String,
    pub should_quit: bool,
    // Stored for lazy boot on menu selection
    authority_bin: PathBuf,
    sidecar_bin: PathBuf,
    demos_dir: PathBuf,
}

impl App {
    fn new(
        menu_entries: Vec<DemoEntry>,
        authority_bin: PathBuf,
        sidecar_bin: PathBuf,
        demos_dir: &Path,
    ) -> Self {
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
            agent_logs: Vec::new(),
            input: String::new(),
            should_quit: false,
            authority_bin,
            sidecar_bin,
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
}

pub fn run(
    demos_dir: &Path,
    initial_demo: Option<&Path>,
    authority_bin: PathBuf,
    sidecar_bin: PathBuf,
) -> Result<()> {
    let menu_entries = discover(demos_dir)?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(menu_entries, authority_bin, sidecar_bin, demos_dir);

    // If .env is missing in demos_dir, start in Config phase
    if !demos_dir.join(".env").exists() {
        app.phase = Phase::Config;
    }

    if let Some(demo_path) = initial_demo {
        let manifest = load(demo_path)?;
        let rt = boot(&manifest, &app.authority_bin, &app.sidecar_bin)?;

        let mut extra_env = HashMap::new();
        for item in &app.config_items {
            if !item.value.is_empty() {
                extra_env.insert(item.key.clone(), item.value.clone());
            }
        }

        let ag = spawn_agent(
            &manifest.agent_script,
            "http://127.0.0.1:8080",
            "", // Empty prompt so it doesn't auto-run
            &extra_env,
        )?;
        app.agent_logs.push("Suggested Prompt:".to_string());
        for line in manifest.agent_prompt.lines() {
            app.agent_logs.push(format!("  {line}"));
        }
        app.agent_logs.push("---".to_string());
        app.agent_logs
            .push("Type a prompt and press Enter to start.".to_string());
        app.agent_logs.push("".to_string());
        app.manifest = Some(manifest);
        app.runtime = Some(rt);
        app.agent = Some(ag);
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
        if let Phase::Running = app.phase {
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
    }
    if let Some(ag) = app.agent.as_ref() {
        while let Ok(line) = ag.output_rx.try_recv() {
            app.agent_logs.push(line);
        }
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match app.phase {
        Phase::Config => handle_config_key(app, key),
        Phase::Menu => handle_menu_key(app, key)?,
        Phase::Running => handle_running_key(app, key),
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
            let rt = boot(&manifest, &app.authority_bin, &app.sidecar_bin)?;

            let mut extra_env = HashMap::new();
            for item in &app.config_items {
                if !item.value.is_empty() {
                    extra_env.insert(item.key.clone(), item.value.clone());
                }
            }

            let ag = spawn_agent(
                &manifest.agent_script,
                "http://127.0.0.1:8080",
                "", // Empty prompt so it doesn't auto-run
                &extra_env,
            )?;
            app.agent_logs.push("Suggested Prompt:".to_string());
            for line in manifest.agent_prompt.lines() {
                app.agent_logs.push(format!("  {line}"));
            }
            app.agent_logs.push("---".to_string());
            app.agent_logs
                .push("Type a prompt and press Enter to start.".to_string());
            app.agent_logs.push("".to_string());
            app.manifest = Some(manifest);
            app.runtime = Some(rt);
            app.agent = Some(ag);
            app.phase = Phase::Running;
        }
        _ => {}
    }
    Ok(())
}

fn handle_running_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Char(c) => {
            app.input.push(c);
        }
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Enter => {
            if let Some(ag) = app.agent.as_ref() {
                let line = std::mem::take(&mut app.input);
                app.agent_logs.push(format!("> {line}"));
                ag.send_input(line);
            }
        }
        _ => {}
    }
}
