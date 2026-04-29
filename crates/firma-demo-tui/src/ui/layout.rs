use ansi_to_tui::IntoText;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use super::{App, Phase};

pub fn render(f: &mut Frame, app: &App) {
    match app.phase {
        Phase::Config => render_config(f, app),
        Phase::Menu => render_menu(f, app),
        Phase::Running => render_running(f, app),
    }
}

fn render_config(f: &mut Frame, app: &App) {
    let area = f.area();
    let block = Block::default()
        .title(" Agent Configuration ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut constraints = Vec::new();
    for _ in 0..app.config_items.len() {
        constraints.push(Constraint::Length(3));
    }
    constraints.push(Constraint::Min(0));
    constraints.push(Constraint::Length(1));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for (i, item) in app.config_items.iter().enumerate() {
        let style = if app.config_selected == i {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::White)
        };

        let title = format!(" {} — {} ", item.key, item.description);
        let input = Paragraph::new(item.value.as_str()).block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(style),
        );

        if i < chunks.len() - 2 {
            f.render_widget(input, chunks[i]);
        }
    }

    let hint = Paragraph::new("Tab/Shift-Tab navigate. Enter next. ESC quit. Manual re-entry: 'c'")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint, chunks[chunks.len() - 1]);
}

fn render_menu(f: &mut Frame, app: &App) {
    let area = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(outer[0]);

    // --- Left: demo list ---
    let list_block = Block::default()
        .title(" Firma Demo System ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let list_inner = list_block.inner(columns[0]);
    f.render_widget(list_block, columns[0]);

    let list_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(list_inner);

    let items: Vec<ListItem> = app
        .menu_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let selected = i == app.menu_selected;
            let prefix = if selected { "> " } else { "  " };
            let name_style = if selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Span::styled(format!("{prefix}{}", entry.name), name_style))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.menu_selected));
    f.render_stateful_widget(List::new(items), list_layout[0], &mut state);

    let hint = Paragraph::new("↑↓/jk navigate  Enter select  c config  ESC quit")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint, list_layout[1]);

    // --- Right: description of selected demo ---
    let selected_entry = app.menu_entries.get(app.menu_selected);
    let desc_title = selected_entry.map_or_else(
        || " Description ".to_owned(),
        |e| format!(" {} ", e.tagline),
    );

    let desc_block = Block::default()
        .title(desc_title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let desc_inner = desc_block.inner(columns[1]);
    f.render_widget(desc_block, columns[1]);

    let desc_text = selected_entry.map_or("", |e| e.description.as_str());

    let desc = Paragraph::new(tui_markdown::from_str(desc_text)).wrap(Wrap { trim: false });
    f.render_widget(desc, desc_inner);

    let status = Paragraph::new("↑↓ navigate   Enter select   c config   ESC quit")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(status, outer[1]);
}

fn render_running(f: &mut Frame, app: &App) {
    let area = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(45),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[0]);

    render_log_pane(f, top[0], " Authority ", &app.authority_logs, Color::Blue);
    render_sidecar_pane(f, top[1], &app.sidecar_logs);
    render_agent_pane(f, outer[1], app);

    let status = Paragraph::new("[Enter] send to agent   [ESC] quit")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(status, outer[2]);
}

fn render_log_pane(f: &mut Frame, area: Rect, title: &str, logs: &[String], color: Color) {
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let start = logs.len().saturating_sub(height);
    let items: Vec<ListItem> = logs[start..]
        .iter()
        .map(|l| {
            let text = l
                .as_bytes()
                .into_text()
                .unwrap_or_else(|_| l.as_str().into());
            ListItem::new(text)
        })
        .collect();

    f.render_widget(List::new(items), inner);
}

fn render_sidecar_pane(f: &mut Frame, area: Rect, logs: &[String]) {
    let block = Block::default()
        .title(" Sidecar ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let start = logs.len().saturating_sub(height);
    let items: Vec<ListItem> = logs[start..]
        .iter()
        .map(|l| {
            // If it has ANSI, use that, otherwise fall back to manual styling
            if l.contains('\x1b') {
                let text = l
                    .as_bytes()
                    .into_text()
                    .unwrap_or_else(|_| l.as_str().into());
                ListItem::new(text)
            } else {
                let style = if l.contains("ALLOW") {
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else if l.contains("DENY") {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(l.as_str(), style)))
            }
        })
        .collect();

    f.render_widget(List::new(items), inner);
}

fn render_agent_pane(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Agent ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);

    let height = chunks[0].height as usize;
    let start = app.agent_logs.len().saturating_sub(height);
    let items: Vec<ListItem> = app.agent_logs[start..]
        .iter()
        .map(|l| {
            let text = l
                .as_bytes()
                .into_text()
                .unwrap_or_else(|_| l.as_str().into());
            ListItem::new(text)
        })
        .collect();
    f.render_widget(List::new(items), chunks[0]);

    let input_line = format!("> {}", app.input);
    let input = Paragraph::new(input_line.as_str()).style(Style::default().fg(Color::White));
    f.render_widget(input, chunks[1]);
}
