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
        Phase::Menu => render_menu(f, app),
        Phase::Description => render_description(f, app),
        Phase::Running => render_running(f, app),
    }
}

fn render_menu(f: &mut Frame, app: &App) {
    let area = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let block = Block::default()
        .title(" Firma Demo System ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(outer[0]);
    f.render_widget(block, outer[0]);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(inner);

    let subtitle = Paragraph::new("Select a demo to run")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(subtitle, layout[0]);

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
            let tagline_style = Style::default().fg(Color::DarkGray);

            ListItem::new(Line::from(vec![
                Span::styled(format!("{prefix}{}", entry.name), name_style),
                Span::raw("  "),
                Span::styled(entry.tagline.as_str(), tagline_style),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.menu_selected));
    f.render_stateful_widget(List::new(items), layout[1], &mut state);

    let hint = Paragraph::new("↑↓ / j k  navigate    Enter  select    q  quit")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint, layout[2]);

    let status = Paragraph::new("↑↓ navigate   Enter select   q quit")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(status, outer[1]);
}

fn render_description(f: &mut Frame, app: &App) {
    let area = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let block = Block::default()
        .title(" Firma Demo ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(outer[0]);
    f.render_widget(block, outer[0]);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);

    let description = app
        .manifest
        .as_ref()
        .map_or("", |m| m.description.as_str());
    let text = Paragraph::new(description).wrap(Wrap { trim: false });
    f.render_widget(text, chunks[0]);

    let hint = Paragraph::new("Press any key to start — q to quit")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint, chunks[1]);

    let status =
        Paragraph::new("[any key] start   [q] quit").style(Style::default().fg(Color::DarkGray));
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

    let status = Paragraph::new("[Enter] send to agent   [q] quit")
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
        .map(|l| ListItem::new(l.as_str()))
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
        .map(|l| ListItem::new(l.as_str()))
        .collect();
    f.render_widget(List::new(items), chunks[0]);

    let input_line = format!("> {}", app.input);
    let input = Paragraph::new(input_line.as_str()).style(Style::default().fg(Color::White));
    f.render_widget(input, chunks[1]);
}
