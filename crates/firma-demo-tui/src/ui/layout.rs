use ansi_to_tui::IntoText;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use serde_json::Value;

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
        let input = Paragraph::new(item.value.as_str())
            .wrap(Wrap { trim: false })
            .block(
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

    let desc = Paragraph::new(description_to_text(desc_text)).wrap(Wrap { trim: false });
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
            Constraint::Percentage(30),
            Constraint::Percentage(25),
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
    render_audit_pane(f, outer[1], &app.audit_logs);
    render_agent_pane(f, outer[2], app);

    let hint = if app.agent.is_none() {
        "[Enter] start demo   [ESC] quit"
    } else {
        "[ESC] quit"
    };
    let status = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
    f.render_widget(status, outer[3]);
}

fn render_log_pane(f: &mut Frame, area: Rect, title: &str, logs: &[String], color: Color) {
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let start = logs.len().saturating_sub(height.saturating_mul(4));
    let text = ansi_lines_to_text(&logs[start..]);
    let scroll = scroll_offset(text.lines.len(), height);
    let pane = Paragraph::new(text)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(pane, inner);
}

fn render_sidecar_pane(f: &mut Frame, area: Rect, logs: &[String]) {
    let block = Block::default()
        .title(" Sidecar ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let start = logs.len().saturating_sub(height.saturating_mul(4));
    let lines: Vec<Line<'_>> = logs[start..]
        .iter()
        .flat_map(|line| sidecar_log_lines(line))
        .collect();
    let text = Text::from(lines);
    let scroll = scroll_offset(text.lines.len(), height);
    let pane = Paragraph::new(text)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(pane, inner);
}

fn render_audit_pane(f: &mut Frame, area: Rect, logs: &[String]) {
    let block = Block::default()
        .title(" Audit Logs ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let start = logs.len().saturating_sub(height.saturating_mul(3));
    let lines = logs[start..]
        .iter()
        .map(|line| audit_log_line(line))
        .collect::<Vec<_>>();
    let text = Text::from(lines);
    let scroll = scroll_offset(text.lines.len(), height);
    let pane = Paragraph::new(text)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(pane, inner);
}

fn render_agent_pane(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Agent ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let start = app
        .agent_logs
        .len()
        .saturating_sub(height.saturating_mul(4));
    let text = ansi_lines_to_text(&app.agent_logs[start..]);
    let scroll = scroll_offset(text.lines.len(), height);
    let output = Paragraph::new(text)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(output, inner);
}

fn ansi_lines_to_text(logs: &[String]) -> Text<'_> {
    let mut lines = Vec::new();
    for log in logs {
        let text = log
            .as_bytes()
            .into_text()
            .unwrap_or_else(|_| log.as_str().into());
        lines.extend(text.lines);
    }
    Text::from(lines)
}

fn sidecar_log_lines(log: &str) -> Vec<Line<'_>> {
    if log.contains('\x1b') {
        return log
            .as_bytes()
            .into_text()
            .map_or_else(|_| vec![Line::from(log.to_owned())], |text| text.lines);
    }

    let style = if log.contains("ALLOW") {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else if log.contains("DENY") {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    vec![Line::from(Span::styled(log.to_owned(), style))]
}

fn audit_log_line(log: &str) -> Line<'static> {
    let Ok(value) = serde_json::from_str::<Value>(log) else {
        return Line::from(log.to_owned());
    };

    let decision = value
        .get("decision")
        .and_then(Value::as_i64)
        .map_or("UNKNOWN", |decision| match decision {
            1 => "ALLOW",
            2 => "DENY",
            3 => "ABORT",
            _ => "UNKNOWN",
        });
    let decision_style = match decision {
        "ALLOW" => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        "DENY" | "ABORT" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::DarkGray),
    };
    let action = value.get("action").and_then(Value::as_str).unwrap_or("-");
    let resource = value.get("resource").and_then(Value::as_str).unwrap_or("-");
    let reason = value
        .get("deny_reason")
        .and_then(Value::as_str)
        .unwrap_or("");

    let mut spans = vec![
        Span::styled(format!("{decision:<5}"), decision_style),
        Span::raw("  "),
        Span::styled(format!("{action:<32}"), Style::default().fg(Color::White)),
        Span::raw("  "),
        Span::styled(resource.to_owned(), Style::default().fg(Color::White)),
    ];

    if !reason.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            reason.to_owned(),
            Style::default().fg(Color::White),
        ));
    }

    Line::from(spans)
}

fn description_to_text(md: &str) -> Text<'static> {
    let md_lines: Vec<&str> = md.lines().collect();
    let mut result: Vec<Line<'static>> = Vec::new();
    let mut i = 0;

    while i < md_lines.len() {
        if is_table_row(md_lines[i]) {
            let start = i;
            while i < md_lines.len() && is_table_row(md_lines[i]) {
                i += 1;
            }
            result.extend(render_table_block(&md_lines[start..i]));
            result.push(Line::default());
        } else {
            let block_start = i;
            while i < md_lines.len() && !is_table_row(md_lines[i]) {
                i += 1;
            }
            let chunk = md_lines[block_start..i].join("\n");
            let text = tui_markdown::from_str(&chunk);
            for line in text.lines {
                let spans = line
                    .spans
                    .into_iter()
                    .map(|s| Span::styled(s.content.into_owned(), s.style))
                    .collect::<Vec<_>>();
                result.push(Line::from(spans).style(line.style));
            }
        }
    }

    Text::from(result)
}

fn is_table_row(line: &str) -> bool {
    let t = line.trim();
    t.starts_with('|') && t.ends_with('|') && t.len() > 1
}

fn is_separator_row(line: &str) -> bool {
    if !is_table_row(line) {
        return false;
    }
    line.trim()
        .chars()
        .all(|c| matches!(c, '|' | '-' | ':' | ' '))
}

fn parse_table_cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(|s| s.trim().to_owned())
        .collect()
}

fn render_table_block(lines: &[&str]) -> Vec<Line<'static>> {
    let rows: Vec<Vec<String>> = lines
        .iter()
        .filter(|&&l| !is_separator_row(l))
        .map(|&l| parse_table_cells(l))
        .collect();

    if rows.is_empty() {
        return vec![];
    }

    let n_cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    if n_cols == 0 {
        return vec![];
    }

    let mut col_widths = vec![1usize; n_cols];
    for row in &rows {
        for (j, cell) in row.iter().enumerate() {
            if j < n_cols {
                col_widths[j] = col_widths[j].max(cell.len());
            }
        }
    }

    let border = Style::default().fg(Color::DarkGray);
    let header_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let body_style = Style::default().fg(Color::White);

    let make_sep = |left: &str, mid: &str, right: &str| -> Line<'static> {
        let mut spans = vec![Span::styled(left.to_owned(), border)];
        for (j, &w) in col_widths.iter().enumerate() {
            spans.push(Span::styled("─".repeat(w + 2), border));
            if j < n_cols - 1 {
                spans.push(Span::styled(mid.to_owned(), border));
            }
        }
        spans.push(Span::styled(right.to_owned(), border));
        Line::from(spans)
    };

    let make_row = |cells: &[String], style: Style| -> Line<'static> {
        let mut spans = vec![Span::styled("│".to_owned(), border)];
        for (j, cell) in cells.iter().enumerate() {
            if j < n_cols {
                let padded = format!(" {:<width$} ", cell, width = col_widths[j]);
                spans.push(Span::styled(padded, style));
                spans.push(Span::styled("│".to_owned(), border));
            }
        }
        Line::from(spans)
    };

    let mut result = vec![make_sep("┌", "┬", "┐")];

    for (row_idx, row) in rows.iter().enumerate() {
        let mut cells = row.clone();
        while cells.len() < n_cols {
            cells.push(String::new());
        }
        let style = if row_idx == 0 {
            header_style
        } else {
            body_style
        };
        result.push(make_row(&cells, style));
        if row_idx == 0 && rows.len() > 1 {
            result.push(make_sep("├", "┼", "┤"));
        }
    }

    result.push(make_sep("└", "┴", "┘"));
    result
}

fn scroll_offset(line_count: usize, height: usize) -> u16 {
    u16::try_from(line_count.saturating_sub(height)).unwrap_or(u16::MAX)
}
