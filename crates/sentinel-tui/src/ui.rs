use ratatui::{
    prelude::*,
    widgets::*,
};
use crate::state::AppState;
use crate::app::Tab;

const SENTINEL_BLUE: Color = Color::Rgb(0, 150, 255);
const SENTINEL_GREEN: Color = Color::Rgb(0, 220, 130);
const SENTINEL_RED: Color = Color::Rgb(255, 70, 70);
const SENTINEL_YELLOW: Color = Color::Rgb(255, 200, 0);
const SENTINEL_DIM: Color = Color::Rgb(100, 110, 130);

pub fn draw(f: &mut Frame, state: &AppState, tab: &Tab, scroll: usize) {
    let area = f.size();

    // Main layout: header, tabs, content, footer
    let layout = Layout::vertical([
        Constraint::Length(3),  // header
        Constraint::Length(3),  // tabs
        Constraint::Min(0),     // content
        Constraint::Length(1),  // footer
    ]).split(area);

    draw_header(f, layout[0], state);
    draw_tabs(f, layout[1], tab);
    draw_content(f, layout[2], state, tab, scroll);
    draw_footer(f, layout[3]);
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState) {
    let connected_str = if state.connected { "● CONNECTED" } else { "● DISCONNECTED" };
    let connected_style = if state.connected {
        Style::default().fg(SENTINEL_GREEN).bold()
    } else {
        Style::default().fg(SENTINEL_RED).bold()
    };

    let uptime = format_uptime(state.status.uptime_seconds);
    let last_updated = state.last_updated
        .map(|t| t.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "--:--:--".to_string());

    let header_left = Paragraph::new(Span::styled(
        format!("  SentinelWall v{}", state.status.version.as_str()),
        Style::default().fg(SENTINEL_BLUE).bold()
    ))
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SENTINEL_BLUE)));

    let _header_right_text = format!(
        " {}  uptime: {}  updated: {}  rules: {}  bans: {} ",
        connected_str,
        uptime,
        last_updated,
        state.status.rules_count,
        state.status.bans_count,
    );

    let layout = Layout::horizontal([
        Constraint::Length(30),
        Constraint::Min(0),
    ]).split(area);

    f.render_widget(header_left, layout[0]);

    let header_right = Paragraph::new(Line::from(vec![
        Span::styled(" ● ", connected_style),
        Span::styled(
            format!(
                "uptime: {}  updated: {}  rules: {}  bans: {} ",
                uptime, last_updated, state.status.rules_count, state.status.bans_count
            ),
            Style::default().fg(Color::Gray)
        ),
    ]))
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SENTINEL_DIM)));

    f.render_widget(header_right, layout[1]);
}

fn draw_tabs(f: &mut Frame, area: Rect, tab: &Tab) {
    let tabs_data = vec![
        ("1 Dashboard", Tab::Dashboard),
        ("2 Rules", Tab::Rules),
        ("3 Bans", Tab::Bans),
        ("4 Threats", Tab::Threats),
        ("5 Logs", Tab::Logs),
    ];

    let tab_titles: Vec<Line> = tabs_data.iter().map(|(title, t)| {
        if t == tab {
            Line::from(Span::styled(
                format!(" {} ", title),
                Style::default().fg(Color::Black).bg(SENTINEL_BLUE).bold()
            ))
        } else {
            Line::from(Span::styled(
                format!(" {} ", title),
                Style::default().fg(Color::Gray)
            ))
        }
    }).collect();

    let tabs = Tabs::new(tab_titles)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(SENTINEL_DIM))
            .title(" Navigation "))
        .divider("|");

    f.render_widget(tabs, area);
}

fn draw_content(f: &mut Frame, area: Rect, state: &AppState, tab: &Tab, scroll: usize) {
    match tab {
        Tab::Dashboard => draw_dashboard(f, area, state),
        Tab::Rules => draw_rules(f, area, state, scroll),
        Tab::Bans => draw_bans(f, area, state, scroll),
        Tab::Threats => draw_threats(f, area, state, scroll),
        Tab::Logs => draw_logs(f, area, state, scroll),
    }
}

fn draw_dashboard(f: &mut Frame, area: Rect, state: &AppState) {
    let layout = Layout::vertical([
        Constraint::Length(8),
        Constraint::Min(0),
    ]).split(area);

    // Stats row
    let stats_layout = Layout::horizontal([
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
    ]).split(layout[0]);

    draw_stat_card(f, stats_layout[0], "RULES", &state.status.rules_count.to_string(), SENTINEL_BLUE);
    draw_stat_card(f, stats_layout[1], "ACTIVE BANS", &state.status.bans_count.to_string(), SENTINEL_RED);
    draw_stat_card(f, stats_layout[2], "BACKEND", &state.status.backend, SENTINEL_GREEN);
    draw_stat_card(f, stats_layout[3], "STATUS", &state.status.status.to_uppercase(), SENTINEL_GREEN);

    // Charts / info
    let bottom_layout = Layout::horizontal([
        Constraint::Ratio(1, 2),
        Constraint::Ratio(1, 2),
    ]).split(layout[1]);

    // Recent bans sparkline
    let ban_data: Vec<u64> = state.stats.ban_history.iter()
        .map(|&v| v as u64).collect();
    let sparkline = Sparkline::default()
        .block(Block::default()
            .title(" Ban Activity ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(SENTINEL_DIM)))
        .data(&ban_data)
        .style(Style::default().fg(SENTINEL_RED));
    f.render_widget(sparkline, bottom_layout[0]);

    // Recent threats
    let threat_text: Vec<ListItem> = state.threats.iter().take(8).map(|t| {
        let sev_color = severity_color(&t.severity);
        ListItem::new(Line::from(vec![
            Span::styled(
                format!("[{}] ", t.timestamp.format("%H:%M:%S")),
                Style::default().fg(SENTINEL_DIM)
            ),
            Span::styled(
                format!("{:8} ", t.severity.to_uppercase()),
                Style::default().fg(sev_color).bold()
            ),
            Span::styled(
                format!("{:16} ", t.ip),
                Style::default().fg(Color::Cyan)
            ),
            Span::styled(
                t.threat_type.clone(),
                Style::default().fg(Color::White)
            ),
        ]))
    }).collect();

    let threat_list = List::new(threat_text)
        .block(Block::default()
            .title(" Recent Threats ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(SENTINEL_DIM)));
    f.render_widget(threat_list, bottom_layout[1]);
}

fn draw_stat_card(f: &mut Frame, area: Rect, label: &str, value: &str, color: Color) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(value, Style::default().fg(color).bold().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled(label, Style::default().fg(SENTINEL_DIM))),
    ];

    let para = Paragraph::new(text)
        .alignment(Alignment::Center)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(SENTINEL_DIM)));

    f.render_widget(para, area);
}

fn draw_rules(f: &mut Frame, area: Rect, state: &AppState, scroll: usize) {
    let header = Row::new(vec!["Priority", "Name", "Action", "Protocol", "Port", "Enabled"])
        .style(Style::default().fg(SENTINEL_BLUE).bold());

    let rows: Vec<Row> = state.rules.iter().skip(scroll).map(|rule| {
        let action = rule["action"].as_str().unwrap_or("?");
        let action_style = match action {
            "accept" => Style::default().fg(SENTINEL_GREEN),
            "drop" | "reject" => Style::default().fg(SENTINEL_RED),
            _ => Style::default(),
        };
        let port = rule["dst_port"]["value"].as_u64()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "any".to_string());

        Row::new(vec![
            Cell::from(rule["priority"].as_i64().unwrap_or(100).to_string()),
            Cell::from(rule["name"].as_str().unwrap_or("?").to_string()),
            Cell::from(Span::styled(action.to_uppercase(), action_style)),
            Cell::from(rule["protocol"].as_str().unwrap_or("any").to_string()),
            Cell::from(port),
            Cell::from(if rule["enabled"].as_bool().unwrap_or(true) { "✓" } else { "✗" }),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(8),
        Constraint::Min(20),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(8),
    ])
    .header(header)
    .block(Block::default()
        .title(format!(" Rules ({}) ", state.rules.len()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SENTINEL_DIM)))
    .highlight_style(Style::default().bg(Color::DarkGray));

    f.render_widget(table, area);
}

fn draw_bans(f: &mut Frame, area: Rect, state: &AppState, scroll: usize) {
    let header = Row::new(vec!["IP Address", "Reason", "Banned At", "Expires"])
        .style(Style::default().fg(SENTINEL_RED).bold());

    let rows: Vec<Row> = state.bans.iter().skip(scroll).map(|ban| {
        Row::new(vec![
            Cell::from(Span::styled(
                ban["ip"].as_str().unwrap_or("?").to_string(),
                Style::default().fg(Color::Cyan)
            )),
            Cell::from(ban["reason"].as_str().unwrap_or("?").to_string()),
            Cell::from(ban["banned_at"].as_str().unwrap_or("?").to_string()),
            Cell::from(Span::styled(
                ban["expires_at"].as_str().unwrap_or("permanent").to_string(),
                if ban["expires_at"].is_null() {
                    Style::default().fg(SENTINEL_RED)
                } else {
                    Style::default().fg(SENTINEL_YELLOW)
                }
            )),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(20),
        Constraint::Min(20),
        Constraint::Length(25),
        Constraint::Length(25),
    ])
    .header(header)
    .block(Block::default()
        .title(format!(" Banned IPs ({}) ", state.bans.len()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SENTINEL_DIM)));

    f.render_widget(table, area);
}

fn draw_threats(f: &mut Frame, area: Rect, state: &AppState, scroll: usize) {
    let items: Vec<ListItem> = state.threats.iter().skip(scroll).map(|t| {
        let sev_color = severity_color(&t.severity);
        ListItem::new(Line::from(vec![
            Span::styled(
                format!("[{}] ", t.timestamp.format("%H:%M:%S")),
                Style::default().fg(SENTINEL_DIM)
            ),
            Span::styled(
                format!("{:8} ", t.severity.to_uppercase()),
                Style::default().fg(sev_color).bold()
            ),
            Span::styled(
                format!("{:18} ", t.ip),
                Style::default().fg(Color::Cyan)
            ),
            Span::styled(
                format!("{:20} ", t.threat_type),
                Style::default().fg(Color::White)
            ),
            Span::styled(
                t.description.chars().take(50).collect::<String>(),
                Style::default().fg(SENTINEL_DIM)
            ),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .title(format!(" Threats ({}) ", state.threats.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(SENTINEL_DIM)));

    f.render_widget(list, area);
}

fn draw_logs(f: &mut Frame, area: Rect, state: &AppState, scroll: usize) {
    let items: Vec<ListItem> = state.logs.iter().skip(scroll).map(|entry| {
        let level_color = match entry.level.as_str() {
            "ERROR" => SENTINEL_RED,
            "WARN" => SENTINEL_YELLOW,
            "INFO" => SENTINEL_BLUE,
            "DEBUG" => SENTINEL_DIM,
            _ => Color::White,
        };

        ListItem::new(Line::from(vec![
            Span::styled(
                format!("[{}] ", entry.timestamp.format("%H:%M:%S")),
                Style::default().fg(SENTINEL_DIM)
            ),
            Span::styled(
                format!("{:5} ", entry.level),
                Style::default().fg(level_color).bold()
            ),
            Span::raw(&entry.message),
        ]))
    }).collect();

    let no_logs = items.is_empty();
    let list = List::new(if no_logs {
        vec![ListItem::new(Span::styled(
            "  No log entries yet. Events will appear here in real-time.",
            Style::default().fg(SENTINEL_DIM).italic()
        ))]
    } else {
        items
    })
    .block(Block::default()
        .title(" Event Log ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SENTINEL_DIM)));

    f.render_widget(list, area);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let help = Paragraph::new(Span::styled(
        "  q:quit  Tab/←→:tabs  1-5:tabs  j/k:scroll  r:refresh  ",
        Style::default().fg(SENTINEL_DIM)
    ));
    f.render_widget(help, area);
}

fn format_uptime(secs: i64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{}h", secs / 86400, (secs % 86400) / 3600)
    }
}

fn severity_color(severity: &str) -> Color {
    match severity.to_lowercase().as_str() {
        "critical" => SENTINEL_RED,
        "high" => Color::Rgb(255, 120, 0),
        "medium" => SENTINEL_YELLOW,
        "low" => SENTINEL_BLUE,
        _ => Color::White,
    }
}
