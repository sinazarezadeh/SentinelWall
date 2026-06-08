use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use crate::state::AppState;
use crate::fetch::ApiClient;
use crate::ui;

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Dashboard,
    Rules,
    Bans,
    Threats,
    Logs,
}

impl Tab {
    pub fn next(&self) -> Self {
        match self {
            Tab::Dashboard => Tab::Rules,
            Tab::Rules => Tab::Bans,
            Tab::Bans => Tab::Threats,
            Tab::Threats => Tab::Logs,
            Tab::Logs => Tab::Dashboard,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            Tab::Dashboard => Tab::Logs,
            Tab::Rules => Tab::Dashboard,
            Tab::Bans => Tab::Rules,
            Tab::Threats => Tab::Bans,
            Tab::Logs => Tab::Threats,
        }
    }
}

pub struct App {
    api: Arc<ApiClient>,
    state: Arc<RwLock<AppState>>,
    refresh_ms: u64,
}

impl App {
    pub fn new(api_url: String, token: Option<String>, refresh_ms: u64) -> Self {
        Self {
            api: Arc::new(ApiClient::new(api_url, token)),
            state: Arc::new(RwLock::new(AppState::default())),
            refresh_ms,
        }
    }

    pub async fn run(self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = self.event_loop(&mut terminal).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        result
    }

    async fn event_loop(&self, terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
        let mut current_tab = Tab::Dashboard;
        let mut scroll_offset: usize = 0;
        let _refresh_duration = Duration::from_millis(self.refresh_ms);

        // Start background refresh
        let state = self.state.clone();
        let api = self.api.clone();
        let refresh_ms = self.refresh_ms;
        tokio::spawn(async move {
            background_refresh(api, state, refresh_ms).await;
        });

        loop {
            // Draw UI
            {
                let state = self.state.read().await;
                let tab = current_tab.clone();
                terminal.draw(|f| ui::draw(f, &state, &tab, scroll_offset))?;
            }

            // Handle input
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            break;
                        }
                        (KeyCode::Tab, _) | (KeyCode::Right, _) => {
                            current_tab = current_tab.next();
                            scroll_offset = 0;
                        }
                        (KeyCode::BackTab, _) | (KeyCode::Left, _) => {
                            current_tab = current_tab.prev();
                            scroll_offset = 0;
                        }
                        (KeyCode::Char('1'), _) => current_tab = Tab::Dashboard,
                        (KeyCode::Char('2'), _) => current_tab = Tab::Rules,
                        (KeyCode::Char('3'), _) => current_tab = Tab::Bans,
                        (KeyCode::Char('4'), _) => current_tab = Tab::Threats,
                        (KeyCode::Char('5'), _) => current_tab = Tab::Logs,
                        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                            scroll_offset = scroll_offset.saturating_add(1);
                        }
                        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                            scroll_offset = scroll_offset.saturating_sub(1);
                        }
                        (KeyCode::PageDown, _) => {
                            scroll_offset = scroll_offset.saturating_add(10);
                        }
                        (KeyCode::PageUp, _) => {
                            scroll_offset = scroll_offset.saturating_sub(10);
                        }
                        (KeyCode::Char('r'), _) => {
                            // Force refresh
                            let api = self.api.clone();
                            let state = self.state.clone();
                            tokio::spawn(async move {
                                do_refresh(&api, &state).await;
                            });
                        }
                        _ => {}
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }
}

async fn background_refresh(api: Arc<ApiClient>, state: Arc<RwLock<AppState>>, refresh_ms: u64) {
    let mut tick = tokio::time::interval(Duration::from_millis(refresh_ms));
    loop {
        tick.tick().await;
        do_refresh(&api, &state).await;
    }
}

async fn do_refresh(api: &ApiClient, state: &RwLock<AppState>) {
    let connected = api.check_connection().await;
    if !connected {
        let mut s = state.write().await;
        s.connected = false;
        s.error = Some("Cannot connect to sentineld".to_string());
        return;
    }

    let mut s = state.write().await;
    s.error = None;

    if let Ok(status) = api.get_status().await {
        let status_data = if status["data"].is_object() { status["data"].clone() } else { status };
        s.update_from_status(&status_data);
    }

    if let Ok(rules) = api.get_rules().await {
        s.rules = rules;
    }

    if let Ok(bans) = api.get_bans().await {
        s.bans = bans;
    }
}
