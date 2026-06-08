use serde_json::Value;
use std::collections::VecDeque;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub struct AppState {
    pub status: StatusState,
    pub rules: Vec<Value>,
    pub bans: Vec<Value>,
    pub threats: VecDeque<ThreatEntry>,
    pub logs: VecDeque<LogEntry>,
    pub stats: StatsState,
    pub last_updated: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub connected: bool,
}

#[derive(Debug, Clone, Default)]
pub struct StatusState {
    pub version: String,
    pub uptime_seconds: i64,
    pub rules_count: u64,
    pub bans_count: u64,
    pub backend: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct ThreatEntry {
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub threat_type: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct StatsState {
    pub connections_per_sec: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_dropped: u64,
    pub threat_history: VecDeque<f64>,
    pub ban_history: VecDeque<f64>,
}

impl AppState {
    pub fn update_from_status(&mut self, status: &Value) {
        self.status.version = status["version"].as_str().unwrap_or("?").to_string();
        self.status.uptime_seconds = status["uptime_seconds"].as_i64().unwrap_or(0);
        self.status.rules_count = status["rules_count"].as_u64().unwrap_or(0);
        self.status.bans_count = status["bans_count"].as_u64().unwrap_or(0);
        self.status.backend = status["backend"].as_str().unwrap_or("nftables").to_string();
        self.status.status = status["status"].as_str().unwrap_or("?").to_string();
        self.connected = true;
        self.last_updated = Some(Utc::now());

        // Update sparkline history
        let bans = self.status.bans_count as f64;
        self.stats.ban_history.push_back(bans);
        if self.stats.ban_history.len() > 60 {
            self.stats.ban_history.pop_front();
        }
    }

    pub fn add_threat(&mut self, threat: ThreatEntry) {
        self.threats.push_front(threat);
        if self.threats.len() > 100 {
            self.threats.pop_back();
        }
    }

    pub fn add_log(&mut self, entry: LogEntry) {
        self.logs.push_front(entry);
        if self.logs.len() > 200 {
            self.logs.pop_back();
        }
    }
}
