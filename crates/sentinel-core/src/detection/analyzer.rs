use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use chrono::{DateTime, Utc, Duration};
use dashmap::DashMap;

use super::{ThreatEvent, ThreatType, Severity, RecommendedAction};
use super::brute_force::BruteForceDetector;
use super::port_scan::PortScanDetector;
use super::flood::FloodDetector;
use crate::config::DetectionConfig;
use crate::events::{Event, EventBus};

#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub ip: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Default)]
pub struct IpStats {
    pub connection_count: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub last_seen: Option<DateTime<Utc>>,
    pub ports_accessed: std::collections::HashSet<u16>,
    pub failed_auths: u32,
    pub threat_score: f64,
}

pub struct ThreatAnalyzer {
    config: DetectionConfig,
    brute_force: BruteForceDetector,
    port_scan: PortScanDetector,
    flood: FloodDetector,
    ip_stats: Arc<DashMap<IpAddr, IpStats>>,
    connection_window: Arc<RwLock<Vec<ConnectionRecord>>>,
    event_bus: Arc<EventBus>,
    threat_history: Arc<DashMap<IpAddr, Vec<ThreatEvent>>>,
}

impl ThreatAnalyzer {
    pub fn new(config: DetectionConfig, event_bus: Arc<EventBus>) -> Self {
        Self {
            brute_force: BruteForceDetector::new(config.brute_force.clone()),
            port_scan: PortScanDetector::new(config.port_scan.clone()),
            flood: FloodDetector::new(config.flood.clone()),
            config,
            ip_stats: Arc::new(DashMap::new()),
            connection_window: Arc::new(RwLock::new(Vec::new())),
            event_bus,
            threat_history: Arc::new(DashMap::new()),
        }
    }

    pub async fn analyze_connection(&self, ip: IpAddr, port: u16, _protocol: &str) -> Vec<ThreatEvent> {
        if !self.config.enabled {
            return vec![];
        }

        let mut threats = Vec::new();
        let now = Utc::now();

        // Update IP stats
        {
            let mut stats = self.ip_stats.entry(ip).or_default();
            stats.connection_count += 1;
            stats.last_seen = Some(now);
            stats.ports_accessed.insert(port);
        }

        // Connection rate check
        if let Some(threat) = self.check_connection_rate(ip, now).await {
            threats.push(threat);
        }

        // Port scan detection
        if let Some(threat) = self.port_scan.check(ip, port, now).await {
            threats.push(threat);
        }

        // Record and emit
        for threat in &threats {
            self.record_threat(ip, threat.clone());
            self.event_bus.emit(Event::ThreatDetected(threat.clone())).await;
        }

        threats
    }

    pub async fn analyze_auth_failure(&self, ip: IpAddr, service: &str, port: u16) -> Option<ThreatEvent> {
        if !self.config.enabled || !self.config.brute_force.enabled {
            return None;
        }

        let now = Utc::now();
        {
            let mut stats = self.ip_stats.entry(ip).or_default();
            stats.failed_auths += 1;
        }

        let threat = self.brute_force.check(ip, service, port, now).await?;
        self.record_threat(ip, threat.clone());
        self.event_bus.emit(Event::ThreatDetected(threat.clone())).await;
        Some(threat)
    }

    pub async fn analyze_packet_rate(&self, ip: IpAddr, protocol: &str, pps: u64) -> Option<ThreatEvent> {
        if !self.config.enabled || !self.config.flood.enabled {
            return None;
        }

        let threat = self.flood.check(ip, protocol, pps, Utc::now()).await?;
        self.record_threat(ip, threat.clone());
        self.event_bus.emit(Event::ThreatDetected(threat.clone())).await;
        Some(threat)
    }

    async fn check_connection_rate(&self, ip: IpAddr, _now: DateTime<Utc>) -> Option<ThreatEvent> {
        let stats = self.ip_stats.get(&ip)?;
        let max = self.config.max_connections_per_ip as u64;

        if stats.connection_count > max {
            let threat = ThreatEvent::new(ip, ThreatType::ConnectionBurst, Severity::High)
                .with_description(format!(
                    "IP {} exceeded max connections per IP: {} > {}",
                    ip, stats.connection_count, max
                ))
                .with_action(RecommendedAction::RateLimit);
            return Some(threat);
        }

        None
    }

    pub fn get_ip_stats(&self, ip: &IpAddr) -> Option<dashmap::mapref::one::Ref<'_, IpAddr, IpStats>> {
        self.ip_stats.get(ip)
    }

    pub fn get_threat_history(&self, ip: &IpAddr) -> Vec<ThreatEvent> {
        self.threat_history.get(ip)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    pub fn get_threat_score(&self, ip: &IpAddr) -> f64 {
        let stats = self.ip_stats.get(ip);
        stats.map(|s| s.threat_score).unwrap_or(0.0)
    }

    pub async fn cleanup_old_data(&self) {
        let cutoff = Utc::now() - Duration::hours(24);

        // Clean connection window
        {
            let mut window = self.connection_window.write().await;
            window.retain(|c| c.timestamp > cutoff);
        }

        // Clean old threat history
        self.threat_history.retain(|_, events| {
            events.retain(|e| e.timestamp > cutoff);
            !events.is_empty()
        });

        // Clean inactive IP stats
        self.ip_stats.retain(|_, stats| {
            stats.last_seen.map(|t| t > cutoff).unwrap_or(false)
        });

        debug!("Cleaned up old detection data");
    }

    fn record_threat(&self, ip: IpAddr, threat: ThreatEvent) {
        let mut history = self.threat_history.entry(ip).or_default();
        history.push(threat.clone());
        if history.len() > 100 {
            history.remove(0);
        }

        // Update threat score
        if let Some(mut stats) = self.ip_stats.get_mut(&ip) {
            let severity_score = match threat.severity {
                Severity::Low => 0.25,
                Severity::Medium => 0.5,
                Severity::High => 0.75,
                Severity::Critical => 1.0,
            };
            stats.threat_score = (stats.threat_score + severity_score * threat.confidence).min(10.0);
        }
    }
}
