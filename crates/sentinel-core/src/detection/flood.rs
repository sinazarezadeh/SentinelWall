use std::net::IpAddr;
use dashmap::DashMap;
use chrono::{DateTime, Utc};
use tracing::warn;

use super::{ThreatEvent, ThreatType, Severity, RecommendedAction};
use crate::config::FloodConfig;

pub struct FloodDetector {
    config: FloodConfig,
    pps_tracker: DashMap<(IpAddr, String), Vec<DateTime<Utc>>>,
}

impl FloodDetector {
    pub fn new(config: FloodConfig) -> Self {
        Self {
            config,
            pps_tracker: DashMap::new(),
        }
    }

    pub async fn check(
        &self,
        ip: IpAddr,
        protocol: &str,
        pps: u64,
        _now: DateTime<Utc>,
    ) -> Option<ThreatEvent> {
        if !self.config.enabled {
            return None;
        }

        let threshold = match protocol.to_lowercase().as_str() {
            "tcp" | "syn" => self.config.syn_pps_threshold,
            "udp" => self.config.udp_pps_threshold,
            "icmp" => self.config.icmp_pps_threshold,
            "http" => self.config.http_rps_threshold,
            _ => self.config.syn_pps_threshold,
        };

        if pps >= threshold {
            warn!("Flood detected from {}: {} {} pps (threshold: {})",
                ip, pps, protocol, threshold);

            let (threat_type, severity) = self.classify_flood(protocol, pps, threshold);

            return Some(ThreatEvent::new(ip, threat_type, severity)
                .with_description(format!(
                    "{} flood detected from {}: {} pps (threshold: {} pps)",
                    protocol.to_uppercase(), ip, pps, threshold
                ))
                .with_evidence(vec![
                    format!("protocol={}", protocol),
                    format!("pps={}", pps),
                    format!("threshold={}", threshold),
                    format!("multiplier={:.1}x", pps as f64 / threshold as f64),
                ])
                .with_action(RecommendedAction::Block)
                .with_ttl(self.config.ban_duration_seconds));
        }

        None
    }

    fn classify_flood(&self, protocol: &str, pps: u64, threshold: u64) -> (ThreatType, Severity) {
        let ratio = pps as f64 / threshold as f64;
        let severity = if ratio >= 10.0 {
            Severity::Critical
        } else if ratio >= 5.0 {
            Severity::High
        } else if ratio >= 2.0 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let threat_type = match protocol.to_lowercase().as_str() {
            "tcp" | "syn" => ThreatType::SynFlood,
            "udp" => ThreatType::UdpFlood,
            "icmp" => ThreatType::IcmpFlood,
            "http" => ThreatType::HttpFlood,
            _ => ThreatType::DdosIndicator,
        };

        (threat_type, severity)
    }
}
