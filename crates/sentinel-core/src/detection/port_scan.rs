use std::net::IpAddr;
use std::collections::HashSet;
use dashmap::DashMap;
use chrono::{DateTime, Utc, Duration};
use tracing::warn;

use super::{ThreatEvent, ThreatType, Severity, RecommendedAction};
use crate::config::PortScanConfig;

struct ScanRecord {
    timestamp: DateTime<Utc>,
    port: u16,
}

pub struct PortScanDetector {
    config: PortScanConfig,
    scan_records: DashMap<IpAddr, Vec<ScanRecord>>,
}

impl PortScanDetector {
    pub fn new(config: PortScanConfig) -> Self {
        Self {
            config,
            scan_records: DashMap::new(),
        }
    }

    pub async fn check(
        &self,
        ip: IpAddr,
        port: u16,
        now: DateTime<Utc>,
    ) -> Option<ThreatEvent> {
        if !self.config.enabled {
            return None;
        }

        let window = Duration::seconds(self.config.window_seconds as i64);
        let cutoff = now - window;

        let mut records = self.scan_records.entry(ip).or_default();
        records.retain(|r| r.timestamp > cutoff);
        records.push(ScanRecord { timestamp: now, port });

        let unique_ports: HashSet<u16> = records.iter().map(|r| r.port).collect();
        let port_count = unique_ports.len() as u32;
        let threshold = self.config.threshold_ports_per_second
            * self.config.window_seconds as u32;

        if port_count >= threshold {
            warn!("Port scan detected from {}: {} unique ports in {}s",
                ip, port_count, self.config.window_seconds);

            let severity = if port_count >= threshold * 3 {
                Severity::Critical
            } else if port_count >= threshold * 2 {
                Severity::High
            } else {
                Severity::Medium
            };

            let is_stealth = self.detect_stealth_scan(&records);
            let threat_type = if is_stealth {
                ThreatType::StealthScan
            } else {
                ThreatType::PortScan
            };

            return Some(ThreatEvent::new(ip, threat_type, severity)
                .with_description(format!(
                    "Port scan detected: {} unique ports probed in {}s{}",
                    port_count,
                    self.config.window_seconds,
                    if is_stealth { " (stealth/SYN scan pattern)" } else { "" }
                ))
                .with_evidence(vec![
                    format!("unique_ports={}", port_count),
                    format!("threshold={}", threshold),
                    format!("window_seconds={}", self.config.window_seconds),
                    format!("stealth={}", is_stealth),
                ])
                .with_action(RecommendedAction::Block)
                .with_ttl(self.config.ban_duration_seconds));
        }

        None
    }

    fn detect_stealth_scan(&self, records: &[ScanRecord]) -> bool {
        // Stealth scans often probe well-known ports in sequential or random order
        // with very short intervals between probes
        if records.len() < 10 {
            return false;
        }

        // Check if ports are being probed in very rapid succession (< 10ms between)
        let mut rapid_count = 0;
        for window in records.windows(2) {
            let delta = (window[1].timestamp - window[0].timestamp).num_milliseconds();
            if delta < 10 {
                rapid_count += 1;
            }
        }

        rapid_count > records.len() / 2
    }
}
