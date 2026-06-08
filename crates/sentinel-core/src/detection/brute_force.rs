use std::net::IpAddr;
use dashmap::DashMap;
use chrono::{DateTime, Utc, Duration};
use tracing::warn;

use super::{ThreatEvent, ThreatType, Severity, RecommendedAction};
use crate::config::BruteForceConfig;

struct AuthAttempt {
    timestamp: DateTime<Utc>,
    service: String,
}

pub struct BruteForceDetector {
    config: BruteForceConfig,
    attempts: DashMap<IpAddr, Vec<AuthAttempt>>,
    ban_counts: DashMap<IpAddr, u32>,
}

impl BruteForceDetector {
    pub fn new(config: BruteForceConfig) -> Self {
        Self {
            config,
            attempts: DashMap::new(),
            ban_counts: DashMap::new(),
        }
    }

    pub async fn check(
        &self,
        ip: IpAddr,
        service: &str,
        _port: u16,
        now: DateTime<Utc>,
    ) -> Option<ThreatEvent> {
        if !self.config.enabled {
            return None;
        }

        let window = Duration::seconds(self.config.window_seconds as i64);
        let cutoff = now - window;

        let mut attempts = self.attempts.entry(ip).or_default();
        attempts.retain(|a| a.timestamp > cutoff);
        attempts.push(AuthAttempt {
            timestamp: now,
            service: service.to_string(),
        });

        let count = attempts.len() as u32;
        drop(attempts);

        if count >= self.config.max_attempts {
            warn!("Brute force detected from {}: {} attempts in {}s on {}",
                ip, count, self.config.window_seconds, service);

            let ban_count = *self.ban_counts.entry(ip).or_insert(0);
            let ban_duration = (self.config.ban_duration_seconds as f64
                * self.config.escalation_multiplier.powi(ban_count as i32)) as u64;

            *self.ban_counts.entry(ip).or_insert(0) += 1;

            let severity = if count >= self.config.max_attempts * 3 {
                Severity::Critical
            } else if count >= self.config.max_attempts * 2 {
                Severity::High
            } else {
                Severity::Medium
            };

            let action = if ban_count >= 3 {
                RecommendedAction::BlockPermanent
            } else {
                RecommendedAction::Block
            };

            return Some(ThreatEvent::new(ip, ThreatType::BruteForce, severity)
                .with_description(format!(
                    "Brute force detected: {} failed authentication attempts on {} in {}s (ban #{}, duration: {}s)",
                    count, service, self.config.window_seconds, ban_count + 1, ban_duration
                ))
                .with_evidence(vec![
                    format!("attempts_count={}", count),
                    format!("service={}", service),
                    format!("window_seconds={}", self.config.window_seconds),
                    format!("ban_count={}", ban_count),
                ])
                .with_action(action)
                .with_ttl(ban_duration));
        }

        None
    }

    pub fn reset(&self, ip: &IpAddr) {
        self.attempts.remove(ip);
        self.ban_counts.remove(ip);
    }
}
