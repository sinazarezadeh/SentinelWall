use std::net::IpAddr;
use std::collections::VecDeque;
use dashmap::DashMap;
use tracing::debug;

use super::{ThreatEvent, ThreatType, Severity, RecommendedAction};

const BASELINE_WINDOW: usize = 1000;
const ANOMALY_SIGMA_THRESHOLD: f64 = 3.0;

#[derive(Debug, Default)]
struct ConnectionMetrics {
    samples: VecDeque<f64>,
    mean: f64,
    variance: f64,
    total: u64,
}

impl ConnectionMetrics {
    fn update(&mut self, value: f64) {
        self.total += 1;
        self.samples.push_back(value);
        if self.samples.len() > BASELINE_WINDOW {
            self.samples.pop_front();
        }
        self.recalculate();
    }

    fn recalculate(&mut self) {
        let n = self.samples.len() as f64;
        if n < 10.0 {
            return;
        }
        self.mean = self.samples.iter().sum::<f64>() / n;
        self.variance = self.samples.iter()
            .map(|x| (x - self.mean).powi(2))
            .sum::<f64>() / n;
    }

    fn std_dev(&self) -> f64 {
        self.variance.sqrt()
    }

    fn is_anomaly(&self, value: f64) -> Option<f64> {
        let std = self.std_dev();
        if std < 0.001 || self.samples.len() < 30 {
            return None;
        }
        let z_score = (value - self.mean).abs() / std;
        if z_score > ANOMALY_SIGMA_THRESHOLD {
            Some(z_score)
        } else {
            None
        }
    }
}

pub struct AnomalyDetector {
    global_metrics: ConnectionMetrics,
    per_ip_metrics: DashMap<IpAddr, ConnectionMetrics>,
    enabled: bool,
}

impl AnomalyDetector {
    pub fn new(enabled: bool) -> Self {
        Self {
            global_metrics: ConnectionMetrics::default(),
            per_ip_metrics: DashMap::new(),
            enabled,
        }
    }

    pub fn record_connection_rate(&mut self, ip: IpAddr, connections_per_sec: f64) {
        if !self.enabled {
            return;
        }
        self.global_metrics.update(connections_per_sec);
        self.per_ip_metrics.entry(ip).or_default().update(connections_per_sec);
    }

    pub fn check_anomaly(&self, ip: IpAddr, connections_per_sec: f64) -> Option<ThreatEvent> {
        if !self.enabled {
            return None;
        }

        let ip_metrics = self.per_ip_metrics.get(&ip)?;

        if let Some(z_score) = ip_metrics.is_anomaly(connections_per_sec) {
            let confidence = (z_score / 10.0).min(1.0);
            debug!("Anomaly detected for {}: z_score={:.2}, connections/s={:.2}", ip, z_score, connections_per_sec);

            let severity = if z_score > 8.0 {
                Severity::Critical
            } else if z_score > 6.0 {
                Severity::High
            } else if z_score > 4.0 {
                Severity::Medium
            } else {
                Severity::Low
            };

            return Some(ThreatEvent::new(ip, ThreatType::AnomalyDetected, severity)
                .with_description(format!(
                    "Statistical anomaly: connection rate {:.1}/s is {:.1}σ above baseline ({:.1}/s ± {:.1})",
                    connections_per_sec,
                    z_score,
                    ip_metrics.mean,
                    ip_metrics.std_dev()
                ))
                .with_confidence(confidence)
                .with_evidence(vec![
                    format!("z_score={:.2}", z_score),
                    format!("baseline_mean={:.2}", ip_metrics.mean),
                    format!("baseline_std={:.2}", ip_metrics.std_dev()),
                    format!("observed={:.2}", connections_per_sec),
                ])
                .with_action(if z_score > 6.0 {
                    RecommendedAction::Block
                } else {
                    RecommendedAction::RateLimit
                }));
        }

        None
    }

    pub fn get_baseline(&self, ip: &IpAddr) -> Option<(f64, f64)> {
        let metrics = self.per_ip_metrics.get(ip)?;
        Some((metrics.mean, metrics.std_dev()))
    }
}
