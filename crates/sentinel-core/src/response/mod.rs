use std::net::IpAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{info, warn};
use reqwest::Client;
use serde_json::json;

use crate::config::ResponseConfig;
use crate::detection::{ThreatEvent, Severity, RecommendedAction};

pub struct ResponseManager {
    config: ResponseConfig,
    http: Client,
    quarantine_ips: Arc<RwLock<HashMap<IpAddr, QuarantineEntry>>>,
}

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub since: chrono::DateTime<chrono::Utc>,
}

impl ResponseManager {
    pub fn new(config: ResponseConfig) -> Self {
        Self {
            config,
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            quarantine_ips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn handle(&self, threat: &ThreatEvent) -> ResponseAction {
        match &threat.recommended_action {
            RecommendedAction::Monitor => ResponseAction::Log,
            RecommendedAction::RateLimit => ResponseAction::RateLimit,
            RecommendedAction::Block => {
                let duration = self.calculate_ban_duration(threat);
                ResponseAction::Ban { duration_secs: duration }
            }
            RecommendedAction::BlockPermanent => ResponseAction::BanPermanent,
            RecommendedAction::Quarantine => {
                self.quarantine(threat.ip, &threat.description).await;
                ResponseAction::Quarantine
            }
            RecommendedAction::Challenge => ResponseAction::Challenge,
            RecommendedAction::Alert => {
                self.send_alert(threat).await;
                ResponseAction::Log
            }
        }
    }

    fn calculate_ban_duration(&self, threat: &ThreatEvent) -> u64 {
        if let Some(ttl) = threat.ttl_seconds {
            return ttl;
        }
        match threat.severity {
            Severity::Low => 600,
            Severity::Medium => 3600,
            Severity::High => 86400,
            Severity::Critical => 86400 * 7,
        }
    }

    async fn quarantine(&self, ip: IpAddr, reason: &str) {
        info!("Quarantining IP: {}", ip);
        let mut map = self.quarantine_ips.write().await;
        map.insert(ip, QuarantineEntry {
            ip,
            reason: reason.to_string(),
            since: chrono::Utc::now(),
        });
    }

    pub fn is_quarantined(&self, ip: &IpAddr) -> bool {
        self.quarantine_ips.try_read()
            .map(|q| q.contains_key(ip))
            .unwrap_or(false)
    }

    async fn send_alert(&self, threat: &ThreatEvent) {
        if let Some(webhook_url) = &self.config.notify_webhook {
            let payload = json!({
                "threat_type": threat.threat_type.to_string(),
                "ip": threat.ip.to_string(),
                "severity": threat.severity.to_string(),
                "description": threat.description,
                "timestamp": threat.timestamp.to_rfc3339(),
            });

            if let Err(e) = self.http.post(webhook_url)
                .json(&payload)
                .send()
                .await
            {
                warn!("Failed to send alert webhook: {}", e);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResponseAction {
    Log,
    RateLimit,
    Ban { duration_secs: u64 },
    BanPermanent,
    Quarantine,
    Challenge,
}
