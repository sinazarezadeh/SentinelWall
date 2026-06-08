use std::net::IpAddr;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::config::ThreatIntelConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelEntry {
    pub ip: IpAddr,
    pub confidence: u8,
    pub categories: Vec<String>,
    pub source: String,
    pub last_reported: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct ThreatIntelFeed {
    config: ThreatIntelConfig,
    blocklist: Arc<RwLock<HashSet<IpAddr>>>,
    entries: Arc<RwLock<Vec<ThreatIntelEntry>>>,
    tor_exits: Arc<RwLock<HashSet<IpAddr>>>,
    http: Client,
}

impl ThreatIntelFeed {
    pub fn new(config: ThreatIntelConfig) -> Self {
        Self {
            config,
            blocklist: Arc::new(RwLock::new(HashSet::new())),
            entries: Arc::new(RwLock::new(Vec::new())),
            tor_exits: Arc::new(RwLock::new(HashSet::new())),
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent(format!("SentinelWall/{}", crate::VERSION))
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn start_updates(&self) {
        if !self.config.enabled {
            return;
        }

        info!("Starting threat intelligence feed updates");

        if self.config.tor_exit_nodes {
            self.update_tor_exits().await;
        }

        for url in &self.config.custom_blocklists {
            self.fetch_blocklist(url).await;
        }
    }

    pub async fn check_ip(&self, ip: IpAddr) -> Option<ThreatIntelEntry> {
        // Check local blocklist
        if self.blocklist.read().await.contains(&ip) {
            return Some(ThreatIntelEntry {
                ip,
                confidence: 100,
                categories: vec!["blocklist".to_string()],
                source: "local_blocklist".to_string(),
                last_reported: Some(chrono::Utc::now()),
            });
        }

        // Check TOR exits
        if self.config.tor_exit_nodes && self.tor_exits.read().await.contains(&ip) {
            return Some(ThreatIntelEntry {
                ip,
                confidence: 95,
                categories: vec!["tor_exit_node".to_string()],
                source: "tor_project".to_string(),
                last_reported: Some(chrono::Utc::now()),
            });
        }

        None
    }

    pub async fn query_abuseipdb(&self, ip: IpAddr) -> Option<ThreatIntelEntry> {
        let api_key = self.config.abuseipdb_api_key.as_ref()?;

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90&verbose",
            ip
        );

        let response = self.http.get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;

        let json: serde_json::Value = response.json().await.ok()?;
        let data = json.get("data")?;

        let confidence = data.get("abuseConfidenceScore")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        if confidence < self.config.abuseipdb_confidence_threshold {
            return None;
        }

        let categories = data.get("reports")
            .and_then(|r| r.as_array())
            .map(|reports| {
                reports.iter()
                    .filter_map(|r| r.get("categories"))
                    .filter_map(|c| c.as_array())
                    .flat_map(|c| c.iter())
                    .filter_map(|v| v.as_u64())
                    .map(|c| category_to_string(c))
                    .collect()
            })
            .unwrap_or_default();

        Some(ThreatIntelEntry {
            ip,
            confidence,
            categories,
            source: "abuseipdb".to_string(),
            last_reported: Some(chrono::Utc::now()),
        })
    }

    async fn update_tor_exits(&self) {
        debug!("Updating TOR exit node list");
        let url = "https://check.torproject.org/torbulkexitlist";

        match self.http.get(url).send().await {
            Ok(response) => {
                if let Ok(text) = response.text().await {
                    let mut exits = self.tor_exits.write().await;
                    exits.clear();
                    for line in text.lines() {
                        let line = line.trim();
                        if !line.is_empty() && !line.starts_with('#') {
                            if let Ok(ip) = line.parse::<IpAddr>() {
                                exits.insert(ip);
                            }
                        }
                    }
                    info!("Updated TOR exit list: {} nodes", exits.len());
                }
            }
            Err(e) => warn!("Failed to update TOR exit list: {}", e),
        }
    }

    async fn fetch_blocklist(&self, url: &str) {
        debug!("Fetching blocklist from {}", url);

        match self.http.get(url).send().await {
            Ok(response) => {
                if let Ok(text) = response.text().await {
                    let mut blocklist = self.blocklist.write().await;
                    let mut count = 0u32;
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let ip_str = line.split_whitespace().next().unwrap_or(line);
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            blocklist.insert(ip);
                            count += 1;
                        }
                    }
                    info!("Loaded {} IPs from blocklist {}", count, url);
                }
            }
            Err(e) => warn!("Failed to fetch blocklist {}: {}", url, e),
        }
    }

    pub fn blocked_count(&self) -> usize {
        self.blocklist.try_read().map(|b| b.len()).unwrap_or(0)
    }

    pub fn tor_exit_count(&self) -> usize {
        self.tor_exits.try_read().map(|t| t.len()).unwrap_or(0)
    }
}

fn category_to_string(cat: u64) -> String {
    match cat {
        3 => "fraud_orders".to_string(),
        4 => "ddos_attack".to_string(),
        5 => "ftp_brute_force".to_string(),
        6 => "ping_of_death".to_string(),
        7 => "phishing".to_string(),
        8 => "fraud_voip".to_string(),
        9 => "open_proxy".to_string(),
        10 => "web_spam".to_string(),
        11 => "email_spam".to_string(),
        12 => "blog_spam".to_string(),
        13 => "vpn_ip".to_string(),
        14 => "port_scan".to_string(),
        15 => "hacking".to_string(),
        16 => "sql_injection".to_string(),
        17 => "spoofing".to_string(),
        18 => "brute_force".to_string(),
        19 => "bad_web_bot".to_string(),
        20 => "exploited_host".to_string(),
        21 => "web_app_attack".to_string(),
        22 => "ssh".to_string(),
        23 => "iot_targeted".to_string(),
        _ => format!("category_{}", cat),
    }
}
