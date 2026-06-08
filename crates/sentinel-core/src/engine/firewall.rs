use std::sync::Arc;
use std::net::IpAddr;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};
use anyhow::Result;
use chrono::Utc;

use crate::config::{SentinelConfig, FirewallBackend};
use crate::rules::{RuleEngine, Rule, RuleId, BannedIp, BanReason};
use crate::nftables::NftablesManager;
use crate::detection::{ThreatAnalyzer, ThreatEvent, RecommendedAction, Severity};
use crate::events::{Event, EventBus};
use crate::metrics::MetricsCollector;

pub struct FirewallEngine {
    config: Arc<RwLock<SentinelConfig>>,
    rules: Arc<RuleEngine>,
    nft: Arc<NftablesManager>,
    detector: Arc<ThreatAnalyzer>,
    metrics: Arc<MetricsCollector>,
    event_bus: Arc<EventBus>,
    start_time: chrono::DateTime<Utc>,
}

impl FirewallEngine {
    pub async fn new(config: SentinelConfig) -> Result<Arc<Self>> {
        info!("Initializing SentinelWall Firewall Engine v{}", crate::VERSION);

        let event_bus = EventBus::new(4096);
        let metrics = MetricsCollector::new()?;

        let nft = Arc::new(NftablesManager::new()
            .with_dry_run(!cfg!(target_os = "linux")));

        let rules = Arc::new(RuleEngine::new(event_bus.clone(), nft.clone()));

        let detector = Arc::new(ThreatAnalyzer::new(
            config.detection.clone(),
            event_bus.clone(),
        ));

        // Check backend availability
        match config.core.backend {
            FirewallBackend::Nftables => {
                if nft.is_available().await {
                    info!("nftables backend available");
                    nft.init().await.unwrap_or_else(|e| {
                        warn!("nftables init warning: {} (may already be initialized)", e);
                    });
                } else {
                    warn!("nftables not available - running in dry-run mode");
                }
            }
            FirewallBackend::Iptables => {
                warn!("iptables backend selected (nftables preferred)");
            }
            FirewallBackend::Hybrid => {
                info!("Hybrid backend: nftables primary, iptables fallback");
            }
        }

        // Record daemon info metric
        metrics.daemon_info
            .with_label_values(&[crate::VERSION, "nftables"])
            .set(1.0);

        let engine = Arc::new(Self {
            config: Arc::new(RwLock::new(config)),
            rules,
            nft,
            detector,
            metrics,
            event_bus,
            start_time: Utc::now(),
        });

        Ok(engine)
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting firewall engine");

        // Load default rules from profile if configured
        {
            let config = self.config.read().await;
            if let Some(profile_name) = &config.core.profile {
                info!("Applying profile: {}", profile_name);
                if let Ok(profile) = profile_name.parse() {
                    let profile_rules = crate::rules::ProfileManager::get_rules(&profile);
                    for rule in profile_rules {
                        self.rules.add_rule(rule).await
                            .unwrap_or_else(|e| {
                                warn!("Failed to add profile rule: {}", e);
                                crate::rules::RuleId::new()
                            });
                    }
                }
            }
        }

        self.event_bus.emit(Event::DaemonStarted {
            version: crate::VERSION.to_string()
        }).await;

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping firewall engine");
        self.event_bus.emit(Event::DaemonStopping).await;
        Ok(())
    }

    pub async fn add_rule(&self, rule: Rule) -> Result<RuleId> {
        self.rules.add_rule(rule).await
    }

    pub async fn remove_rule(&self, id: &RuleId) -> Result<bool> {
        self.rules.remove_rule(id).await
    }

    pub async fn get_rules(&self) -> Vec<Rule> {
        self.rules.get_rules().await
    }

    pub async fn ban_ip(
        &self,
        ip: IpAddr,
        reason: BanReason,
        duration_secs: Option<u64>,
        evidence: Vec<String>,
    ) -> Result<()> {
        let config = self.config.read().await;
        let max_duration = config.response.max_ban_duration_secs;
        drop(config);

        let expires_at = duration_secs.map(|d| {
            Utc::now() + chrono::Duration::seconds(d.min(max_duration) as i64)
        });

        let ban = BannedIp {
            ip,
            reason: reason.clone(),
            banned_at: Utc::now(),
            expires_at,
            ban_count: 1,
            source: "engine".to_string(),
            evidence,
        };

        self.rules.ban_ip(ip, ban).await?;
        self.metrics.record_ban(&reason.to_string());

        Ok(())
    }

    pub async fn unban_ip(&self, ip: &IpAddr) -> Result<bool> {
        let result = self.rules.unban_ip(ip).await?;
        if result {
            self.metrics.record_unban();
        }
        Ok(result)
    }

    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        self.rules.is_banned(ip)
    }

    pub async fn get_banned_ips(&self) -> Vec<BannedIp> {
        self.rules.get_banned_ips().await
    }

    pub async fn handle_threat(&self, threat: ThreatEvent) -> Result<()> {
        let config = self.config.read().await;
        if !config.response.auto_ban {
            debug!("Auto-ban disabled, threat recorded but not acted upon");
            return Ok(());
        }

        let should_ban = matches!(
            threat.recommended_action,
            RecommendedAction::Block | RecommendedAction::BlockPermanent | RecommendedAction::Quarantine
        );

        if !should_ban {
            return Ok(());
        }

        let reason = match &threat.threat_type {
            crate::detection::ThreatType::BruteForce => BanReason::BruteForce,
            crate::detection::ThreatType::PortScan | crate::detection::ThreatType::StealthScan => BanReason::PortScan,
            crate::detection::ThreatType::SynFlood => BanReason::SynFlood,
            crate::detection::ThreatType::UdpFlood => BanReason::UdpFlood,
            crate::detection::ThreatType::HttpFlood => BanReason::HttpFlood,
            crate::detection::ThreatType::DdosIndicator => BanReason::DdosIndicator,
            crate::detection::ThreatType::TorExitNode => BanReason::ThreatIntel,
            crate::detection::ThreatType::AbuseipdbMatch => BanReason::ThreatIntel,
            crate::detection::ThreatType::AnomalyDetected => BanReason::MlDetection,
            _ => BanReason::PolicyViolation,
        };

        let duration = match (&threat.severity, threat.ttl_seconds) {
            (_, Some(ttl)) => Some(ttl),
            (Severity::Critical, _) => Some(86400 * 7),
            (Severity::High, _) => Some(86400),
            (Severity::Medium, _) => Some(3600),
            (Severity::Low, _) => Some(600),
        };

        self.ban_ip(threat.ip, reason, duration, threat.evidence.clone()).await?;

        self.metrics.record_threat(
            &threat.threat_type.to_string(),
            &threat.severity.to_string(),
        );

        Ok(())
    }

    pub async fn apply_profile(&self, profile: &crate::config::types::FirewallProfile) -> Result<()> {
        info!("Applying profile: {}", profile);
        let rules = crate::rules::ProfileManager::get_rules(profile);
        let count = rules.len();

        for rule in rules {
            self.add_rule(rule).await?;
        }

        self.event_bus.emit(Event::ProfileApplied { profile: profile.to_string() }).await;
        info!("Applied {} rules from profile {}", count, profile);
        Ok(())
    }

    pub async fn reload_config(&self, new_config: SentinelConfig) -> Result<()> {
        info!("Reloading configuration");
        new_config.validate()?;
        {
            let mut config = self.config.write().await;
            *config = new_config;
        }
        self.event_bus.emit(Event::ConfigReloaded).await;
        Ok(())
    }

    pub async fn flush_rules(&self) -> Result<()> {
        self.rules.flush_rules().await
    }

    pub fn metrics(&self) -> Arc<MetricsCollector> {
        self.metrics.clone()
    }

    pub fn event_bus(&self) -> Arc<EventBus> {
        self.event_bus.clone()
    }

    pub fn uptime_seconds(&self) -> i64 {
        (Utc::now() - self.start_time).num_seconds()
    }

    pub async fn start_background_tasks(self: &Arc<Self>) {
        // Ban cleanup task
        let engine = self.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                engine.rules.cleanup_expired_bans().await;
                engine.metrics.daemon_uptime_seconds.set(engine.uptime_seconds());
            }
        });

        // Threat detection cleanup
        let detector = self.detector.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                detector.cleanup_old_data().await;
            }
        });

        info!("Background tasks started");
    }
}
