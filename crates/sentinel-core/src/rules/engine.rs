use std::net::IpAddr;
use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use anyhow::Result;
use chrono::Utc;

use super::types::*;
use crate::events::{Event, EventBus};
use crate::nftables::NftablesManager;

pub struct RuleEngine {
    rules: Arc<RwLock<RuleSet>>,
    banned_ips: Arc<DashMap<IpAddr, BannedIp>>,
    event_bus: Arc<EventBus>,
    nft: Arc<NftablesManager>,
}

impl RuleEngine {
    pub fn new(event_bus: Arc<EventBus>, nft: Arc<NftablesManager>) -> Self {
        Self {
            rules: Arc::new(RwLock::new(RuleSet::new())),
            banned_ips: Arc::new(DashMap::new()),
            event_bus,
            nft,
        }
    }

    pub async fn add_rule(&self, rule: Rule) -> Result<RuleId> {
        let id = rule.id.clone();
        info!("Adding rule: {} (id={})", rule.name, id);

        {
            let mut rules = self.rules.write().await;
            rules.add(rule.clone());
        }

        self.nft.apply_rule(&rule).await?;
        self.event_bus.emit(Event::RuleAdded { rule }).await;

        Ok(id)
    }

    pub async fn remove_rule(&self, id: &RuleId) -> Result<bool> {
        info!("Removing rule: {}", id);

        let removed = {
            let mut rules = self.rules.write().await;
            rules.remove(id)
        };

        if removed {
            self.nft.remove_rule(id).await?;
            self.event_bus.emit(Event::RuleRemoved { id: id.clone() }).await;
        }

        Ok(removed)
    }

    pub async fn update_rule(&self, rule: Rule) -> Result<()> {
        let id = rule.id.clone();
        info!("Updating rule: {}", id);

        {
            let mut rules = self.rules.write().await;
            if let Some(existing) = rules.get_mut(&id) {
                *existing = rule.clone();
                existing.updated_at = Utc::now();
            } else {
                anyhow::bail!("Rule not found: {}", id);
            }
        }

        self.nft.update_rule(&rule).await?;
        self.event_bus.emit(Event::RuleUpdated { rule }).await;

        Ok(())
    }

    pub async fn get_rules(&self) -> Vec<Rule> {
        self.rules.read().await.rules.clone()
    }

    pub async fn get_rule(&self, id: &RuleId) -> Option<Rule> {
        self.rules.read().await.get(id).cloned()
    }

    pub async fn ban_ip(&self, ip: IpAddr, ban: BannedIp) -> Result<()> {
        info!("Banning IP: {} (reason: {})", ip, ban.reason);

        self.banned_ips.insert(ip, ban.clone());
        self.nft.block_ip(ip, ban.expires_at).await?;
        self.event_bus.emit(Event::IpBanned { ip, ban }).await;

        Ok(())
    }

    pub async fn unban_ip(&self, ip: &IpAddr) -> Result<bool> {
        if let Some((_, ban)) = self.banned_ips.remove(ip) {
            info!("Unbanning IP: {}", ip);
            self.nft.unblock_ip(ip).await?;
            self.event_bus.emit(Event::IpUnbanned { ip: *ip, ban }).await;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        if let Some(ban) = self.banned_ips.get(ip) {
            !ban.is_expired()
        } else {
            false
        }
    }

    pub async fn get_banned_ips(&self) -> Vec<BannedIp> {
        self.banned_ips.iter().map(|e| e.value().clone()).collect()
    }

    pub async fn cleanup_expired_bans(&self) -> u32 {
        let expired: Vec<IpAddr> = self.banned_ips
            .iter()
            .filter(|e| e.value().is_expired())
            .map(|e| *e.key())
            .collect();

        let count = expired.len() as u32;
        for ip in expired {
            if let Err(e) = self.unban_ip(&ip).await {
                warn!("Failed to unban expired IP {}: {}", ip, e);
            }
        }

        if count > 0 {
            debug!("Cleaned up {} expired bans", count);
        }
        count
    }

    pub async fn flush_rules(&self) -> Result<()> {
        warn!("Flushing all rules!");
        {
            let mut rules = self.rules.write().await;
            *rules = RuleSet::new();
        }
        self.nft.flush_all().await?;
        self.event_bus.emit(Event::RulesFlushed).await;
        Ok(())
    }

    pub async fn reload_rules(&self, new_rules: RuleSet) -> Result<()> {
        info!("Reloading {} rules (version {})", new_rules.rules.len(), new_rules.version);

        {
            let mut rules = self.rules.write().await;
            *rules = new_rules;
        }

        self.nft.reload().await?;
        let rules = self.rules.read().await;
        for rule in rules.active_rules() {
            self.nft.apply_rule(rule).await?;
        }

        Ok(())
    }

    pub async fn evaluate_packet(&self, packet: &PacketInfo) -> RuleAction {
        let rules = self.rules.read().await;

        if self.is_banned(&packet.src_ip) {
            return RuleAction::Drop;
        }

        for rule in rules.active_rules() {
            if rule_matches(rule, packet) {
                return rule.action.clone();
            }
        }

        RuleAction::Drop
    }
}

fn rule_matches(rule: &Rule, packet: &PacketInfo) -> bool {
    if let Some(proto) = &rule.protocol.as_match() {
        if proto != &packet.protocol {
            return false;
        }
    }

    if let Some(src) = &rule.src_addr {
        if !src.matches(&packet.src_ip) {
            return false;
        }
    }

    if let Some(dst) = &rule.dst_addr {
        if !dst.matches(&packet.dst_ip) {
            return false;
        }
    }

    if let Some(src_port) = &rule.src_port {
        if let Some(port) = packet.src_port {
            if !src_port.matches(port) {
                return false;
            }
        }
    }

    if let Some(dst_port) = &rule.dst_port {
        if let Some(port) = packet.dst_port {
            if !dst_port.matches(port) {
                return false;
            }
        }
    }

    true
}

impl Protocol {
    fn as_match(&self) -> Option<Protocol> {
        match self {
            Protocol::Any => None,
            other => Some(other.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub size: u32,
    pub flags: u8,
}
