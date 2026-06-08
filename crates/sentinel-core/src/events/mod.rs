use std::sync::Arc;
use std::net::IpAddr;
use serde::{Serialize, Deserialize};
use tokio::sync::broadcast;
use tracing::debug;

use crate::rules::types::{Rule, RuleId, BannedIp};
use crate::detection::ThreatEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    // Rule events
    RuleAdded { rule: Rule },
    RuleRemoved { id: RuleId },
    RuleUpdated { rule: Rule },
    RulesFlushed,

    // Ban events
    IpBanned { ip: IpAddr, ban: BannedIp },
    IpUnbanned { ip: IpAddr, ban: BannedIp },

    // Threat events
    ThreatDetected(ThreatEvent),

    // Connection events
    ConnectionAccepted { src_ip: IpAddr, dst_port: u16 },
    ConnectionRejected { src_ip: IpAddr, dst_port: u16, reason: String },

    // System events
    DaemonStarted { version: String },
    DaemonStopping,
    ConfigReloaded,
    ProfileApplied { profile: String },
    BackendError { message: String },

    // Cluster events
    PeerConnected { peer_addr: String },
    PeerDisconnected { peer_addr: String },
    RulesSynced { peer_addr: String, rule_count: u32 },
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Event::RuleAdded { .. } => "rule_added",
            Event::RuleRemoved { .. } => "rule_removed",
            Event::RuleUpdated { .. } => "rule_updated",
            Event::RulesFlushed => "rules_flushed",
            Event::IpBanned { .. } => "ip_banned",
            Event::IpUnbanned { .. } => "ip_unbanned",
            Event::ThreatDetected(_) => "threat_detected",
            Event::ConnectionAccepted { .. } => "connection_accepted",
            Event::ConnectionRejected { .. } => "connection_rejected",
            Event::DaemonStarted { .. } => "daemon_started",
            Event::DaemonStopping => "daemon_stopping",
            Event::ConfigReloaded => "config_reloaded",
            Event::ProfileApplied { .. } => "profile_applied",
            Event::BackendError { .. } => "backend_error",
            Event::PeerConnected { .. } => "peer_connected",
            Event::PeerDisconnected { .. } => "peer_disconnected",
            Event::RulesSynced { .. } => "rules_synced",
        }
    }
}

pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Arc<Self> {
        let (tx, _) = broadcast::channel(capacity);
        Arc::new(Self { tx })
    }

    pub async fn emit(&self, event: Event) {
        debug!("Event emitted: {}", event.name());
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}
