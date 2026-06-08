pub mod analyzer;
pub mod brute_force;
pub mod port_scan;
pub mod flood;
pub mod anomaly;

pub use analyzer::ThreatAnalyzer;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: uuid::Uuid,
    pub ip: IpAddr,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub evidence: Vec<String>,
    pub recommended_action: RecommendedAction,
    pub ttl_seconds: Option<u64>,
}

impl ThreatEvent {
    pub fn new(ip: IpAddr, threat_type: ThreatType, severity: Severity) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            ip,
            threat_type,
            severity,
            confidence: 1.0,
            timestamp: Utc::now(),
            description: String::new(),
            evidence: vec![],
            recommended_action: RecommendedAction::Block,
            ttl_seconds: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_action(mut self, action: RecommendedAction) -> Self {
        self.recommended_action = action;
        self
    }

    pub fn with_ttl(mut self, ttl: u64) -> Self {
        self.ttl_seconds = Some(ttl);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    BruteForce,
    PortScan,
    StealthScan,
    SynFlood,
    UdpFlood,
    IcmpFlood,
    HttpFlood,
    Slowloris,
    DdosIndicator,
    InvalidPackets,
    BotnetBehavior,
    MaliciousAsn,
    TorExitNode,
    AbuseipdbMatch,
    GeoBlock,
    AnomalyDetected,
    ConnectionBurst,
    RateLimitViolation,
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::BruteForce => write!(f, "Brute Force"),
            ThreatType::PortScan => write!(f, "Port Scan"),
            ThreatType::StealthScan => write!(f, "Stealth Scan"),
            ThreatType::SynFlood => write!(f, "SYN Flood"),
            ThreatType::UdpFlood => write!(f, "UDP Flood"),
            ThreatType::IcmpFlood => write!(f, "ICMP Flood"),
            ThreatType::HttpFlood => write!(f, "HTTP Flood"),
            ThreatType::Slowloris => write!(f, "Slowloris"),
            ThreatType::DdosIndicator => write!(f, "DDoS Indicator"),
            ThreatType::InvalidPackets => write!(f, "Invalid Packets"),
            ThreatType::BotnetBehavior => write!(f, "Botnet Behavior"),
            ThreatType::MaliciousAsn => write!(f, "Malicious ASN"),
            ThreatType::TorExitNode => write!(f, "TOR Exit Node"),
            ThreatType::AbuseipdbMatch => write!(f, "AbuseIPDB Match"),
            ThreatType::GeoBlock => write!(f, "Geographic Block"),
            ThreatType::AnomalyDetected => write!(f, "Anomaly Detected"),
            ThreatType::ConnectionBurst => write!(f, "Connection Burst"),
            ThreatType::RateLimitViolation => write!(f, "Rate Limit Violation"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    Monitor,
    RateLimit,
    Block,
    BlockPermanent,
    Quarantine,
    Challenge,
    Alert,
}
