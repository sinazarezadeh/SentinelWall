use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use ipnet::IpNet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RuleId(pub Uuid);

impl RuleId {
    pub fn new() -> Self {
        RuleId(Uuid::new_v4())
    }
}

impl Default for RuleId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub name: String,
    pub description: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub action: RuleAction,
    pub direction: TrafficDirection,
    pub protocol: Protocol,
    pub src_addr: Option<AddrSpec>,
    pub dst_addr: Option<AddrSpec>,
    pub src_port: Option<PortSpec>,
    pub dst_port: Option<PortSpec>,
    pub interface: Option<String>,
    pub zone: Option<String>,
    pub state: Option<Vec<ConnectionState>>,
    pub rate_limit: Option<RateLimit>,
    pub log: bool,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub source: RuleSource,
    pub hit_count: u64,
}

impl Rule {
    pub fn new(name: impl Into<String>, action: RuleAction) -> Self {
        let now = Utc::now();
        Self {
            id: RuleId::new(),
            name: name.into(),
            description: None,
            priority: 100,
            enabled: true,
            action,
            direction: TrafficDirection::Both,
            protocol: Protocol::Any,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            interface: None,
            zone: None,
            state: None,
            rate_limit: None,
            log: false,
            comment: None,
            tags: vec![],
            created_at: now,
            updated_at: now,
            expires_at: None,
            source: RuleSource::Manual,
            hit_count: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    pub fn allow(name: impl Into<String>) -> Self {
        Self::new(name, RuleAction::Accept)
    }

    pub fn deny(name: impl Into<String>) -> Self {
        Self::new(name, RuleAction::Drop)
    }

    pub fn reject(name: impl Into<String>) -> Self {
        Self::new(name, RuleAction::Reject)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Accept,
    Drop,
    Reject,
    Log,
    Queue,
    Return,
    Jump(String),
    Tarpit,
    RateLimit(Box<RateLimit>),
}

impl std::fmt::Display for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleAction::Accept => write!(f, "accept"),
            RuleAction::Drop => write!(f, "drop"),
            RuleAction::Reject => write!(f, "reject"),
            RuleAction::Log => write!(f, "log"),
            RuleAction::Queue => write!(f, "queue"),
            RuleAction::Return => write!(f, "return"),
            RuleAction::Jump(chain) => write!(f, "jump {}", chain),
            RuleAction::Tarpit => write!(f, "tarpit"),
            RuleAction::RateLimit(rl) => write!(f, "rate-limit {}/{}", rl.rate, rl.unit),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Any,
    Custom(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Icmpv6 => write!(f, "icmpv6"),
            Protocol::Any => write!(f, "any"),
            Protocol::Custom(n) => write!(f, "{}", n),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "icmpv6" => Ok(Protocol::Icmpv6),
            "any" | "" => Ok(Protocol::Any),
            n => n.parse::<u8>()
                .map(Protocol::Custom)
                .map_err(|_| anyhow::anyhow!("Unknown protocol: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Both,
    Forward,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
pub enum AddrSpec {
    Single(IpAddr),
    Network(IpNet),
    Range { start: IpAddr, end: IpAddr },
    Set(Vec<IpAddr>),
    Any,
}

impl AddrSpec {
    pub fn matches(&self, addr: &IpAddr) -> bool {
        match self {
            AddrSpec::Single(ip) => ip == addr,
            AddrSpec::Network(net) => net.contains(addr),
            AddrSpec::Range { start, end } => addr >= start && addr <= end,
            AddrSpec::Set(ips) => ips.contains(addr),
            AddrSpec::Any => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
    Set(Vec<u16>),
    Any,
}

impl PortSpec {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortSpec::Single(p) => *p == port,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
            PortSpec::Set(ports) => ports.contains(&port),
            PortSpec::Any => true,
        }
    }
}

impl std::str::FromStr for PortSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "any" || s.is_empty() {
            return Ok(PortSpec::Any);
        }
        if s.contains('-') {
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            let start = parts[0].parse::<u16>()?;
            let end = parts[1].parse::<u16>()?;
            return Ok(PortSpec::Range(start, end));
        }
        if s.contains(',') {
            let ports = s.split(',')
                .map(|p| p.trim().parse::<u16>())
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(PortSpec::Set(ports));
        }
        Ok(PortSpec::Single(s.parse()?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimit {
    pub rate: u64,
    pub unit: RateUnit,
    pub burst: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RateUnit {
    Second,
    Minute,
    Hour,
    Day,
}

impl std::fmt::Display for RateUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateUnit::Second => write!(f, "second"),
            RateUnit::Minute => write!(f, "minute"),
            RateUnit::Hour => write!(f, "hour"),
            RateUnit::Day => write!(f, "day"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    Manual,
    Profile(String),
    Detection,
    ThreatIntel,
    Cluster,
    Api,
    Migration,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub version: u64,
    pub checksum: String,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| a.priority.cmp(&b.priority));
        self.version += 1;
        self.update_checksum();
    }

    pub fn remove(&mut self, id: &RuleId) -> bool {
        let len = self.rules.len();
        self.rules.retain(|r| &r.id != id);
        if self.rules.len() < len {
            self.version += 1;
            self.update_checksum();
            true
        } else {
            false
        }
    }

    pub fn get(&self, id: &RuleId) -> Option<&Rule> {
        self.rules.iter().find(|r| &r.id == id)
    }

    pub fn get_mut(&mut self, id: &RuleId) -> Option<&mut Rule> {
        self.rules.iter_mut().find(|r| &r.id == id)
    }

    pub fn active_rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.enabled && !r.is_expired())
    }

    fn update_checksum(&mut self) {
        use sha2::{Sha256, Digest};
        let data = serde_json::to_string(&self.rules).unwrap_or_default();
        let hash = Sha256::digest(data.as_bytes());
        self.checksum = hex::encode(hash);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannedIp {
    pub ip: IpAddr,
    pub reason: BanReason,
    pub banned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub ban_count: u32,
    pub source: String,
    pub evidence: Vec<String>,
}

impl BannedIp {
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    pub fn is_permanent(&self) -> bool {
        self.expires_at.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BanReason {
    BruteForce,
    PortScan,
    SynFlood,
    UdpFlood,
    HttpFlood,
    Slowloris,
    DdosIndicator,
    ThreatIntel,
    ManualBan,
    MlDetection,
    PolicyViolation,
    GeoBlock,
    InvalidPackets,
}

impl std::fmt::Display for BanReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanReason::BruteForce => write!(f, "Brute Force Attack"),
            BanReason::PortScan => write!(f, "Port Scanning"),
            BanReason::SynFlood => write!(f, "SYN Flood"),
            BanReason::UdpFlood => write!(f, "UDP Flood"),
            BanReason::HttpFlood => write!(f, "HTTP Flood"),
            BanReason::Slowloris => write!(f, "Slowloris Attack"),
            BanReason::DdosIndicator => write!(f, "DDoS Indicator"),
            BanReason::ThreatIntel => write!(f, "Threat Intelligence Match"),
            BanReason::ManualBan => write!(f, "Manual Ban"),
            BanReason::MlDetection => write!(f, "ML Anomaly Detection"),
            BanReason::PolicyViolation => write!(f, "Policy Violation"),
            BanReason::GeoBlock => write!(f, "Geographic Block"),
            BanReason::InvalidPackets => write!(f, "Invalid Packets"),
        }
    }
}
