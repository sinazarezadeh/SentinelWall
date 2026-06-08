use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use ipnet::IpNet;

pub mod types;
pub use types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    #[serde(default)]
    pub core: CoreConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub detection: DetectionConfig,
    #[serde(default)]
    pub response: ResponseConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub geo: GeoConfig,
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,
    #[serde(default)]
    pub ml: MlConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            core: CoreConfig::default(),
            network: NetworkConfig::default(),
            detection: DetectionConfig::default(),
            response: ResponseConfig::default(),
            api: ApiConfig::default(),
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
            geo: GeoConfig::default(),
            threat_intel: ThreatIntelConfig::default(),
            ml: MlConfig::default(),
            cluster: ClusterConfig::default(),
        }
    }
}

impl SentinelConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let config: SentinelConfig = toml::from_str(&content)
            .with_context(|| "Failed to parse configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_default(path: &Path) -> Self {
        Self::load(path).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.api.port == 0 {
            anyhow::bail!("API port cannot be 0");
        }
        if self.detection.max_connections_per_ip == 0 {
            anyhow::bail!("max_connections_per_ip cannot be 0");
        }
        Ok(())
    }

    pub fn default_config_path() -> PathBuf {
        PathBuf::from("/etc/sentinelwall/sentinelwall.toml")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    pub backend: FirewallBackend,
    pub state_file: PathBuf,
    pub rules_dir: PathBuf,
    pub plugins_dir: PathBuf,
    pub profile: Option<String>,
    pub worker_threads: usize,
    pub privilege_drop_user: Option<String>,
    pub privilege_drop_group: Option<String>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Nftables,
            state_file: PathBuf::from("/var/lib/sentinelwall/state.db"),
            rules_dir: PathBuf::from("/etc/sentinelwall/rules.d"),
            plugins_dir: PathBuf::from("/etc/sentinelwall/plugins"),
            profile: None,
            worker_threads: 4,
            privilege_drop_user: Some("sentinel".to_string()),
            privilege_drop_group: Some("sentinel".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub interfaces: Vec<String>,
    pub trusted_networks: Vec<IpNet>,
    pub blocked_countries: Vec<String>,
    pub allowed_countries: Vec<String>,
    pub ipv6_enabled: bool,
    pub default_policy: DefaultPolicy,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interfaces: vec!["eth0".to_string()],
            trusted_networks: vec![
                "127.0.0.0/8".parse().unwrap(),
                "::1/128".parse().unwrap(),
            ],
            blocked_countries: vec![],
            allowed_countries: vec![],
            ipv6_enabled: true,
            default_policy: DefaultPolicy::Drop,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    pub enabled: bool,
    pub brute_force: BruteForceConfig,
    pub port_scan: PortScanConfig,
    pub flood: FloodConfig,
    pub max_connections_per_ip: u32,
    pub connection_rate_limit: u32,
    pub new_connection_rate: u32,
    pub syn_cookies: bool,
    pub invalid_packet_drop: bool,
    pub stealth_scan_detection: bool,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            brute_force: BruteForceConfig::default(),
            port_scan: PortScanConfig::default(),
            flood: FloodConfig::default(),
            max_connections_per_ip: 100,
            connection_rate_limit: 1000,
            new_connection_rate: 50,
            syn_cookies: true,
            invalid_packet_drop: true,
            stealth_scan_detection: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BruteForceConfig {
    pub enabled: bool,
    pub max_attempts: u32,
    pub window_seconds: u64,
    pub ban_duration_seconds: u64,
    pub escalation_multiplier: f64,
    pub ssh_port: u16,
    pub ftp_port: u16,
    pub smtp_port: u16,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 5,
            window_seconds: 300,
            ban_duration_seconds: 3600,
            escalation_multiplier: 2.0,
            ssh_port: 22,
            ftp_port: 21,
            smtp_port: 25,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PortScanConfig {
    pub enabled: bool,
    pub threshold_ports_per_second: u32,
    pub window_seconds: u64,
    pub ban_duration_seconds: u64,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_ports_per_second: 15,
            window_seconds: 10,
            ban_duration_seconds: 86400,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FloodConfig {
    pub enabled: bool,
    pub syn_pps_threshold: u64,
    pub udp_pps_threshold: u64,
    pub icmp_pps_threshold: u64,
    pub http_rps_threshold: u64,
    pub ban_duration_seconds: u64,
}

impl Default for FloodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            syn_pps_threshold: 1000,
            udp_pps_threshold: 5000,
            icmp_pps_threshold: 100,
            http_rps_threshold: 500,
            ban_duration_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseConfig {
    pub auto_ban: bool,
    pub tarpit: bool,
    pub tarpit_delay_ms: u64,
    pub challenge_response: bool,
    pub quarantine_mode_threshold: u32,
    pub max_ban_duration_secs: u64,
    pub whitelist_bypass: bool,
    pub notify_webhook: Option<String>,
    pub notify_email: Option<String>,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            auto_ban: true,
            tarpit: false,
            tarpit_delay_ms: 5000,
            challenge_response: false,
            quarantine_mode_threshold: 1000,
            max_ban_duration_secs: 86400 * 30,
            whitelist_bypass: true,
            notify_webhook: None,
            notify_email: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub bind: String,
    pub port: u16,
    pub tls: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub jwt_secret: Option<String>,
    pub token_expiry_hours: u64,
    pub rate_limit_rps: u32,
    pub cors_origins: Vec<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".to_string(),
            port: 8765,
            tls: false,
            tls_cert: None,
            tls_key: None,
            jwt_secret: None,
            token_expiry_hours: 24,
            rate_limit_rps: 100,
            cors_origins: vec!["http://localhost:3000".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
    pub file: Option<PathBuf>,
    pub rotate: bool,
    pub max_size_mb: u64,
    pub max_files: u32,
    pub audit_log: Option<PathBuf>,
    pub attack_log: Option<PathBuf>,
    pub syslog: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Json,
            file: Some(PathBuf::from("/var/log/sentinelwall/sentinel.log")),
            rotate: true,
            max_size_mb: 100,
            max_files: 10,
            audit_log: Some(PathBuf::from("/var/log/sentinelwall/audit.log")),
            attack_log: Some(PathBuf::from("/var/log/sentinelwall/attacks.log")),
            syslog: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
    Pretty,
    Syslog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
    pub path: String,
    pub push_gateway: Option<String>,
    pub push_interval_secs: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "0.0.0.0".to_string(),
            port: 9100,
            path: "/metrics".to_string(),
            push_gateway: None,
            push_interval_secs: 15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoConfig {
    pub enabled: bool,
    pub database_path: PathBuf,
    pub update_url: String,
    pub update_interval_hours: u64,
    pub asn_database_path: Option<PathBuf>,
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: PathBuf::from("/var/lib/sentinelwall/GeoLite2-Country.mmdb"),
            update_url: "https://db-ip.com/db/download/ip-to-country-lite".to_string(),
            update_interval_hours: 24 * 7,
            asn_database_path: Some(PathBuf::from("/var/lib/sentinelwall/GeoLite2-ASN.mmdb")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub abuseipdb_api_key: Option<String>,
    pub abuseipdb_confidence_threshold: u8,
    pub virustotal_api_key: Option<String>,
    pub crowdsec_api_key: Option<String>,
    pub crowdsec_url: Option<String>,
    pub tor_exit_nodes: bool,
    pub update_interval_secs: u64,
    pub custom_blocklists: Vec<String>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            abuseipdb_api_key: None,
            abuseipdb_confidence_threshold: 75,
            virustotal_api_key: None,
            crowdsec_api_key: None,
            crowdsec_url: None,
            tor_exit_nodes: true,
            update_interval_secs: 3600,
            custom_blocklists: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MlConfig {
    pub enabled: bool,
    pub service_url: String,
    pub model_path: PathBuf,
    pub inference_timeout_ms: u64,
    pub risk_threshold: f64,
    pub auto_block_threshold: f64,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_url: "http://127.0.0.1:8766".to_string(),
            model_path: PathBuf::from("/var/lib/sentinelwall/models"),
            inference_timeout_ms: 100,
            risk_threshold: 0.7,
            auto_block_threshold: 0.9,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub node_id: Option<String>,
    pub peers: Vec<String>,
    pub sync_interval_secs: u64,
    pub auth_token: Option<String>,
    pub tls: bool,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: None,
            peers: vec![],
            sync_interval_secs: 30,
            auth_token: None,
            tls: true,
        }
    }
}
