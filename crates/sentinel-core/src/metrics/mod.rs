use std::sync::Arc;
use prometheus::{
    Registry, Counter, GaugeVec, Histogram, HistogramVec,
    IntCounterVec, IntGauge,
    Opts, HistogramOpts,
};
use anyhow::Result;

pub struct MetricsCollector {
    pub registry: Registry,

    // Connection metrics
    pub connections_total: IntCounterVec,
    pub connections_active: IntGauge,
    pub connections_rejected_total: IntCounterVec,

    // Rule metrics
    pub rules_total: IntGauge,
    pub rules_matched_total: IntCounterVec,

    // Threat metrics
    pub threats_detected_total: IntCounterVec,
    pub bans_active: IntGauge,
    pub bans_total: IntCounterVec,

    // Traffic metrics
    pub bytes_in_total: Counter,
    pub bytes_out_total: Counter,
    pub packets_in_total: Counter,
    pub packets_out_total: Counter,
    pub packets_dropped_total: Counter,

    // Performance metrics
    pub rule_evaluation_duration: Histogram,
    pub threat_analysis_duration: Histogram,
    pub nft_operation_duration: Histogram,
    pub api_request_duration: HistogramVec,

    // System metrics
    pub daemon_uptime_seconds: IntGauge,
    pub daemon_info: GaugeVec,
}

impl MetricsCollector {
    pub fn new() -> Result<Arc<Self>> {
        let registry = Registry::new();

        macro_rules! register {
            ($metric:expr) => {{
                registry.register(Box::new($metric.clone()))?;
                $metric
            }};
        }

        let connections_total = register!(IntCounterVec::new(
            Opts::new("sentinel_connections_total", "Total connections processed"),
            &["interface", "direction", "protocol"],
        )?);

        let connections_active = register!(IntGauge::new(
            "sentinel_connections_active", "Currently active connections",
        )?);

        let connections_rejected_total = register!(IntCounterVec::new(
            Opts::new("sentinel_connections_rejected_total", "Total connections rejected"),
            &["reason"],
        )?);

        let rules_total = register!(IntGauge::new(
            "sentinel_rules_total", "Total number of active rules",
        )?);

        let rules_matched_total = register!(IntCounterVec::new(
            Opts::new("sentinel_rules_matched_total", "Total rule matches"),
            &["rule_name", "action"],
        )?);

        let threats_detected_total = register!(IntCounterVec::new(
            Opts::new("sentinel_threats_detected_total", "Total threats detected"),
            &["threat_type", "severity"],
        )?);

        let bans_active = register!(IntGauge::new(
            "sentinel_bans_active", "Currently active IP bans",
        )?);

        let bans_total = register!(IntCounterVec::new(
            Opts::new("sentinel_bans_total", "Total IP bans applied"),
            &["reason"],
        )?);

        let bytes_in_total = register!(Counter::new(
            "sentinel_bytes_in_total", "Total bytes received",
        )?);

        let bytes_out_total = register!(Counter::new(
            "sentinel_bytes_out_total", "Total bytes sent",
        )?);

        let packets_in_total = register!(Counter::new(
            "sentinel_packets_in_total", "Total packets received",
        )?);

        let packets_out_total = register!(Counter::new(
            "sentinel_packets_out_total", "Total packets sent",
        )?);

        let packets_dropped_total = register!(Counter::new(
            "sentinel_packets_dropped_total", "Total packets dropped",
        )?);

        let rule_evaluation_duration = register!(Histogram::with_opts(
            HistogramOpts::new(
                "sentinel_rule_evaluation_duration_seconds",
                "Time to evaluate rules for a packet",
            ).buckets(vec![0.0001, 0.001, 0.01, 0.05, 0.1]),
        )?);

        let threat_analysis_duration = register!(Histogram::with_opts(
            HistogramOpts::new(
                "sentinel_threat_analysis_duration_seconds",
                "Time to analyze a connection for threats",
            ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5]),
        )?);

        let nft_operation_duration = register!(Histogram::with_opts(
            HistogramOpts::new(
                "sentinel_nft_operation_duration_seconds",
                "Time for nftables operations",
            ).buckets(vec![0.001, 0.01, 0.05, 0.1, 0.5, 1.0]),
        )?);

        let api_request_duration = register!(HistogramVec::new(
            HistogramOpts::new(
                "sentinel_api_request_duration_seconds",
                "API request latency",
            ).buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["method", "path", "status"],
        )?);

        let daemon_uptime_seconds = register!(IntGauge::new(
            "sentinel_daemon_uptime_seconds", "Daemon uptime in seconds",
        )?);

        let daemon_info = register!(GaugeVec::new(
            Opts::new("sentinel_daemon_info", "Daemon version information"),
            &["version", "backend"],
        )?);

        Ok(Arc::new(Self {
            registry,
            connections_total,
            connections_active,
            connections_rejected_total,
            rules_total,
            rules_matched_total,
            threats_detected_total,
            bans_active,
            bans_total,
            bytes_in_total,
            bytes_out_total,
            packets_in_total,
            packets_out_total,
            packets_dropped_total,
            rule_evaluation_duration,
            threat_analysis_duration,
            nft_operation_duration,
            api_request_duration,
            daemon_uptime_seconds,
            daemon_info,
        }))
    }

    pub fn render(&self) -> Result<String> {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }

    pub fn record_threat(&self, threat_type: &str, severity: &str) {
        self.threats_detected_total
            .with_label_values(&[threat_type, severity])
            .inc();
    }

    pub fn record_ban(&self, reason: &str) {
        self.bans_total.with_label_values(&[reason]).inc();
        self.bans_active.inc();
    }

    pub fn record_unban(&self) {
        self.bans_active.dec();
    }

    pub fn record_connection(&self, interface: &str, direction: &str, protocol: &str) {
        self.connections_total
            .with_label_values(&[interface, direction, protocol])
            .inc();
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Arc::try_unwrap(Self::new().expect("Failed to create metrics collector"))
            .unwrap_or_else(|_| panic!("single Arc reference on construction"))
    }
}
