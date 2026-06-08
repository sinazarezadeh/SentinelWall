# Configuration Reference

SentinelWall is configured via `/etc/sentinelwall/sentinelwall.toml` (default path, override with `--config`).

## [core]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `backend` | string | `"nftables"` | Firewall backend: `"nftables"` or `"iptables"` |
| `state_file` | path | `/var/lib/sentinelwall/state.db` | SQLite database path |
| `rules_dir` | path | `/etc/sentinelwall/rules.d` | Directory for additional rule files |
| `profile` | string | `"server"` | Active profile name |

## [network]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `trusted_networks` | string[] | `["127.0.0.0/8"]` | CIDRs that bypass threat detection |
| `blocked_countries` | string[] | `[]` | ISO 3166-1 alpha-2 country codes to block |
| `dns_servers` | string[] | `["1.1.1.1", "8.8.8.8"]` | DNS servers for reverse lookups |

## [detection]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `brute_force_enabled` | bool | `true` | Enable brute-force detection |
| `brute_force_threshold` | int | `5` | Failed attempts before triggering |
| `brute_force_window_secs` | int | `300` | Sliding window size (seconds) |
| `brute_force_ban_duration` | int | `3600` | Initial ban duration (seconds) |
| `brute_force_escalation_multiplier` | float | `2.0` | Multiplier per re-offense |
| `port_scan_enabled` | bool | `true` | Enable port scan detection |
| `port_scan_threshold` | int | `20` | Unique ports per window before triggering |
| `port_scan_window_secs` | int | `60` | Port scan window (seconds) |
| `port_scan_stealth_threshold_ms` | int | `10` | Inter-probe interval for stealth scan detection |
| `flood_detection_enabled` | bool | `true` | Enable flood/DDoS detection |
| `flood_syn_pps` | int | `1000` | SYN packets/sec threshold |
| `flood_udp_pps` | int | `5000` | UDP packets/sec threshold |
| `flood_icmp_pps` | int | `100` | ICMP packets/sec threshold |
| `flood_http_pps` | int | `500` | HTTP requests/sec threshold |
| `max_connections_per_ip` | int | `1000` | Max concurrent connections from one IP |
| `max_new_connections_per_sec` | int | `100` | Max new connections/sec from one IP |
| `anomaly_detection_enabled` | bool | `true` | Enable statistical anomaly detection |
| `anomaly_z_score_threshold` | float | `3.0` | Z-score threshold for anomaly |
| `ml_detection_enabled` | bool | `true` | Enable ML-based detection |
| `ml_service_url` | string | `"http://127.0.0.1:8766"` | ML service URL |
| `ml_score_threshold` | float | `0.65` | Minimum ML risk score to act on |

## [response]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auto_ban` | bool | `true` | Auto-ban on high/critical threats |
| `ban_duration_secs` | int | `3600` | Default ban duration (seconds) |
| `escalating_bans` | bool | `true` | Multiply duration per re-offense |
| `max_ban_multiplier` | int | `32` | Cap on escalation multiplier |
| `tarpit_enabled` | bool | `false` | Enable tarpit mode |
| `tarpit_delay_ms` | int | `5000` | Tarpit response delay (ms) |
| `quarantine_enabled` | bool | `false` | Enable quarantine zone |
| `notify_webhook` | string | `""` | HTTP webhook for notifications |

## [api]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind` | string | `"127.0.0.1"` | API listen address |
| `port` | int | `8765` | API listen port |
| `jwt_secret` | string | `""` | JWT signing secret (random if empty) |
| `jwt_expiry_secs` | int | `86400` | Token validity (seconds) |
| `refresh_expiry_secs` | int | `604800` | Refresh token validity (seconds) |
| `cors_origins` | string[] | `[]` | CORS allowed origins |
| `tls_cert` | path | `""` | TLS certificate path (enables TLS) |
| `tls_key` | path | `""` | TLS key path |
| `api_rate_limit` | int | `100` | Max API requests/minute per IP |

## [logging]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `"info"` | Log level: error/warn/info/debug/trace |
| `format` | string | `"pretty"` | Log format: `"pretty"` or `"json"` |
| `file` | path | `""` | Log file path (stdout if empty) |
| `log_max_size_mb` | int | `100` | Log rotation size threshold |
| `log_max_backups` | int | `10` | Number of rotated logs to keep |
| `audit_log_enabled` | bool | `true` | Enable audit log |

## [metrics]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable Prometheus metrics |
| `bind` | string | `"127.0.0.1"` | Metrics server bind address |
| `port` | int | `9100` | Metrics server port |
| `path` | string | `"/metrics"` | Metrics path |

## [geo]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable geo-IP lookups |
| `db_path` | path | `""` | Path to MaxMind GeoLite2 .mmdb file |

## [threat_intel]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable threat intel lookups |
| `abuseipdb_key` | string | `""` | AbuseIPDB API key |
| `abuseipdb_confidence_threshold` | int | `85` | Minimum confidence score to act on |
| `virustotal_key` | string | `""` | VirusTotal API key |
| `crowdsec_key` | string | `""` | CrowdSec API key |
| `tor_exit_nodes_enabled` | bool | `true` | Block TOR exit nodes |
| `tor_update_interval_secs` | int | `3600` | TOR list update interval |
| `custom_blocklists` | string[] | `[]` | URLs to custom IP blocklists |

## [ml]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable ML service integration |
| `service_url` | string | `"http://127.0.0.1:8766"` | ML service URL |
| `retrain_interval_secs` | int | `86400` | Auto-retrain interval |
| `min_samples_for_training` | int | `100` | Minimum samples before training |

## [cluster]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable cluster mode |
| `node_id` | string | `""` | Unique node identifier |
| `peers` | string[] | `[]` | Peer node API URLs |
| `sync_interval_secs` | int | `30` | Sync interval (seconds) |
| `cluster_secret` | string | `""` | Shared secret for peer auth |

## Environment Variables

Environment variables override config file values.

| Variable | Config Key | Description |
|----------|-----------|-------------|
| `SENTINEL_ADMIN_PASSWORD` | — | Initial admin password (first startup only) |
| `SENTINEL_JWT_SECRET` | `api.jwt_secret` | JWT secret override |
| `SENTINEL_DRY_RUN` | — | Run without modifying nftables (testing) |
| `RUST_LOG` | `logging.level` | Override log level |
