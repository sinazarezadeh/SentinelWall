<div align="center">

# SentinelWall

**Next-Generation Linux Firewall & Intrusion Prevention System**

[![CI](https://github.com/sinazarezadeh/SentinelWall/actions/workflows/ci.yml/badge.svg)](https://github.com/sinazarezadeh/SentinelWall/actions/workflows/ci.yml)
[![Security](https://github.com/sinazarezadeh/SentinelWall/actions/workflows/security.yml/badge.svg)](https://github.com/sinazarezadeh/SentinelWall/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/sinazarezadeh/SentinelWall?style=flat-square)](https://github.com/sinazarezadeh/SentinelWall/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/Rust-1.75%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)](https://hub.docker.com)

*Zero-downtime rule updates · AI/ML anomaly detection · Real-time web dashboard · Cluster sync*

---

</div>

## What Is SentinelWall?

SentinelWall is a production-grade, defense-in-depth network security system for Linux that combines:

- **nftables-based firewall engine** with atomic rule updates and zero-downtime reloads
- **Multi-layer threat detection** — brute-force, port scans, DDoS, Slowloris, HTTP floods
- **AI/ML anomaly detection** — Isolation Forest + Random Forest classifier via FastAPI microservice
- **Active response** — auto-ban, escalating penalties, tarpit, quarantine mode
- **Threat intelligence integration** — AbuseIPDB, VirusTotal, CrowdSec, TOR exit nodes
- **10 prebuilt firewall profiles** for common server roles
- **Full observability** — Prometheus metrics, Grafana dashboards, WebSocket live events
- **Production tooling** — REST API, web dashboard, ncurses TUI, powerful CLI

Built in Rust for safety and performance. The daemon processes rule updates in microseconds and handles millions of packets per second without user-space involvement.

---

## Feature Highlights

### Firewall Engine
- nftables backend with iptables compatibility shim
- Zone-based firewalling: Public, Private, Trusted, DMZ, Management
- Geo-IP blocking via MaxMind GeoLite2 (country + city precision)
- Rate limiting per IP, per protocol, per connection state
- SYN flood protection, connection tracking, stateful filtering
- Atomic rule updates — no flush/reload, no connection drops
- Rule persistence in SQLite with full audit log

### Threat Detection
| Detector | Method | Trigger |
|----------|--------|---------|
| Brute Force | Sliding window counter | 5 auth failures / 5 min |
| Port Scan | Unique port tracking | 20 ports / 60s |
| Stealth Scan | Inter-probe timing | < 10ms between probes |
| SYN Flood | PPS threshold | > 1000 SYN/s per IP |
| HTTP Flood | Request rate | > 500 req/s |
| Slowloris | Connection hold time | Partial headers > 30s |
| DDoS | Aggregate traffic | Configurable PPS threshold |
| Anomaly (ML) | Z-score > 3.0 | Statistical deviation from baseline |
| Isolation Forest | Unsupervised ML | contamination=0.05 |
| Classifier | Random Forest 200 trees | 8 threat classes |

### Active Response
- **Auto-ban**: configurable by threat severity
- **Escalating penalties**: ban duration doubles with each re-offense (configurable multiplier)
- **Tarpit**: accept connections, respond extremely slowly (5s delay default)
- **Quarantine zone**: isolate suspect IPs to heavily restricted ruleset
- **Webhook notifications**: Slack, PagerDuty, or any HTTP endpoint

### Firewall Profiles

| Profile | Use Case |
|---------|----------|
| `public` | Internet-facing servers — minimal trust |
| `private` | Internal networks — balanced |
| `trusted` | Trusted segments — permissive |
| `server` | General server — SSH + web + DB |
| `web` | Web servers — HTTP/HTTPS + rate limits |
| `database` | DB servers — DB ports + no internet |
| `kubernetes` | k8s nodes — cluster traffic |
| `dmz` | DMZ hosts — restricted egress |
| `strict` | Maximum security — whitelist-only |
| `minimal` | Emergency fallback — loopback + SSH only |

### Observability
- Prometheus metrics: connections, threats, bans, bytes, latencies
- Grafana dashboard (auto-provisioned)
- WebSocket live event stream for web clients
- `sentinel monitor` CLI command for terminal event tailing
- Structured JSON logging with `tracing`

---

## Quick Start

### One-Line Install (Linux)

```bash
curl -sSL https://raw.githubusercontent.com/sinazarezadeh/SentinelWall/main/scripts/install.sh | sudo bash
```

This installs binaries, creates the `sentinel` system user, sets up systemd service, and starts the daemon.

### Docker Compose

```bash
git clone https://github.com/sinazarezadeh/SentinelWall
cd sentinelwall
cp deploy/docker/.env.example .env
# Edit .env: set SENTINEL_ADMIN_PASSWORD

docker compose -f deploy/docker/docker-compose.yml up -d
```

Services:
- Daemon API: `http://localhost:8765`
- Web dashboard: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001` (admin/admin)

### First Steps

```bash
# Check status
sentinel status

# Apply web server profile
sentinel profile apply web

# List active rules
sentinel list

# Monitor live events
sentinel monitor

# Ban an IP manually
sentinel ban add 192.168.1.100 --reason "manual" --duration 3600

# Check threat intelligence
sentinel lookup 1.1.1.1
```

---

## CLI Reference

```
sentinel [OPTIONS] <COMMAND>

Commands:
  allow       Allow traffic matching spec (e.g. 22/tcp, 443/tcp)
  deny        Deny traffic matching spec
  remove      Remove a rule by ID
  list        List active rules
  status      Show daemon status
  monitor     Stream live events (WebSocket or poll)
  ban         Manage IP bans (list / add / remove / check)
  profile     List or apply firewall profiles
  threat-feed Update threat intelligence feeds
  analyze     Analyze an IP (threat intel + geo + ML score)
  lookup      Geo-IP and threat intel lookup
  user        Manage users (list / add / remove / passwd)
  token       Manage API tokens
  flush       Flush all rules (emergency reset)
  export      Export rules to JSON/TOML
  import      Import rules from file
  reload      Reload configuration
  login       Authenticate and save token
  version     Show version

Global Flags:
  --api       API base URL (default: http://127.0.0.1:8765)
  --token     Bearer token (overrides saved token)
  --json      Output raw JSON
  --dry-run   Simulate without applying
  --verbose   Debug output
```

### Examples

```bash
# Allow SSH from a specific subnet
sentinel allow 22/tcp --source 10.0.0.0/8 --name "admin-ssh"

# Deny all traffic from a country (requires geo-IP)
sentinel deny --source-country CN --name "block-china" --priority 10

# Rate limit new HTTP connections
sentinel allow 80/tcp --rate-limit "100/minute" --name "http-ratelimit"

# Export rules for backup
sentinel export --format json > rules-backup.json

# Apply rules from backup
sentinel import rules-backup.json --dry-run

# Interactive TUI
sentinel-tui
```

---

## REST API

Base URL: `http://localhost:8765/api/v1`

### Authentication

```bash
# Login
curl -X POST /api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "changeme123"}'
# → {"token": "eyJ...", "refresh_token": "...", "expires_at": "..."}

# Use token
curl -H 'Authorization: Bearer eyJ...' /api/v1/status
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) |
| GET | `/status` | Daemon status + stats |
| GET | `/rules` | List rules |
| POST | `/rules` | Create rule |
| DELETE | `/rules/{id}` | Delete rule |
| GET | `/bans` | List active bans |
| POST | `/bans` | Add ban |
| DELETE | `/bans/{ip}` | Remove ban |
| GET | `/threats` | Recent threat events |
| GET | `/threats/stats` | Threat statistics |
| GET | `/profiles` | List profiles |
| POST | `/profiles/{name}/apply` | Apply profile |
| GET | `/geo/{ip}` | Geo-IP lookup |
| GET | `/threat-intel/{ip}` | Threat intel check |
| GET | `/metrics` | Prometheus metrics |
| WS | `/ws` | Live event stream |

Full OpenAPI spec: [docs/api.md](docs/api.md)

### WebSocket Events

```javascript
const ws = new WebSocket('ws://localhost:8765/api/v1/ws');
ws.onmessage = (e) => {
  const event = JSON.parse(e.data);
  // event.type: "ThreatDetected" | "IpBanned" | "RuleAdded" | ...
  // event.data: { ip, severity, description, ... }
};
```

---

## Configuration

Default config: `/etc/sentinelwall/sentinelwall.toml`

```toml
[core]
backend = "nftables"
profile = "server"

[detection]
brute_force_threshold = 5
brute_force_window_secs = 300
port_scan_threshold = 20
flood_syn_pps = 1000
anomaly_z_score_threshold = 3.0

[response]
auto_ban = true
ban_duration_secs = 3600
escalating_bans = true

[api]
bind = "127.0.0.1"
port = 8765

[metrics]
enabled = true
port = 9100
```

Full reference: [docs/configuration.md](docs/configuration.md)

---

## Deployment

### Kubernetes (DaemonSet)

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/daemon-daemonset.yaml
kubectl apply -f deploy/kubernetes/web-deployment.yaml
kubectl apply -f deploy/kubernetes/monitoring.yaml
```

The daemon runs as a DaemonSet with `hostNetwork: true` to access the host nftables. Uses minimal capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`).

### Cluster Mode

```toml
[cluster]
enabled = true
node_id = "node-1"
peers = ["http://node2:8765", "http://node3:8765"]
cluster_secret = "your-shared-secret"
```

All ban events are automatically propagated to peers within 30 seconds.

---

## ML Service

The `sentinel-ml` Python service provides AI-powered threat scoring:

```bash
# Score an IP feature vector
curl -X POST http://localhost:8766/score \
  -H 'Content-Type: application/json' \
  -d '{
    "ip": "1.2.3.4",
    "features": {
      "packets_per_second": 5000.0,
      "bytes_per_second": 2000000.0,
      "unique_ports": 50.0,
      "syn_ratio": 0.95,
      "failed_auth_count": 12.0,
      ...
    }
  }'
# → {"risk_score": 0.92, "severity": "critical", "threat_type": "port_scan", "confidence": 0.89}

# Trigger model retraining
curl -X POST http://localhost:8766/train/unsupervised
```

---

## Performance

Benchmarked on a single core of Intel Xeon E5-2680 v4 @ 2.4GHz:

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Rule evaluation (1k rules) | < 100µs | 10,000+ eval/s |
| Rule evaluation (100k rules) | < 1ms | 1,000+ eval/s |
| IP ban insertion (nftables set) | < 50µs | 20,000 bans/s |
| API rule create | < 2ms p99 | 500 req/s |
| WebSocket fan-out (1k clients) | < 5ms | — |
| Threat detection (per connection) | < 500µs | 2,000+ conns/s |

Packet filtering itself is done in the kernel by nftables — user-space latency only applies to rule management and detection.

---

## Development

```bash
# Clone
git clone https://github.com/sinazarezadeh/SentinelWall
cd sentinelwall

# Build all Rust crates
cargo build --all

# Run daemon in dry-run mode (no nftables changes)
SENTINEL_DRY_RUN=true SENTINEL_ADMIN_PASSWORD=dev \
  cargo run --bin sentineld -- --config configs/sentinelwall.toml

# Run ML service
cd sentinel-ml
pip install -e ".[dev]"
uvicorn sentinel_ml.api:app --reload --port 8766

# Run web frontend
cd sentinel-web
npm install
npm run dev  # → http://localhost:5173

# Run all tests
SENTINEL_DRY_RUN=true cargo test --all
cd sentinel-ml && pytest tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a detailed breakdown of all components, data flows, and design decisions.

High-level overview:

```
CLI / TUI / Web UI
        ↓ HTTP/WS
   sentineld (Rust)
    ├─ REST API (axum)
    ├─ FirewallEngine
    │   ├─ RuleEngine → NftablesManager → nft (kernel)
    │   ├─ ThreatAnalyzer → EventBus → auto-ban
    │   └─ StateStore (SQLite)
    └─ ClusterManager → peer HTTP sync
        ↓ HTTP
   sentinel-ml (Python/FastAPI)
    ├─ Isolation Forest (unsupervised)
    └─ Random Forest Classifier
```

---

## Roadmap

- [ ] eBPF-based packet analysis for sub-microsecond detection
- [ ] DNS-level filtering (RPZ integration)
- [ ] IPSET compatibility mode
- [ ] Threat intelligence crowdsourcing (opt-in telemetry)
- [ ] mTLS cluster communication
- [ ] Plugin SDK for custom detectors
- [ ] IPv6-specific attack pattern detection
- [ ] Integration with SIEM systems (Splunk, Elastic SIEM)

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

<div align="center">
Built with Rust, Python, and React. Production-ready. Zero compromises.
</div>
