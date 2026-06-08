# SentinelWall Architecture

## Overview

SentinelWall is a multi-layer Linux firewall and intrusion prevention system built around three core principles: **performance** (Rust async runtime, zero-copy packet handling), **intelligence** (ML-based threat detection, statistical anomaly analysis), and **operability** (production-grade API, real-time observability, cluster sync).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            SentinelWall Stack                           │
├──────────────┬──────────────┬──────────────────┬────────────────────────┤
│  Web UI      │  CLI         │  TUI             │  REST API / WebSocket  │
│  React+Vite  │  sentinel    │  sentinel-tui    │  /api/v1/*             │
├──────────────┴──────────────┴──────────────────┴────────────────────────┤
│                     sentinel-daemon (sentineld)                          │
│  ┌───────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ Firewall  │  │ Threat     │  │ Auth Manager │  │  Cluster Sync    │ │
│  │ Engine    │  │ Analyzer   │  │ JWT + Argon2 │  │  Peer HTTP sync  │ │
│  └─────┬─────┘  └─────┬──────┘  └──────────────┘  └──────────────────┘ │
│        │               │                                                  │
│  ┌─────▼─────────────▼───────────────────────────────────────────────┐  │
│  │                    sentinel-core (library)                         │  │
│  │  RuleEngine │ NftablesManager │ StateStore │ EventBus │ Metrics   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────┤
│               Linux Kernel — nftables / netfilter                        │
└──────────────────────────────────────────────────────────────────────────┘
                              │
                   ┌──────────▼──────────┐
                   │   sentinel-ml       │
                   │  FastAPI + sklearn  │
                   │  Isolation Forest  │
                   │  Random Forest     │
                   └─────────────────────┘
```

## Component Breakdown

### `sentinel-core` (Library Crate)

The heart of SentinelWall. All stateful logic lives here, consumed by the daemon binary.

| Module | Responsibility |
|--------|---------------|
| `config/` | TOML configuration loading and validation |
| `rules/` | Rule types, matching engine, profile templates |
| `nftables/` | nftables rule builder and async executor |
| `detection/` | BruteForce, PortScan, Flood, Anomaly detectors |
| `events/` | `broadcast::channel`-based event bus (4096 cap) |
| `metrics/` | Prometheus registry, counters/gauges/histograms |
| `engine/` | `FirewallEngine` — orchestrates all subsystems |
| `store/` | SQLite persistence via sqlx (WAL mode) |
| `threat/` | Threat intel feeds: TOR, AbuseIPDB, CrowdSec |

**Key data flows:**

1. Packet → `ThreatAnalyzer::analyze_connection()` → `ThreatEvent` → `FirewallEngine::handle_threat()` → `RuleEngine::ban_ip()` → `NftablesManager::block_ip()` → nft set
2. Rule mutation → `RuleEngine` → `NftablesManager::apply_rule()` → `nft -j` subprocess → handle stored in `rule_handle_map`
3. State change → `EventBus::publish()` → broadcast to all subscribers (API WebSocket, metrics, cluster sync)

### `sentinel-daemon` (Binary)

The long-running system daemon (`sentineld`). Composes `sentinel-core` with:

- **Axum REST API** — all `/api/v1/*` routes with JWT middleware
- **WebSocket server** — real-time event streaming, subscribe via `EventBus`
- **AuthManager** — Argon2 password hashing, JWT HS256 tokens, API token SHA256 hashes
- **Metrics server** — separate Axum app on port 9100 serving Prometheus text format
- **ClusterManager** — periodic HTTP push of ban list to peer nodes

The daemon handles `SIGTERM` and `SIGHUP` (config reload) via tokio signal handlers. Systemd `Type=notify` integration signals readiness on startup completion.

### `sentinel-cli` (Binary)

`sentinel` — the primary operator interface. Uses `reqwest` for HTTP, `tokio-tungstenite` for WebSocket monitor command. All output goes through the `output` module for consistent color/emoji formatting and optional `--json` mode.

Authentication flow: `sentinel login` stores JWT in `~/.config/sentinel/token`. Subsequent commands attach it via `Authorization: Bearer` header.

### `sentinel-tui` (Binary)

`sentinel-tui` — interactive ncurses-style dashboard using `ratatui` + `crossterm`. Runs a background tokio task polling the API every 5 seconds. The main thread runs the crossterm event loop at 250ms tick rate.

Tab layout: Dashboard → Rules → Bans → Threats → Logs

### `sentinel-ml` (Python Service)

FastAPI microservice exposing:

| Endpoint | Description |
|----------|-------------|
| `POST /score` | Score single IP feature vector |
| `POST /score/batch` | Batch scoring |
| `POST /train` | Supervised training with labeled samples |
| `POST /train/unsupervised` | Retrain Isolation Forest |
| `GET /models/info` | Model metadata and accuracy metrics |
| `GET /metrics` | Prometheus metrics |

The **scoring pipeline** chains three detectors:

1. `StatisticalAnomalyDetector` — per-IP rolling baseline, z-score ≥ 3.0 = anomaly
2. `IsolationForestDetector` — global unsupervised model (contamination=0.05)
3. `ThreatClassifier` — RandomForest(200 trees) for threat type classification

`RiskScorer` combines their outputs with weights (0.30 / 0.35 / 0.35) into a 0–1 risk score. Thresholds: critical ≥ 0.85, high ≥ 0.65, medium ≥ 0.40.

### `sentinel-web` (React SPA)

Vite + React 18 + TypeScript + Tailwind CSS. State management via Zustand (auth store) + TanStack Query (server state). WebSocket hook with auto-reconnect.

Pages: Dashboard, Rules, Bans, Threats, Analytics, Profiles, Users, Settings.

The web UI calls the daemon API directly — `nginx` in the Docker setup proxies `/api/*` to `sentineld:8765`.

## Data Persistence

```
/var/lib/sentinelwall/
├── state.db           # SQLite: rules, bans, audit_log, threat_events
└── models/            # Serialized ML models (joblib)
    ├── isolation_forest.pkl
    ├── random_forest.pkl
    └── baselines.pkl
```

SQLite uses WAL mode and `PRAGMA synchronous = NORMAL` for maximum write throughput while maintaining durability.

## nftables Integration

SentinelWall creates a dedicated `inet sentinel` table at startup:

```nft
table inet sentinel {
    set banned_ipv4 {
        type ipv4_addr
        flags timeout
    }
    set banned_ipv6 {
        type ipv6_addr
        flags timeout
    }
    chain input {
        type filter hook input priority -100; policy accept;
        ip saddr @banned_ipv4 drop
        ip6 saddr @banned_ipv6 drop
        # ... dynamic rules follow
    }
}
```

Rules are applied via `nft -j --echo` which returns the assigned kernel handle. The handle is stored in memory and used for O(1) rule deletion — no need to rebuild the entire ruleset.

**Atomic updates**: rule changes are applied one-by-one via nft, not by flushing and re-adding. This ensures zero-downtime for live connections.

## Event Bus

All significant state changes emit `Event` variants on the broadcast channel:

```
PacketDropped, PacketAllowed, RuleAdded, RuleRemoved,
ThreatDetected, IpBanned, IpUnbanned, ProfileChanged,
ConnectionTrack, AnomalyDetected, GeoBlocked,
ThreatIntelHit, ClusterSync, ConfigReloaded, ServiceStarted, ServiceStopped
```

Consumers: WebSocket handler (→ web clients), metrics collector (→ Prometheus counters), cluster manager (→ peers), audit log (→ SQLite).

## Security Architecture

### Privilege Separation

- Daemon runs as unprivileged `sentinel` user
- Only `CAP_NET_ADMIN` and `CAP_NET_RAW` via ambient capabilities
- `setcap cap_net_admin,cap_net_raw+eip /usr/local/bin/sentineld`
- `NoNewPrivileges=yes` prevents privilege escalation
- `MemoryDenyWriteExecute=yes` prevents JIT shellcode injection

### Authentication

- Passwords: Argon2id with random salt, memory=65536, iterations=3
- Sessions: HS256 JWT signed with random 256-bit secret
- API tokens: SHA256 hash stored, shown once at creation
- All API routes require `Authorization: Bearer <token>` except `/health`, `/login`

### TLS

Production deployments should terminate TLS at the daemon or upstream reverse proxy. Config fields `tls_cert` and `tls_key` enable native TLS in axum via `axum-server`.

## Performance Design

| Subsystem | Mechanism |
|-----------|-----------|
| Rule lookup | Sorted Vec by priority, short-circuit on first match |
| IP ban check | nftables kernel set (O(log n) via rbtree) |
| Per-IP tracking | `DashMap<IpAddr, IpStats>` — lock-free concurrent hashmap |
| Event distribution | `broadcast::channel` — zero-copy fan-out |
| API server | tokio + axum — async I/O, connection pooling |
| DB writes | Write-ahead log, batched inserts for audit events |

Target: < 1ms rule evaluation latency at 100k rules, < 50µs ban insertion via nftables set.

## Cluster Sync

Multi-node deployments sync ban lists via REST API push:

```
Node A bans 1.2.3.4
    → ClusterManager::sync_bans()
    → POST /api/v1/bans to each peer
    → Peers add ban with same TTL
```

Sync interval: 30 seconds (configurable). Split-brain is handled gracefully — each node independently protects itself, sync is best-effort.
