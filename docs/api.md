# SentinelWall API Reference

Base URL: `http://localhost:8765/api/v1`

All endpoints except `/health` and `POST /auth/login` require:
```
Authorization: Bearer <jwt_token>
```

## Authentication

### POST /auth/login

```json
Request:  { "username": "admin", "password": "changeme123" }
Response: {
  "token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "expires_at": "2024-01-02T00:00:00Z",
  "user": { "id": "uuid", "username": "admin", "role": "admin" }
}
```

### POST /auth/refresh

```json
Request:  { "refresh_token": "eyJhbGci..." }
Response: { "token": "eyJhbGci...", "expires_at": "..." }
```

### POST /auth/logout

Invalidates the current session token. No request body.

### GET /auth/me

Returns the currently authenticated user.

---

## System

### GET /health

No authentication required.

```json
{ "status": "ok", "version": "0.1.0", "uptime_secs": 3600 }
```

### GET /status

```json
{
  "version": "0.1.0",
  "uptime_secs": 3600,
  "active_rules": 42,
  "active_bans": 17,
  "profile": "server",
  "backend": "nftables",
  "threats_today": 5,
  "packets_processed": 1234567,
  "bytes_processed": 987654321
}
```

### GET /metrics

Prometheus text format metrics. Also available on port 9100 without auth.

### POST /config/reload

Reload configuration from disk without restarting.

### GET /config

Returns current running configuration (sensitive fields redacted).

### PUT /config

Update configuration. Requires admin role.

---

## Rules

### GET /rules

Query params: `?enabled=true&action=allow&protocol=tcp&page=1&limit=50`

```json
{
  "rules": [
    {
      "id": "uuid",
      "name": "allow-ssh",
      "priority": 100,
      "action": "allow",
      "direction": "in",
      "protocol": "tcp",
      "dst_port": { "single": 22 },
      "enabled": true,
      "hit_count": 1234,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 42
}
```

### POST /rules

```json
Request: {
  "name": "block-smtp",
  "priority": 50,
  "action": "drop",
  "direction": "in",
  "protocol": "tcp",
  "dst_port": { "single": 25 },
  "enabled": true
}
Response: { "id": "uuid", ...rule }
```

### GET /rules/{id}

Returns a single rule.

### PUT /rules/{id}

Update rule fields. Partial update supported.

### DELETE /rules/{id}

Remove rule immediately (atomic nftables deletion by handle).

### POST /rules/flush

Remove all rules. Emergency reset. Requires admin role.

### GET /rules/export

Export all rules as JSON array.

### POST /rules/import

Import rules from JSON array. Query param: `?mode=replace|merge`

---

## Bans

### GET /bans

Query params: `?page=1&limit=50&reason=brute_force`

```json
{
  "bans": [
    {
      "ip": "1.2.3.4",
      "reason": "brute_force",
      "added_at": "2024-01-01T12:00:00Z",
      "expires_at": "2024-01-01T13:00:00Z",
      "hit_count": 12
    }
  ],
  "total": 17
}
```

### POST /bans

```json
Request: {
  "ip": "1.2.3.4",
  "reason": "manual",
  "duration_secs": 3600,
  "comment": "suspicious behavior"
}
```

### DELETE /bans/{ip}

Unban an IP immediately.

### GET /bans/{ip}

Check if an IP is banned.

```json
{ "banned": true, "reason": "brute_force", "expires_at": "..." }
```

---

## Threats

### GET /threats

Recent threat events. Query params: `?severity=critical&limit=100`

```json
{
  "threats": [
    {
      "id": "uuid",
      "ip": "5.6.7.8",
      "threat_type": "brute_force",
      "severity": "high",
      "confidence": 0.95,
      "description": "12 failed SSH attempts in 5 minutes",
      "evidence": { "attempt_count": 12, "window_secs": 300 },
      "recommended_action": "ban",
      "detected_at": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### GET /threats/stats

```json
{
  "total_today": 42,
  "by_severity": { "critical": 2, "high": 8, "medium": 15, "low": 17 },
  "by_type": { "brute_force": 20, "port_scan": 10, "flood": 5, "anomaly": 7 },
  "top_sources": [{ "ip": "1.2.3.4", "count": 8 }]
}
```

---

## Profiles

### GET /profiles

```json
{
  "profiles": ["public", "private", "trusted", "server", "web", "database", "kubernetes", "dmz", "strict", "minimal"],
  "active": "server"
}
```

### POST /profiles/{name}/apply

Apply a profile. Replaces current rule set with profile defaults.

```json
Response: { "applied": "web", "rules_loaded": 18 }
```

---

## Geo-IP

### GET /geo/{ip}

```json
{
  "ip": "8.8.8.8",
  "country_code": "US",
  "country_name": "United States",
  "city": "Mountain View",
  "latitude": 37.3861,
  "longitude": -122.0839,
  "is_blocked": false
}
```

---

## Threat Intelligence

### GET /threat-intel/{ip}

```json
{
  "ip": "1.2.3.4",
  "is_tor_exit": false,
  "abuseipdb_score": 95,
  "abuseipdb_reports": 120,
  "in_blocklist": false,
  "crowdsec_score": null
}
```

### POST /threat-intel/feeds/update

Trigger manual update of all threat intel feeds.

---

## Users

### GET /users

List all users (admin only).

### POST /users

Create user.

```json
Request: { "username": "ops", "password": "secure123", "role": "operator" }
```

### PUT /users/{id}

Update user. Can change password or role.

### DELETE /users/{id}

Delete user. Cannot delete your own account.

---

## API Tokens

### GET /tokens

List tokens for the current user.

### POST /tokens

Create a new API token.

```json
Request: { "name": "monitoring-script", "expires_in_days": 90 }
Response: { "id": "uuid", "name": "monitoring-script", "token": "sw_...", "expires_at": "..." }
```

**The raw token is only shown once.**

### DELETE /tokens/{id}

Revoke a token.

---

## Zones

### GET /zones

List firewall zones.

### POST /zones

Create a custom zone.

### PUT /zones/{name}

Update zone configuration (interfaces, trusted networks).

### DELETE /zones/{name}

Delete a zone.

---

## WebSocket

### WS /ws

Connect to receive real-time events.

```javascript
const ws = new WebSocket('ws://localhost:8765/api/v1/ws');
// First message is auth
ws.send(JSON.stringify({ type: 'auth', token: 'eyJ...' }));

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  // msg.type: one of Event variant names
  // msg.data: event-specific payload
  // msg.timestamp: ISO8601
};
```

Event types: `PacketDropped`, `PacketAllowed`, `RuleAdded`, `RuleRemoved`, `ThreatDetected`, `IpBanned`, `IpUnbanned`, `ProfileChanged`, `ConnectionTrack`, `AnomalyDetected`, `GeoBlocked`, `ThreatIntelHit`, `ClusterSync`, `ConfigReloaded`, `ServiceStarted`, `ServiceStopped`

---

## Error Responses

All errors follow this format:

```json
{
  "error": "rule_not_found",
  "message": "No rule with id 'abc123'",
  "status": 404
}
```

Common status codes:
- `400` — Bad request / validation error
- `401` — Unauthenticated
- `403` — Insufficient permissions
- `404` — Resource not found
- `409` — Conflict (e.g., duplicate rule name)
- `429` — Rate limit exceeded
- `500` — Internal server error
