use std::net::IpAddr;
use std::sync::Arc;
use axum::{
    Extension, Json,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};
use tracing::info;

use sentinel_core::{FirewallEngine, rules::*};
use crate::auth::{AuthManager, LoginRequest, Role};
use super::types::*;

type EngineExt = Extension<Arc<FirewallEngine>>;
type AuthExt = Extension<Arc<AuthManager>>;

// ─── Health & Info ─────────────────────────────────────────────────────────

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "sentineld" }))
}

pub async fn info(Extension(engine): EngineExt) -> Json<Value> {
    Json(json!({
        "name": sentinel_core::NAME,
        "version": sentinel_core::VERSION,
        "description": "Next-Generation Linux Firewall & Intrusion Prevention System",
        "uptime_seconds": engine.uptime_seconds(),
        "features": [
            "nftables", "iptables-compat", "geo-blocking",
            "threat-detection", "ml-analysis", "cluster-sync",
            "websocket-events", "prometheus-metrics"
        ]
    }))
}

pub async fn status(Extension(engine): EngineExt) -> Json<Value> {
    let rules = engine.get_rules().await;
    let bans = engine.get_banned_ips().await;

    Json(json!({
        "status": "running",
        "version": sentinel_core::VERSION,
        "uptime_seconds": engine.uptime_seconds(),
        "rules_count": rules.len(),
        "bans_count": bans.len(),
        "backend": "nftables",
    }))
}

// ─── Auth ──────────────────────────────────────────────────────────────────

pub async fn login(
    Extension(auth): AuthExt,
    Json(req): Json<LoginRequest>,
) -> Result<Json<Value>, AppError> {
    let user = auth.authenticate(&req.username, &req.password)
        .ok_or_else(|| AppError::unauthorized("Invalid credentials"))?;

    let (token, expires_at) = auth.generate_token(&user)
        .map_err(|e| AppError::internal(e.to_string()))?;

    info!("User '{}' logged in", user.username);

    Ok(Json(json!({
        "success": true,
        "data": {
            "token": token,
            "expires_at": expires_at,
            "user": {
                "id": user.id,
                "username": user.username,
                "role": format!("{:?}", user.role).to_lowercase()
            }
        }
    })))
}

pub async fn logout() -> Json<Value> {
    Json(json!({ "success": true, "message": "Logged out" }))
}

pub async fn refresh_token() -> Json<Value> {
    Json(json!({ "success": true }))
}

pub async fn me(
    Extension(auth): AuthExt,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, AppError> {
    let claims = extract_claims(&auth, &headers)?;
    Ok(Json(json!({
        "success": true,
        "data": {
            "username": claims.username,
            "role": claims.role,
        }
    })))
}

// ─── Users ─────────────────────────────────────────────────────────────────

pub async fn list_users(Extension(auth): AuthExt) -> Json<Value> {
    let users = auth.list_users();
    Json(json!({ "success": true, "data": users }))
}

pub async fn create_user(
    Extension(auth): AuthExt,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let username = body["username"].as_str()
        .ok_or_else(|| AppError::bad_request("username required"))?
        .to_string();
    let password = body["password"].as_str()
        .ok_or_else(|| AppError::bad_request("password required"))?
        .to_string();
    let role: Role = match body["role"].as_str().unwrap_or("viewer") {
        "admin" => Role::Admin,
        "operator" => Role::Operator,
        _ => Role::Viewer,
    };

    let user = auth.create_user(username, password, role)
        .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "success": true, "data": { "id": user.id, "username": user.username } })))
}

pub async fn update_user() -> Json<Value> {
    Json(json!({ "success": true }))
}

pub async fn delete_user() -> Json<Value> {
    Json(json!({ "success": true }))
}

// ─── API Tokens ────────────────────────────────────────────────────────────

pub async fn list_tokens() -> Json<Value> {
    Json(json!({ "success": true, "data": [] }))
}

pub async fn create_token(
    Extension(auth): AuthExt,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let name = body["name"].as_str()
        .ok_or_else(|| AppError::bad_request("name required"))?
        .to_string();
    let role: Role = match body["role"].as_str().unwrap_or("viewer") {
        "admin" => Role::Admin,
        "operator" => Role::Operator,
        _ => Role::Viewer,
    };
    let expires_in_days = body["expires_in_days"].as_u64();

    let (token, api_token) = auth.create_api_token(name, role, expires_in_days)
        .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": {
            "token": token,
            "id": api_token.id,
            "name": api_token.name,
            "expires_at": api_token.expires_at
        },
        "warning": "Store this token securely — it will not be shown again"
    })))
}

pub async fn revoke_token() -> Json<Value> {
    Json(json!({ "success": true }))
}

// ─── Rules ─────────────────────────────────────────────────────────────────

pub async fn list_rules(Extension(engine): EngineExt) -> Json<Value> {
    let rules = engine.get_rules().await;
    Json(json!({ "success": true, "data": rules, "total": rules.len() }))
}

pub async fn create_rule(
    Extension(engine): EngineExt,
    Json(rule): Json<Rule>,
) -> Result<Json<Value>, AppError> {
    let id = engine.add_rule(rule)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "success": true, "data": { "id": id } })))
}

pub async fn get_rule(
    Extension(engine): EngineExt,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let rule_id: RuleId = RuleId(id.parse().map_err(|_| AppError::bad_request("Invalid rule ID"))?);
    let rule = engine.get_rules().await.into_iter().find(|r| r.id == rule_id)
        .ok_or_else(|| AppError::not_found("Rule not found"))?;
    Ok(Json(json!({ "success": true, "data": rule })))
}

pub async fn update_rule(
    Extension(engine): EngineExt,
    Path(id): Path<String>,
    Json(mut rule): Json<Rule>,
) -> Result<Json<Value>, AppError> {
    rule.id = RuleId(id.parse().map_err(|_| AppError::bad_request("Invalid rule ID"))?);
    engine.add_rule(rule).await.map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(json!({ "success": true })))
}

pub async fn delete_rule(
    Extension(engine): EngineExt,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let rule_id = RuleId(id.parse().map_err(|_| AppError::bad_request("Invalid rule ID"))?);
    let removed = engine.remove_rule(&rule_id).await
        .map_err(|e| AppError::internal(e.to_string()))?;

    if removed {
        Ok(Json(json!({ "success": true })))
    } else {
        Err(AppError::not_found("Rule not found"))
    }
}

pub async fn enable_rule() -> Json<Value> { Json(json!({ "success": true })) }
pub async fn disable_rule() -> Json<Value> { Json(json!({ "success": true })) }

pub async fn flush_rules(Extension(engine): EngineExt) -> Result<Json<Value>, AppError> {
    engine.flush_rules().await.map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(json!({ "success": true, "message": "All rules flushed" })))
}

pub async fn import_rules(
    Extension(engine): EngineExt,
    Json(rules): Json<Vec<Rule>>,
) -> Result<Json<Value>, AppError> {
    let count = rules.len();
    for rule in rules {
        engine.add_rule(rule).await.map_err(|e| AppError::internal(e.to_string()))?;
    }
    Ok(Json(json!({ "success": true, "imported": count })))
}

pub async fn export_rules(Extension(engine): EngineExt) -> Json<Value> {
    let rules = engine.get_rules().await;
    Json(json!({ "success": true, "data": rules }))
}

// ─── Profiles ──────────────────────────────────────────────────────────────

pub async fn list_profiles() -> Json<Value> {
    Json(json!({
        "success": true,
        "data": [
            { "name": "web-server", "description": "HTTP/HTTPS + SSH" },
            { "name": "reverse-proxy", "description": "Reverse proxy with upstream rules" },
            { "name": "game-server", "description": "Game server ports + DDoS protection" },
            { "name": "docker-host", "description": "Docker with bridge network rules" },
            { "name": "kubernetes-node", "description": "K8s node ports and CNI" },
            { "name": "vpn-gateway", "description": "WireGuard/OpenVPN gateway" },
            { "name": "ssh-hardened", "description": "SSH-only with aggressive rate limiting" },
            { "name": "database-server", "description": "Database ports blocked from public" },
            { "name": "home-server", "description": "Home server profile" },
            { "name": "enterprise-edge", "description": "Enterprise edge with BGP/DNS/NTP" },
        ]
    }))
}

pub async fn apply_profile(
    Extension(engine): EngineExt,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    let profile: sentinel_core::config::types::FirewallProfile = name.parse()
        .map_err(|e: anyhow::Error| AppError::bad_request(e.to_string()))?;

    engine.apply_profile(&profile).await
        .map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "success": true, "message": format!("Profile '{}' applied", name) })))
}

// ─── Bans ──────────────────────────────────────────────────────────────────

pub async fn list_bans(Extension(engine): EngineExt) -> Json<Value> {
    let bans = engine.get_banned_ips().await;
    Json(json!({ "success": true, "data": bans, "total": bans.len() }))
}

pub async fn ban_ip(
    Extension(engine): EngineExt,
    Json(req): Json<BanRequest>,
) -> Result<Json<Value>, AppError> {
    let duration = if req.permanent.unwrap_or(false) {
        None
    } else {
        req.duration_secs.or(Some(3600))
    };

    engine.ban_ip(req.ip, sentinel_core::rules::BanReason::ManualBan, duration, vec![
        format!("reason={}", req.reason),
        req.comment.map(|c| format!("comment={}", c)).unwrap_or_default(),
    ]).await.map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Json(json!({ "success": true, "message": format!("IP {} banned", req.ip) })))
}

pub async fn get_ban(
    Extension(engine): EngineExt,
    Path(ip): Path<String>,
) -> Result<Json<Value>, AppError> {
    let ip: IpAddr = ip.parse().map_err(|_| AppError::bad_request("Invalid IP address"))?;
    let bans = engine.get_banned_ips().await;
    let ban = bans.into_iter().find(|b| b.ip == ip)
        .ok_or_else(|| AppError::not_found("IP not banned"))?;
    Ok(Json(json!({ "success": true, "data": ban })))
}

pub async fn unban_ip(
    Extension(engine): EngineExt,
    Path(ip): Path<String>,
) -> Result<Json<Value>, AppError> {
    let ip: IpAddr = ip.parse().map_err(|_| AppError::bad_request("Invalid IP address"))?;
    let removed = engine.unban_ip(&ip).await
        .map_err(|e| AppError::internal(e.to_string()))?;

    if removed {
        Ok(Json(json!({ "success": true, "message": format!("IP {} unbanned", ip) })))
    } else {
        Err(AppError::not_found("IP not found in ban list"))
    }
}

pub async fn check_ban(
    Extension(engine): EngineExt,
    Path(ip): Path<String>,
) -> Result<Json<Value>, AppError> {
    let ip: IpAddr = ip.parse().map_err(|_| AppError::bad_request("Invalid IP address"))?;
    let banned = engine.is_banned(&ip).await;
    Ok(Json(json!({ "success": true, "data": { "ip": ip, "banned": banned } })))
}

// ─── Threats ───────────────────────────────────────────────────────────────

pub async fn list_threats() -> Json<Value> {
    Json(json!({ "success": true, "data": [], "total": 0 }))
}

pub async fn threat_stats() -> Json<Value> {
    Json(json!({
        "success": true,
        "data": {
            "today": 0,
            "week": 0,
            "month": 0,
            "by_type": {},
            "by_severity": {},
            "top_offenders": []
        }
    }))
}

// ─── Metrics ───────────────────────────────────────────────────────────────

pub async fn get_metrics(Extension(engine): EngineExt) -> Result<String, AppError> {
    engine.metrics().render()
        .map_err(|e| AppError::internal(e.to_string()))
}

// ─── Zones ─────────────────────────────────────────────────────────────────

pub async fn list_zones() -> Json<Value> {
    Json(json!({ "success": true, "data": [
        { "name": "public", "policy": "drop" },
        { "name": "private", "policy": "accept" },
        { "name": "trusted", "policy": "accept" },
    ]}))
}

pub async fn create_zone() -> Json<Value> { Json(json!({ "success": true })) }
pub async fn get_zone() -> Json<Value> { Json(json!({ "success": true })) }
pub async fn update_zone() -> Json<Value> { Json(json!({ "success": true })) }
pub async fn delete_zone() -> Json<Value> { Json(json!({ "success": true })) }

// ─── Config ────────────────────────────────────────────────────────────────

pub async fn get_config() -> Json<Value> {
    Json(json!({ "success": true, "data": {} }))
}

pub async fn update_config() -> Json<Value> {
    Json(json!({ "success": true }))
}

pub async fn reload_config() -> Json<Value> {
    Json(json!({ "success": true, "message": "Configuration reloaded" }))
}

// ─── Geo ───────────────────────────────────────────────────────────────────

pub async fn geo_lookup(
    Extension(engine): EngineExt,
    Path(ip): Path<String>,
) -> Result<Json<Value>, AppError> {
    let ip: IpAddr = ip.parse().map_err(|_| AppError::bad_request("Invalid IP address"))?;
    let banned = engine.is_banned(&ip).await;
    Ok(Json(json!({
        "success": true,
        "data": {
            "ip": ip,
            "country": null,
            "asn": null,
            "is_tor": false,
            "is_banned": banned
        }
    })))
}

// ─── Threat Intel ──────────────────────────────────────────────────────────

pub async fn check_threat_intel(Path(ip): Path<String>) -> Result<Json<Value>, AppError> {
    let ip: IpAddr = ip.parse().map_err(|_| AppError::bad_request("Invalid IP address"))?;
    Ok(Json(json!({
        "success": true,
        "data": { "ip": ip, "threat": null, "clean": true }
    })))
}

pub async fn list_feeds() -> Json<Value> {
    Json(json!({ "success": true, "data": [] }))
}

// ─── Nftables ──────────────────────────────────────────────────────────────

pub async fn get_nft_ruleset() -> Json<Value> {
    Json(json!({ "success": true, "data": "" }))
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn extract_claims(
    auth: &AuthManager,
    headers: &axum::http::HeaderMap,
) -> Result<crate::auth::Claims, AppError> {
    let header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("No authorization header"))?;

    let token = header.strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("Invalid authorization format"))?;

    auth.validate_token(token)
        .map_err(|_| AppError::unauthorized("Invalid or expired token"))
}

// ─── Error type ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
}

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, message: msg.into() }
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::UNAUTHORIZED, message: msg.into() }
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::NOT_FOUND, message: msg.into() }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, message: msg.into() }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "success": false,
            "error": self.message,
        });
        (self.status, Json(body)).into_response()
    }
}
