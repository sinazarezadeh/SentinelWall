use axum::{
    Router,
    routing::{get, post, put, delete},
};

use super::handlers::*;
use super::websocket::ws_handler;

pub fn api_router() -> Router {
    Router::new()
        // Health & info
        .route("/health", get(health))
        .route("/api/v1/info", get(info))
        .route("/api/v1/status", get(status))

        // Auth
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/refresh", post(refresh_token))
        .route("/api/v1/auth/me", get(me))

        // Users (admin only)
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/:id", put(update_user).delete(delete_user))

        // API tokens
        .route("/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/api/v1/tokens/:id", delete(revoke_token))

        // Rules
        .route("/api/v1/rules", get(list_rules).post(create_rule))
        .route("/api/v1/rules/:id", get(get_rule).put(update_rule).delete(delete_rule))
        .route("/api/v1/rules/:id/enable", post(enable_rule))
        .route("/api/v1/rules/:id/disable", post(disable_rule))
        .route("/api/v1/rules/flush", post(flush_rules))
        .route("/api/v1/rules/import", post(import_rules))
        .route("/api/v1/rules/export", get(export_rules))

        // Profiles
        .route("/api/v1/profiles", get(list_profiles))
        .route("/api/v1/profiles/:name/apply", post(apply_profile))

        // Bans
        .route("/api/v1/bans", get(list_bans).post(ban_ip))
        .route("/api/v1/bans/:ip", get(get_ban).delete(unban_ip))
        .route("/api/v1/bans/check/:ip", get(check_ban))

        // Threats
        .route("/api/v1/threats", get(list_threats))
        .route("/api/v1/threats/stats", get(threat_stats))

        // Metrics
        .route("/api/v1/metrics", get(get_metrics))

        // Zones
        .route("/api/v1/zones", get(list_zones).post(create_zone))
        .route("/api/v1/zones/:name", get(get_zone).put(update_zone).delete(delete_zone))

        // Config
        .route("/api/v1/config", get(get_config).put(update_config))
        .route("/api/v1/config/reload", post(reload_config))

        // Geo
        .route("/api/v1/geo/lookup/:ip", get(geo_lookup))

        // Threat intel
        .route("/api/v1/threat-intel/check/:ip", get(check_threat_intel))
        .route("/api/v1/threat-intel/feeds", get(list_feeds))

        // WebSocket
        .route("/api/v1/ws", get(ws_handler))

        // Nftables
        .route("/api/v1/nftables/ruleset", get(get_nft_ruleset))
}
