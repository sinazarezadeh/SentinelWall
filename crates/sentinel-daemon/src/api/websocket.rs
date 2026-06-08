use std::sync::Arc;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use tracing::{info, debug, warn};
use serde_json::json;

use sentinel_core::FirewallEngine;
use sentinel_core::events::Event;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Extension(engine): Extension<Arc<FirewallEngine>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, engine))
}

async fn handle_socket(socket: WebSocket, engine: Arc<FirewallEngine>) {
    let (mut sender, mut receiver) = socket.split();
    let mut event_rx = engine.event_bus().subscribe();

    info!("WebSocket client connected");

    // Send welcome message
    let welcome = json!({
        "type": "connected",
        "version": sentinel_core::VERSION,
        "message": "Connected to SentinelWall event stream"
    });
    if let Err(e) = sender.send(Message::Text(welcome.to_string())).await {
        warn!("Failed to send WebSocket welcome: {}", e);
        return;
    }

    // Forward events to WebSocket client
    let mut send_task = tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    let msg = serialize_event(&event);
                    if let Err(e) = sender.send(Message::Text(msg)).await {
                        debug!("WebSocket send error (client likely disconnected): {}", e);
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("WebSocket event stream lagged by {} events", n);
                }
                Err(_) => break,
            }
        }
    });

    // Handle messages from client (ping/pong, commands)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Ping(data) => {
                    debug!("WebSocket ping received");
                    // pong is handled automatically by axum
                }
                Message::Close(_) => {
                    info!("WebSocket client disconnected");
                    break;
                }
                Message::Text(text) => {
                    debug!("WebSocket message from client: {}", text);
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }

    info!("WebSocket connection closed");
}

fn serialize_event(event: &Event) -> String {
    let payload = match event {
        Event::ThreatDetected(t) => json!({
            "type": "threat",
            "data": {
                "id": t.id,
                "ip": t.ip,
                "threat_type": t.threat_type.to_string(),
                "severity": t.severity.to_string(),
                "description": t.description,
                "timestamp": t.timestamp
            }
        }),
        Event::IpBanned { ip, ban } => json!({
            "type": "ban",
            "data": {
                "ip": ip,
                "reason": ban.reason.to_string(),
                "expires_at": ban.expires_at,
                "timestamp": ban.banned_at
            }
        }),
        Event::IpUnbanned { ip, .. } => json!({
            "type": "unban",
            "data": { "ip": ip }
        }),
        Event::RuleAdded { rule } => json!({
            "type": "rule_added",
            "data": { "id": rule.id, "name": rule.name }
        }),
        Event::RuleRemoved { id } => json!({
            "type": "rule_removed",
            "data": { "id": id }
        }),
        _ => json!({
            "type": event.name(),
            "data": {}
        }),
    };

    payload.to_string()
}
