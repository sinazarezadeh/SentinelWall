use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};
use anyhow::Result;
use reqwest::Client;
use serde_json::json;

use sentinel_core::FirewallEngine;
use sentinel_core::config::ClusterConfig;

pub struct ClusterManager {
    config: ClusterConfig,
    engine: Arc<FirewallEngine>,
    http: Client,
    node_id: String,
}

impl ClusterManager {
    pub fn new(config: ClusterConfig, engine: Arc<FirewallEngine>) -> Self {
        let node_id = config.node_id.clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Self {
            config,
            engine,
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent(format!("SentinelWall/{}", sentinel_core::VERSION))
                .build()
                .unwrap_or_default(),
            node_id,
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!("Starting cluster sync (node_id={})", self.node_id);
        let mut tick = interval(Duration::from_secs(self.config.sync_interval_secs));

        loop {
            tick.tick().await;
            for peer in &self.config.peers {
                if let Err(e) = self.sync_with_peer(peer).await {
                    warn!("Cluster sync failed with {}: {}", peer, e);
                }
            }
        }
    }

    async fn sync_with_peer(&self, peer: &str) -> Result<()> {
        debug!("Syncing with peer: {}", peer);

        // Push our bans to peer
        let bans = self.engine.get_banned_ips().await;
        let payload = json!({
            "node_id": self.node_id,
            "bans": bans,
        });

        let url = format!("http://{}/api/v1/cluster/sync", peer);
        self.http.post(&url)
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }
}
