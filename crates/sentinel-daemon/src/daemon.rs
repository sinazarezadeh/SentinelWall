use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn};

use sentinel_core::{SentinelConfig, FirewallEngine};
use crate::api::ApiServer;
use crate::auth::AuthManager;
use crate::cluster::ClusterManager;

pub struct Daemon {
    engine: Arc<FirewallEngine>,
    api: Arc<ApiServer>,
    auth: Arc<AuthManager>,
    config: SentinelConfig,
}

impl Daemon {
    pub async fn new(config: SentinelConfig, _dry_run: bool) -> Result<Self> {
        info!("Initializing daemon");

        let engine = FirewallEngine::new(config.clone()).await?;
        engine.start().await?;
        engine.start_background_tasks().await;

        let auth = Arc::new(AuthManager::new(config.api.jwt_secret.clone()));
        let api = ApiServer::new(engine.clone(), auth.clone(), config.api.clone());

        Ok(Self {
            engine,
            api: Arc::new(api),
            auth,
            config,
        })
    }

    pub async fn run(&self) -> Result<()> {
        info!("Starting API server on {}:{}", self.config.api.bind, self.config.api.port);

        // Start metrics server if enabled
        if self.config.metrics.enabled {
            let metrics = self.engine.metrics();
            let bind = self.config.metrics.bind.clone();
            let port = self.config.metrics.port;
            let path = self.config.metrics.path.clone();

            tokio::spawn(async move {
                if let Err(e) = serve_metrics(metrics, &bind, port, &path).await {
                    warn!("Metrics server error: {}", e);
                }
            });
        }

        // Start cluster sync if enabled
        if self.config.cluster.enabled {
            let cluster = ClusterManager::new(self.config.cluster.clone(), self.engine.clone());
            tokio::spawn(async move {
                if let Err(e) = cluster.run().await {
                    warn!("Cluster sync error: {}", e);
                }
            });
        }

        // Run API server (blocking)
        self.api.run().await
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping daemon");
        self.engine.stop().await
    }

    pub async fn flush(&self) -> Result<()> {
        self.engine.flush_rules().await
    }
}

async fn serve_metrics(
    metrics: Arc<sentinel_core::MetricsCollector>,
    bind: &str,
    port: u16,
    path: &str,
) -> Result<()> {
    use axum::{Router, routing::get, extract::State, response::Response};
    use axum::body::Body;

    let path_clone = path.to_string();
    let app = Router::new()
        .route(&path_clone, get(move |State(m): State<Arc<sentinel_core::MetricsCollector>>| async move {
            match m.render() {
                Ok(text) => Response::builder()
                    .header("Content-Type", "text/plain; version=0.0.4")
                    .body(Body::from(text))
                    .unwrap(),
                Err(e) => Response::builder()
                    .status(500)
                    .body(Body::from(format!("Error: {}", e)))
                    .unwrap(),
            }
        }))
        .with_state(metrics);

    let addr = format!("{}:{}", bind, port);
    info!("Metrics server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
