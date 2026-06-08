pub mod routes;
pub mod handlers;
pub mod middleware;
pub mod websocket;
pub mod types;

use std::sync::Arc;
use anyhow::Result;
use axum::{Router, Extension};
use tower_http::cors::{CorsLayer, Any};
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use sentinel_core::FirewallEngine;
use sentinel_core::config::ApiConfig;
use crate::auth::AuthManager;

pub struct ApiServer {
    engine: Arc<FirewallEngine>,
    auth: Arc<AuthManager>,
    config: ApiConfig,
}

impl ApiServer {
    pub fn new(engine: Arc<FirewallEngine>, auth: Arc<AuthManager>, config: ApiConfig) -> Self {
        Self { engine, auth, config }
    }

    pub async fn run(&self) -> Result<()> {
        let app = self.build_router();
        let addr = format!("{}:{}", self.config.bind, self.config.port);
        info!("API listening on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }

    fn build_router(&self) -> Router {
        let engine = self.engine.clone();
        let auth = self.auth.clone();

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        Router::new()
            .merge(routes::api_router())
            .layer(Extension(engine))
            .layer(Extension(auth))
            .layer(cors)
            .layer(CompressionLayer::new())
            .layer(TraceLayer::new_for_http())
    }
}
