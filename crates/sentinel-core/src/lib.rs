pub mod config;
pub mod engine;
pub mod nftables;
pub mod rules;
pub mod detection;
pub mod events;
pub mod metrics;
pub mod geo;
pub mod response;
pub mod store;
pub mod threat;

pub use config::SentinelConfig;
pub use engine::FirewallEngine;
pub use rules::{Rule, RuleAction, Protocol, RuleSet};
pub use events::{Event, EventBus};
pub use metrics::MetricsCollector;

use anyhow::Result;

/// Initialize the core library with tracing
pub fn init_tracing(level: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(level))
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();
}

/// SentinelWall version info
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = "SentinelWall";

/// Core result type
pub type SentinelResult<T> = Result<T>;
