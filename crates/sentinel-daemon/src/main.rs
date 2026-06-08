use std::path::PathBuf;
use anyhow::Result;
use clap::Parser;
use tracing::{info, warn, error};

mod daemon;
mod api;
mod auth;
mod cluster;

#[derive(Parser, Debug)]
#[command(
    name = "sentineld",
    about = "SentinelWall Daemon — Next-Generation Linux Firewall & IPS",
    version,
    long_about = None
)]
struct Cli {
    #[arg(short, long, default_value = "/etc/sentinelwall/sentinelwall.toml", env = "SENTINEL_CONFIG")]
    config: PathBuf,

    #[arg(short, long, default_value = "info", env = "SENTINEL_LOG")]
    log_level: String,

    #[arg(long, help = "Run without applying nftables rules")]
    dry_run: bool,

    #[arg(long, help = "Validate configuration and exit")]
    check_config: bool,

    #[arg(long, help = "Dump default configuration and exit")]
    dump_config: bool,

    #[arg(long, help = "Flush all rules and exit")]
    flush: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    sentinel_core::init_tracing(&cli.log_level);

    info!("  ____            _   _            _  __        __    _ _ ");
    info!(" / ___|  ___ _ __ | |_(_)_ __   ___| | \\ \\      / /_ _| | |");
    info!(" \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |  \\ \\ /\\ / / _` | | |");
    info!("  ___) |  __/ | | | |_| | | | |  __/ |   \\ V  V / (_| | | |");
    info!(" |____/ \\___|_| |_|\\__|_|_| |_|\\___|_|    \\_/\\_/ \\__,_|_|_|");
    info!("                                                              ");
    info!(" SentinelWall v{} — Next-Generation Linux Firewall & IPS", sentinel_core::VERSION);
    info!("");

    if cli.dump_config {
        let config = sentinel_core::SentinelConfig::default();
        println!("{}", toml::to_string_pretty(&config)?);
        return Ok(());
    }

    // Load configuration
    let config = if cli.config.exists() {
        info!("Loading config: {}", cli.config.display());
        sentinel_core::SentinelConfig::load(&cli.config)?
    } else {
        warn!("Config not found at {}, using defaults", cli.config.display());
        sentinel_core::SentinelConfig::default()
    };

    if cli.check_config {
        config.validate()?;
        info!("Configuration is valid");
        return Ok(());
    }

    // Initialize daemon
    let daemon = daemon::Daemon::new(config, cli.dry_run).await?;

    if cli.flush {
        daemon.flush().await?;
        info!("All rules flushed");
        return Ok(());
    }

    // Setup graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    ctrlc_handler(shutdown_tx.clone());

    // Run daemon
    tokio::select! {
        result = daemon.run() => {
            if let Err(e) = result {
                error!("Daemon error: {}", e);
                std::process::exit(1);
            }
        }
        _ = shutdown_rx.recv() => {
            info!("Shutdown signal received");
            daemon.stop().await?;
        }
    }

    info!("SentinelWall stopped");
    Ok(())
}

fn ctrlc_handler(tx: tokio::sync::broadcast::Sender<()>) {
    let tx2 = tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        info!("Received SIGINT");
        let _ = tx2.send(());
    });

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to listen for SIGTERM");
        let tx2 = tx.clone();
        tokio::spawn(async move {
            sigterm.recv().await;
            info!("Received SIGTERM");
            let _ = tx2.send(());
        });
    }
}
