use anyhow::Result;
use clap::Parser;

mod app;
mod ui;
mod state;
mod fetch;

#[derive(Parser)]
#[command(name = "sentinel-tui", about = "SentinelWall Terminal Dashboard")]
struct Cli {
    #[arg(short, long, default_value = "http://127.0.0.1:8765", env = "SENTINEL_API")]
    api: String,

    #[arg(short, long, env = "SENTINEL_TOKEN")]
    token: Option<String>,

    #[arg(long, default_value = "1000")]
    refresh_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Suppress tracing output in TUI mode
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let app = app::App::new(cli.api, cli.token, cli.refresh_ms);
    app.run().await
}
