use anyhow::Result;
use clap::{Parser, Subcommand};

mod client;
mod output;
mod commands;

use commands::*;

#[derive(Parser)]
#[command(
    name = "sentinel",
    about = "SentinelWall CLI — Control your firewall from the command line",
    version,
    long_about = "SentinelWall CLI provides complete control over the SentinelWall\nfirewall daemon. Manage rules, bans, profiles, and monitor live traffic.",
    propagate_version = true,
)]
pub struct Cli {
    #[arg(
        short, long,
        default_value = "http://127.0.0.1:8765",
        env = "SENTINEL_API",
        global = true,
        help = "SentinelWall API endpoint"
    )]
    pub api: String,

    #[arg(
        short, long,
        env = "SENTINEL_TOKEN",
        global = true,
        help = "API token or JWT"
    )]
    pub token: Option<String>,

    #[arg(
        long,
        global = true,
        help = "Output as JSON"
    )]
    pub json: bool,

    #[arg(
        long,
        global = true,
        help = "Dry-run: show what would be done without applying"
    )]
    pub dry_run: bool,

    #[arg(
        short = 'v',
        long,
        global = true,
        action = clap::ArgAction::Count,
        help = "Verbosity level (-v, -vv, -vvv)"
    )]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Allow traffic matching the given specification
    Allow(AllowArgs),

    /// Deny traffic matching the given specification
    Deny(DenyArgs),

    /// Remove a rule by ID or name
    #[command(alias = "rm")]
    Remove(RemoveArgs),

    /// List all firewall rules
    #[command(alias = "ls")]
    List(ListArgs),

    /// Show firewall status and statistics
    Status(StatusArgs),

    /// Monitor live traffic and events
    Monitor(MonitorArgs),

    /// Manage banned IPs
    #[command(subcommand)]
    Ban(BanCommands),

    /// Apply a firewall profile
    #[command(subcommand)]
    Profile(ProfileCommands),

    /// Manage threat intelligence feeds
    #[command(subcommand)]
    ThreatFeed(ThreatFeedCommands),

    /// Analyze traffic patterns
    Analyze(AnalyzeArgs),

    /// Lookup IP information (geo, threat intel)
    Lookup(LookupArgs),

    /// Manage user accounts
    #[command(subcommand)]
    User(UserCommands),

    /// Manage API tokens
    #[command(subcommand)]
    Token(TokenCommands),

    /// Flush all rules (DANGEROUS!)
    Flush(FlushArgs),

    /// Export rules to file
    Export(ExportArgs),

    /// Import rules from file
    Import(ImportArgs),

    /// Reload configuration
    Reload,

    /// Login to the API
    Login(LoginArgs),

    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_target(false)
        .init();

    let ctx = client::Context::new(cli.api.clone(), cli.token.clone(), cli.json, cli.dry_run);

    match cli.command {
        Commands::Allow(args) => allow::run(ctx, args).await,
        Commands::Deny(args) => deny::run(ctx, args).await,
        Commands::Remove(args) => remove::run(ctx, args).await,
        Commands::List(args) => list::run(ctx, args).await,
        Commands::Status(args) => status::run(ctx, args).await,
        Commands::Monitor(args) => monitor::run(ctx, args).await,
        Commands::Ban(cmds) => ban::run(ctx, cmds).await,
        Commands::Profile(cmds) => profile::run(ctx, cmds).await,
        Commands::ThreatFeed(cmds) => threat_feed::run(ctx, cmds).await,
        Commands::Analyze(args) => analyze::run(ctx, args).await,
        Commands::Lookup(args) => lookup::run(ctx, args).await,
        Commands::User(cmds) => user::run(ctx, cmds).await,
        Commands::Token(cmds) => token::run(ctx, cmds).await,
        Commands::Flush(args) => flush::run(ctx, args).await,
        Commands::Export(args) => export::run(ctx, args).await,
        Commands::Import(args) => import::run(ctx, args).await,
        Commands::Reload => reload::run(ctx).await,
        Commands::Login(args) => login::run(ctx, args).await,
        Commands::Version => {
            println!("SentinelWall v{}", sentinel_core::VERSION);
            println!("CLI: sentinel");
            Ok(())
        }
    }
}
