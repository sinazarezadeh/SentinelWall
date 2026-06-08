pub mod allow;
pub mod deny;
pub mod remove;
pub mod list;
pub mod status;
pub mod monitor;
pub mod ban;
pub mod profile;
pub mod threat_feed;
pub mod analyze;
pub mod lookup;
pub mod user;
pub mod token;
pub mod flush;
pub mod export;
pub mod import;
pub mod reload;
pub mod login;

use clap::{Args, Subcommand};
use std::path::PathBuf;

// ─── Allow ─────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct AllowArgs {
    /// Port/protocol spec: 443/tcp, 22, 80-90/tcp, or "any"
    pub spec: String,

    /// Source IP or CIDR to allow from (optional)
    #[arg(long = "from")]
    pub from: Option<String>,

    /// Network interface
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Rule name/comment
    #[arg(short, long)]
    pub name: Option<String>,

    /// Rule priority (lower = higher priority)
    #[arg(short, long, default_value = "100")]
    pub priority: i32,

    /// Log matches
    #[arg(long)]
    pub log: bool,
}

// ─── Deny ──────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct DenyArgs {
    /// Port/protocol spec: 443/tcp, 22, 80-90/tcp, or "any"
    pub spec: String,

    /// Source IP or CIDR to deny from (optional)
    #[arg(long = "from")]
    pub from: Option<String>,

    #[arg(short, long)]
    pub interface: Option<String>,

    #[arg(short, long)]
    pub name: Option<String>,

    #[arg(short, long, default_value = "100")]
    pub priority: i32,

    #[arg(long)]
    pub log: bool,

    /// Use reject instead of drop
    #[arg(long)]
    pub reject: bool,
}

// ─── Remove ────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Rule ID or name
    pub id: String,
}

// ─── List ──────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter by action (allow/deny)
    #[arg(long)]
    pub action: Option<String>,

    /// Filter by protocol
    #[arg(long)]
    pub protocol: Option<String>,

    /// Show disabled rules too
    #[arg(long)]
    pub all: bool,
}

// ─── Status ────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct StatusArgs {}

// ─── Monitor ───────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct MonitorArgs {
    /// Show only threats
    #[arg(long)]
    pub threats_only: bool,

    /// Show only bans
    #[arg(long)]
    pub bans_only: bool,

    /// Filter by minimum severity
    #[arg(long, default_value = "low")]
    pub min_severity: String,
}

// ─── Ban ───────────────────────────────────────────────────────────────────
#[derive(Subcommand, Debug)]
pub enum BanCommands {
    /// List all banned IPs
    List,

    /// Ban an IP address
    Add(BanAddArgs),

    /// Remove a ban
    #[command(alias = "del")]
    Remove(BanRemoveArgs),

    /// Check if an IP is banned
    Check(BanCheckArgs),
}

#[derive(Args, Debug)]
pub struct BanAddArgs {
    /// IP address to ban
    pub ip: String,

    /// Reason for the ban
    #[arg(short, long, default_value = "manual ban")]
    pub reason: String,

    /// Ban duration in seconds (omit for permanent)
    #[arg(short, long)]
    pub duration: Option<u64>,

    /// Make ban permanent
    #[arg(long)]
    pub permanent: bool,
}

#[derive(Args, Debug)]
pub struct BanRemoveArgs {
    pub ip: String,
}

#[derive(Args, Debug)]
pub struct BanCheckArgs {
    pub ip: String,
}

// ─── Profile ───────────────────────────────────────────────────────────────
#[derive(Subcommand, Debug)]
pub enum ProfileCommands {
    /// List available profiles
    List,

    /// Apply a profile
    Apply(ProfileApplyArgs),
}

#[derive(Args, Debug)]
pub struct ProfileApplyArgs {
    /// Profile name
    pub profile: String,

    /// Clear existing rules before applying
    #[arg(long)]
    pub flush_first: bool,
}

// ─── Threat Feed ───────────────────────────────────────────────────────────
#[derive(Subcommand, Debug)]
pub enum ThreatFeedCommands {
    /// List threat intel feeds
    List,

    /// Enable a feed
    Enable(ThreatFeedArgs),

    /// Disable a feed
    Disable(ThreatFeedArgs),

    /// Force-update a feed
    Update(ThreatFeedArgs),
}

#[derive(Args, Debug)]
pub struct ThreatFeedArgs {
    pub feed: String,
}

// ─── Analyze ───────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    #[command(subcommand)]
    pub target: Option<AnalyzeTarget>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AnalyzeTarget {
    Traffic,
    Threats,
    Bans,
    Connections,
}

// ─── Lookup ────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct LookupArgs {
    /// IP address to look up
    pub ip: String,

    /// Also query threat intel
    #[arg(long)]
    pub threat: bool,
}

// ─── User ──────────────────────────────────────────────────────────────────
#[derive(Subcommand, Debug)]
pub enum UserCommands {
    List,
    Add(UserAddArgs),
    Remove { username: String },
    Password { username: String },
}

#[derive(Args, Debug)]
pub struct UserAddArgs {
    pub username: String,
    #[arg(short, long, default_value = "viewer")]
    pub role: String,
}

// ─── Token ─────────────────────────────────────────────────────────────────
#[derive(Subcommand, Debug)]
pub enum TokenCommands {
    List,
    Create(TokenCreateArgs),
    Revoke { id: String },
}

#[derive(Args, Debug)]
pub struct TokenCreateArgs {
    pub name: String,
    #[arg(short, long, default_value = "viewer")]
    pub role: String,
    #[arg(long)]
    pub expires_days: Option<u64>,
}

// ─── Flush ─────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct FlushArgs {
    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

// ─── Export ────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct ExportArgs {
    #[arg(short, long, default_value = "rules.json")]
    pub output: PathBuf,
}

// ─── Import ────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct ImportArgs {
    pub file: PathBuf,
    #[arg(long)]
    pub merge: bool,
}

// ─── Login ─────────────────────────────────────────────────────────────────
#[derive(Args, Debug)]
pub struct LoginArgs {
    #[arg(short, long, default_value = "admin")]
    pub username: String,
}
