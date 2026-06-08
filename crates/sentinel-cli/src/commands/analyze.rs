use anyhow::Result;
use colored::Colorize;
use crate::client::Context;
use crate::output;
use super::{AnalyzeArgs, AnalyzeTarget};

pub async fn run(ctx: Context, args: AnalyzeArgs) -> Result<()> {
    let target = args.target.unwrap_or(AnalyzeTarget::Traffic);

    match target {
        AnalyzeTarget::Traffic => analyze_traffic(ctx).await,
        AnalyzeTarget::Threats => analyze_threats(ctx).await,
        AnalyzeTarget::Bans => analyze_bans(ctx).await,
        AnalyzeTarget::Connections => analyze_connections(ctx).await,
    }
}

async fn analyze_traffic(ctx: Context) -> Result<()> {
    let req = ctx.get("/api/v1/status");
    let status = ctx.send(req).await?;

    println!();
    output::header("Traffic Analysis");
    println!();
    println!("  Active Bans:    {}", status["bans_count"].as_u64().unwrap_or(0).to_string().yellow());
    println!("  Active Rules:   {}", status["rules_count"].as_u64().unwrap_or(0).to_string().cyan());
    println!();
    Ok(())
}

async fn analyze_threats(ctx: Context) -> Result<()> {
    let req = ctx.get("/api/v1/threats/stats");
    let stats = ctx.send(req).await?;

    println!();
    output::header("Threat Analysis");
    println!();
    if ctx.json_output {
        output::json(&stats);
    } else {
        println!("  Today:  {}", stats["data"]["today"].as_u64().unwrap_or(0));
        println!("  Week:   {}", stats["data"]["week"].as_u64().unwrap_or(0));
        println!("  Month:  {}", stats["data"]["month"].as_u64().unwrap_or(0));
    }
    println!();
    Ok(())
}

async fn analyze_bans(ctx: Context) -> Result<()> {
    let req = ctx.get("/api/v1/bans");
    let bans = ctx.send(req).await?;
    let count = bans["data"].as_array().map(|a| a.len()).unwrap_or(0);
    println!();
    output::header("Ban Analysis");
    println!();
    println!("  Total active bans: {}", count.to_string().yellow());
    println!();
    Ok(())
}

async fn analyze_connections(_ctx: Context) -> Result<()> {
    println!();
    output::header("Connection Analysis");
    println!();
    output::info("Live connection analysis requires nftables monitoring (coming soon)");
    println!();
    Ok(())
}
