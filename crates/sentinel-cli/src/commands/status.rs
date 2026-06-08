use anyhow::Result;
use colored::Colorize;
use crate::client::Context;
use crate::output;
use super::StatusArgs;

pub async fn run(ctx: Context, args: StatusArgs) -> Result<()> {
    let req = ctx.get("/api/v1/status");
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
        return Ok(());
    }

    let data = &response["data"].as_object()
        .or_else(|| response.as_object())
        .cloned()
        .unwrap_or_default();

    let status = data.get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");

    println!();
    println!("  {}  SentinelWall Firewall", "●".green().bold());
    println!();
    println!("  Status:      {}", output::status_badge(status));
    println!("  Version:     {}", data.get("version").and_then(|v| v.as_str()).unwrap_or("-").cyan());
    println!("  Uptime:      {}", format_uptime(data.get("uptime_seconds").and_then(|v| v.as_i64()).unwrap_or(0)));
    println!("  Backend:     {}", data.get("backend").and_then(|v| v.as_str()).unwrap_or("nftables").blue());
    println!("  Rules:       {}", data.get("rules_count").and_then(|v| v.as_u64()).unwrap_or(0));
    println!("  Active Bans: {}", data.get("bans_count").and_then(|v| v.as_u64()).unwrap_or(0));
    println!("  Threats:     {}", data.get("threats_today").and_then(|v| v.as_u64()).unwrap_or(0));
    println!();

    if args.verbose {
        let info_req = ctx.get("/api/v1/info");
        if let Ok(info) = ctx.send(info_req).await {
            println!("  Features:");
            if let Some(features) = info["features"].as_array() {
                for f in features {
                    println!("    {} {}", "·".dimmed(), f.as_str().unwrap_or("").green());
                }
            }
            println!();
        }
    }

    Ok(())
}

fn format_uptime(secs: i64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}
