use anyhow::Result;
use colored::Colorize;
use crate::client::Context;
use crate::output;
use super::LookupArgs;

pub async fn run(ctx: Context, args: LookupArgs) -> Result<()> {
    let req = ctx.get(&format!("/api/v1/geo/lookup/{}", args.ip));
    let geo = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&geo);
        return Ok(());
    }

    let data = &geo["data"];
    println!();
    println!("  IP:       {}", args.ip.cyan().bold());
    println!("  Country:  {}", data["country"].as_str().unwrap_or("Unknown").white());
    println!("  ASN:      {}", data["asn"].as_u64().map(|a| a.to_string()).unwrap_or_else(|| "Unknown".into()).white());
    println!("  TOR:      {}", if data["is_tor"].as_bool().unwrap_or(false) { "Yes".red() } else { "No".green() });
    println!("  Banned:   {}", if data["is_banned"].as_bool().unwrap_or(false) { "Yes".red().bold() } else { "No".green() });

    if args.threat {
        let req = ctx.get(&format!("/api/v1/threat-intel/check/{}", args.ip));
        if let Ok(threat) = ctx.send(req).await {
            let clean = threat["data"]["clean"].as_bool().unwrap_or(true);
            println!("  Threat:   {}", if clean { "Clean".green() } else { "FLAGGED".red().bold() });
        }
    }

    println!();
    Ok(())
}
