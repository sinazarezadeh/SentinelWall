use anyhow::Result;
use colored::Colorize;
use serde_json::json;
use crate::client::Context;
use crate::output;
use super::{BanCommands, BanAddArgs, BanRemoveArgs, BanCheckArgs};

pub async fn run(ctx: Context, cmds: BanCommands) -> Result<()> {
    match cmds {
        BanCommands::List => list_bans(ctx).await,
        BanCommands::Add(args) => add_ban(ctx, args).await,
        BanCommands::Remove(args) => remove_ban(ctx, args).await,
        BanCommands::Check(args) => check_ban(ctx, args).await,
    }
}

async fn list_bans(ctx: Context) -> Result<()> {
    let req = ctx.get("/api/v1/bans");
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
        return Ok(());
    }

    let bans = response["data"].as_array().cloned().unwrap_or_default();

    if bans.is_empty() {
        output::info("No active bans");
        return Ok(());
    }

    println!();
    println!("{:<20} {:<22} {:<12} {:<20}",
        "IP".bold(), "REASON".bold(), "BAN #".bold(), "EXPIRES".bold()
    );
    println!("{}", "─".repeat(75).dimmed());

    for ban in &bans {
        let ip = ban["ip"].as_str().unwrap_or("?");
        let reason = ban["reason"].as_str().unwrap_or("?");
        let ban_count = ban["ban_count"].as_u64().unwrap_or(1);
        let expires = ban["expires_at"].as_str()
            .unwrap_or("permanent");

        let expires_colored = if expires == "permanent" || ban["expires_at"].is_null() {
            "permanent".red().to_string()
        } else {
            expires.yellow().to_string()
        };

        println!("{:<20} {:<22} {:<12} {}",
            ip.cyan(),
            reason.white(),
            ban_count.to_string().yellow(),
            expires_colored
        );
    }

    println!();
    println!("{}", format!("Total: {} bans", bans.len()).dimmed());
    Ok(())
}

async fn add_ban(ctx: Context, args: BanAddArgs) -> Result<()> {
    if ctx.dry_run {
        output::warning(&format!("DRY RUN — would ban {}", args.ip));
        return Ok(());
    }

    let payload = json!({
        "ip": args.ip,
        "reason": args.reason,
        "duration_secs": args.duration,
        "permanent": args.permanent || args.duration.is_none(),
        "comment": format!("Manual ban via CLI"),
    });

    let req = ctx.post("/api/v1/bans").json(&payload);
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
    } else {
        output::success(&format!("Banned {} — {}", args.ip.red().bold(), args.reason));
    }
    Ok(())
}

async fn remove_ban(ctx: Context, args: BanRemoveArgs) -> Result<()> {
    if ctx.dry_run {
        output::warning(&format!("DRY RUN — would unban {}", args.ip));
        return Ok(());
    }

    let req = ctx.delete(&format!("/api/v1/bans/{}", args.ip));
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
    } else {
        output::success(&format!("Unbanned {}", args.ip.green().bold()));
    }
    Ok(())
}

async fn check_ban(ctx: Context, args: BanCheckArgs) -> Result<()> {
    let req = ctx.get(&format!("/api/v1/bans/check/{}", args.ip));
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
        return Ok(());
    }

    let banned = response["data"]["banned"].as_bool().unwrap_or(false);
    if banned {
        println!("{} {} is {}", "●".red(), args.ip.cyan(), "BANNED".red().bold());
    } else {
        println!("{} {} is {}", "●".green(), args.ip.cyan(), "NOT BANNED".green().bold());
    }
    Ok(())
}
