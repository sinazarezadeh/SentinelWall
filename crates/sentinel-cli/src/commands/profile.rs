use anyhow::Result;
use colored::Colorize;
use dialoguer::Confirm;
use crate::client::Context;
use crate::output;
use super::{ProfileCommands, ProfileApplyArgs};

pub async fn run(ctx: Context, cmds: ProfileCommands) -> Result<()> {
    match cmds {
        ProfileCommands::List => list_profiles(ctx).await,
        ProfileCommands::Apply(args) => apply_profile(ctx, args).await,
    }
}

async fn list_profiles(ctx: Context) -> Result<()> {
    let req = ctx.get("/api/v1/profiles");
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
        return Ok(());
    }

    let profiles = response["data"].as_array().cloned().unwrap_or_default();
    println!();
    output::header("Available Profiles");
    println!();
    for p in &profiles {
        println!("  {:20} {}",
            p["name"].as_str().unwrap_or("?").cyan().bold(),
            p["description"].as_str().unwrap_or("").dimmed()
        );
    }
    println!();
    println!("{}", "Usage: sentinel profile apply <name>".dimmed());
    Ok(())
}

async fn apply_profile(ctx: Context, args: ProfileApplyArgs) -> Result<()> {
    if ctx.dry_run {
        output::warning(&format!("DRY RUN — would apply profile '{}'", args.profile));
        return Ok(());
    }

    if args.flush_first {
        let confirmed = Confirm::new()
            .with_prompt("This will flush all existing rules. Continue?")
            .default(false)
            .interact()?;
        if !confirmed {
            return Ok(());
        }
        let req = ctx.post("/api/v1/rules/flush");
        ctx.send(req).await?;
        output::success("Flushed existing rules");
    }

    let req = ctx.post(&format!("/api/v1/profiles/{}/apply", args.profile));
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
    } else {
        output::success(&format!("Profile '{}' applied successfully", args.profile.cyan()));
    }
    Ok(())
}
