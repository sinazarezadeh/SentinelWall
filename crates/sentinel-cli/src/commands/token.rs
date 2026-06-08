use anyhow::Result;
use colored::Colorize;
use crate::client::Context;
use crate::output;
use super::TokenCommands;

pub async fn run(ctx: Context, cmds: TokenCommands) -> Result<()> {
    match cmds {
        TokenCommands::List => {
            let req = ctx.get("/api/v1/tokens");
            let response = ctx.send(req).await?;
            if ctx.json_output {
                output::json(&response);
            } else {
                let tokens = response["data"].as_array().cloned().unwrap_or_default();
                if tokens.is_empty() {
                    output::info("No API tokens");
                } else {
                    for t in &tokens {
                        println!("  {:30} {:10} {}",
                            t["name"].as_str().unwrap_or("?").cyan(),
                            t["role"].as_str().unwrap_or("?").yellow(),
                            t["id"].as_str().unwrap_or("?").dimmed()
                        );
                    }
                }
            }
        }
        TokenCommands::Create(args) => {
            let req = ctx.post("/api/v1/tokens").json(&serde_json::json!({
                "name": args.name,
                "role": args.role,
                "expires_in_days": args.expires_days,
            }));
            let response = ctx.send(req).await?;
            if ctx.json_output {
                output::json(&response);
            } else {
                if let Some(token) = response["data"]["token"].as_str() {
                    output::success(&format!("API token created: {}", args.name.cyan()));
                    println!();
                    println!("  {} {}", "Token:".dimmed(), token.yellow().bold());
                    println!();
                    println!("{}", "Store this securely — it will not be shown again!".red());
                }
            }
        }
        TokenCommands::Revoke { id } => {
            let req = ctx.delete(&format!("/api/v1/tokens/{}", id));
            ctx.send(req).await?;
            output::success(&format!("Token {} revoked", id));
        }
    }
    Ok(())
}
