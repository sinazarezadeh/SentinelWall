use anyhow::Result;
use colored::Colorize;
use dialoguer::{Input, Password};
use crate::client::Context;
use crate::output;
use super::LoginArgs;

pub async fn run(ctx: Context, args: LoginArgs) -> Result<()> {
    println!("{}", "SentinelWall Login".bold());
    println!("{}", format!("API: {}", ctx.api).dimmed());
    println!();

    let username: String = Input::new()
        .with_prompt("Username")
        .default(args.username.clone())
        .interact_text()?;

    let password = Password::new()
        .with_prompt("Password")
        .interact()?;

    let req = ctx.post("/api/v1/auth/login").json(&serde_json::json!({
        "username": username,
        "password": password,
    }));

    let response = ctx.send(req).await?;

    if let Some(token) = response["data"]["token"].as_str() {
        println!();
        output::success("Login successful!");
        println!();
        println!("  {} {}", "Token:".dimmed(), token.cyan());
        println!();
        println!("{}", "Set environment variable for CLI access:".dimmed());
        println!("  export SENTINEL_TOKEN=\"{}\"", token.yellow());
        println!();
        println!("{}", format!("Expires: {}", response["data"]["expires_at"].as_str().unwrap_or("?")).dimmed());
    } else {
        output::error("Login failed");
    }

    Ok(())
}
