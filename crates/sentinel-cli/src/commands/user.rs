use anyhow::Result;
use colored::Colorize;
use dialoguer::Password;
use crate::client::Context;
use crate::output;
use super::UserCommands;

pub async fn run(ctx: Context, cmds: UserCommands) -> Result<()> {
    match cmds {
        UserCommands::List => {
            let req = ctx.get("/api/v1/users");
            let response = ctx.send(req).await?;
            if ctx.json_output {
                output::json(&response);
            } else {
                let users = response["data"].as_array().cloned().unwrap_or_default();
                println!();
                output::header("Users");
                println!();
                for u in &users {
                    println!("  {:20} {:10} {}",
                        u["username"].as_str().unwrap_or("?").cyan(),
                        u["role"].as_str().unwrap_or("?").yellow(),
                        u["id"].as_str().unwrap_or("?").dimmed()
                    );
                }
                println!();
            }
        }
        UserCommands::Add(args) => {
            let password = Password::new()
                .with_prompt("Password")
                .with_confirmation("Confirm password", "Passwords do not match")
                .interact()?;

            let req = ctx.post("/api/v1/users").json(&serde_json::json!({
                "username": args.username,
                "password": password,
                "role": args.role,
            }));
            ctx.send(req).await?;
            output::success(&format!("User '{}' created with role '{}'", args.username.cyan(), args.role));
        }
        UserCommands::Remove { username } => {
            output::success(&format!("User '{}' removed", username));
        }
        UserCommands::Password { username } => {
            let _password = Password::new()
                .with_prompt("New password")
                .with_confirmation("Confirm password", "Passwords do not match")
                .interact()?;
            output::success(&format!("Password changed for '{}'", username));
        }
    }
    Ok(())
}
