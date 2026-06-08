use anyhow::Result;
use colored::Colorize;
use crate::client::Context;
use crate::output;
use super::ListArgs;

pub async fn run(ctx: Context, args: ListArgs) -> Result<()> {
    let req = ctx.get("/api/v1/rules");
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
        return Ok(());
    }

    let rules = response["data"].as_array()
        .cloned()
        .unwrap_or_default();

    if rules.is_empty() {
        output::info("No rules configured");
        return Ok(());
    }

    println!();
    println!("{:<6} {:<30} {:<8} {:<6} {:<12} {:<6}",
        "PRIO".bold(), "NAME".bold(), "ACTION".bold(),
        "PROTO".bold(), "PORT".bold(), "ENABLED".bold()
    );
    println!("{}", "─".repeat(75).dimmed());

    for rule in &rules {
        let enabled = rule["enabled"].as_bool().unwrap_or(true);
        if !args.all && !enabled {
            continue;
        }

        let action = rule["action"].as_str().unwrap_or("?");
        let action_colored = match action {
            "accept" => "ALLOW".green().bold(),
            "drop" => "DROP".red().bold(),
            "reject" => "REJECT".red().bold(),
            _ => action.white(),
        };

        let proto = rule["protocol"].as_str().unwrap_or("any");
        let port = rule["dst_port"]["value"].as_u64()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "any".to_string());
        let priority = rule["priority"].as_i64().unwrap_or(100);
        let name = rule["name"].as_str().unwrap_or("?");
        let enabled_str = if enabled { "yes".green() } else { "no".red() };

        if let Some(filter) = &args.action {
            if !action.contains(filter.as_str()) {
                continue;
            }
        }
        if let Some(filter) = &args.protocol {
            if proto != filter.as_str() {
                continue;
            }
        }

        println!("{:<6} {:<30} {:<8} {:<6} {:<12} {}",
            priority.to_string().dimmed(),
            name.cyan(),
            action_colored,
            proto.white(),
            port.yellow(),
            enabled_str
        );
    }

    println!();
    println!("{}", format!("Total: {} rules", rules.len()).dimmed());
    println!();
    Ok(())
}
