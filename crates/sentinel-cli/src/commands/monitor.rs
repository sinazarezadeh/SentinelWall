use anyhow::Result;
use colored::Colorize;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures::StreamExt;
use crate::client::Context;
use crate::output;
use super::MonitorArgs;

pub async fn run(ctx: Context, args: MonitorArgs) -> Result<()> {
    let ws_url = ctx.api.replace("http://", "ws://").replace("https://", "wss://");
    let ws_url = format!("{}/api/v1/ws", ws_url);

    output::info(&format!("Connecting to event stream: {}", ws_url));
    println!("{}", "Monitoring live events — Press Ctrl+C to stop".dimmed());
    println!("{}", "─".repeat(70).dimmed());

    // Try WebSocket
    match connect_async(&ws_url).await {
        Ok((stream, _)) => {
            let (_, mut reader) = stream.split();
            while let Some(msg) = reader.next().await {
                match msg? {
                    Message::Text(text) => {
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&text) {
                            print_event(&event, &args);
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
        Err(_) => {
            // Fall back to polling
            output::warning("WebSocket unavailable — falling back to polling");
            poll_events(&ctx, &args).await?;
        }
    }

    Ok(())
}

fn print_event(event: &serde_json::Value, args: &MonitorArgs) {
    let event_type = event["type"].as_str().unwrap_or("unknown");
    let timestamp = chrono::Utc::now().format("%H:%M:%S");

    match event_type {
        "threat" if !args.bans_only => {
            let severity = event["data"]["severity"].as_str().unwrap_or("unknown");
            let ip = event["data"]["ip"].as_str().unwrap_or("?");
            let threat_type = event["data"]["threat_type"].as_str().unwrap_or("?");
            let desc = event["data"]["description"].as_str().unwrap_or("");

            println!(
                "[{}] {} {} {} {} — {}",
                timestamp.to_string().dimmed(),
                "THREAT".yellow().bold(),
                output::severity_badge(severity),
                output::ip_display(ip),
                threat_type.white(),
                desc.dimmed()
            );
        }
        "ban" if !args.threats_only => {
            let ip = event["data"]["ip"].as_str().unwrap_or("?");
            let reason = event["data"]["reason"].as_str().unwrap_or("?");
            println!(
                "[{}] {}  {} — {}",
                timestamp.to_string().dimmed(),
                "BAN".red().bold(),
                output::ip_display(ip),
                reason.dimmed()
            );
        }
        "unban" if !args.threats_only => {
            let ip = event["data"]["ip"].as_str().unwrap_or("?");
            println!(
                "[{}] {} {}",
                timestamp.to_string().dimmed(),
                "UNBAN".green().bold(),
                output::ip_display(ip)
            );
        }
        "rule_added" => {
            let name = event["data"]["name"].as_str().unwrap_or("?");
            println!(
                "[{}] {} {}",
                timestamp.to_string().dimmed(),
                "RULE+".blue().bold(),
                name.cyan()
            );
        }
        "connected" => {
            output::success("Connected to event stream");
        }
        _ => {}
    }
}

async fn poll_events(ctx: &Context, _args: &MonitorArgs) -> Result<()> {
    use tokio::time::{interval, Duration};
    let mut tick = interval(Duration::from_secs(5));

    loop {
        tick.tick().await;
        // In polling mode we just show current status
        let req = ctx.get("/api/v1/status");
        if let Ok(status) = ctx.send(req).await {
            let bans = status["bans_count"].as_u64().unwrap_or(0);
            let rules = status["rules_count"].as_u64().unwrap_or(0);
            println!(
                "[{}] rules={} bans={}",
                chrono::Utc::now().format("%H:%M:%S").to_string().dimmed(),
                rules,
                bans
            );
        }
    }
}
