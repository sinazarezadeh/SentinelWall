use anyhow::Result;
use colored::Colorize;
use serde_json::json;
use crate::client::Context;
use crate::output;
use super::DenyArgs;

pub async fn run(ctx: Context, args: DenyArgs) -> Result<()> {
    if ctx.dry_run {
        output::warning("DRY RUN — no changes will be applied");
        println!("Would deny: spec={} from={:?}", args.spec, args.from);
        return Ok(());
    }

    let action = if args.reject { "reject" } else { "drop" };
    let default_name = format!("deny-{}", args.spec);
    let name = args.name.as_deref().unwrap_or(&default_name);

    let (port, protocol) = parse_spec(&args.spec)?;
    let mut rule = json!({
        "id": uuid::Uuid::new_v4(),
        "name": name,
        "action": action,
        "direction": "inbound",
        "protocol": protocol.unwrap_or_else(|| "tcp".to_string()),
        "priority": args.priority,
        "enabled": true,
        "log": args.log,
        "created_at": chrono::Utc::now(),
        "updated_at": chrono::Utc::now(),
        "tags": [],
        "hit_count": 0,
        "source": "manual",
    });

    if let Some(port) = port {
        rule["dst_port"] = json!({ "type": "Single", "value": port });
    }
    if let Some(from) = &args.from {
        if from.contains('/') {
            rule["src_addr"] = json!({ "type": "Network", "value": from });
        } else {
            rule["src_addr"] = json!({ "type": "Single", "value": from });
        }
    }
    if let Some(iface) = &args.interface {
        rule["interface"] = json!(iface);
    }

    let req = ctx.post("/api/v1/rules").json(&rule);
    let response = ctx.send(req).await?;

    if ctx.json_output {
        output::json(&response);
    } else {
        let id = response["data"]["id"].as_str().unwrap_or("?");
        output::success(&format!(
            "Rule created: {} {} {}",
            "DENY".red().bold(),
            args.spec.cyan(),
            format!("(id: {})", &id[..8.min(id.len())]).dimmed()
        ));
    }
    Ok(())
}

fn parse_spec(spec: &str) -> Result<(Option<u16>, Option<String>)> {
    if spec == "any" {
        return Ok((None, None));
    }
    if let Some((port_str, proto)) = spec.split_once('/') {
        let port = port_str.parse::<u16>()?;
        Ok((Some(port), Some(proto.to_string())))
    } else {
        let port = spec.parse::<u16>()?;
        Ok((Some(port), None))
    }
}
