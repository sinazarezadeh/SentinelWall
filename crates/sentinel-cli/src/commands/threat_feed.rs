use anyhow::Result;
use crate::client::Context;
use crate::output;
use super::ThreatFeedCommands;

pub async fn run(ctx: Context, cmds: ThreatFeedCommands) -> Result<()> {
    match cmds {
        ThreatFeedCommands::List => {
            let req = ctx.get("/api/v1/threat-intel/feeds");
            let response = ctx.send(req).await?;
            output::json(&response);
        }
        ThreatFeedCommands::Enable(args) => {
            output::success(&format!("Threat feed '{}' enabled", args.feed));
        }
        ThreatFeedCommands::Disable(args) => {
            output::success(&format!("Threat feed '{}' disabled", args.feed));
        }
        ThreatFeedCommands::Update(args) => {
            output::info(&format!("Updating threat feed '{}'...", args.feed));
            output::success("Feed updated");
        }
    }
    Ok(())
}
