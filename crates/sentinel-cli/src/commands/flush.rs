use anyhow::Result;
use dialoguer::Confirm;
use crate::client::Context;
use crate::output;
use super::FlushArgs;

pub async fn run(ctx: Context, args: FlushArgs) -> Result<()> {
    if !args.yes {
        let confirmed = Confirm::new()
            .with_prompt("⚠️  This will FLUSH ALL RULES. This action cannot be undone. Continue?")
            .default(false)
            .interact()?;
        if !confirmed {
            output::info("Aborted");
            return Ok(());
        }
    }

    if ctx.dry_run {
        output::warning("DRY RUN — would flush all rules");
        return Ok(());
    }

    let req = ctx.post("/api/v1/rules/flush");
    ctx.send(req).await?;
    output::success("All rules flushed");
    Ok(())
}
