use anyhow::Result;
use crate::client::Context;
use crate::output;
use super::RemoveArgs;

pub async fn run(ctx: Context, args: RemoveArgs) -> Result<()> {
    if ctx.dry_run {
        output::warning(&format!("DRY RUN — would remove rule '{}'", args.id));
        return Ok(());
    }
    let req = ctx.delete(&format!("/api/v1/rules/{}", args.id));
    let response = ctx.send(req).await?;
    if ctx.json_output {
        output::json(&response);
    } else {
        output::success(&format!("Rule '{}' removed", args.id));
    }
    Ok(())
}
