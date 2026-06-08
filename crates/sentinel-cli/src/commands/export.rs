use anyhow::Result;
use crate::client::Context;
use crate::output;
use super::ExportArgs;

pub async fn run(ctx: Context, args: ExportArgs) -> Result<()> {
    let req = ctx.get("/api/v1/rules/export");
    let response = ctx.send(req).await?;
    let rules = &response["data"];
    let json = serde_json::to_string_pretty(rules)?;
    std::fs::write(&args.output, &json)?;
    output::success(&format!("Rules exported to {}", args.output.display()));
    Ok(())
}
