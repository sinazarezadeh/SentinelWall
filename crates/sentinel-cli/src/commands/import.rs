use anyhow::Result;
use crate::client::Context;
use crate::output;
use super::ImportArgs;

pub async fn run(ctx: Context, args: ImportArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.file)?;
    let rules: serde_json::Value = serde_json::from_str(&content)?;
    let req = ctx.post("/api/v1/rules/import").json(&rules);
    let response = ctx.send(req).await?;
    if ctx.json_output {
        output::json(&response);
    } else {
        let imported = response["imported"].as_u64().unwrap_or(0);
        output::success(&format!("Imported {} rules from {}", imported, args.file.display()));
    }
    Ok(())
}
