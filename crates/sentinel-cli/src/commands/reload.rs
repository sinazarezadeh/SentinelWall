use anyhow::Result;
use crate::client::Context;
use crate::output;

pub async fn run(ctx: Context) -> Result<()> {
    let req = ctx.post("/api/v1/config/reload");
    ctx.send(req).await?;
    output::success("Configuration reloaded");
    Ok(())
}
