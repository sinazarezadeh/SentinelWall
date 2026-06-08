use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, error};
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};

use crate::rules::types::{Rule, RuleId};
use super::builder::NftablesBuilder;

pub struct NftablesManager {
    nft_binary: String,
    rule_handle_map: Arc<Mutex<std::collections::HashMap<RuleId, u64>>>,
    dry_run: bool,
}

impl NftablesManager {
    pub fn new() -> Self {
        Self {
            nft_binary: "/usr/sbin/nft".to_string(),
            rule_handle_map: Arc::new(Mutex::new(std::collections::HashMap::new())),
            dry_run: false,
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub async fn init(&self) -> Result<()> {
        info!("Initializing nftables backend");
        let table_init = NftablesBuilder::build_table_init();
        self.exec_nft_script(&table_init).await
            .context("Failed to initialize nftables tables")?;
        info!("nftables initialized successfully");
        Ok(())
    }

    pub async fn apply_rule(&self, rule: &Rule) -> Result<()> {
        debug!("Applying nftables rule: {}", rule.name);
        let nft_rule = NftablesBuilder::build_rule(rule, "sentinel_input");
        let cmd = format!("add rule inet sentinel sentinel_input {}", nft_rule);
        let handle = self.exec_nft_get_handle(&cmd).await?;
        if let Some(h) = handle {
            self.rule_handle_map.lock().await.insert(rule.id.clone(), h);
        }
        Ok(())
    }

    pub async fn remove_rule(&self, id: &RuleId) -> Result<()> {
        let handle = {
            let map = self.rule_handle_map.lock().await;
            map.get(id).copied()
        };

        if let Some(handle) = handle {
            let cmd = format!("delete rule inet sentinel sentinel_input handle {}", handle);
            self.exec_nft(&cmd).await?;
            self.rule_handle_map.lock().await.remove(id);
        }

        Ok(())
    }

    pub async fn update_rule(&self, rule: &Rule) -> Result<()> {
        self.remove_rule(&rule.id).await?;
        self.apply_rule(rule).await
    }

    pub async fn block_ip(&self, ip: IpAddr, expires: Option<DateTime<Utc>>) -> Result<()> {
        info!("Blocking IP: {}", ip);
        let cmd = if ip.is_ipv4() {
            NftablesBuilder::build_ban_ipv4(&ip, expires)
        } else {
            NftablesBuilder::build_ban_ipv6(&ip, expires)
        };
        self.exec_nft(&cmd).await
    }

    pub async fn unblock_ip(&self, ip: &IpAddr) -> Result<()> {
        info!("Unblocking IP: {}", ip);
        let cmd = if ip.is_ipv4() {
            NftablesBuilder::build_unban_ipv4(ip)
        } else {
            NftablesBuilder::build_unban_ipv6(ip)
        };
        self.exec_nft(&cmd).await
            .unwrap_or_else(|e| warn!("Failed to unblock {} (may already be removed): {}", ip, e));
        Ok(())
    }

    pub async fn flush_all(&self) -> Result<()> {
        warn!("Flushing all nftables rules");
        self.exec_nft(NftablesBuilder::build_flush_table()).await?;
        self.rule_handle_map.lock().await.clear();
        Ok(())
    }

    pub async fn reload(&self) -> Result<()> {
        self.flush_all().await?;
        self.init().await
    }

    pub async fn list_ruleset(&self) -> Result<String> {
        self.exec_nft_output(NftablesBuilder::build_list_rules()).await
    }

    pub async fn is_available(&self) -> bool {
        Command::new(&self.nft_binary)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn exec_nft(&self, cmd: &str) -> Result<()> {
        if self.dry_run {
            debug!("[DRY-RUN] nft {}", cmd);
            return Ok(());
        }

        debug!("nft {}", cmd);
        let output = Command::new(&self.nft_binary)
            .arg(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute nft")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("nft error: {}", stderr);
            anyhow::bail!("nft command failed: {}", stderr);
        }

        Ok(())
    }

    async fn exec_nft_output(&self, cmd: &str) -> Result<String> {
        let output = Command::new(&self.nft_binary)
            .arg(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute nft")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nft command failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn exec_nft_script(&self, script: &str) -> Result<()> {
        if self.dry_run {
            debug!("[DRY-RUN] nft script ({} chars)", script.len());
            return Ok(());
        }

        let mut child = Command::new(&self.nft_binary)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn nft")?;

        use tokio::io::AsyncWriteExt;
        if let Some(stdin) = child.stdin.take() {
            let mut stdin = stdin;
            stdin.write_all(script.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nft script failed: {}", stderr);
        }

        Ok(())
    }

    async fn exec_nft_get_handle(&self, cmd: &str) -> Result<Option<u64>> {
        if self.dry_run {
            return Ok(None);
        }

        // --echo and --json must be separate args, not appended to the command string.
        // Passing them as part of cmd would embed them in the nft language → syntax error.
        let output = Command::new(&self.nft_binary)
            .arg("--echo")
            .arg("--json")
            .arg(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute nft")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("nft error: {}", stderr);
            anyhow::bail!("nft command failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(handle) = json
                .get("nftables")
                .and_then(|n| n.as_array())
                .and_then(|arr| arr.iter().find(|v| v.get("rule").is_some()))
                .and_then(|v| v.get("rule"))
                .and_then(|r| r.get("handle"))
                .and_then(|h| h.as_u64())
            {
                return Ok(Some(handle));
            }
        }

        Ok(None)
    }
}

impl Default for NftablesManager {
    fn default() -> Self {
        Self::new()
    }
}
