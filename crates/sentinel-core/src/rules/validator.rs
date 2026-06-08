use anyhow::{Result, bail};
use super::types::*;

pub struct RuleValidator;

impl RuleValidator {
    pub fn validate(rule: &Rule) -> Result<()> {
        if rule.name.is_empty() {
            bail!("Rule name cannot be empty");
        }
        if rule.name.len() > 128 {
            bail!("Rule name too long (max 128 chars)");
        }
        if !rule.name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ') {
            bail!("Rule name contains invalid characters");
        }
        if rule.priority < -100 || rule.priority > 10000 {
            bail!("Rule priority must be between -100 and 10000");
        }
        if let Some(PortSpec::Range(start, end)) = &rule.src_port {
            if start > end {
                bail!("Invalid source port range: {} > {}", start, end);
            }
        }
        if let Some(PortSpec::Range(start, end)) = &rule.dst_port {
            if start > end {
                bail!("Invalid destination port range: {} > {}", start, end);
            }
        }
        if let Some(AddrSpec::Range { start, end }) = &rule.src_addr {
            if start > end {
                bail!("Invalid source address range");
            }
        }
        if let Some(AddrSpec::Range { start, end }) = &rule.dst_addr {
            if start > end {
                bail!("Invalid destination address range");
            }
        }
        if let Some(rate) = &rule.rate_limit {
            if rate.rate == 0 {
                bail!("Rate limit rate must be > 0");
            }
        }
        Ok(())
    }
}
