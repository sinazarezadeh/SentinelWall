/// Standard SentinelWall nftables table and chain definitions

pub const SENTINEL_TABLE: &str = "inet sentinel";
pub const INPUT_CHAIN: &str = "input";
pub const OUTPUT_CHAIN: &str = "output";
pub const FORWARD_CHAIN: &str = "forward";
pub const SENTINEL_INPUT_CHAIN: &str = "sentinel_input";
pub const SENTINEL_OUTPUT_CHAIN: &str = "sentinel_output";

pub const BANNED_IPV4_SET: &str = "banned_ipv4";
pub const BANNED_IPV6_SET: &str = "banned_ipv6";
pub const RATE_TRACKED_SET: &str = "rate_tracked";
pub const GEO_BLOCKED_SET: &str = "geo_blocked";
pub const ALLOWLIST_SET: &str = "allowlist";

#[derive(Debug, Clone)]
pub struct NftTable {
    pub family: String,
    pub name: String,
}

impl NftTable {
    pub fn sentinel() -> Self {
        Self {
            family: "inet".to_string(),
            name: "sentinel".to_string(),
        }
    }
}

impl std::fmt::Display for NftTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.family, self.name)
    }
}
