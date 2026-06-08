use crate::rules::types::*;
use std::net::IpAddr;
use chrono::{DateTime, Utc};

/// Builds nftables rule strings from Rule structs
pub struct NftablesBuilder;

impl NftablesBuilder {
    pub fn build_table_init() -> String {
        r#"
table inet sentinel {
    set banned_ipv4 {
        type ipv4_addr
        flags dynamic, timeout
        comment "SentinelWall banned IPv4 addresses"
    }
    set banned_ipv6 {
        type ipv6_addr
        flags dynamic, timeout
        comment "SentinelWall banned IPv6 addresses"
    }
    set rate_tracked {
        type ipv4_addr
        flags dynamic
        comment "Rate tracking set"
    }
    chain input {
        type filter hook input priority 0; policy drop;
        # Loopback
        iifname lo accept
        # Drop invalid
        ct state invalid drop
        # Allow established/related
        ct state { established, related } accept
        # Jump to sentinel checks
        jump sentinel_input
    }
    chain sentinel_input {
        # Check banned IPs
        ip saddr @banned_ipv4 drop
        ip6 saddr @banned_ipv6 drop
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state { established, related } accept
    }
    chain prerouting {
        type nat hook prerouting priority -100;
    }
    chain postrouting {
        type nat hook postrouting priority 100;
    }
}
"#.trim().to_string()
    }

    pub fn build_rule(rule: &Rule, _chain: &str) -> String {
        let mut parts = Vec::new();

        // Interface match
        if let Some(iface) = &rule.interface {
            match rule.direction {
                TrafficDirection::Inbound => parts.push(format!("iifname \"{}\"", iface)),
                TrafficDirection::Outbound => parts.push(format!("oifname \"{}\"", iface)),
                _ => parts.push(format!("iifname \"{}\"", iface)),
            }
        }

        // Protocol
        match &rule.protocol {
            Protocol::Tcp => parts.push("tcp".to_string()),
            Protocol::Udp => parts.push("udp".to_string()),
            Protocol::Icmp => parts.push("icmp".to_string()),
            Protocol::Icmpv6 => parts.push("icmpv6".to_string()),
            Protocol::Custom(n) => parts.push(format!("meta l4proto {}", n)),
            Protocol::Any => {}
        }

        // Source address
        if let Some(src) = &rule.src_addr {
            parts.push(format!("ip saddr {}", addr_spec_to_nft(src)));
        }

        // Destination address
        if let Some(dst) = &rule.dst_addr {
            parts.push(format!("ip daddr {}", addr_spec_to_nft(dst)));
        }

        // Source port (only for TCP/UDP)
        if matches!(rule.protocol, Protocol::Tcp | Protocol::Udp) {
            if let Some(src_port) = &rule.src_port {
                parts.push(format!("sport {}", port_spec_to_nft(src_port)));
            }
            if let Some(dst_port) = &rule.dst_port {
                parts.push(format!("dport {}", port_spec_to_nft(dst_port)));
            }
        }

        // Connection state
        if let Some(states) = &rule.state {
            let state_strs: Vec<&str> = states.iter().map(|s| match s {
                ConnectionState::New => "new",
                ConnectionState::Established => "established",
                ConnectionState::Related => "related",
                ConnectionState::Invalid => "invalid",
                ConnectionState::Untracked => "untracked",
            }).collect();
            parts.push(format!("ct state {{ {} }}", state_strs.join(", ")));
        }

        // Rate limit
        if let Some(rate) = &rule.rate_limit {
            let unit = match rate.unit {
                RateUnit::Second => "second",
                RateUnit::Minute => "minute",
                RateUnit::Hour => "hour",
                RateUnit::Day => "day",
            };
            if let Some(burst) = rate.burst {
                parts.push(format!("limit rate {}/{} burst {} packets", rate.rate, unit, burst));
            } else {
                parts.push(format!("limit rate {}/{}", rate.rate, unit));
            }
        }

        // Logging
        if rule.log {
            parts.push(format!("log prefix \"[sentinel] {}\" flags all", rule.name));
        }

        // Action
        let action = match &rule.action {
            RuleAction::Accept => "accept".to_string(),
            RuleAction::Drop => "drop".to_string(),
            RuleAction::Reject => "reject with icmpx type port-unreachable".to_string(),
            RuleAction::Log => "log".to_string(),
            RuleAction::Queue => "queue".to_string(),
            RuleAction::Return => "return".to_string(),
            RuleAction::Jump(chain) => format!("jump {}", chain),
            RuleAction::Tarpit => "drop".to_string(), // Tarpit handled at higher level
            RuleAction::RateLimit(rl) => format!("limit rate {}/{}", rl.rate, match rl.unit {
                RateUnit::Second => "second",
                RateUnit::Minute => "minute",
                RateUnit::Hour => "hour",
                RateUnit::Day => "day",
            }),
        };
        parts.push(action);

        // Comment
        let comment = rule.comment.as_deref()
            .unwrap_or(&rule.name);
        parts.push(format!("comment \"{}\"", comment.replace('"', "'")));

        format!("    {}", parts.join(" "))
    }

    pub fn build_ban_ipv4(ip: &IpAddr, timeout: Option<DateTime<Utc>>) -> String {
        let timeout_str = if let Some(expires) = timeout {
            let secs = (expires - Utc::now()).num_seconds().max(0);
            format!(" timeout {}s", secs)
        } else {
            String::new()
        };
        format!("add element inet sentinel banned_ipv4 {{ {}{} }}", ip, timeout_str)
    }

    pub fn build_ban_ipv6(ip: &IpAddr, timeout: Option<DateTime<Utc>>) -> String {
        let timeout_str = if let Some(expires) = timeout {
            let secs = (expires - Utc::now()).num_seconds().max(0);
            format!(" timeout {}s", secs)
        } else {
            String::new()
        };
        format!("add element inet sentinel banned_ipv6 {{ {}{} }}", ip, timeout_str)
    }

    pub fn build_unban_ipv4(ip: &IpAddr) -> String {
        format!("delete element inet sentinel banned_ipv4 {{ {} }}", ip)
    }

    pub fn build_unban_ipv6(ip: &IpAddr) -> String {
        format!("delete element inet sentinel banned_ipv6 {{ {} }}", ip)
    }

    pub fn build_list_rules() -> &'static str {
        "list ruleset"
    }

    pub fn build_flush_table() -> &'static str {
        "flush table inet sentinel"
    }
}

fn addr_spec_to_nft(spec: &AddrSpec) -> String {
    match spec {
        AddrSpec::Single(ip) => ip.to_string(),
        AddrSpec::Network(net) => net.to_string(),
        AddrSpec::Range { start, end } => format!("{}-{}", start, end),
        AddrSpec::Set(ips) => {
            let list = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");
            format!("{{ {} }}", list)
        },
        AddrSpec::Any => String::new(),
    }
}

fn port_spec_to_nft(spec: &PortSpec) -> String {
    match spec {
        PortSpec::Single(p) => p.to_string(),
        PortSpec::Range(start, end) => format!("{}-{}", start, end),
        PortSpec::Set(ports) => {
            let list = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
            format!("{{ {} }}", list)
        },
        PortSpec::Any => String::new(),
    }
}
