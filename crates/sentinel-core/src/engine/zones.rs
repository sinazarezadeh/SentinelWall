use std::collections::HashMap;
use ipnet::IpNet;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    pub name: String,
    pub interfaces: Vec<String>,
    pub networks: Vec<IpNet>,
    pub default_policy: ZonePolicy,
    pub masquerade: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ZonePolicy {
    Accept,
    Drop,
    Reject,
}

pub struct ZoneManager {
    zones: HashMap<String, ZoneConfig>,
}

impl ZoneManager {
    pub fn new() -> Self {
        let mut manager = Self {
            zones: HashMap::new(),
        };
        manager.init_defaults();
        manager
    }

    fn init_defaults(&mut self) {
        self.zones.insert("public".to_string(), ZoneConfig {
            name: "public".to_string(),
            interfaces: vec![],
            networks: vec![],
            default_policy: ZonePolicy::Drop,
            masquerade: false,
        });

        self.zones.insert("private".to_string(), ZoneConfig {
            name: "private".to_string(),
            interfaces: vec![],
            networks: vec![
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
            ],
            default_policy: ZonePolicy::Accept,
            masquerade: false,
        });

        self.zones.insert("trusted".to_string(), ZoneConfig {
            name: "trusted".to_string(),
            interfaces: vec!["lo".to_string()],
            networks: vec!["127.0.0.0/8".parse().unwrap()],
            default_policy: ZonePolicy::Accept,
            masquerade: false,
        });
    }

    pub fn add_zone(&mut self, zone: ZoneConfig) {
        self.zones.insert(zone.name.clone(), zone);
    }

    pub fn get_zone(&self, name: &str) -> Option<&ZoneConfig> {
        self.zones.get(name)
    }

    pub fn list_zones(&self) -> Vec<&ZoneConfig> {
        self.zones.values().collect()
    }

    pub fn get_zone_for_interface(&self, iface: &str) -> Option<&ZoneConfig> {
        self.zones.values().find(|z| z.interfaces.contains(&iface.to_string()))
    }
}

impl Default for ZoneManager {
    fn default() -> Self {
        Self::new()
    }
}
