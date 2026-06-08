use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallZone {
    Public,
    Private,
    Trusted,
    Dmz,
    Management,
}

impl std::fmt::Display for FirewallZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallZone::Public => write!(f, "public"),
            FirewallZone::Private => write!(f, "private"),
            FirewallZone::Trusted => write!(f, "trusted"),
            FirewallZone::Dmz => write!(f, "dmz"),
            FirewallZone::Management => write!(f, "management"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallProfile {
    WebServer,
    ReverseProxy,
    GameServer,
    DockerHost,
    KubernetesNode,
    VpnGateway,
    SshHardened,
    DatabaseServer,
    HomeServer,
    EnterpriseEdge,
    Custom(String),
}

impl std::fmt::Display for FirewallProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallProfile::WebServer => write!(f, "web-server"),
            FirewallProfile::ReverseProxy => write!(f, "reverse-proxy"),
            FirewallProfile::GameServer => write!(f, "game-server"),
            FirewallProfile::DockerHost => write!(f, "docker-host"),
            FirewallProfile::KubernetesNode => write!(f, "kubernetes-node"),
            FirewallProfile::VpnGateway => write!(f, "vpn-gateway"),
            FirewallProfile::SshHardened => write!(f, "ssh-hardened"),
            FirewallProfile::DatabaseServer => write!(f, "database-server"),
            FirewallProfile::HomeServer => write!(f, "home-server"),
            FirewallProfile::EnterpriseEdge => write!(f, "enterprise-edge"),
            FirewallProfile::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

impl std::str::FromStr for FirewallProfile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "web-server" | "web" => Ok(FirewallProfile::WebServer),
            "reverse-proxy" | "proxy" => Ok(FirewallProfile::ReverseProxy),
            "game-server" | "game" => Ok(FirewallProfile::GameServer),
            "docker-host" | "docker" => Ok(FirewallProfile::DockerHost),
            "kubernetes-node" | "k8s" => Ok(FirewallProfile::KubernetesNode),
            "vpn-gateway" | "vpn" => Ok(FirewallProfile::VpnGateway),
            "ssh-hardened" | "ssh" => Ok(FirewallProfile::SshHardened),
            "database-server" | "db" => Ok(FirewallProfile::DatabaseServer),
            "home-server" | "home" => Ok(FirewallProfile::HomeServer),
            "enterprise-edge" | "enterprise" => Ok(FirewallProfile::EnterpriseEdge),
            _ if s.starts_with("custom:") => Ok(FirewallProfile::Custom(s[7..].to_string())),
            _ => anyhow::bail!("Unknown profile: {}", s),
        }
    }
}
