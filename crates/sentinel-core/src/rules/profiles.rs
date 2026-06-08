use crate::rules::types::*;
use crate::config::types::FirewallProfile;

pub struct ProfileManager;

impl ProfileManager {
    pub fn get_rules(profile: &FirewallProfile) -> Vec<Rule> {
        match profile {
            FirewallProfile::WebServer => web_server_rules(),
            FirewallProfile::ReverseProxy => reverse_proxy_rules(),
            FirewallProfile::GameServer => game_server_rules(),
            FirewallProfile::DockerHost => docker_host_rules(),
            FirewallProfile::KubernetesNode => kubernetes_node_rules(),
            FirewallProfile::VpnGateway => vpn_gateway_rules(),
            FirewallProfile::SshHardened => ssh_hardened_rules(),
            FirewallProfile::DatabaseServer => database_server_rules(),
            FirewallProfile::HomeServer => home_server_rules(),
            FirewallProfile::EnterpriseEdge => enterprise_edge_rules(),
            FirewallProfile::Custom(_) => vec![],
        }
    }
}

fn base_rules() -> Vec<Rule> {
    vec![
        {
            let mut r = Rule::allow("allow-loopback");
            r.description = Some("Allow loopback interface".into());
            r.interface = Some("lo".into());
            r.priority = 1;
            r
        },
        {
            let mut r = Rule::deny("drop-invalid");
            r.description = Some("Drop invalid connection state packets".into());
            r.state = Some(vec![ConnectionState::Invalid]);
            r.priority = 5;
            r
        },
        {
            let mut r = Rule::allow("allow-established");
            r.description = Some("Allow established and related connections".into());
            r.state = Some(vec![ConnectionState::Established, ConnectionState::Related]);
            r.priority = 10;
            r
        },
    ]
}

fn web_server_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-http");
            r.description = Some("Allow inbound HTTP".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(80));
            r.direction = TrafficDirection::Inbound;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-https");
            r.description = Some("Allow inbound HTTPS".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(443));
            r.direction = TrafficDirection::Inbound;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-ssh");
            r.description = Some("Allow SSH (rate-limited)".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(22));
            r.direction = TrafficDirection::Inbound;
            r.rate_limit = Some(RateLimit { rate: 10, unit: RateUnit::Minute, burst: Some(20) });
            r.priority = 60;
            r
        },
        {
            let mut r = Rule::allow("allow-icmp");
            r.description = Some("Allow ICMP ping".into());
            r.protocol = Protocol::Icmp;
            r.rate_limit = Some(RateLimit { rate: 10, unit: RateUnit::Second, burst: Some(20) });
            r.priority = 70;
            r
        },
        {
            let mut r = Rule::deny("deny-all-inbound");
            r.description = Some("Default deny all inbound traffic".into());
            r.direction = TrafficDirection::Inbound;
            r.priority = 9999;
            r
        },
    ]);

    rules
}

fn reverse_proxy_rules() -> Vec<Rule> {
    let mut rules = web_server_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-http-upstream");
            r.description = Some("Allow HTTP to upstream services".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Range(8000, 9000));
            r.direction = TrafficDirection::Outbound;
            r.priority = 55;
            r
        },
    ]);

    rules
}

fn game_server_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-game-tcp");
            r.description = Some("Allow game server TCP".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Range(25000, 30000));
            r.direction = TrafficDirection::Inbound;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-game-udp");
            r.description = Some("Allow game server UDP".into());
            r.protocol = Protocol::Udp;
            r.dst_port = Some(PortSpec::Range(25000, 30000));
            r.direction = TrafficDirection::Inbound;
            r.rate_limit = Some(RateLimit { rate: 10000, unit: RateUnit::Second, burst: Some(50000) });
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-ssh");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(22));
            r.direction = TrafficDirection::Inbound;
            r.priority = 60;
            r
        },
        {
            let mut r = Rule::deny("deny-all-inbound");
            r.direction = TrafficDirection::Inbound;
            r.priority = 9999;
            r
        },
    ]);

    rules
}

fn docker_host_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-docker-bridge");
            r.description = Some("Allow Docker bridge network".into());
            r.interface = Some("docker0".into());
            r.priority = 20;
            r
        },
        {
            let mut r = Rule::allow("allow-ssh");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(22));
            r.direction = TrafficDirection::Inbound;
            r.rate_limit = Some(RateLimit { rate: 5, unit: RateUnit::Minute, burst: Some(10) });
            r.priority = 60;
            r
        },
        {
            let mut r = Rule::deny("deny-docker-registry-public");
            r.description = Some("Block direct registry access from public".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(5000));
            r.direction = TrafficDirection::Inbound;
            r.priority = 70;
            r
        },
        {
            let mut r = Rule::deny("deny-all-inbound");
            r.direction = TrafficDirection::Inbound;
            r.priority = 9999;
            r
        },
    ]);

    rules
}

fn kubernetes_node_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-apiserver");
            r.description = Some("Allow Kubernetes API server".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(6443));
            r.direction = TrafficDirection::Inbound;
            r.priority = 40;
            r
        },
        {
            let mut r = Rule::allow("allow-kubelet");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Range(10250, 10260));
            r.direction = TrafficDirection::Inbound;
            r.priority = 41;
            r
        },
        {
            let mut r = Rule::allow("allow-etcd");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Range(2379, 2380));
            r.direction = TrafficDirection::Inbound;
            r.priority = 42;
            r
        },
        {
            let mut r = Rule::allow("allow-nodeport");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Range(30000, 32767));
            r.direction = TrafficDirection::Inbound;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-cni");
            r.description = Some("Allow CNI overlay traffic".into());
            r.protocol = Protocol::Udp;
            r.dst_port = Some(PortSpec::Set(vec![4789, 8472]));
            r.direction = TrafficDirection::Inbound;
            r.priority = 45;
            r
        },
    ]);

    rules
}

fn vpn_gateway_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-wireguard");
            r.protocol = Protocol::Udp;
            r.dst_port = Some(PortSpec::Single(51820));
            r.direction = TrafficDirection::Inbound;
            r.priority = 40;
            r
        },
        {
            let mut r = Rule::allow("allow-openvpn");
            r.protocol = Protocol::Udp;
            r.dst_port = Some(PortSpec::Single(1194));
            r.direction = TrafficDirection::Inbound;
            r.priority = 41;
            r
        },
        {
            let mut r = Rule::allow("allow-ssh");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(22));
            r.direction = TrafficDirection::Inbound;
            r.rate_limit = Some(RateLimit { rate: 3, unit: RateUnit::Minute, burst: Some(5) });
            r.priority = 60;
            r
        },
        {
            let mut r = Rule::deny("deny-all-inbound");
            r.direction = TrafficDirection::Inbound;
            r.priority = 9999;
            r
        },
    ]);

    rules
}

fn ssh_hardened_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-ssh-hardened");
            r.description = Some("SSH with aggressive rate limiting".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(22));
            r.direction = TrafficDirection::Inbound;
            r.rate_limit = Some(RateLimit { rate: 3, unit: RateUnit::Minute, burst: Some(5) });
            r.log = true;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::deny("deny-all-inbound");
            r.direction = TrafficDirection::Inbound;
            r.priority = 9999;
            r
        },
    ]);

    rules
}

fn database_server_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-ssh-mgmt");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(22));
            r.direction = TrafficDirection::Inbound;
            r.rate_limit = Some(RateLimit { rate: 5, unit: RateUnit::Minute, burst: Some(10) });
            r.priority = 60;
            r
        },
        {
            let mut r = Rule::deny("deny-mysql-public");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(3306));
            r.direction = TrafficDirection::Inbound;
            r.priority = 70;
            r
        },
        {
            let mut r = Rule::deny("deny-postgres-public");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(5432));
            r.direction = TrafficDirection::Inbound;
            r.priority = 71;
            r
        },
        {
            let mut r = Rule::deny("deny-redis-public");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(6379));
            r.direction = TrafficDirection::Inbound;
            r.priority = 72;
            r
        },
        {
            let mut r = Rule::deny("deny-all-inbound");
            r.direction = TrafficDirection::Inbound;
            r.priority = 9999;
            r
        },
    ]);

    rules
}

fn home_server_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-http");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(80));
            r.direction = TrafficDirection::Inbound;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-https");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(443));
            r.direction = TrafficDirection::Inbound;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-ssh");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(22));
            r.direction = TrafficDirection::Inbound;
            r.priority = 60;
            r
        },
        {
            let mut r = Rule::allow("allow-plex");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(32400));
            r.direction = TrafficDirection::Inbound;
            r.priority = 70;
            r
        },
        {
            let mut r = Rule::deny("deny-all-inbound");
            r.direction = TrafficDirection::Inbound;
            r.priority = 9999;
            r
        },
    ]);

    rules
}

fn enterprise_edge_rules() -> Vec<Rule> {
    let mut rules = base_rules();

    rules.extend([
        {
            let mut r = Rule::allow("allow-http");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(80));
            r.direction = TrafficDirection::Inbound;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-https");
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(443));
            r.direction = TrafficDirection::Inbound;
            r.priority = 50;
            r
        },
        {
            let mut r = Rule::allow("allow-dns");
            r.protocol = Protocol::Udp;
            r.dst_port = Some(PortSpec::Single(53));
            r.priority = 45;
            r
        },
        {
            let mut r = Rule::allow("allow-ntp");
            r.protocol = Protocol::Udp;
            r.dst_port = Some(PortSpec::Single(123));
            r.priority = 46;
            r
        },
        {
            let mut r = Rule::allow("allow-bgp");
            r.description = Some("Allow BGP for routing".into());
            r.protocol = Protocol::Tcp;
            r.dst_port = Some(PortSpec::Single(179));
            r.priority = 47;
            r
        },
        {
            let mut r = Rule::deny("deny-all-inbound");
            r.direction = TrafficDirection::Inbound;
            r.priority = 9999;
            r
        },
    ]);

    rules
}
