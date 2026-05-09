// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod cli;
pub mod toml;
pub mod validate;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub wireguard: Wireguard,
    pub vhost_user: VhostUser,
    pub dhcp: Dhcp,
    pub network: Network,
    pub vm: Vm,
    #[serde(default)]
    pub busy_poll: BusyPoll,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Wireguard {
    pub private_key_file: Option<std::path::PathBuf>,
    pub private_key: Option<String>,
    pub listen_port: u16,
    pub peers: Vec<WgPeer>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostUser {
    pub socket: std::path::PathBuf,
    pub queue_size: u16,
    pub num_queues: u16,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp {
    pub pool: DhcpPool,
    pub decline_probation_secs: u64,
    pub checkpoint_secs: u64,
    pub reservations: Vec<DhcpReservation>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub subnet: ip_network::Ipv4Network,
    pub gateway: std::net::Ipv4Addr,
    pub dns: Vec<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vm {
    pub mtu: u16,
    pub mac: mac_address::MacAddress,
    pub ip: std::net::Ipv4Addr,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WgPeer {
    pub name: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub preshared_key_file: Option<std::path::PathBuf>,
    pub endpoint: std::net::SocketAddr,
    pub allowed_ips: Vec<ip_network::IpNetwork>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpPool {
    pub start: std::net::Ipv4Addr,
    pub end: std::net::Ipv4Addr,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpReservation {
    pub mac: mac_address::MacAddress,
    pub ip: std::net::Ipv4Addr,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BusyPoll {
    #[serde(default = "default_busy_poll_budget_us")]
    pub budget_us: u32,
    #[serde(default = "default_busy_poll_initial_packets")]
    pub initial_packets: u32,
    #[serde(default = "default_busy_poll_min_packets")]
    pub min_packets: u32,
    #[serde(default = "default_busy_poll_max_packets")]
    pub max_packets: u32,
}

impl Default for BusyPoll {
    fn default() -> Self {
        Self {
            budget_us: default_busy_poll_budget_us(),
            initial_packets: default_busy_poll_initial_packets(),
            min_packets: default_busy_poll_min_packets(),
            max_packets: default_busy_poll_max_packets(),
        }
    }
}

fn default_busy_poll_budget_us() -> u32 {
    50
}
fn default_busy_poll_initial_packets() -> u32 {
    8
}
fn default_busy_poll_min_packets() -> u32 {
    1
}
fn default_busy_poll_max_packets() -> u32 {
    64
}
