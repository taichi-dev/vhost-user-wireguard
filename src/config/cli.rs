// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::Ipv4Addr;
use std::path::PathBuf;

use super::Config;

/// CLI argument parser that produces overrides for Config.
/// Every field is Option<T> so unset flags don't override TOML values.
#[derive(clap::Parser, Debug, Default)]
#[command(author, version, about)]
pub struct CliArgs {
    /// Path to the TOML configuration file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Validate configuration and exit
    #[arg(long)]
    pub check_config: bool,

    /// WireGuard listen port
    #[arg(long)]
    pub wireguard_listen_port: Option<u16>,

    /// WireGuard private key (inline base64)
    #[arg(long)]
    pub wireguard_private_key: Option<String>,

    /// WireGuard private key file path
    #[arg(long)]
    pub wireguard_private_key_file: Option<PathBuf>,

    /// vhost-user socket path
    #[arg(long)]
    pub vhost_user_socket: Option<PathBuf>,

    /// vhost-user queue size
    #[arg(long)]
    pub vhost_user_queue_size: Option<u16>,

    /// vhost-user number of queues
    #[arg(long)]
    pub vhost_user_num_queues: Option<u16>,

    /// Network subnet in CIDR notation
    #[arg(long)]
    pub network_subnet: Option<ip_network::Ipv4Network>,

    /// Network gateway IP address
    #[arg(long)]
    pub network_gateway: Option<Ipv4Addr>,

    /// VM MTU
    #[arg(long)]
    pub vm_mtu: Option<u16>,

    /// VM MAC address
    #[arg(long)]
    pub vm_mac: Option<mac_address::MacAddress>,

    /// VM IP address
    #[arg(long)]
    pub vm_ip: Option<Ipv4Addr>,

    /// DHCP decline probation duration in seconds
    #[arg(long)]
    pub dhcp_decline_probation_secs: Option<u64>,

    /// DHCP checkpoint interval in seconds
    #[arg(long)]
    pub dhcp_checkpoint_secs: Option<u64>,

    /// Log format: "text" or "json"
    #[arg(long)]
    pub log_format: Option<String>,

    /// Log filter (e.g. "info,vhost_user_wireguard=debug")
    #[arg(long)]
    pub log_filter: Option<String>,
}

/// Merge CLI overrides into a Config, returning the updated Config.
/// Only fields set (Some) in args override the corresponding Config field.
pub fn apply_overrides(mut config: Config, args: &CliArgs) -> Config {
    if let Some(port) = args.wireguard_listen_port {
        config.wireguard.listen_port = port;
    }
    if let Some(ref key) = args.wireguard_private_key {
        config.wireguard.private_key = Some(key.clone());
    }
    if let Some(ref path) = args.wireguard_private_key_file {
        config.wireguard.private_key_file = Some(path.clone());
    }
    if let Some(ref socket) = args.vhost_user_socket {
        config.vhost_user.socket = socket.clone();
    }
    if let Some(queue_size) = args.vhost_user_queue_size {
        config.vhost_user.queue_size = queue_size;
    }
    if let Some(num_queues) = args.vhost_user_num_queues {
        config.vhost_user.num_queues = num_queues;
    }
    if let Some(subnet) = args.network_subnet {
        config.network.subnet = subnet;
    }
    if let Some(gateway) = args.network_gateway {
        config.network.gateway = gateway;
    }
    if let Some(mtu) = args.vm_mtu {
        config.vm.mtu = mtu;
    }
    if let Some(mac) = args.vm_mac {
        config.vm.mac = mac;
    }
    if let Some(ip) = args.vm_ip {
        config.vm.ip = ip;
    }
    if let Some(secs) = args.dhcp_decline_probation_secs {
        config.dhcp.decline_probation_secs = secs;
    }
    if let Some(secs) = args.dhcp_checkpoint_secs {
        config.dhcp.checkpoint_secs = secs;
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Dhcp, DhcpPool, Network, VhostUser, Vm, Wireguard};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn make_test_config() -> Config {
        Config {
            wireguard: Wireguard {
                private_key_file: None,
                private_key: None,
                listen_port: 51820,
                peers: vec![],
            },
            vhost_user: VhostUser {
                socket: PathBuf::from("/tmp/vhost.sock"),
                queue_size: 256,
                num_queues: 2,
            },
            dhcp: Dhcp {
                pool: DhcpPool {
                    start: Ipv4Addr::new(10, 0, 0, 2),
                    end: Ipv4Addr::new(10, 0, 0, 254),
                },
                decline_probation_secs: 30,
                checkpoint_secs: 60,
                reservations: vec![],
            },
            network: Network {
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                dns: vec![],
            },
            vm: Vm {
                mtu: 1420,
                mac: "52:54:00:12:34:56".parse().unwrap(),
                ip: Ipv4Addr::new(10, 0, 0, 100),
            },
        }
    }

    #[test]
    fn test_no_overrides_unchanged() {
        let config = make_test_config();
        let args = CliArgs::default();
        let result = apply_overrides(config.clone(), &args);

        assert_eq!(result.wireguard.listen_port, config.wireguard.listen_port);
        assert_eq!(result.vhost_user.socket, config.vhost_user.socket);
        assert_eq!(result.vhost_user.queue_size, config.vhost_user.queue_size);
        assert_eq!(result.network.gateway, config.network.gateway);
        assert_eq!(result.vm.mtu, config.vm.mtu);
        assert_eq!(result.dhcp.decline_probation_secs, config.dhcp.decline_probation_secs);
    }

    #[test]
    fn test_socket_override() {
        let config = make_test_config();
        let new_socket = PathBuf::from("/run/vhost-new.sock");
        let args = CliArgs {
            vhost_user_socket: Some(new_socket.clone()),
            ..Default::default()
        };
        let result = apply_overrides(config, &args);
        assert_eq!(result.vhost_user.socket, new_socket);
    }

    #[test]
    fn test_listen_port_override() {
        let config = make_test_config();
        let args = CliArgs {
            wireguard_listen_port: Some(12345),
            ..Default::default()
        };
        let result = apply_overrides(config, &args);
        assert_eq!(result.wireguard.listen_port, 12345);
    }
}
