// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic validation pass for [`crate::config::Config`].
//!
//! Collects ALL violations at once and returns them together as a single
//! [`ConfigError::Validation`] error. Every check runs even if earlier ones
//! fail, so users see the full list of problems on one shot.

use crate::config::Config;
use crate::error::ConfigError;
use mac_address::MacAddress;
use std::collections::HashSet;
use std::net::Ipv4Addr;

/// Validate a [`Config`] against semantic rules.
///
/// Returns `Ok(())` if every check passes, otherwise returns a
/// [`ConfigError::Validation`] containing every collected issue.
pub fn validate(config: &Config) -> Result<(), ConfigError> {
    let mut issues: Vec<String> = Vec::new();

    // 1. Subnet must be /30
    let prefix = config.network.subnet.netmask();
    if prefix != 30 {
        issues.push(format!(
            "network.subnet must be /30 (got /{n})",
            n = prefix
        ));
    }

    let net_addr = config.network.subnet.network_address();
    let bcast_addr = config.network.subnet.broadcast_address();
    let gateway = config.network.gateway;

    // 2. Gateway must be inside the configured subnet
    if !config.network.subnet.contains(gateway) {
        issues.push(format!(
            "network.gateway {ip} is outside network.subnet {sub}",
            ip = gateway,
            sub = config.network.subnet,
        ));
    }

    // 3. Gateway cannot be the network or broadcast address
    if gateway == net_addr || gateway == bcast_addr {
        issues.push(format!(
            "network.gateway {ip} cannot be the network or broadcast address",
            ip = gateway,
        ));
    }

    // 4. MTU must be inside the legal range
    let mtu = config.vm.mtu;
    if !(576..=9000).contains(&mtu) {
        issues.push(format!("vm.mtu {n} out of range [576, 9000]", n = mtu));
    }

    // 5. MTU vs WG overhead — emit a soft warning if above safe ceiling
    if mtu > 1420 {
        issues.push(format!(
            "vm.mtu {n} may exceed WG path MTU (recommended <= 1420)",
            n = mtu,
        ));
    }

    // 6. DHCP pool must sit inside the subnet, ordered, and avoid net/bcast
    let pool_start = config.dhcp.pool.start;
    let pool_end = config.dhcp.pool.end;
    let pool_start_in_subnet = config.network.subnet.contains(pool_start);
    let pool_end_in_subnet = config.network.subnet.contains(pool_end);
    if !pool_start_in_subnet {
        issues.push(format!(
            "dhcp.pool.start {ip} is outside network.subnet {sub}",
            ip = pool_start,
            sub = config.network.subnet,
        ));
    }
    if !pool_end_in_subnet {
        issues.push(format!(
            "dhcp.pool.end {ip} is outside network.subnet {sub}",
            ip = pool_end,
            sub = config.network.subnet,
        ));
    }
    if u32::from(pool_start) > u32::from(pool_end) {
        issues.push(format!(
            "dhcp.pool.start {start} must be <= dhcp.pool.end {end}",
            start = pool_start,
            end = pool_end,
        ));
    }
    if pool_start_in_subnet && pool_start == net_addr {
        issues.push(format!(
            "dhcp.pool.start {ip} cannot be the network address",
            ip = pool_start,
        ));
    }
    if pool_end_in_subnet && pool_end == bcast_addr {
        issues.push(format!(
            "dhcp.pool.end {ip} cannot be the broadcast address",
            ip = pool_end,
        ));
    }

    // 7. Reservations must be in subnet and never collide with the gateway
    for reservation in &config.dhcp.reservations {
        if !config.network.subnet.contains(reservation.ip) {
            issues.push(format!(
                "dhcp.reservation {ip} is outside network.subnet {sub}",
                ip = reservation.ip,
                sub = config.network.subnet,
            ));
        }
        if reservation.ip == gateway {
            issues.push(format!(
                "dhcp.reservation {ip} conflicts with gateway",
                ip = reservation.ip,
            ));
        }
    }

    // 8. Reservation MACs must be unique
    {
        let mut seen: HashSet<MacAddress> = HashSet::new();
        for reservation in &config.dhcp.reservations {
            if !seen.insert(reservation.mac) {
                issues.push(format!(
                    "dhcp.reservations: duplicate MAC {mac}",
                    mac = reservation.mac,
                ));
            }
        }
    }

    // 9. Reservation IPs must be unique and must not overlap the pool
    {
        let mut seen: HashSet<Ipv4Addr> = HashSet::new();
        let pool_lo = u32::from(pool_start);
        let pool_hi = u32::from(pool_end);
        for reservation in &config.dhcp.reservations {
            if !seen.insert(reservation.ip) {
                issues.push(format!(
                    "dhcp.reservations: duplicate IP {ip}",
                    ip = reservation.ip,
                ));
                continue;
            }
            let ip_u = u32::from(reservation.ip);
            if pool_lo <= pool_hi && ip_u >= pool_lo && ip_u <= pool_hi {
                issues.push(format!(
                    "dhcp.reservations: duplicate IP {ip}",
                    ip = reservation.ip,
                ));
            }
        }
    }

    // 10. Exactly one of private_key_file / private_key must be configured
    match (
        &config.wireguard.private_key_file,
        &config.wireguard.private_key,
    ) {
        (Some(_), Some(_)) => issues.push(
            "wireguard: must specify exactly one of private_key_file or private_key (got both)"
                .to_string(),
        ),
        (None, None) => issues.push(
            "wireguard: must specify either private_key_file or private_key (got neither)"
                .to_string(),
        ),
        _ => {}
    }

    // 11. WG endpoints — already parsed as SocketAddr by serde, no-op here.

    // 12. Peer public keys must be unique
    {
        let mut seen: HashSet<&str> = HashSet::new();
        for peer in &config.wireguard.peers {
            if !seen.insert(peer.public_key.as_str()) {
                let fingerprint = if peer.public_key.len() >= 8 {
                    format!("{}...", &peer.public_key[..8])
                } else {
                    peer.public_key.clone()
                };
                issues.push(format!(
                    "wireguard.peers: duplicate public key {fp}",
                    fp = fingerprint,
                ));
            }
        }
    }

    // 13. Listen port must not be zero
    if config.wireguard.listen_port == 0 {
        issues.push("wireguard.listen_port must not be 0".to_string());
    }

    // 14. vhost-user socket parent dir must exist
    if let Some(parent) = config.vhost_user.socket.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            issues.push(format!(
                "vhost_user.socket parent dir {p} does not exist",
                p = parent.display(),
            ));
        }
    }

    // 15. queue_size must be a power of two within [64, 4096]
    let qs = config.vhost_user.queue_size;
    if !qs.is_power_of_two() || !(64..=4096).contains(&qs) {
        issues.push(format!(
            "vhost_user.queue_size {n} must be a power of 2 between 64 and 4096",
            n = qs,
        ));
    }

    // 16. num_queues must equal 2 (RX + TX, no MQ in MVP)
    if config.vhost_user.num_queues != 2 {
        issues.push(format!(
            "vhost_user.num_queues must be 2 (got {n})",
            n = config.vhost_user.num_queues,
        ));
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Validation { issues })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, Dhcp, DhcpPool, DhcpReservation, Network, VhostUser, Vm, WgPeer, Wireguard,
    };
    use ip_network::Ipv4Network;
    use std::path::PathBuf;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn parse_mac(s: &str) -> MacAddress {
        s.parse::<MacAddress>().expect("mac")
    }

    fn valid_config() -> Config {
        Config {
            wireguard: Wireguard {
                private_key_file: None,
                private_key: Some(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                ),
                listen_port: 51820,
                peers: vec![WgPeer {
                    name: "peer1".to_string(),
                    public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
                        .to_string(),
                    preshared_key: None,
                    preshared_key_file: None,
                    endpoint: "1.2.3.4:51820".parse().expect("endpoint"),
                    allowed_ips: vec![],
                    persistent_keepalive: None,
                }],
            },
            vhost_user: VhostUser {
                socket: PathBuf::from("/tmp/vhu.sock"),
                queue_size: 256,
                num_queues: 2,
            },
            dhcp: Dhcp {
                pool: DhcpPool {
                    start: ipv4(10, 0, 0, 2),
                    end: ipv4(10, 0, 0, 2),
                },
                decline_probation_secs: 86400,
                checkpoint_secs: 60,
                reservations: vec![],
            },
            network: Network {
                subnet: Ipv4Network::new(ipv4(10, 0, 0, 0), 30).expect("net"),
                gateway: ipv4(10, 0, 0, 1),
                dns: vec![ipv4(8, 8, 8, 8)],
            },
            vm: Vm {
                mtu: 1420,
                mac: parse_mac("52:54:00:12:34:56"),
                ip: ipv4(10, 0, 0, 2),
            },
        }
    }

    fn unwrap_issues(result: Result<(), ConfigError>) -> Vec<String> {
        match result {
            Err(ConfigError::Validation { issues }) => issues,
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    fn assert_issue_contains(issues: &[String], needle: &str) {
        assert!(
            issues.iter().any(|i| i.contains(needle)),
            "expected an issue containing {needle:?}, got {issues:?}"
        );
    }

    #[test]
    fn test_valid_config_passes() {
        let config = valid_config();
        let result = validate(&config);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn test_subnet_not_30_rejected() {
        let mut config = valid_config();
        config.network.subnet =
            Ipv4Network::new(ipv4(10, 0, 0, 0), 28).expect("net");
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "network.subnet must be /30 (got /28)");
    }

    #[test]
    fn test_subnet_29_rejected() {
        // AC-CFG-2
        let mut config = valid_config();
        config.network.subnet =
            Ipv4Network::new(ipv4(10, 0, 0, 0), 29).expect("net");
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "network.subnet must be /30 (got /29)");
    }

    #[test]
    fn test_subnet_31_rejected() {
        // AC-CFG-3
        let mut config = valid_config();
        config.network.subnet =
            Ipv4Network::new(ipv4(10, 0, 0, 0), 31).expect("net");
        // gateway 10.0.0.1 happens to be the broadcast in /31; just check the prefix issue
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "network.subnet must be /30 (got /31)");
    }

    #[test]
    fn test_gateway_outside_subnet() {
        let mut config = valid_config();
        config.network.gateway = ipv4(192, 168, 7, 1);
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "network.gateway 192.168.7.1 is outside network.subnet",
        );
    }

    #[test]
    fn test_gateway_is_network_addr() {
        let mut config = valid_config();
        config.network.gateway = ipv4(10, 0, 0, 0);
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "network.gateway 10.0.0.0 cannot be the network or broadcast address",
        );
    }

    #[test]
    fn test_gateway_is_broadcast_addr() {
        let mut config = valid_config();
        config.network.gateway = ipv4(10, 0, 0, 3);
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "network.gateway 10.0.0.3 cannot be the network or broadcast address",
        );
    }

    #[test]
    fn test_mtu_too_low() {
        let mut config = valid_config();
        config.vm.mtu = 200;
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "vm.mtu 200 out of range [576, 9000]");
    }

    #[test]
    fn test_mtu_too_high() {
        let mut config = valid_config();
        config.vm.mtu = 9001;
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "vm.mtu 9001 out of range [576, 9000]");
    }

    #[test]
    fn test_mtu_warning_above_1420() {
        let mut config = valid_config();
        config.vm.mtu = 1500;
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "vm.mtu 1500 may exceed WG path MTU (recommended <= 1420)",
        );
    }

    #[test]
    fn test_pool_start_outside_subnet() {
        let mut config = valid_config();
        config.dhcp.pool.start = ipv4(192, 168, 1, 5);
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "dhcp.pool.start 192.168.1.5 is outside network.subnet",
        );
    }

    #[test]
    fn test_pool_end_outside_subnet() {
        let mut config = valid_config();
        config.dhcp.pool.end = ipv4(192, 168, 1, 6);
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "dhcp.pool.end 192.168.1.6 is outside network.subnet",
        );
    }

    #[test]
    fn test_pool_start_after_end() {
        let mut config = valid_config();
        config.dhcp.pool.start = ipv4(10, 0, 0, 2);
        config.dhcp.pool.end = ipv4(10, 0, 0, 1);
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "dhcp.pool.start 10.0.0.2 must be <= dhcp.pool.end 10.0.0.1",
        );
    }

    #[test]
    fn test_pool_start_is_network_addr() {
        let mut config = valid_config();
        config.dhcp.pool.start = ipv4(10, 0, 0, 0);
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "dhcp.pool.start 10.0.0.0 cannot be the network address",
        );
    }

    #[test]
    fn test_pool_end_is_broadcast_addr() {
        let mut config = valid_config();
        config.dhcp.pool.end = ipv4(10, 0, 0, 3);
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "dhcp.pool.end 10.0.0.3 cannot be the broadcast address",
        );
    }

    #[test]
    fn test_reservation_ip_outside_subnet() {
        let mut config = valid_config();
        config.dhcp.reservations.push(DhcpReservation {
            mac: parse_mac("52:54:00:aa:bb:cc"),
            ip: ipv4(192, 168, 9, 9),
            hostname: None,
        });
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "dhcp.reservation 192.168.9.9 is outside network.subnet",
        );
    }

    #[test]
    fn test_reservation_ip_is_gateway() {
        let mut config = valid_config();
        config.dhcp.reservations.push(DhcpReservation {
            mac: parse_mac("52:54:00:aa:bb:cc"),
            ip: ipv4(10, 0, 0, 1),
            hostname: None,
        });
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "dhcp.reservation 10.0.0.1 conflicts with gateway",
        );
    }

    #[test]
    fn test_reservation_duplicate_mac() {
        let mut config = valid_config();
        // Two reservations sharing a MAC. Use a /29 subnet to give us room for two IPs.
        config.network.subnet =
            Ipv4Network::new(ipv4(10, 0, 0, 0), 29).expect("net");
        config.dhcp.reservations.push(DhcpReservation {
            mac: parse_mac("52:54:00:aa:bb:cc"),
            ip: ipv4(10, 0, 0, 4),
            hostname: None,
        });
        config.dhcp.reservations.push(DhcpReservation {
            mac: parse_mac("52:54:00:aa:bb:cc"),
            ip: ipv4(10, 0, 0, 5),
            hostname: None,
        });
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "dhcp.reservations: duplicate MAC 52:54:00:AA:BB:CC",
        );
    }

    #[test]
    fn test_reservation_duplicate_ip() {
        let mut config = valid_config();
        // Move pool out of the way so we test only the dup-IP path.
        config.network.subnet =
            Ipv4Network::new(ipv4(10, 0, 0, 0), 29).expect("net");
        config.dhcp.pool.start = ipv4(10, 0, 0, 2);
        config.dhcp.pool.end = ipv4(10, 0, 0, 2);
        config.dhcp.reservations.push(DhcpReservation {
            mac: parse_mac("52:54:00:aa:bb:cc"),
            ip: ipv4(10, 0, 0, 4),
            hostname: None,
        });
        config.dhcp.reservations.push(DhcpReservation {
            mac: parse_mac("52:54:00:dd:ee:ff"),
            ip: ipv4(10, 0, 0, 4),
            hostname: None,
        });
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "dhcp.reservations: duplicate IP 10.0.0.4");
    }

    #[test]
    fn test_reservation_overlaps_pool() {
        let mut config = valid_config();
        config.dhcp.reservations.push(DhcpReservation {
            mac: parse_mac("52:54:00:aa:bb:cc"),
            ip: ipv4(10, 0, 0, 2),
            hostname: None,
        });
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "dhcp.reservations: duplicate IP 10.0.0.2");
    }

    #[test]
    fn test_wg_both_keys_set() {
        // AC-CFG-8b
        let mut config = valid_config();
        config.wireguard.private_key_file = Some(PathBuf::from("/etc/wg/key"));
        config.wireguard.private_key =
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "wireguard: must specify exactly one of private_key_file or private_key (got both)",
        );
    }

    #[test]
    fn test_wg_neither_key_set() {
        // AC-CFG-8c
        let mut config = valid_config();
        config.wireguard.private_key_file = None;
        config.wireguard.private_key = None;
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "wireguard: must specify either private_key_file or private_key (got neither)",
        );
    }

    #[test]
    fn test_wg_duplicate_peer_public_key() {
        let mut config = valid_config();
        let key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=".to_string();
        config.wireguard.peers = vec![
            WgPeer {
                name: "p1".to_string(),
                public_key: key.clone(),
                preshared_key: None,
                preshared_key_file: None,
                endpoint: "1.2.3.4:51820".parse().expect("ep"),
                allowed_ips: vec![],
                persistent_keepalive: None,
            },
            WgPeer {
                name: "p2".to_string(),
                public_key: key.clone(),
                preshared_key: None,
                preshared_key_file: None,
                endpoint: "5.6.7.8:51820".parse().expect("ep"),
                allowed_ips: vec![],
                persistent_keepalive: None,
            },
        ];
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "wireguard.peers: duplicate public key CCCCCCCC...",
        );
    }

    #[test]
    fn test_listen_port_zero() {
        let mut config = valid_config();
        config.wireguard.listen_port = 0;
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "wireguard.listen_port must not be 0");
    }

    #[test]
    fn test_socket_parent_dir_missing() {
        let mut config = valid_config();
        config.vhost_user.socket =
            PathBuf::from("/this/does/not/exist/anywhere/foo.sock");
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "vhost_user.socket parent dir /this/does/not/exist/anywhere does not exist",
        );
    }

    #[test]
    fn test_queue_size_not_power_of_two() {
        let mut config = valid_config();
        config.vhost_user.queue_size = 100;
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "vhost_user.queue_size 100 must be a power of 2 between 64 and 4096",
        );
    }

    #[test]
    fn test_queue_size_too_small() {
        let mut config = valid_config();
        config.vhost_user.queue_size = 32; // power of 2 but < 64
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "vhost_user.queue_size 32 must be a power of 2 between 64 and 4096",
        );
    }

    #[test]
    fn test_queue_size_too_large() {
        let mut config = valid_config();
        config.vhost_user.queue_size = 8192; // power of 2 but > 4096
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(
            &issues,
            "vhost_user.queue_size 8192 must be a power of 2 between 64 and 4096",
        );
    }

    #[test]
    fn test_num_queues_not_two() {
        let mut config = valid_config();
        config.vhost_user.num_queues = 4;
        let issues = unwrap_issues(validate(&config));
        assert_issue_contains(&issues, "vhost_user.num_queues must be 2 (got 4)");
    }

    #[test]
    fn test_collects_multiple_issues() {
        let mut config = valid_config();
        // Trigger 4 distinct issues at once
        config.network.subnet =
            Ipv4Network::new(ipv4(10, 0, 0, 0), 28).expect("net"); // #1
        config.vm.mtu = 100; // #4
        config.wireguard.listen_port = 0; // #13
        config.vhost_user.num_queues = 8; // #16

        let issues = unwrap_issues(validate(&config));
        assert!(
            issues.len() >= 4,
            "expected at least 4 issues, got {}: {:?}",
            issues.len(),
            issues
        );
        assert_issue_contains(&issues, "network.subnet must be /30");
        assert_issue_contains(&issues, "vm.mtu 100 out of range");
        assert_issue_contains(&issues, "wireguard.listen_port must not be 0");
        assert_issue_contains(&issues, "vhost_user.num_queues must be 2 (got 8)");
    }
}
