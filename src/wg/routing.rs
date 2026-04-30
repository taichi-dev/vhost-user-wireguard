// SPDX-License-Identifier: MIT OR Apache-2.0

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::net::Ipv4Addr;

pub struct AllowedIpsRouter {
    table: IpNetworkTable<usize>,
}

impl AllowedIpsRouter {
    pub fn new() -> Self {
        Self {
            table: IpNetworkTable::new(),
        }
    }

    pub fn insert(&mut self, network: IpNetwork, peer_idx: usize) {
        self.table.insert(network, peer_idx);
    }

    pub fn lookup_v4(&self, ip: Ipv4Addr) -> Option<usize> {
        self.table
            .longest_match(std::net::IpAddr::V4(ip))
            .map(|(_, peer_idx)| *peer_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNetwork {
        s.parse().unwrap()
    }

    #[test]
    fn test_lookup_match() {
        let mut router = AllowedIpsRouter::new();
        router.insert(net("10.0.0.0/8"), 0);
        assert_eq!(router.lookup_v4("10.1.2.3".parse().unwrap()), Some(0));
    }

    #[test]
    fn test_lookup_no_match() {
        let router = AllowedIpsRouter::new();
        assert_eq!(router.lookup_v4("192.168.1.1".parse().unwrap()), None);
    }

    #[test]
    fn test_longest_prefix_wins() {
        let mut router = AllowedIpsRouter::new();
        router.insert(net("10.0.0.0/8"), 0);
        router.insert(net("10.0.0.0/24"), 1);
        assert_eq!(router.lookup_v4("10.0.0.5".parse().unwrap()), Some(1));
    }
}
