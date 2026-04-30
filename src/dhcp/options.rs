// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::Ipv4Addr;

use dhcproto::v4::{DhcpOption, DhcpOptions, MessageType};
use ipnet::Ipv4Net;

/// A classless static route entry per RFC 3442.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClasslessRoute {
    pub prefix: ip_network::Ipv4Network,
    pub next_hop: Ipv4Addr,
}

/// Builder for DHCP response options (ACK, OFFER, NAK).
pub struct DhcpOptionsBuilder {
    opts: DhcpOptions,
}

impl DhcpOptionsBuilder {
    /// Create a new builder, setting option 53 (message type).
    pub fn new(msg_type: MessageType) -> Self {
        let mut opts = DhcpOptions::default();
        opts.insert(DhcpOption::MessageType(msg_type));
        Self { opts }
    }

    /// Set option 54 — server identifier.
    pub fn with_server_id(mut self, addr: Ipv4Addr) -> Self {
        self.opts.insert(DhcpOption::ServerIdentifier(addr));
        self
    }

    /// Set option 51 — IP address lease time (seconds).
    pub fn with_lease_time(mut self, secs: u32) -> Self {
        self.opts.insert(DhcpOption::AddressLeaseTime(secs));
        self
    }

    /// Set option 58 — renewal (T1) time (seconds).
    pub fn with_renewal(mut self, secs: u32) -> Self {
        self.opts.insert(DhcpOption::Renewal(secs));
        self
    }

    /// Set option 59 — rebinding (T2) time (seconds).
    pub fn with_rebinding(mut self, secs: u32) -> Self {
        self.opts.insert(DhcpOption::Rebinding(secs));
        self
    }

    /// Set option 1 — subnet mask.
    pub fn with_subnet_mask(mut self, mask: Ipv4Addr) -> Self {
        self.opts.insert(DhcpOption::SubnetMask(mask));
        self
    }

    /// Set option 3 — router (default gateway).
    pub fn with_router(mut self, gateway: Ipv4Addr) -> Self {
        self.opts.insert(DhcpOption::Router(vec![gateway]));
        self
    }

    /// Set option 6 — domain name servers.
    pub fn with_dns(mut self, servers: &[Ipv4Addr]) -> Self {
        self.opts
            .insert(DhcpOption::DomainNameServer(servers.to_vec()));
        self
    }

    /// Set option 26 — interface MTU.
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.opts.insert(DhcpOption::InterfaceMtu(mtu));
        self
    }

    /// Set option 28 — broadcast address.
    pub fn with_broadcast(mut self, addr: Ipv4Addr) -> Self {
        self.opts.insert(DhcpOption::BroadcastAddr(addr));
        self
    }

    /// Set option 121 — classless static routes (RFC 3442).
    pub fn with_classless_routes(mut self, routes: &[ClasslessRoute]) -> Self {
        let encoded: Vec<(Ipv4Net, Ipv4Addr)> = routes
            .iter()
            .map(|r| {
                let prefix_len = r.prefix.netmask();
                let net_addr = r.prefix.network_address();
                // SAFETY: ip_network::Ipv4Network::netmask() returns 0..=32; Ipv4Net::new only
                // fails if prefix_len > 32, which cannot happen here.
                let ipnet = Ipv4Net::new(net_addr, prefix_len)
                    .expect("ip_network prefix_len is always valid");
                (ipnet, r.next_hop)
            })
            .collect();
        self.opts.insert(DhcpOption::ClasslessStaticRoute(encoded));
        self
    }

    /// Set option 56 — message (NAK reason text).
    pub fn with_message(mut self, msg: &str) -> Self {
        self.opts.insert(DhcpOption::Message(msg.to_owned()));
        self
    }

    /// Consume the builder and return the completed [`DhcpOptions`].
    pub fn build(self) -> DhcpOptions {
        self.opts
    }
}

/// Build a DHCPACK response for a DHCPINFORM request.
///
/// Per RFC 2131 §4.3.5, options 51, 54, 58, 59 MUST NOT be included.
pub fn build_inform_response(
    subnet_mask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns: &[Ipv4Addr],
    mtu: u16,
) -> DhcpOptions {
    let gw_u32 = u32::from(gateway);
    let mask_u32 = u32::from(subnet_mask);
    let broadcast = Ipv4Addr::from((gw_u32 & mask_u32) | !mask_u32);

    DhcpOptionsBuilder::new(MessageType::Ack)
        .with_subnet_mask(subnet_mask)
        .with_router(gateway)
        .with_dns(dns)
        .with_mtu(mtu)
        .with_broadcast(broadcast)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::{DhcpOption, MessageType, OptionCode};

    #[test]
    fn test_ack_has_lease_options() {
        let opts = DhcpOptionsBuilder::new(MessageType::Ack)
            .with_lease_time(3600)
            .with_server_id("192.168.1.1".parse().unwrap())
            .with_renewal(1800)
            .with_rebinding(3150)
            .build();

        assert!(opts.get(OptionCode::AddressLeaseTime).is_some());
        assert!(opts.get(OptionCode::ServerIdentifier).is_some());
        assert!(opts.get(OptionCode::Renewal).is_some());
        assert!(opts.get(OptionCode::Rebinding).is_some());
    }

    #[test]
    fn test_inform_excludes_lease_options() {
        let dns: Vec<Ipv4Addr> = vec!["8.8.8.8".parse().unwrap()];
        let opts = build_inform_response(
            "255.255.255.0".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            &dns,
            1500,
        );

        assert!(opts.get(OptionCode::AddressLeaseTime).is_none());
        assert!(opts.get(OptionCode::ServerIdentifier).is_none());
        assert!(opts.get(OptionCode::Renewal).is_none());
        assert!(opts.get(OptionCode::Rebinding).is_none());
    }

    #[test]
    fn test_classless_routes_24() {
        let route = ClasslessRoute {
            prefix: "192.168.1.0/24".parse().unwrap(),
            next_hop: "10.0.0.1".parse().unwrap(),
        };
        let opts = DhcpOptionsBuilder::new(MessageType::Offer)
            .with_classless_routes(&[route])
            .build();

        let opt = opts.get(OptionCode::ClasslessStaticRoute).unwrap();
        if let DhcpOption::ClasslessStaticRoute(routes) = opt {
            assert_eq!(routes.len(), 1);
            let (net, hop) = &routes[0];
            assert_eq!(net.prefix_len(), 24);
            assert_eq!(net.network(), "192.168.1.0".parse::<Ipv4Addr>().unwrap());
            assert_eq!(*hop, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        } else {
            panic!("expected ClasslessStaticRoute option");
        }
    }

    #[test]
    fn test_classless_routes_default() {
        let route = ClasslessRoute {
            prefix: "0.0.0.0/0".parse().unwrap(),
            next_hop: "10.0.0.1".parse().unwrap(),
        };
        let opts = DhcpOptionsBuilder::new(MessageType::Offer)
            .with_classless_routes(&[route])
            .build();

        let opt = opts.get(OptionCode::ClasslessStaticRoute).unwrap();
        if let DhcpOption::ClasslessStaticRoute(routes) = opt {
            assert_eq!(routes.len(), 1);
            let (net, hop) = &routes[0];
            assert_eq!(net.prefix_len(), 0);
            assert_eq!(*hop, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        } else {
            panic!("expected ClasslessStaticRoute option");
        }
    }

    #[test]
    fn test_nak_has_message() {
        let reason = "address not available";
        let opts = DhcpOptionsBuilder::new(MessageType::Nak)
            .with_message(reason)
            .build();

        let opt = opts.get(OptionCode::Message).unwrap();
        if let DhcpOption::Message(text) = opt {
            assert_eq!(text, reason);
        } else {
            panic!("expected Message option");
        }
    }

    #[test]
    fn test_builder_chaining() {
        let dns: Vec<Ipv4Addr> = vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
        let routes = vec![ClasslessRoute {
            prefix: "10.0.0.0/8".parse().unwrap(),
            next_hop: "10.0.0.1".parse().unwrap(),
        }];

        let opts = DhcpOptionsBuilder::new(MessageType::Offer)
            .with_server_id("192.168.1.1".parse().unwrap())
            .with_lease_time(86400)
            .with_renewal(43200)
            .with_rebinding(75600)
            .with_subnet_mask("255.255.255.0".parse().unwrap())
            .with_router("192.168.1.1".parse().unwrap())
            .with_dns(&dns)
            .with_mtu(1500)
            .with_broadcast("192.168.1.255".parse().unwrap())
            .with_classless_routes(&routes)
            .build();

        assert!(opts.get(OptionCode::MessageType).is_some());
        assert!(opts.get(OptionCode::ServerIdentifier).is_some());
        assert!(opts.get(OptionCode::AddressLeaseTime).is_some());
        assert!(opts.get(OptionCode::Renewal).is_some());
        assert!(opts.get(OptionCode::Rebinding).is_some());
        assert!(opts.get(OptionCode::SubnetMask).is_some());
        assert!(opts.get(OptionCode::Router).is_some());
        assert!(opts.get(OptionCode::DomainNameServer).is_some());
        assert!(opts.get(OptionCode::InterfaceMtu).is_some());
        assert!(opts.get(OptionCode::BroadcastAddr).is_some());
        assert!(opts.get(OptionCode::ClasslessStaticRoute).is_some());
    }
}
