// SPDX-License-Identifier: MIT OR Apache-2.0

//! DHCPv4 server state machine (RFC 2131 compliant).

pub mod lease;
pub mod options;
pub mod persist;

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use dhcproto::v4::{
    Decodable, Decoder, DhcpOption, Encodable, Encoder, Flags, HType, Message, MessageType, Opcode,
    OptionCode,
};
use etherparse::{EtherType, Ethernet2Slice, IpNumber, Ipv4Slice, PacketBuilder, UdpSlice};

use crate::config::{Dhcp, Network, Vm};
use crate::dhcp::lease::{LeaseState, LeaseStore};
use crate::dhcp::options::{DhcpOptionsBuilder, build_inform_response};
use crate::dhcp::persist::{LeaseFile, LeaseSnapshot};
use crate::error::DhcpError;

const DEFAULT_LEASE_SECS: u32 = 3600;
const DEFAULT_RENEWAL_SECS: u32 = DEFAULT_LEASE_SECS / 2;
const DEFAULT_REBINDING_SECS: u32 = DEFAULT_LEASE_SECS * 7 / 8;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
const REPLY_TTL: u8 = 64;

/// DHCPv4 server. Handles DISCOVER, REQUEST, DECLINE, RELEASE, INFORM per RFC 2131.
pub struct DhcpServer {
    network: Network,
    dhcp_cfg: Dhcp,
    store: LeaseStore,
    persist: LeaseFile,
    last_checkpoint: Instant,
    gateway_mac: [u8; 6],
    vm: Vm,
}

impl DhcpServer {
    pub fn new(
        network: Network,
        dhcp_cfg: Dhcp,
        gateway_mac: [u8; 6],
        vm: Vm,
        persist_path: PathBuf,
    ) -> Result<Self, DhcpError> {
        let persist = LeaseFile::new(persist_path);
        let snap: LeaseSnapshot = persist.load()?;

        let reservations: Vec<([u8; 6], Ipv4Addr)> = dhcp_cfg
            .reservations
            .iter()
            .map(|r| (r.mac.bytes(), r.ip))
            .collect();

        let mut store = LeaseStore::new(reservations, dhcp_cfg.pool.start, dhcp_cfg.pool.end);

        let now = SystemTime::now();
        for lease in snap.leases {
            if let LeaseState::Bound { expires_at } = lease.state {
                let remaining = expires_at.duration_since(now).unwrap_or_default();
                let secs = u32::try_from(remaining.as_secs()).unwrap_or(u32::MAX);
                if secs > 0 {
                    let _ = store.bind(lease.mac, lease.ip, secs, now);
                }
            }
        }

        Ok(Self {
            network,
            dhcp_cfg,
            store,
            persist,
            last_checkpoint: Instant::now(),
            gateway_mac,
            vm,
        })
    }

    pub fn handle_packet(
        &mut self,
        eth_in: &[u8],
        now: SystemTime,
    ) -> Result<Option<Vec<u8>>, DhcpError> {
        self.store.gc(now);

        let eth = match Ethernet2Slice::from_slice_without_fcs(eth_in) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };
        if eth.ether_type() != EtherType::IPV4 {
            return Ok(None);
        }
        let ipv4 = match Ipv4Slice::from_slice(eth.payload_slice()) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        if ipv4.header().protocol() != IpNumber::UDP {
            return Ok(None);
        }
        let udp = match UdpSlice::from_slice(ipv4.payload().payload) {
            Ok(u) => u,
            Err(_) => return Ok(None),
        };
        if udp.destination_port() != DHCP_SERVER_PORT {
            return Ok(None);
        }

        let dhcp = Message::decode(&mut Decoder::new(udp.payload()))?;

        let chaddr = match chaddr_to_mac(dhcp.chaddr()) {
            Some(m) => m,
            None => return Ok(None),
        };
        if chaddr != self.vm.mac.bytes() {
            return Ok(None);
        }

        let msg_type = dhcp.opts().msg_type();
        let reply = match msg_type {
            Some(MessageType::Discover) => Some(self.handle_discover(&dhcp, chaddr, now)?),
            Some(MessageType::Request) => self.handle_request(&dhcp, chaddr, now)?,
            Some(MessageType::Decline) => {
                self.handle_decline(&dhcp, now);
                None
            }
            Some(MessageType::Release) => {
                self.handle_release(chaddr);
                None
            }
            Some(MessageType::Inform) => Some(self.handle_inform(&dhcp)?),
            _ => return Ok(None),
        };

        match reply {
            Some(reply_msg) => {
                let frame = self.encode_reply(&reply_msg, &dhcp, chaddr)?;
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    pub fn checkpoint(&mut self) -> Result<(), DhcpError> {
        let leases: Vec<crate::dhcp::lease::Lease> = self.store.iter_leases().cloned().collect();
        let snap = LeaseSnapshot { version: 1, leases };
        self.persist.save(&snap)?;
        self.last_checkpoint = Instant::now();
        Ok(())
    }

    fn handle_discover(
        &mut self,
        request: &Message,
        chaddr: [u8; 6],
        now: SystemTime,
    ) -> Result<Message, DhcpError> {
        let yiaddr = self.store.allocate(chaddr, now)?;
        let opts = self.build_lease_options(MessageType::Offer);
        Ok(build_dhcp_reply(request, yiaddr, opts))
    }

    fn handle_request(
        &mut self,
        request: &Message,
        chaddr: [u8; 6],
        now: SystemTime,
    ) -> Result<Option<Message>, DhcpError> {
        let server_id_set = request.opts().get(OptionCode::ServerIdentifier).is_some();
        let requested_ip = match request.opts().get(OptionCode::RequestedIpAddress) {
            Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
            _ => None,
        };
        let ciaddr = request.ciaddr();

        // SELECTING: server-id present, requested-ip present, ciaddr=0 (RFC 2131 §4.3.2).
        if server_id_set {
            let yiaddr = match requested_ip {
                Some(ip) => ip,
                None => return Ok(None),
            };
            self.store.bind(chaddr, yiaddr, DEFAULT_LEASE_SECS, now)?;
            let opts = self.build_lease_options(MessageType::Ack);
            return Ok(Some(build_dhcp_reply(request, yiaddr, opts)));
        }

        // INIT-REBOOT: no server-id, requested-ip present, ciaddr=0 (RFC 2131 §4.3.2).
        if let Some(yiaddr) = requested_ip {
            let matches_lease = match self.store.lookup_by_mac(chaddr) {
                Some(lease) => lease.ip == yiaddr && !matches!(lease.state, LeaseState::Released),
                None => false,
            };
            if matches_lease {
                self.store.bind(chaddr, yiaddr, DEFAULT_LEASE_SECS, now)?;
                let opts = self.build_lease_options(MessageType::Ack);
                return Ok(Some(build_dhcp_reply(request, yiaddr, opts)));
            } else {
                let opts = DhcpOptionsBuilder::new(MessageType::Nak)
                    .with_server_id(self.network.gateway)
                    .with_message("requested IP does not match a known lease")
                    .build();
                return Ok(Some(build_nak_reply(request, opts)));
            }
        }

        // RENEWING/REBINDING: no server-id, no requested-ip, ciaddr set (RFC 2131 §4.3.2).
        if ciaddr != Ipv4Addr::UNSPECIFIED {
            self.store.bind(chaddr, ciaddr, DEFAULT_LEASE_SECS, now)?;
            let opts = self.build_lease_options(MessageType::Ack);
            return Ok(Some(build_dhcp_reply(request, ciaddr, opts)));
        }

        Ok(None)
    }

    fn handle_decline(&mut self, request: &Message, now: SystemTime) {
        let declined_ip = match request.opts().get(OptionCode::RequestedIpAddress) {
            Some(DhcpOption::RequestedIpAddress(ip)) => *ip,
            _ => return,
        };
        let probation_until =
            now + std::time::Duration::from_secs(self.dhcp_cfg.decline_probation_secs);
        self.store.decline(declined_ip, probation_until);
    }

    fn handle_release(&mut self, chaddr: [u8; 6]) {
        self.store.release(chaddr);
    }

    fn handle_inform(&self, request: &Message) -> Result<Message, DhcpError> {
        let prefix_len = self.network.subnet.netmask();
        let subnet_mask = prefix_to_mask(prefix_len);
        let opts = build_inform_response(
            subnet_mask,
            self.network.gateway,
            &self.network.dns,
            self.vm.mtu,
        );

        let mut reply = Message::default();
        reply.set_opcode(Opcode::BootReply);
        reply.set_htype(request.htype());
        reply.set_xid(request.xid());
        reply.set_secs(0);
        reply.set_flags(request.flags());
        reply.set_ciaddr(request.ciaddr());
        reply.set_yiaddr(Ipv4Addr::UNSPECIFIED);
        reply.set_siaddr(Ipv4Addr::UNSPECIFIED);
        reply.set_giaddr(request.giaddr());
        reply.set_chaddr(request.chaddr());
        reply.set_opts(opts);
        Ok(reply)
    }

    fn build_lease_options(&self, msg_type: MessageType) -> dhcproto::v4::DhcpOptions {
        let prefix_len = self.network.subnet.netmask();
        let subnet_mask = prefix_to_mask(prefix_len);
        let broadcast = self.network.subnet.broadcast_address();

        DhcpOptionsBuilder::new(msg_type)
            .with_server_id(self.network.gateway)
            .with_lease_time(DEFAULT_LEASE_SECS)
            .with_renewal(DEFAULT_RENEWAL_SECS)
            .with_rebinding(DEFAULT_REBINDING_SECS)
            .with_subnet_mask(subnet_mask)
            .with_router(self.network.gateway)
            .with_dns(&self.network.dns)
            .with_mtu(self.vm.mtu)
            .with_broadcast(broadcast)
            .build()
    }

    fn encode_reply(
        &self,
        reply: &Message,
        request: &Message,
        chaddr: [u8; 6],
    ) -> Result<Vec<u8>, DhcpError> {
        let msg_type = reply.opts().msg_type();
        let (dst_ip, dst_mac) = self.determine_reply_dst(reply, request, chaddr, msg_type);

        let mut dhcp_buf = Vec::new();
        {
            let mut encoder = Encoder::new(&mut dhcp_buf);
            reply.encode(&mut encoder)?;
        }

        let builder = PacketBuilder::ethernet2(self.gateway_mac, dst_mac)
            .ipv4(self.network.gateway.octets(), dst_ip.octets(), REPLY_TTL)
            .udp(DHCP_SERVER_PORT, DHCP_CLIENT_PORT);
        let mut frame = Vec::with_capacity(builder.size(dhcp_buf.len()));
        builder
            .write_to_vec(&mut frame, &dhcp_buf)
            .map_err(|e| DhcpError::FrameBuild(e.to_string()))?;
        Ok(frame)
    }

    fn determine_reply_dst(
        &self,
        reply: &Message,
        request: &Message,
        chaddr: [u8; 6],
        msg_type: Option<MessageType>,
    ) -> (Ipv4Addr, [u8; 6]) {
        // NAK is always broadcast per RFC 2131 §4.3.2.
        if matches!(msg_type, Some(MessageType::Nak)) {
            return (Ipv4Addr::BROADCAST, BROADCAST_MAC);
        }

        // RENEWING (unicast) vs REBINDING (broadcast) distinguished by broadcast flag (RFC 2131 §4.3.6).
        if request.ciaddr() != Ipv4Addr::UNSPECIFIED
            && !matches!(msg_type, Some(MessageType::Offer))
        {
            if request.flags().broadcast() {
                return (Ipv4Addr::BROADCAST, BROADCAST_MAC);
            }
            return (request.ciaddr(), chaddr);
        }

        if matches!(msg_type, Some(MessageType::Ack))
            && reply.yiaddr() == Ipv4Addr::UNSPECIFIED
            && request.ciaddr() != Ipv4Addr::UNSPECIFIED
        {
            return (request.ciaddr(), chaddr);
        }

        if request.flags().broadcast() {
            return (Ipv4Addr::BROADCAST, BROADCAST_MAC);
        }

        (reply.yiaddr(), chaddr)
    }
}

fn chaddr_to_mac(chaddr: &[u8]) -> Option<[u8; 6]> {
    if chaddr.len() < 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&chaddr[..6]);
    Some(mac)
}

fn prefix_to_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    if prefix_len >= 32 {
        return Ipv4Addr::new(255, 255, 255, 255);
    }
    Ipv4Addr::from(!((1u32 << (32 - prefix_len)) - 1))
}

fn build_dhcp_reply(
    request: &Message,
    yiaddr: Ipv4Addr,
    opts: dhcproto::v4::DhcpOptions,
) -> Message {
    let mut reply = Message::default();
    reply.set_opcode(Opcode::BootReply);
    reply.set_htype(HType::Eth);
    reply.set_xid(request.xid());
    reply.set_secs(0);
    reply.set_flags(request.flags());
    reply.set_ciaddr(Ipv4Addr::UNSPECIFIED);
    reply.set_yiaddr(yiaddr);
    reply.set_siaddr(Ipv4Addr::UNSPECIFIED);
    reply.set_giaddr(request.giaddr());
    reply.set_chaddr(request.chaddr());
    reply.set_opts(opts);
    reply
}

fn build_nak_reply(request: &Message, opts: dhcproto::v4::DhcpOptions) -> Message {
    let mut reply = Message::default();
    reply.set_opcode(Opcode::BootReply);
    reply.set_htype(HType::Eth);
    reply.set_xid(request.xid());
    reply.set_secs(0);
    reply.set_flags(Flags::default().set_broadcast());
    reply.set_ciaddr(Ipv4Addr::UNSPECIFIED);
    reply.set_yiaddr(Ipv4Addr::UNSPECIFIED);
    reply.set_siaddr(Ipv4Addr::UNSPECIFIED);
    reply.set_giaddr(request.giaddr());
    reply.set_chaddr(request.chaddr());
    reply.set_opts(opts);
    reply
}

impl LeaseStore {
    pub fn iter_leases(&self) -> impl Iterator<Item = &crate::dhcp::lease::Lease> {
        self.leases_for_snapshot()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use dhcproto::v4::{DhcpOptions, Flags as DhcpFlags};
    use ip_network::Ipv4Network;
    use mac_address::MacAddress;
    use tempfile::TempDir;

    use super::*;
    use crate::config::{DhcpPool, DhcpReservation};

    const VM_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

    fn make_server(persist_dir: &TempDir) -> DhcpServer {
        let network = Network {
            subnet: Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap(),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            dns: vec![Ipv4Addr::new(10, 0, 0, 1)],
        };
        let dhcp_cfg = Dhcp {
            pool: DhcpPool {
                start: Ipv4Addr::new(10, 0, 0, 100),
                end: Ipv4Addr::new(10, 0, 0, 105),
            },
            decline_probation_secs: 600,
            checkpoint_secs: 60,
            reservations: vec![],
        };
        let vm = Vm {
            mtu: 1500,
            mac: MacAddress::from(VM_MAC),
            ip: Ipv4Addr::new(10, 0, 0, 100),
        };
        let path = persist_dir.path().join("leases.json");
        DhcpServer::new(network, dhcp_cfg, GW_MAC, vm, path).expect("server new")
    }

    fn make_server_with_reservation(persist_dir: &TempDir, reserved_ip: Ipv4Addr) -> DhcpServer {
        let network = Network {
            subnet: Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap(),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            dns: vec![Ipv4Addr::new(10, 0, 0, 1)],
        };
        let dhcp_cfg = Dhcp {
            pool: DhcpPool {
                start: Ipv4Addr::new(10, 0, 0, 100),
                end: Ipv4Addr::new(10, 0, 0, 105),
            },
            decline_probation_secs: 600,
            checkpoint_secs: 60,
            reservations: vec![DhcpReservation {
                mac: MacAddress::from(VM_MAC),
                ip: reserved_ip,
                hostname: None,
            }],
        };
        let vm = Vm {
            mtu: 1500,
            mac: MacAddress::from(VM_MAC),
            ip: reserved_ip,
        };
        let path = persist_dir.path().join("leases.json");
        DhcpServer::new(network, dhcp_cfg, GW_MAC, vm, path).expect("server new")
    }

    fn build_request_frame(
        chaddr: [u8; 6],
        msg_type: MessageType,
        extra_opts: Vec<DhcpOption>,
        ciaddr: Ipv4Addr,
        broadcast_flag: bool,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let mut opts = DhcpOptions::default();
        opts.insert(DhcpOption::MessageType(msg_type));
        for o in extra_opts {
            opts.insert(o);
        }

        let mut dhcp = Message::default();
        dhcp.set_opcode(Opcode::BootRequest);
        dhcp.set_htype(HType::Eth);
        dhcp.set_chaddr(&chaddr);
        dhcp.set_ciaddr(ciaddr);
        if broadcast_flag {
            dhcp.set_flags(DhcpFlags::default().set_broadcast());
        }
        dhcp.set_opts(opts);

        let mut dhcp_buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut dhcp_buf);
            dhcp.encode(&mut enc).unwrap();
        }

        let dst_mac = if broadcast_flag || dst_ip == Ipv4Addr::BROADCAST {
            BROADCAST_MAC
        } else {
            GW_MAC
        };

        let builder = PacketBuilder::ethernet2(chaddr, dst_mac)
            .ipv4(src_ip.octets(), dst_ip.octets(), 64)
            .udp(DHCP_CLIENT_PORT, DHCP_SERVER_PORT);
        let mut frame = Vec::with_capacity(builder.size(dhcp_buf.len()));
        builder.write(&mut frame, &dhcp_buf).unwrap();
        frame
    }

    fn parse_reply(frame: &[u8]) -> (Message, Ipv4Addr, [u8; 6]) {
        let eth = Ethernet2Slice::from_slice_without_fcs(frame).expect("eth");
        assert_eq!(eth.ether_type(), EtherType::IPV4);
        let ipv4 = Ipv4Slice::from_slice(eth.payload_slice()).expect("ipv4");
        let udp = UdpSlice::from_slice(ipv4.payload().payload).expect("udp");
        assert_eq!(udp.destination_port(), DHCP_CLIENT_PORT);
        assert_eq!(udp.source_port(), DHCP_SERVER_PORT);
        let dhcp = Message::decode(&mut Decoder::new(udp.payload())).expect("dhcp decode");
        (dhcp, ipv4.header().destination_addr(), eth.destination())
    }

    #[test]
    fn test_discover_returns_offer() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let frame = build_request_frame(
            VM_MAC,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let reply_bytes = server
            .handle_packet(&frame, now)
            .expect("handle ok")
            .expect("reply produced");
        let (reply, _dst_ip, _dst_mac) = parse_reply(&reply_bytes);

        assert_eq!(reply.opcode(), Opcode::BootReply);
        assert_eq!(reply.opts().msg_type(), Some(MessageType::Offer));
        assert!(reply.opts().get(OptionCode::ServerIdentifier).is_some());
        assert!(reply.opts().get(OptionCode::AddressLeaseTime).is_some());
        assert!(reply.opts().get(OptionCode::Renewal).is_some());
        assert!(reply.opts().get(OptionCode::Rebinding).is_some());
        assert!(reply.opts().get(OptionCode::SubnetMask).is_some());
        assert!(reply.opts().get(OptionCode::Router).is_some());
        assert_ne!(reply.yiaddr(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_selecting_request_returns_ack() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let discover = build_request_frame(
            VM_MAC,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let offer = server
            .handle_packet(&discover, now)
            .unwrap()
            .expect("offer");
        let (offer_msg, _, _) = parse_reply(&offer);
        let yiaddr = offer_msg.yiaddr();

        let req = build_request_frame(
            VM_MAC,
            MessageType::Request,
            vec![
                DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 1)),
                DhcpOption::RequestedIpAddress(yiaddr),
            ],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let ack_bytes = server.handle_packet(&req, now).unwrap().expect("ack");
        let (ack, _, _) = parse_reply(&ack_bytes);
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), yiaddr);
    }

    #[test]
    fn test_init_reboot_match_returns_ack() {
        let dir = TempDir::new().unwrap();
        let reserved = Ipv4Addr::new(10, 0, 0, 50);
        let mut server = make_server_with_reservation(&dir, reserved);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let _ = server
            .handle_packet(
                &build_request_frame(
                    VM_MAC,
                    MessageType::Discover,
                    vec![],
                    Ipv4Addr::UNSPECIFIED,
                    true,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                ),
                now,
            )
            .unwrap();

        let req = build_request_frame(
            VM_MAC,
            MessageType::Request,
            vec![DhcpOption::RequestedIpAddress(reserved)],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let ack_bytes = server.handle_packet(&req, now).unwrap().expect("ack");
        let (ack, _, _) = parse_reply(&ack_bytes);
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), reserved);
    }

    #[test]
    fn test_init_reboot_mismatch_returns_nak() {
        let dir = TempDir::new().unwrap();
        let reserved = Ipv4Addr::new(10, 0, 0, 50);
        let mut server = make_server_with_reservation(&dir, reserved);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let req = build_request_frame(
            VM_MAC,
            MessageType::Request,
            vec![DhcpOption::RequestedIpAddress(Ipv4Addr::new(
                192, 168, 99, 1,
            ))],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let nak_bytes = server.handle_packet(&req, now).unwrap().expect("nak");
        let (nak, dst_ip, dst_mac) = parse_reply(&nak_bytes);
        assert_eq!(nak.opts().msg_type(), Some(MessageType::Nak));
        assert_eq!(dst_ip, Ipv4Addr::BROADCAST);
        assert_eq!(dst_mac, BROADCAST_MAC);
        assert_eq!(nak.yiaddr(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_renewing_returns_unicast_ack() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let discover = build_request_frame(
            VM_MAC,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let offer = server.handle_packet(&discover, now).unwrap().unwrap();
        let (offer_msg, _, _) = parse_reply(&offer);
        let leased = offer_msg.yiaddr();

        let _ = server
            .handle_packet(
                &build_request_frame(
                    VM_MAC,
                    MessageType::Request,
                    vec![
                        DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 1)),
                        DhcpOption::RequestedIpAddress(leased),
                    ],
                    Ipv4Addr::UNSPECIFIED,
                    true,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                ),
                now,
            )
            .unwrap();

        let renew = build_request_frame(
            VM_MAC,
            MessageType::Request,
            vec![],
            leased,
            false,
            leased,
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let ack_bytes = server.handle_packet(&renew, now).unwrap().expect("ack");
        let (ack, dst_ip, dst_mac) = parse_reply(&ack_bytes);
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), leased);
        assert_eq!(dst_ip, leased, "RENEWING ACK should be unicast to client");
        assert_eq!(dst_mac, VM_MAC);
    }

    #[test]
    fn test_rebinding_returns_broadcast_ack() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let discover = build_request_frame(
            VM_MAC,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let offer = server.handle_packet(&discover, now).unwrap().unwrap();
        let (offer_msg, _, _) = parse_reply(&offer);
        let leased = offer_msg.yiaddr();

        let _ = server
            .handle_packet(
                &build_request_frame(
                    VM_MAC,
                    MessageType::Request,
                    vec![
                        DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 1)),
                        DhcpOption::RequestedIpAddress(leased),
                    ],
                    Ipv4Addr::UNSPECIFIED,
                    true,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                ),
                now,
            )
            .unwrap();

        let rebind = build_request_frame(
            VM_MAC,
            MessageType::Request,
            vec![],
            leased,
            true,
            leased,
            Ipv4Addr::BROADCAST,
        );
        let ack_bytes = server.handle_packet(&rebind, now).unwrap().expect("ack");
        let (ack, dst_ip, dst_mac) = parse_reply(&ack_bytes);
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), leased);
        assert_eq!(dst_ip, Ipv4Addr::BROADCAST);
        assert_eq!(dst_mac, BROADCAST_MAC);
    }

    #[test]
    fn test_decline_creates_probation() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let discover = build_request_frame(
            VM_MAC,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let offer = server.handle_packet(&discover, now).unwrap().unwrap();
        let (offer_msg, _, _) = parse_reply(&offer);
        let leased = offer_msg.yiaddr();

        let decline = build_request_frame(
            VM_MAC,
            MessageType::Decline,
            vec![DhcpOption::RequestedIpAddress(leased)],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let reply = server.handle_packet(&decline, now).unwrap();
        assert!(reply.is_none(), "DECLINE must not produce a reply");

        let next_ip = server.store.allocate([0xaa; 6], now).expect("alloc fresh");
        assert_ne!(next_ip, leased, "probation IP should not be reallocated");
    }

    #[test]
    fn test_release_frees_lease() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let discover = build_request_frame(
            VM_MAC,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let offer = server.handle_packet(&discover, now).unwrap().unwrap();
        let (offer_msg, _, _) = parse_reply(&offer);
        let leased = offer_msg.yiaddr();
        let _ = server
            .handle_packet(
                &build_request_frame(
                    VM_MAC,
                    MessageType::Request,
                    vec![
                        DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 1)),
                        DhcpOption::RequestedIpAddress(leased),
                    ],
                    Ipv4Addr::UNSPECIFIED,
                    true,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                ),
                now,
            )
            .unwrap();

        let release = build_request_frame(
            VM_MAC,
            MessageType::Release,
            vec![],
            leased,
            false,
            leased,
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let reply = server.handle_packet(&release, now).unwrap();
        assert!(reply.is_none(), "RELEASE must not produce a reply");
        let lease = server.store.lookup_by_mac(VM_MAC).expect("lease exists");
        assert!(matches!(lease.state, LeaseState::Released));
    }

    #[test]
    fn test_inform_excludes_lease_options() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let inform = build_request_frame(
            VM_MAC,
            MessageType::Inform,
            vec![],
            Ipv4Addr::new(10, 0, 0, 200),
            false,
            Ipv4Addr::new(10, 0, 0, 200),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let ack_bytes = server.handle_packet(&inform, now).unwrap().expect("ack");
        let (ack, _, _) = parse_reply(&ack_bytes);

        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert!(
            ack.opts().get(OptionCode::AddressLeaseTime).is_none(),
            "INFORM ACK must not include option 51"
        );
        assert!(
            ack.opts().get(OptionCode::ServerIdentifier).is_none(),
            "INFORM ACK must not include option 54"
        );
        assert!(
            ack.opts().get(OptionCode::Renewal).is_none(),
            "INFORM ACK must not include option 58"
        );
        assert!(
            ack.opts().get(OptionCode::Rebinding).is_none(),
            "INFORM ACK must not include option 59"
        );
        assert_eq!(
            ack.yiaddr(),
            Ipv4Addr::UNSPECIFIED,
            "INFORM ACK yiaddr must be 0"
        );
    }

    #[test]
    fn test_chaddr_mismatch_drops() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let wrong_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let frame = build_request_frame(
            wrong_mac,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let reply = server.handle_packet(&frame, now).unwrap();
        assert!(reply.is_none(), "wrong chaddr must be silently dropped");
    }

    #[test]
    fn test_unknown_message_type_drops() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let frame = build_request_frame(
            VM_MAC,
            MessageType::Offer,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let reply = server.handle_packet(&frame, now).unwrap();
        assert!(reply.is_none(), "unexpected message type must be dropped");
    }

    #[test]
    fn test_full_dora() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let discover = build_request_frame(
            VM_MAC,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let offer_bytes = server.handle_packet(&discover, now).unwrap().unwrap();
        let (offer, _, _) = parse_reply(&offer_bytes);
        assert_eq!(offer.opts().msg_type(), Some(MessageType::Offer));
        let yiaddr = offer.yiaddr();

        let req = build_request_frame(
            VM_MAC,
            MessageType::Request,
            vec![
                DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 1)),
                DhcpOption::RequestedIpAddress(yiaddr),
            ],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let ack_bytes = server.handle_packet(&req, now).unwrap().unwrap();
        let (ack, _, _) = parse_reply(&ack_bytes);
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), yiaddr);

        let lease = server.store.lookup_by_mac(VM_MAC).expect("bound lease");
        assert!(matches!(lease.state, LeaseState::Bound { .. }));
    }

    #[test]
    fn test_checkpoint_persists_leases() {
        let dir = TempDir::new().unwrap();
        let mut server = make_server(&dir);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let discover = build_request_frame(
            VM_MAC,
            MessageType::Discover,
            vec![],
            Ipv4Addr::UNSPECIFIED,
            true,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let offer = server.handle_packet(&discover, now).unwrap().unwrap();
        let (offer_msg, _, _) = parse_reply(&offer);
        let yiaddr = offer_msg.yiaddr();
        let _ = server
            .handle_packet(
                &build_request_frame(
                    VM_MAC,
                    MessageType::Request,
                    vec![
                        DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 1)),
                        DhcpOption::RequestedIpAddress(yiaddr),
                    ],
                    Ipv4Addr::UNSPECIFIED,
                    true,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                ),
                now,
            )
            .unwrap();

        server.checkpoint().expect("checkpoint ok");
        let path = dir.path().join("leases.json");
        assert!(path.exists(), "lease file should exist after checkpoint");
    }
}
