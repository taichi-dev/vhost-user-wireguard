// SPDX-License-Identifier: MIT OR Apache-2.0

//! DHCP lease lifecycle management.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use crate::error::DhcpError;

/// State of a DHCP lease.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum LeaseState {
    Offered {
        #[serde(with = "serde_system_time")]
        expires_at: SystemTime,
    },
    Bound {
        #[serde(with = "serde_system_time")]
        expires_at: SystemTime,
    },
    Released,
    Probation {
        #[serde(with = "serde_system_time")]
        until: SystemTime,
    },
}

/// A single DHCP lease record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Lease {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub state: LeaseState,
    pub hostname: Option<String>,
}

mod serde_system_time {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

/// Manages DHCP lease allocation, binding, release, decline, and garbage collection.
pub struct LeaseStore {
    reservations: Vec<([u8; 6], Ipv4Addr)>,
    pool: Vec<Ipv4Addr>,
    leases: HashMap<[u8; 6], Lease>,
    probation: HashMap<Ipv4Addr, SystemTime>,
}

impl LeaseStore {
    /// Create a new LeaseStore with static reservations and a dynamic pool.
    pub fn new(
        reservations: Vec<([u8; 6], Ipv4Addr)>,
        pool_start: Ipv4Addr,
        pool_end: Ipv4Addr,
    ) -> Self {
        let start = u32::from(pool_start);
        let end = u32::from(pool_end);
        let pool = (start..=end).map(Ipv4Addr::from).collect();
        Self {
            reservations,
            pool,
            leases: HashMap::new(),
            probation: HashMap::new(),
        }
    }

    /// Allocate an IP for the given MAC. Returns the IP or PoolExhausted.
    pub fn allocate(&mut self, mac: [u8; 6], now: SystemTime) -> Result<Ipv4Addr, DhcpError> {
        if let Some(&(_, ip)) = self.reservations.iter().find(|(m, _)| *m == mac) {
            let expires_at = now + Duration::from_secs(30);
            self.leases.insert(
                mac,
                Lease {
                    mac,
                    ip,
                    state: LeaseState::Offered { expires_at },
                    hostname: None,
                },
            );
            return Ok(ip);
        }

        let ip = self
            .pool
            .iter()
            .copied()
            .find(|&candidate| {
                if self.probation.contains_key(&candidate) {
                    return false;
                }
                for (m, lease) in &self.leases {
                    if *m == mac {
                        continue;
                    }
                    if lease.ip == candidate {
                        match &lease.state {
                            LeaseState::Offered { .. } | LeaseState::Bound { .. } => {
                                return false;
                            }
                            _ => {}
                        }
                    }
                }
                true
            })
            .ok_or(DhcpError::PoolExhausted)?;

        let expires_at = now + Duration::from_secs(30);
        self.leases.insert(
            mac,
            Lease {
                mac,
                ip,
                state: LeaseState::Offered { expires_at },
                hostname: None,
            },
        );
        Ok(ip)
    }

    /// Transition an Offered lease to Bound, or create a Bound lease directly.
    pub fn bind(
        &mut self,
        mac: [u8; 6],
        ip: Ipv4Addr,
        lease_secs: u32,
        now: SystemTime,
    ) -> Result<(), DhcpError> {
        let expires_at = now + Duration::from_secs(u64::from(lease_secs));
        let lease = self.leases.entry(mac).or_insert(Lease {
            mac,
            ip,
            state: LeaseState::Bound { expires_at },
            hostname: None,
        });
        lease.ip = ip;
        lease.state = LeaseState::Bound { expires_at };
        Ok(())
    }

    /// Mark a lease as Released.
    pub fn release(&mut self, mac: [u8; 6]) {
        if let Some(lease) = self.leases.get_mut(&mac) {
            lease.state = LeaseState::Released;
        }
    }

    /// Put an IP into probation and remove any lease for it.
    pub fn decline(&mut self, ip: Ipv4Addr, probation_until: SystemTime) {
        self.probation.insert(ip, probation_until);
        self.leases.retain(|_, lease| lease.ip != ip);
    }

    /// Look up a lease by MAC address.
    pub fn lookup_by_mac(&self, mac: [u8; 6]) -> Option<&Lease> {
        self.leases.get(&mac)
    }

    /// Look up a lease by IP address.
    pub fn lookup_by_ip(&self, ip: Ipv4Addr) -> Option<&Lease> {
        self.leases.values().find(|lease| lease.ip == ip)
    }

    /// Garbage collect expired Offered leases and expired probation entries.
    pub fn gc(&mut self, now: SystemTime) {
        self.leases.retain(|_, lease| {
            if let LeaseState::Offered { expires_at } = &lease.state {
                *expires_at > now
            } else {
                true
            }
        });
        self.probation.retain(|_, until| *until > now);
    }

    pub(crate) fn leases_for_snapshot(&self) -> impl Iterator<Item = &Lease> {
        self.leases.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn mac(b: u8) -> [u8; 6] {
        [b, 0, 0, 0, 0, 0]
    }

    fn store_123() -> LeaseStore {
        LeaseStore::new(
            vec![],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 3),
        )
    }

    #[test]
    fn test_allocate_from_pool() {
        let mut store = store_123();
        let now = SystemTime::now();
        let ip = store.allocate(mac(1), now).expect("should allocate");
        let start = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let end = u32::from(Ipv4Addr::new(10, 0, 0, 3));
        let ip_u32 = u32::from(ip);
        assert!(ip_u32 >= start && ip_u32 <= end, "IP {ip} not in pool range");
    }

    #[test]
    fn test_allocate_reservation_first() {
        let reserved_ip = Ipv4Addr::new(10, 0, 0, 99);
        let m = mac(2);
        let mut store = LeaseStore::new(
            vec![(m, reserved_ip)],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 3),
        );
        let now = SystemTime::now();
        let ip = store.allocate(m, now).expect("should allocate reservation");
        assert_eq!(ip, reserved_ip, "should get reserved IP, not pool IP");
    }

    #[test]
    fn test_bind_transitions_state() {
        let mut store = store_123();
        let now = SystemTime::now();
        let m = mac(3);
        let ip = store.allocate(m, now).expect("allocate");
        store.bind(m, ip, 3600, now).expect("bind");
        let lease = store.lookup_by_mac(m).expect("lease exists");
        assert!(
            matches!(lease.state, LeaseState::Bound { .. }),
            "state should be Bound"
        );
    }

    #[test]
    fn test_release() {
        let mut store = store_123();
        let now = SystemTime::now();
        let m = mac(4);
        let ip = store.allocate(m, now).expect("allocate");
        store.bind(m, ip, 3600, now).expect("bind");
        store.release(m);
        let lease = store.lookup_by_mac(m).expect("lease exists after release");
        assert!(
            matches!(lease.state, LeaseState::Released),
            "state should be Released"
        );
    }

    #[test]
    fn test_decline_probation() {
        let mut store = store_123();
        let now = SystemTime::now();
        let m = mac(5);
        let ip = store.allocate(m, now).expect("first allocate");
        let probation_until = now + Duration::from_secs(9999);
        store.decline(ip, probation_until);

        let m2 = mac(6);
        let ip2 = store.allocate(m2, now).expect("second allocate");
        assert_ne!(ip2, ip, "should not re-allocate declined IP");

        let m3 = mac(7);
        let ip3 = store.allocate(m3, now).expect("third allocate");
        assert_ne!(ip3, ip, "should not re-allocate declined IP");

        let m4 = mac(8);
        let result = store.allocate(m4, now);
        assert!(
            matches!(result, Err(DhcpError::PoolExhausted)),
            "should be exhausted"
        );
    }

    #[test]
    fn test_gc_removes_expired_offered() {
        let mut store = store_123();
        let now = SystemTime::now();
        let m = mac(9);
        store.allocate(m, now).expect("allocate");
        let future = now + Duration::from_secs(60);
        store.gc(future);
        assert!(
            store.lookup_by_mac(m).is_none(),
            "expired Offered lease should be GC'd"
        );
    }
}
