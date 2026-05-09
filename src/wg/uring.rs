// SPDX-License-Identifier: MIT OR Apache-2.0

//! io_uring-backed UDP I/O for the WireGuard datapath.
//!
//! Replaces per-datagram `recv_from` / `send_to` syscalls with a single
//! `io_uring_enter` per burst:
//!
//! * Sends are batched via `IORING_OP_SEND` with `dest_addr` (kernel \>= 5.6).
//!   Up to `SEND_POOL_SIZE` outbound packets can be in flight simultaneously.
//! * Recvs are kept topped up at `RECV_POOL_SIZE` in-flight `IORING_OP_RECVMSG`
//!   ops. Each completion is dispatched to a sink and the same pool slot is
//!   immediately re-armed.
//! * An eventfd registered with both the ring and the framework's epoll lets
//!   the existing event loop discover ring completions without polling.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use io_uring::{IoUring, opcode, types};
use socket2::SockAddr;

use crate::error::WgError;

const RECV_POOL_SIZE: usize = 64;
const SEND_POOL_SIZE: usize = 256;
const RECV_BUF_LEN: usize = 1500 + 32 + 16;
const SEND_BUF_LEN: usize = 2048;
const RING_ENTRIES: u32 = 1024;

/// `user_data` discriminator: bit 63 distinguishes recv slot indices from
/// send slot indices in the unified completion stream.
const RECV_USER_DATA_TAG: u64 = 1u64 << 63;

/// One pre-allocated recv slot. Buffer + msghdr + iovec + sockaddr_storage all
/// live in stable heap allocations so the kernel can DMA into them via the raw
/// pointers stored in the SQE for the lifetime of the slot.
///
/// Aliasing model: each slot is logically owned by *either* the kernel (between
/// SQE submission and CQE arrival) or by `WgUring` (otherwise). Rust references
/// into the slot are taken only when we own it, and the kernel only writes via
/// raw pointers it received in the SQE — they never coexist with a Rust `&mut`.
struct RecvSlot {
    buf: Box<[u8; RECV_BUF_LEN]>,
    src_addr: Box<libc::sockaddr_storage>,
    iov: Box<libc::iovec>,
    msg: Box<libc::msghdr>,
}

impl RecvSlot {
    fn new() -> Self {
        let buf: Box<[u8; RECV_BUF_LEN]> = Box::new([0u8; RECV_BUF_LEN]);
        let src_addr: Box<libc::sockaddr_storage> = Box::new(unsafe { mem::zeroed() });
        let mut iov: Box<libc::iovec> = Box::new(libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: RECV_BUF_LEN,
        });
        let mut msg: Box<libc::msghdr> = Box::new(unsafe { mem::zeroed() });
        msg.msg_name = (&*src_addr as *const libc::sockaddr_storage) as *mut libc::c_void;
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut *iov;
        msg.msg_iovlen = 1;
        Self {
            buf,
            src_addr,
            iov,
            msg,
        }
    }

    fn reset_for_resubmit(&mut self) {
        self.msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        self.msg.msg_controllen = 0;
        self.msg.msg_flags = 0;
        self.iov.iov_len = RECV_BUF_LEN;
    }

    fn decode_src_addr(&self) -> Option<SocketAddr> {
        let family = self.src_addr.ss_family as libc::c_int;
        match family {
            libc::AF_INET => {
                // SAFETY: kernel populated sockaddr_storage with AF_INET → sockaddr_in layout.
                let sin = unsafe {
                    &*(&*self.src_addr as *const libc::sockaddr_storage
                        as *const libc::sockaddr_in)
                };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            libc::AF_INET6 => {
                // SAFETY: kernel populated sockaddr_storage with AF_INET6 → sockaddr_in6 layout.
                let sin6 = unsafe {
                    &*(&*self.src_addr as *const libc::sockaddr_storage
                        as *const libc::sockaddr_in6)
                };
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

/// One pre-allocated send slot. Holds buffer bytes + the destination sockaddr
/// in stable heap memory; both pointers are read by the kernel until the CQE.
struct SendSlot {
    buf: Box<[u8; SEND_BUF_LEN]>,
    addr: Box<libc::sockaddr_storage>,
    addr_len: u32,
    in_flight: bool,
}

impl SendSlot {
    fn new() -> Self {
        Self {
            buf: Box::new([0u8; SEND_BUF_LEN]),
            addr: Box::new(unsafe { mem::zeroed() }),
            addr_len: 0,
            in_flight: false,
        }
    }
}

pub struct WgUring {
    ring: IoUring,
    socket_fd: RawFd,
    eventfd: OwnedFd,
    recv_slots: Vec<RecvSlot>,
    send_slots: Vec<SendSlot>,
    send_free: Vec<usize>,
    recv_armed: bool,
    pending_submit: bool,
}

// SAFETY: vhost-user-backend serializes all `WgNetBackend` access through a Mutex.
// `WgUring`'s raw-pointer fields (`libc::msghdr.msg_name/msg_iov`,
// `libc::iovec.iov_base`) point at heap allocations owned by the same `WgUring`
// and are never shared with another Rust thread; the kernel reads them via
// shared SQ memory but that's outside Rust's aliasing model.
unsafe impl Send for WgUring {}
unsafe impl Sync for WgUring {}

impl WgUring {
    pub fn new(socket_fd: RawFd) -> Result<Self, WgError> {
        let ring: IoUring = IoUring::builder()
            .setup_coop_taskrun()
            .setup_submit_all()
            .build(RING_ENTRIES)
            .map_err(uring_err)?;

        let eventfd_raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if eventfd_raw < 0 {
            return Err(WgError::SocketSend(io::Error::last_os_error()));
        }
        // SAFETY: eventfd_raw is a fresh fd we just created; ownership transfers in.
        let eventfd = unsafe { OwnedFd::from_raw_fd_checked(eventfd_raw) }?;

        ring.submitter()
            .register_eventfd(eventfd.as_raw_fd())
            .map_err(uring_err)?;

        let recv_slots: Vec<RecvSlot> = (0..RECV_POOL_SIZE).map(|_| RecvSlot::new()).collect();
        let send_slots: Vec<SendSlot> = (0..SEND_POOL_SIZE).map(|_| SendSlot::new()).collect();
        let send_free: Vec<usize> = (0..SEND_POOL_SIZE).rev().collect();

        let mut this = Self {
            ring,
            socket_fd,
            eventfd,
            recv_slots,
            send_slots,
            send_free,
            recv_armed: false,
            pending_submit: false,
        };
        this.arm_recvs()?;
        Ok(this)
    }

    pub fn eventfd(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }

    /// Drain the eventfd counter so subsequent CQ-non-empty transitions wake
    /// the framework's epoll. Idempotent.
    pub fn drain_eventfd(&self) {
        let mut buf = [0u8; 8];
        // SAFETY: read up to 8 bytes from a non-blocking eventfd into a local buf.
        let _ = unsafe {
            libc::read(
                self.eventfd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                8,
            )
        };
    }

    fn arm_recvs(&mut self) -> Result<(), WgError> {
        if self.recv_armed {
            return Ok(());
        }
        for idx in 0..self.recv_slots.len() {
            self.submit_recv(idx)?;
        }
        self.recv_armed = true;
        self.ring.submit().map_err(uring_err)?;
        self.pending_submit = false;
        Ok(())
    }

    fn submit_recv(&mut self, idx: usize) -> Result<(), WgError> {
        let slot = &mut self.recv_slots[idx];
        slot.reset_for_resubmit();
        let msg_ptr: *mut libc::msghdr = &mut *slot.msg;
        let entry = opcode::RecvMsg::new(types::Fd(self.socket_fd), msg_ptr)
            .build()
            .user_data(RECV_USER_DATA_TAG | idx as u64);
        // SAFETY: SQE references heap memory owned by `slot`; lifetime exceeds CQE.
        let mut sq = self.ring.submission();
        unsafe {
            sq.push(&entry).map_err(|_| {
                WgError::SocketSend(io::Error::other("io_uring SQ full while arming recv"))
            })?;
        }
        drop(sq);
        self.pending_submit = true;
        Ok(())
    }

    /// Queue a UDP send. Caller's bytes are copied into a pool slot; the slot
    /// is freed when the send CQE arrives. Returns `WgError::SocketSend` with
    /// `WouldBlock` semantics when the send pool is exhausted (the caller may
    /// retry after `submit_and_drain`).
    pub fn queue_send(&mut self, payload: &[u8], addr: SocketAddr) -> Result<(), WgError> {
        if payload.len() > SEND_BUF_LEN {
            return Err(WgError::SocketSend(io::Error::other(format!(
                "send payload {} exceeds slot {}",
                payload.len(),
                SEND_BUF_LEN
            ))));
        }
        // If the send pool is exhausted, flush whatever's pending and ask the
        // caller to back off — DO NOT try to drain CQEs inline. Recv CQEs in
        // the same CQ would have to be dropped (we have no sink here), which
        // would leak in-flight RecvMsgs and ultimately starve the recv path.
        // The natural eventfd → epoll → handle_socket_burst path will reap
        // send completions correctly on the next wake-up.
        let slot_idx = self.send_free.pop().ok_or_else(|| {
            if self.pending_submit {
                let _ = self.ring.submit();
                self.pending_submit = false;
            }
            WgError::SocketSend(io::Error::from(io::ErrorKind::WouldBlock))
        })?;
        let slot = &mut self.send_slots[slot_idx];
        slot.buf[..payload.len()].copy_from_slice(payload);
        let sock = SockAddr::from(addr);
        slot.addr_len = sock.len();
        // SAFETY: copy the OS sockaddr bytes into our stable storage.
        unsafe {
            std::ptr::copy_nonoverlapping(
                sock.as_ptr() as *const u8,
                &mut *slot.addr as *mut libc::sockaddr_storage as *mut u8,
                sock.len() as usize,
            );
        }
        slot.in_flight = true;
        let buf_ptr = slot.buf.as_ptr();
        let addr_ptr = &*slot.addr as *const libc::sockaddr_storage as *const libc::sockaddr;
        let addr_len = slot.addr_len;
        let entry = opcode::Send::new(types::Fd(self.socket_fd), buf_ptr, payload.len() as u32)
            .dest_addr(addr_ptr)
            .dest_addr_len(addr_len)
            .build()
            .user_data(slot_idx as u64);
        // SAFETY: SQE references slot.buf and slot.addr; both live in stable Boxes.
        let mut sq = self.ring.submission();
        unsafe {
            if sq.push(&entry).is_err() {
                drop(sq);
                self.ring.submit().map_err(uring_err)?;
                self.pending_submit = false;
                let mut sq2 = self.ring.submission();
                sq2.push(&entry).map_err(|_| {
                    WgError::SocketSend(io::Error::other("io_uring SQ full after flush"))
                })?;
            }
        }
        self.pending_submit = true;
        Ok(())
    }

    pub fn submit(&mut self) -> Result<(), WgError> {
        if !self.pending_submit {
            return Ok(());
        }
        self.ring.submit().map_err(uring_err)?;
        self.pending_submit = false;
        Ok(())
    }

    /// Drain up to `max_recvs` completed recv CQEs, dispatching each via
    /// `sink`. Send CQEs are reaped opportunistically (no max). Re-arms each
    /// drained recv slot so the kernel keeps delivering. Returns the number
    /// of recv datagrams dispatched.
    pub fn handle_completions<F>(&mut self, max_recvs: usize, mut sink: F) -> Result<usize, WgError>
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        let mut recvs = 0usize;
        let mut any_resubmit = false;
        while recvs < max_recvs {
            // Pull ONE CQE; cqueue::Entry is Copy so we can drop the borrow.
            let entry = {
                let mut cq = self.ring.completion();
                cq.next()
            };
            let (user_data, result) = match entry {
                Some(e) => (e.user_data(), e.result()),
                None => break,
            };
            if user_data & RECV_USER_DATA_TAG != 0 {
                let idx = (user_data & !RECV_USER_DATA_TAG) as usize;
                if result >= 0 {
                    let slot = &self.recv_slots[idx];
                    let n = result as usize;
                    if let Some(src) = slot.decode_src_addr() {
                        sink(src, &slot.buf[..n]);
                        recvs += 1;
                    }
                } else {
                    tracing::trace!(errno = -result, slot = idx, "wg_uring_recv_error");
                }
                self.submit_recv(idx)?;
                any_resubmit = true;
            } else {
                let idx = user_data as usize;
                if let Some(slot) = self.send_slots.get_mut(idx) {
                    if result < 0 {
                        tracing::trace!(errno = -result, slot = idx, "wg_uring_send_error");
                    }
                    slot.in_flight = false;
                    self.send_free.push(idx);
                }
            }
        }
        if any_resubmit {
            self.ring.submit().map_err(uring_err)?;
            self.pending_submit = false;
        }
        Ok(recvs)
    }

}

fn uring_err(e: io::Error) -> WgError {
    WgError::SocketSend(e)
}

trait FromRawFdChecked: Sized {
    unsafe fn from_raw_fd_checked(fd: RawFd) -> Result<Self, WgError>;
}

impl FromRawFdChecked for OwnedFd {
    unsafe fn from_raw_fd_checked(fd: RawFd) -> Result<Self, WgError> {
        if fd < 0 {
            Err(WgError::SocketSend(io::Error::last_os_error()))
        } else {
            // SAFETY: caller asserts fd ownership transfers.
            Ok(unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn bind_v6_dual_stack() -> UdpSocket {
        let owned = rustix::net::socket(
            rustix::net::AddressFamily::INET6,
            rustix::net::SocketType::DGRAM,
            None,
        )
        .unwrap();
        rustix::net::sockopt::set_ipv6_v6only(&owned, false).unwrap();
        let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        rustix::net::bind(&owned, &bind_addr).unwrap();
        UdpSocket::from(owned)
    }

    #[test]
    fn test_uring_constructs_and_arms_recvs() {
        let socket = bind_v6_dual_stack();
        let _ = WgUring::new(socket.as_raw_fd()).expect("build");
    }

    #[test]
    fn test_uring_round_trip_local_loopback() {
        let receiver = bind_v6_dual_stack();
        let recv_port = receiver.local_addr().unwrap().port();
        let sender = bind_v6_dual_stack();

        let mut uring = WgUring::new(receiver.as_raw_fd()).expect("build");

        let dst: SocketAddr = format!("[::1]:{}", recv_port).parse().unwrap();
        let payload = b"hello-uring";
        sender.send_to(payload, dst).expect("send");

        let mut got: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while got.is_empty() && std::time::Instant::now() < deadline {
            uring.drain_eventfd();
            let _ = uring.handle_completions(8, |src, buf| got.push((src, buf.to_vec())));
            if got.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        assert_eq!(got.len(), 1, "expected exactly one recv CQE");
        assert_eq!(&got[0].1, payload);
    }

    #[test]
    fn test_uring_send_to_loopback() {
        let receiver = bind_v6_dual_stack();
        let recv_port = receiver.local_addr().unwrap().port();
        let sender = bind_v6_dual_stack();

        let mut uring = WgUring::new(sender.as_raw_fd()).expect("build");
        let dst: SocketAddr = format!("[::1]:{}", recv_port).parse().unwrap();
        let payload = b"sent-via-uring";
        uring.queue_send(payload, dst).expect("queue");
        uring.submit().expect("submit");

        let mut buf = [0u8; 64];
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let (n, _) = receiver.recv_from(&mut buf).expect("recv");
        assert_eq!(&buf[..n], payload);
    }

    /// Regression test for the production wake-up path: register the
    /// `WgUring` eventfd with a level-triggered epoll (mimicking the
    /// vhost-user-backend framework) and confirm that the kernel writes
    /// to the eventfd whenever a CQE arrives.
    #[test]
    fn test_eventfd_wakes_epoll_on_recv() {
        let receiver = bind_v6_dual_stack();
        let recv_port = receiver.local_addr().unwrap().port();
        let sender = bind_v6_dual_stack();
        let mut uring = WgUring::new(receiver.as_raw_fd()).expect("build");

        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(epoll_fd >= 0, "epoll_create1 failed");
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 1,
        };
        let r = unsafe {
            libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, uring.eventfd(), &mut ev)
        };
        assert_eq!(r, 0, "epoll_ctl(ADD) failed: {}", io::Error::last_os_error());

        let dst: SocketAddr = format!("[::1]:{}", recv_port).parse().unwrap();
        sender.send_to(b"wake-up", dst).expect("send");

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let n =
            unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 4, 2000) };
        assert!(n >= 1, "epoll_wait did not surface eventfd within 2s (n={})", n);

        uring.drain_eventfd();
        let mut got: Vec<Vec<u8>> = Vec::new();
        let _ = uring.handle_completions(8, |_, buf| got.push(buf.to_vec()));
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0], b"wake-up");

        unsafe { libc::close(epoll_fd) };
    }
}
