//! Linux data-plane backend: batched UDP I/O via `sendmmsg(2)`/`recvmmsg(2)`
//! plus the file syscalls (`fallocate`, `sync_file_range`) and socket pacing
//! (`SO_MAX_PACING_RATE`) used by the data plane.
//!
//! Collapsing one syscall per packet into one per batch is the single biggest
//! win for a single high-rate flow on a fast LFN. There is no async runtime:
//! each data-plane role is a blocking OS thread, mirroring the Go goroutine
//! layout.

use super::{no_batch, RecvMsg};
use socket2::SockAddr;
use std::fs::File;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

/// Sets the kernel egress pacing ceiling (SO_MAX_PACING_RATE, bytes/sec).
pub fn set_max_pacing_rate(sock: &UdpSocket, bps: u64) {
    let mut bytes_per_sec = bps / 8;
    if bytes_per_sec > u32::MAX as u64 {
        bytes_per_sec = u32::MAX as u64;
    }
    let v = bytes_per_sec as libc::c_uint;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MAX_PACING_RATE,
            &v as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_uint>() as libc::socklen_t,
        );
    }
}

/// Allocates real blocks for `f` up to `size` (caller falls back to ftruncate on
/// error). Avoids sparse-file random-write costs under retransmission.
pub fn fallocate(f: &File, size: i64) -> io::Result<()> {
    let r = unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, size) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Kicks asynchronous (non-blocking) writeback for `[offset, offset+nbytes)`.
pub fn sync_file_range_write(f: &File, offset: i64, nbytes: i64) {
    unsafe {
        libc::sync_file_range(f.as_raw_fd(), offset, nbytes, libc::SYNC_FILE_RANGE_WRITE);
    }
}

// --- sender side: sendmmsg --------------------------------------------------

/// Emits a group of UDP datagrams with a single `sendmmsg(2)` call. Falls back
/// transparently to per-packet `send_to` if batched writes are unsupported.
///
/// The `iovec`/`mmsghdr` arrays are allocated once and reused across batches
/// (only the per-slot data pointer/length and the kernel-written `msg_len` are
/// updated each flush), so the hot pacing loop performs no per-batch heap
/// allocation.
pub struct BatchSender<'s> {
    sock: &'s UdpSocket,
    fd: RawFd,
    peer: Box<SockAddr>, // boxed => stable address for msg_name across moves
    peer_std: SocketAddr,
    cap: usize,
    n: usize,
    iovs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    bad: bool,
}

impl<'s> BatchSender<'s> {
    pub fn new(sock: &'s UdpSocket, peer: SocketAddr, cap_hint: usize) -> Self {
        let cap = cap_hint.max(8);
        let mut bs = BatchSender {
            sock,
            fd: sock.as_raw_fd(),
            peer: Box::new(SockAddr::from(peer)),
            peer_std: peer,
            cap,
            n: 0,
            iovs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0
                };
                cap
            ],
            msgs: Vec::with_capacity(cap),
            bad: no_batch(),
        };
        // Wire each mmsghdr to its iovec slot and the (stable, boxed) peer once.
        let name = bs.peer.as_ptr() as *mut libc::c_void;
        let namelen = bs.peer.len();
        for i in 0..cap {
            let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
            hdr.msg_name = name;
            hdr.msg_namelen = namelen;
            hdr.msg_iov = &mut bs.iovs[i] as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            bs.msgs.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }
        bs
    }

    pub fn reset(&mut self) {
        self.n = 0;
    }

    /// Appends a datagram. `p` must stay valid until `flush` returns.
    pub fn add(&mut self, p: &[u8]) {
        if self.n >= self.cap {
            return;
        }
        self.iovs[self.n].iov_base = p.as_ptr() as *mut libc::c_void;
        self.iovs[self.n].iov_len = p.len();
        self.n += 1;
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Sends all queued datagrams, returning the count actually sent.
    pub fn flush(&mut self) -> usize {
        let n = self.n;
        if n == 0 {
            return 0;
        }
        let mut sent = 0usize;
        if !self.bad {
            while sent < n {
                let r = unsafe {
                    libc::sendmmsg(
                        self.fd,
                        self.msgs[sent..].as_mut_ptr(),
                        (n - sent) as libc::c_uint,
                        0,
                    )
                };
                if r < 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.bad = true; // permanently fall back
                    break;
                }
                if r == 0 {
                    break;
                }
                sent += r as usize;
            }
        }
        // Per-packet fallback for anything not sent (unsupported or partial).
        for iov in self.iovs[..n].iter().skip(sent) {
            let buf = unsafe { std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len) };
            if self.sock.send_to(buf, self.peer_std).is_ok() {
                sent += 1;
            }
        }
        sent
    }
}

// --- receiver side: recvmmsg ------------------------------------------------

/// Pulls many datagrams per `recvmmsg(2)` syscall, raising the socket-drain
/// rate so the kernel receive buffer does not overflow during arrival bursts.
pub struct BatchReceiver {
    cap: usize,
    buf_len: usize,
    bufs: Vec<u8>, // contiguous: slot i at [i*buf_len, (i+1)*buf_len)
    iovs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    addrs: Vec<libc::sockaddr_storage>,
    bad: bool,
}

// The internal iovec/mmsghdr pointers reference this receiver's own heap-backed
// `Vec`s, which keep their addresses when the struct itself is moved, so the
// receiver can be handed to an ingest worker thread safely. It is only ever used
// by that one thread thereafter (never shared), so `Send` (not `Sync`) suffices.
unsafe impl Send for BatchReceiver {}

impl BatchReceiver {
    pub fn new(cap: usize, buf_len: usize) -> Self {
        let mut r = BatchReceiver {
            cap,
            buf_len,
            bufs: vec![0u8; cap * buf_len],
            iovs: Vec::with_capacity(cap),
            msgs: Vec::with_capacity(cap),
            addrs: vec![unsafe { mem::zeroed() }; cap],
            bad: no_batch(),
        };
        // Wire iovecs to buffer slots once; pointers stay valid (no realloc).
        let base = r.bufs.as_mut_ptr();
        for i in 0..cap {
            r.iovs.push(libc::iovec {
                iov_base: unsafe { base.add(i * buf_len) } as *mut libc::c_void,
                iov_len: buf_len,
            });
        }
        for i in 0..cap {
            let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
            hdr.msg_iov = &mut r.iovs[i] as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            hdr.msg_name = &mut r.addrs[i] as *mut _ as *mut libc::c_void;
            hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            r.msgs.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }
        r
    }

    /// Performs one receive, returning the number of datagrams obtained. Uses
    /// `recvmmsg` unless batching is disabled/unsupported, in which case it
    /// falls back to a single `recv_from` into slot 0. `Err` with `is_timeout()`
    /// true indicates an idle timeout.
    pub fn recv(&mut self, sock: &UdpSocket) -> io::Result<usize> {
        if self.bad {
            return self.recv_one(sock);
        }
        // Reset per-call output fields the kernel mutates.
        for m in self.msgs.iter_mut() {
            m.msg_len = 0;
            m.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        }
        loop {
            let r = unsafe {
                libc::recvmmsg(
                    sock.as_raw_fd(),
                    self.msgs.as_mut_ptr(),
                    self.cap as libc::c_uint,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if e.raw_os_error() == Some(libc::ENOSYS) {
                    self.bad = true; // recvmmsg unsupported; fall back permanently
                    return self.recv_one(sock);
                }
                return Err(e);
            }
            return Ok(r as usize);
        }
    }

    /// Single-datagram fallback into slot 0 (batching disabled/unsupported).
    fn recv_one(&mut self, sock: &UdpSocket) -> io::Result<usize> {
        let (n, addr) = sock.recv_from(&mut self.bufs[0..self.buf_len])?;
        self.msgs[0].msg_len = n as libc::c_uint;
        let sa = SockAddr::from(addr);
        unsafe {
            std::ptr::copy_nonoverlapping(
                sa.as_ptr() as *const u8,
                &mut self.addrs[0] as *mut _ as *mut u8,
                sa.len() as usize,
            );
        }
        self.msgs[0].msg_hdr.msg_namelen = sa.len();
        Ok(1)
    }

    /// Borrows received datagram `i` (0-based, `i < recv()`'s return).
    pub fn message(&self, i: usize) -> RecvMsg<'_> {
        let m = &self.msgs[i];
        let n = m.msg_len as usize;
        let off = i * self.buf_len;
        let data = &self.bufs[off..off + n.min(self.buf_len)];
        let addr = sockaddr_to_socketaddr(&self.addrs[i], m.msg_hdr.msg_namelen);
        RecvMsg { data, addr }
    }

    /// Mutable slice of slot `i` (for in-place decryption).
    pub fn message_mut(&mut self, i: usize) -> (&mut [u8], Option<SocketAddr>) {
        let n = self.msgs[i].msg_len as usize;
        let namelen = self.msgs[i].msg_hdr.msg_namelen;
        let addr = sockaddr_to_socketaddr(&self.addrs[i], namelen);
        let off = i * self.buf_len;
        let end = off + n.min(self.buf_len);
        (&mut self.bufs[off..end], addr)
    }
}

/// Per-worker recvmmsg batch size (datagrams pulled per syscall).
const RECV_BATCH: usize = 32;

/// Per-socket receive engine. On Linux each ingest worker runs its own
/// `recvmmsg` loop directly on the shared socket, so the engine just carries
/// the per-worker buffer geometry and hands out a [`BatchReceiver`] per worker.
pub struct RecvEngine {
    buf_len: usize,
}

impl RecvEngine {
    pub fn new(_sock: &Arc<UdpSocket>, _workers: usize, buf_len: usize) -> io::Result<Self> {
        Ok(RecvEngine { buf_len })
    }

    /// Builds one independent receiver for an ingest worker thread.
    pub fn worker(&self) -> io::Result<BatchReceiver> {
        Ok(BatchReceiver::new(RECV_BATCH, self.buf_len))
    }

    /// Returns a handle for the feedback thread to transmit NACKs / feedback.
    /// On Linux this is just the shared UDP socket (no RIO restriction).
    pub fn feedback_sender(&self, sock: &Arc<UdpSocket>) -> FeedbackSender {
        FeedbackSender { sock: sock.clone() }
    }
}

/// Cloneable feedback transmit handle. On Linux/portable the receive socket can
/// send directly, so this wraps it (parity with the Windows RIO backend, where
/// sends must go through RIO).
#[derive(Clone)]
pub struct FeedbackSender {
    sock: Arc<UdpSocket>,
}

impl FeedbackSender {
    pub fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.sock.send_to(buf, peer)
    }
}

/// Parses a kernel `sockaddr_storage` into a Rust `SocketAddr`.
fn sockaddr_to_socketaddr(ss: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            if (len as usize) < mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            let sin = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            if (len as usize) < mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            let sin6 = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
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
