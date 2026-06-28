//! Portable data-plane backend for non-Linux targets (Windows, macOS, BSD).
//!
//! Windows has no `sendmmsg`/`recvmmsg`, so this backend does one syscall per
//! datagram via `UdpSocket::send_to`/`recv_from`. It is fully correct and
//! wire-compatible; single-flow throughput on a fast path is lower than the
//! Linux batched backend because of per-packet syscall overhead. On Windows the
//! standard library backs these calls with overlapped I/O via the OS, which
//! softens the cost. Recovering true batching needs an IOCP/RIO engine — see
//! cross-platform.md.
//!
//! The file hints have no portable equivalents and are no-ops here:
//!   - `fallocate`           -> unsupported; caller falls back to set_len/Truncate.
//!   - `sync_file_range`     -> no-op (durability happens at close/flush).
//!   - `SO_MAX_PACING_RATE`  -> no-op (the userspace pacer still applies).

use std::fs::File;
use std::io;
use std::net::{SocketAddr, UdpSocket};

// The receiver half is only used on non-Windows non-Linux targets (macOS/BSD);
// Windows takes its receiver from sys::iocp instead.
#[cfg(not(target_os = "windows"))]
use super::RecvMsg;
#[cfg(not(target_os = "windows"))]
use std::sync::Arc;

/// No kernel pacing primitive off Linux; the userspace pacer still applies.
pub fn set_max_pacing_rate(_sock: &UdpSocket, _bps: u64) {}

/// No portable preallocation primitive; signal the caller to use set_len.
pub fn fallocate(_f: &File, _size: i64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "fallocate unsupported on this platform",
    ))
}

/// No portable async-writeback hint; durability happens at close/flush.
pub fn sync_file_range_write(_f: &File, _offset: i64, _nbytes: i64) {}

// --- sender side: per-packet send_to ----------------------------------------

/// Buffers datagrams and emits them one `send_to` at a time on `flush`. Mirrors
/// the batched API so the data-plane logic is identical across platforms. Stores
/// raw pointer/length pairs (same contract as the Linux backend: each `p` must
/// stay valid until `flush` returns), so the hot path performs no copy.
pub struct BatchSender<'s> {
    sock: &'s UdpSocket,
    peer: SocketAddr,
    cap: usize,
    pkts: Vec<(*const u8, usize)>,
}

impl<'s> BatchSender<'s> {
    pub fn new(sock: &'s UdpSocket, peer: SocketAddr, cap_hint: usize) -> Self {
        let cap = cap_hint.max(8);
        BatchSender {
            sock,
            peer,
            cap,
            pkts: Vec::with_capacity(cap),
        }
    }

    pub fn reset(&mut self) {
        self.pkts.clear();
    }

    /// Appends a datagram. `p` must stay valid until `flush` returns.
    pub fn add(&mut self, p: &[u8]) {
        if self.pkts.len() >= self.cap {
            return;
        }
        self.pkts.push((p.as_ptr(), p.len()));
    }

    pub fn len(&self) -> usize {
        self.pkts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pkts.is_empty()
    }

    pub fn flush(&mut self) -> usize {
        let mut sent = 0usize;
        for &(ptr, len) in &self.pkts {
            let buf = unsafe { std::slice::from_raw_parts(ptr, len) };
            if self.sock.send_to(buf, self.peer).is_ok() {
                sent += 1;
            }
        }
        sent
    }
}

// --- receiver side: per-packet recv_from ------------------------------------

/// Per-socket receive engine. The portable backend has no shared kernel state,
/// so each ingest worker just gets its own single-datagram [`BatchReceiver`] on
/// the shared socket.
#[cfg(not(target_os = "windows"))]
pub struct RecvEngine {
    buf_len: usize,
}

#[cfg(not(target_os = "windows"))]
impl RecvEngine {
    pub fn new(_sock: &Arc<UdpSocket>, _workers: usize, buf_len: usize) -> io::Result<Self> {
        Ok(RecvEngine { buf_len })
    }

    pub fn worker(&self) -> io::Result<BatchReceiver> {
        Ok(BatchReceiver::new(1, self.buf_len))
    }

    /// Returns a handle for the feedback thread (the receive socket itself; no
    /// RIO restriction off Windows).
    pub fn feedback_sender(&self, sock: &Arc<UdpSocket>) -> FeedbackSender {
        FeedbackSender { sock: sock.clone() }
    }
}

/// Cloneable feedback transmit handle wrapping the receive socket.
#[cfg(not(target_os = "windows"))]
#[derive(Clone)]
pub struct FeedbackSender {
    sock: Arc<UdpSocket>,
}

#[cfg(not(target_os = "windows"))]
impl FeedbackSender {
    pub fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.sock.send_to(buf, peer)
    }
}

/// Pulls one datagram per `recv_from`, exposing the same slot-based API as the
/// Linux batched receiver. `recv` always fills slot 0 and returns 1 (or a
/// timeout error).
#[cfg(not(target_os = "windows"))]
pub struct BatchReceiver {
    buf_len: usize,
    buf: Vec<u8>,
    len: usize,
    addr: Option<SocketAddr>,
}

#[cfg(not(target_os = "windows"))]
impl BatchReceiver {
    pub fn new(_cap: usize, buf_len: usize) -> Self {
        BatchReceiver {
            buf_len,
            buf: vec![0u8; buf_len],
            len: 0,
            addr: None,
        }
    }

    /// Receives a single datagram into slot 0. `Err` with `is_timeout()` true
    /// indicates an idle timeout.
    pub fn recv(&mut self, sock: &UdpSocket) -> io::Result<usize> {
        let (n, addr) = sock.recv_from(&mut self.buf[..self.buf_len])?;
        self.len = n.min(self.buf_len);
        self.addr = Some(addr);
        Ok(1)
    }

    pub fn message(&self, _i: usize) -> RecvMsg<'_> {
        RecvMsg {
            data: &self.buf[..self.len],
            addr: self.addr,
        }
    }

    pub fn message_mut(&mut self, _i: usize) -> (&mut [u8], Option<SocketAddr>) {
        (&mut self.buf[..self.len], self.addr)
    }
}
