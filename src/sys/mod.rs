//! Platform abstraction layer for the data plane.
//!
//! The hot path uses Linux-only batched syscalls (`sendmmsg`/`recvmmsg`) and
//! file hints (`fallocate`, `sync_file_range`, `SO_MAX_PACING_RATE`) for peak
//! throughput on a fast LFN. Everything OS-specific is isolated here so the rest
//! of the crate is platform-neutral:
//!
//!   - Linux           -> [`linux`]: true batched UDP I/O + file syscalls.
//!   - everything else -> [`portable`]: per-packet UDP I/O + no-op file hints.
//!
//! On non-Linux targets the per-packet fallback keeps the protocol fully
//! functional and wire-compatible; it just performs one syscall per datagram
//! instead of one per batch, so single-flow throughput on a fast path is lower.
//! Recovering batching there needs overlapped I/O / RIO (see cross-platform.md).
//!
//! Positional file I/O and signal handling differ along the unix/windows axis
//! and are handled inline below.

use socket2::Socket;
use socket2::{Domain, Protocol, Type};
use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    fallocate, set_max_pacing_rate, sync_file_range_write, BatchReceiver, BatchSender,
    FeedbackSender, RecvEngine,
};

// Portable backend supplies the per-packet sender and the no-op file hints for
// every non-Linux target (Windows included — the sender was never the
// bottleneck and the per-packet path saturates the path on push).
#[cfg(not(target_os = "linux"))]
mod portable;
#[cfg(not(target_os = "linux"))]
pub use portable::{fallocate, set_max_pacing_rate, sync_file_range_write, BatchSender};

// Receive backend: Windows uses the RIO (Registered I/O) overlapped engine;
// other non-Linux targets (macOS/BSD) use the portable per-packet receiver.
#[cfg(target_os = "windows")]
mod rio;
#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
pub use portable::{BatchReceiver, FeedbackSender, RecvEngine};
#[cfg(target_os = "windows")]
pub use rio::{BatchReceiver, FeedbackSender, RecvEngine};

/// One received datagram view: payload + source address.
pub struct RecvMsg<'a> {
    pub data: &'a [u8],
    pub addr: Option<SocketAddr>,
}

/// Force per-packet sends/recvs (debug parity with Go's `GIRTH_NOBATCH`).
pub fn no_batch() -> bool {
    std::env::var_os("GIRTH_NOBATCH").is_some()
}

/// Binds a UDP socket with enlarged kernel buffers (essential on a high-BDP LFN
/// path so the OS can hold a full window of in-flight packets without dropping)
/// and a short read timeout so blocking receive threads wake periodically to
/// check for shutdown / the `done` flag at end-of-transfer.
///
/// `rio` is ignored off Windows. On Windows it requests a RIO-registered socket
/// for the receive path; senders must pass `false` because a `WSA_FLAG_REGISTERED_IO`
/// socket cannot reliably use the standard `send_to` path the sender relies on.
#[cfg(not(target_os = "windows"))]
pub fn new_udp_socket(port: u16, _rio: bool) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // Best-effort; capped by the OS receive/send buffer maximum.
    let _ = sock.set_recv_buffer_size(64 << 20);
    let _ = sock.set_send_buffer_size(64 << 20);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(25)));
    let addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port);
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// Windows variant. When `rio` is true the socket is created with
/// `WSA_FLAG_REGISTERED_IO` so the receive side can use the RIO engine (see
/// [`rio`], the recvmmsg analog) — a plain socket cannot be RIO-registered after
/// the fact. When `rio` is false (the sender) a normal socket is created, since a
/// RIO-registered socket does not reliably support the standard `send_to` path.
#[cfg(target_os = "windows")]
pub fn new_udp_socket(port: u16, rio: bool) -> io::Result<UdpSocket> {
    if !rio {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let _ = sock.set_recv_buffer_size(64 << 20);
        let _ = sock.set_send_buffer_size(64 << 20);
        let _ = sock.set_read_timeout(Some(Duration::from_millis(25)));
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port);
        sock.bind(&addr.into())?;
        return Ok(sock.into());
    }
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        WSASocketW, WSAStartup, AF_INET, INVALID_SOCKET, IPPROTO_UDP, SOCK_DGRAM, WSADATA,
        WSA_FLAG_OVERLAPPED, WSA_FLAG_REGISTERED_IO,
    };
    let s = unsafe {
        // Idempotent (refcounted): the control TCP connection has normally
        // initialised Winsock already; this guards against ordering changes.
        let mut wsadata: WSADATA = std::mem::zeroed();
        let _ = WSAStartup(0x0202, &mut wsadata);
        WSASocketW(
            AF_INET as i32,
            SOCK_DGRAM,
            IPPROTO_UDP,
            std::ptr::null(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO,
        )
    };
    if s == INVALID_SOCKET {
        return Err(io::Error::last_os_error());
    }
    // Take ownership, then configure/bind via socket2 (round-trips the handle
    // without closing it).
    let sock = Socket::from(unsafe { UdpSocket::from_raw_socket(s as u64) });
    let _ = sock.set_recv_buffer_size(64 << 20);
    let _ = sock.set_send_buffer_size(64 << 20);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(25)));
    let addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port);
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

pub fn local_udp_port(s: &UdpSocket) -> u16 {
    s.local_addr().map(|a| a.port()).unwrap_or(0)
}

/// True if `err` is a timeout (SO_RCVTIMEO) / would-block condition.
pub fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

// --- positional file I/O (unix/windows) -------------------------------------

/// Reads exactly `buf.len()` bytes starting at byte `offset`, independent of any
/// file cursor (safe for concurrent positional I/O from multiple threads).
#[cfg(unix)]
pub fn read_exact_at(f: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, offset)
}

/// Writes all of `buf` starting at byte `offset`, independent of any file cursor.
#[cfg(unix)]
pub fn write_all_at(f: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.write_all_at(buf, offset)
}

// Windows `seek_read`/`seek_write` take an explicit offset (passed via OVERLAPPED)
// so the actual I/O location is correct under concurrency even though the file
// cursor is touched; the cursor is never relied upon here. They can short-read /
// short-write, so we loop to provide the exact/all semantics the callers expect.
#[cfg(windows)]
pub fn read_exact_at(f: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match f.seek_read(buf, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ))
            }
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
                offset += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn write_all_at(f: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match f.seek_write(buf, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ))
            }
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// --- termination signals (unix/windows) -------------------------------------

static SIGNALLED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
fn arm_signals() {
    extern "C" fn on_signal(_sig: libc::c_int) {
        SIGNALLED.store(true, Ordering::SeqCst);
    }
    unsafe {
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
    }
}

#[cfg(windows)]
fn arm_signals() {
    // Minimal kernel32 binding (kernel32 is linked by default), avoiding an
    // extra crate dependency. CTRL_C_EVENT/CTRL_BREAK/CLOSE all map to "stop".
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }
    extern "system" fn on_ctrl(_ctrl_type: u32) -> i32 {
        SIGNALLED.store(true, Ordering::SeqCst);
        1 // TRUE: handled
    }
    unsafe {
        SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
}

/// Installs SIGINT/SIGTERM (Ctrl-C on Windows) handlers and returns a flag that
/// flips to `true` on first signal, for cooperative shutdown.
pub fn install_termination_handler() -> Arc<AtomicBool> {
    arm_signals();
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    std::thread::spawn(move || loop {
        if SIGNALLED.load(Ordering::SeqCst) {
            s.store(true, Ordering::SeqCst);
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    });
    stop
}
