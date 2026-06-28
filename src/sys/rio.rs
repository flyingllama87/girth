//! Windows data-plane receive backend: a RIO (Registered I/O) engine — the
//! Windows analogue of Linux `recvmmsg`.
//!
//! The portable per-packet `recv_from` fallback hits a hard single-socket
//! ceiling on a high-BDP LFN path (~250-280 Mbps here): every datagram costs a
//! receive *syscall*, and Windows serialises concurrent `recvfrom` on one socket
//! behind a lock, so neither extra threads nor IOCP (which still needs one
//! `WSARecvFrom` submit per packet) get past it.
//!
//! RIO removes the per-packet syscall entirely. Receive buffers are registered
//! once; receives are posted into a request queue and harvested from a
//! completion queue as plain user-space ring operations — no kernel transition
//! per datagram. Thousands of receives stay posted so arrival bursts are never
//! dropped, and completions are drained in large batches. The send side stays
//! per-packet (see `portable.rs`); it already saturates the path on push.
//!
//! The receiver runs single-threaded on Windows (the receiver forces one ingest
//! worker), so the request/completion queues are touched by exactly one thread
//! and need no locking. CRC/decrypt happen inline on that thread; hardware
//! CRC32C and AES-NI keep one core well ahead of the path.
//!
//! Safety model: the registered data/address regions and the descriptor arrays
//! live in the heap-pinned [`RioCore`] for the engine's whole lifetime, and the
//! engine outlives every harvester. A slot's buffer is only written by the
//! kernel while its receive is posted, and only read by the single harvester
//! between completion and re-post, so the raw-pointer accesses are sound.

use super::RecvMsg;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::ptr;
use std::sync::Arc;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSAIoctl, AF_INET, AF_INET6, RIORESULT, RIO_BUF, RIO_BUFFERID, RIO_CQ,
    RIO_EVENT_COMPLETION, RIO_EXTENSION_FUNCTION_TABLE, RIO_NOTIFICATION_COMPLETION, RIO_RQ,
    SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET, SOCKET, WSAID_MULTIPLE_RIO,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

/// Total receives kept posted on the socket; large enough to absorb multi-Gbps
/// arrival bursts without ever lacking a landing buffer, but bounded so the
/// outstanding requests stay within the per-process non-paged-pool / locked-
/// buffer quota (too many → `RIOReceiveEx` fails with WSAENOBUFS, 10055).
const NSLOTS: usize = 4096;
/// Completions harvested per `RIODequeueCompletion`.
const DEQ: usize = 512;
/// Per-slot address scratch (a `SOCKADDR_INET` is ~28 bytes; round to 32).
const ADDR_SLOT: usize = 32;
/// Outstanding-send ring for the low-rate feedback/NACK path. Sends complete in
/// microseconds, so a small ring is never exhausted before a slot is reusable.
const SEND_RING: usize = 16;
/// Request-context sentinel marking a send completion (vs a receive whose
/// context is its slot index), so the harvester can skip it.
const SEND_CTX: usize = usize::MAX;
/// IOCTL to fetch the RIO function-pointer table (mswsock; not in windows-sys).
const SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTERS: u32 = 0xC800_0024;
/// RIORegisterBuffer failure sentinel ((RIO_BUFFERID)0xFFFFFFFF in mswsock.h).
const RIO_INVALID_BUFFERID: RIO_BUFFERID = 0xFFFF_FFFF;

/// Shared, heap-pinned RIO state: function table, queues, registered regions and
/// the per-slot descriptors.
struct RioCore {
    _sock: Arc<UdpSocket>, // keep the socket (hence the RIO queues) alive
    rio: RIO_EXTENSION_FUNCTION_TABLE,
    cq: RIO_CQ,
    // Separate completion queue for the feedback/NACK send path. Sends MUST NOT
    // share the receive CQ: during a loss-driven NACK storm the send completions
    // would pile into the receive CQ faster than the harvester drains them and
    // overflow it (RIO_CORRUPT_CQ), killing the receiver. With its own CQ —
    // drained inline by `send_to` — sends can never starve or corrupt receives.
    send_cq: RIO_CQ,
    rq: RIO_RQ,
    event: HANDLE, // signaled by RIONotify when a completion lands
    data_bufid: RIO_BUFFERID,
    addr_bufid: RIO_BUFFERID,
    data: Box<[u8]>,
    _addr: Box<[u8]>,
    data_ptr: *mut u8,
    addr_ptr: *mut u8,
    data_descs: Vec<RIO_BUF>,
    addr_descs: Vec<RIO_BUF>,
    buf_len: usize,
    // Feedback send path (RIOSendEx). The request queue is shared between the
    // ingest thread (receive re-posts) and the feedback thread (sends); RIO RQ
    // submits are not thread-safe, so `rq_mu` serialises every submit. The mutex
    // value is the next send-ring slot.
    rq_mu: std::sync::Mutex<u32>,
    send_data_bufid: RIO_BUFFERID,
    send_addr_bufid: RIO_BUFFERID,
    _send_data: Box<[u8]>,
    _send_addr: Box<[u8]>,
    send_data_ptr: *mut u8,
    send_addr_ptr: *mut u8,
}

// Touched by one harvester at a time (Windows forces a single ingest worker);
// the engine handle that constructs it never races the harvester.
unsafe impl Send for RioCore {}
unsafe impl Sync for RioCore {}

impl RioCore {
    fn new(sock: &Arc<UdpSocket>, buf_len: usize) -> io::Result<Arc<RioCore>> {
        let sock = sock.clone();
        let sock_raw = sock.as_raw_socket() as SOCKET;

        // 1. Fetch the RIO function table for this socket.
        let mut rio: RIO_EXTENSION_FUNCTION_TABLE = unsafe { mem::zeroed() };
        let mut guid: GUID = WSAID_MULTIPLE_RIO;
        let mut bytes: u32 = 0;
        let r = unsafe {
            WSAIoctl(
                sock_raw,
                SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTERS,
                &mut guid as *mut GUID as *const core::ffi::c_void,
                mem::size_of::<GUID>() as u32,
                &mut rio as *mut RIO_EXTENSION_FUNCTION_TABLE as *mut core::ffi::c_void,
                mem::size_of::<RIO_EXTENSION_FUNCTION_TABLE>() as u32,
                &mut bytes,
                ptr::null_mut(),
                None,
            )
        };
        if r != 0 {
            return Err(io::Error::other(format!(
                "RIO WSAIoctl(get fn table) failed: r={r} wsa={}",
                unsafe { WSAGetLastError() }
            )));
        }

        // 2. Allocate and register the data + address regions.
        let data: Box<[u8]> = vec![0u8; NSLOTS * buf_len].into_boxed_slice();
        let addr: Box<[u8]> = vec![0u8; NSLOTS * ADDR_SLOT].into_boxed_slice();
        let data_ptr = data.as_ptr() as *mut u8;
        let addr_ptr = addr.as_ptr() as *mut u8;
        let register = rio.RIORegisterBuffer.unwrap();
        let data_bufid = unsafe { register(data_ptr, (NSLOTS * buf_len) as u32) };
        if data_bufid == RIO_INVALID_BUFFERID {
            return Err(io::Error::other(format!(
                "RIORegisterBuffer(data {} bytes) failed: wsa={}",
                NSLOTS * buf_len,
                unsafe { WSAGetLastError() }
            )));
        }
        let addr_bufid = unsafe { register(addr_ptr, (NSLOTS * ADDR_SLOT) as u32) };
        if addr_bufid == RIO_INVALID_BUFFERID {
            return Err(io::Error::other(format!(
                "RIORegisterBuffer(addr {} bytes) failed: wsa={}",
                NSLOTS * ADDR_SLOT,
                unsafe { WSAGetLastError() }
            )));
        }

        // 2b. Send-side regions for the feedback path (RIOSendEx).
        let send_data: Box<[u8]> = vec![0u8; SEND_RING * buf_len].into_boxed_slice();
        let send_addr: Box<[u8]> = vec![0u8; SEND_RING * ADDR_SLOT].into_boxed_slice();
        let send_data_ptr = send_data.as_ptr() as *mut u8;
        let send_addr_ptr = send_addr.as_ptr() as *mut u8;
        let send_data_bufid = unsafe { register(send_data_ptr, (SEND_RING * buf_len) as u32) };
        let send_addr_bufid = unsafe { register(send_addr_ptr, (SEND_RING * ADDR_SLOT) as u32) };
        if send_data_bufid == RIO_INVALID_BUFFERID || send_addr_bufid == RIO_INVALID_BUFFERID {
            return Err(io::Error::other(format!(
                "RIORegisterBuffer(send) failed: wsa={}",
                unsafe { WSAGetLastError() }
            )));
        }

        // 3. Create an auto-reset event and an event-notified completion queue,
        //    then the request queue bound to the socket. A NULL-notification
        //    (pure-poll) CQ does not deliver completions reliably here, so we use
        //    RIO_EVENT_COMPLETION: each armed RIONotify signals the event when a
        //    completion lands, and the harvester waits on it.
        let event = unsafe {
            CreateEventW(
                ptr::null(),
                0, /* auto-reset */
                0, /* nonsignaled */
                ptr::null(),
            )
        };
        if event.is_null() {
            return Err(io::Error::other(format!(
                "CreateEventW failed: {}",
                io::Error::last_os_error()
            )));
        }
        let mut notify: RIO_NOTIFICATION_COMPLETION = unsafe { mem::zeroed() };
        notify.Type = RIO_EVENT_COMPLETION;
        notify.Anonymous.Event.EventHandle = event;
        notify.Anonymous.Event.NotifyReset = 0; // RIO does not reset; auto-reset event does

        let create_cq = rio.RIOCreateCompletionQueue.unwrap();
        // Receive CQ: event-notified, holds the receive completions only
        // (MaxOutstandingReceive = NSLOTS, plus slack). Sends go to their own CQ
        // below, so a NACK storm can no longer overflow this queue.
        let cq_size = (NSLOTS + 16) as u32;
        let cq = unsafe { create_cq(cq_size, &notify) };
        if cq == 0 {
            return Err(io::Error::other(format!(
                "RIOCreateCompletionQueue({cq_size}) failed: wsa={}",
                unsafe { WSAGetLastError() }
            )));
        }
        // Send CQ: pure-poll (NULL notification), drained inline by `send_to`.
        // Sized well above SEND_RING so transient bursts never overflow before
        // the next drain.
        let send_cq_size = (SEND_RING * 4) as u32;
        let send_cq = unsafe { create_cq(send_cq_size, ptr::null()) };
        if send_cq == 0 {
            return Err(io::Error::other(format!(
                "RIOCreateCompletionQueue(send, {send_cq_size}) failed: wsa={}",
                unsafe { WSAGetLastError() }
            )));
        }
        let create_rq = rio.RIOCreateRequestQueue.unwrap();
        let rq = unsafe {
            create_rq(
                sock_raw,
                NSLOTS as u32,
                1,
                SEND_RING as u32,
                1,
                cq,      // receive completion queue
                send_cq, // send completion queue (separate)
                ptr::null(),
            )
        };
        if rq == 0 {
            return Err(io::Error::other(format!(
                "RIOCreateRequestQueue(maxRecv={NSLOTS}) failed: wsa={}",
                unsafe { WSAGetLastError() }
            )));
        }

        // 4. Build per-slot descriptors into the registered regions.
        let mut data_descs = Vec::with_capacity(NSLOTS);
        let mut addr_descs = Vec::with_capacity(NSLOTS);
        for i in 0..NSLOTS {
            data_descs.push(RIO_BUF {
                BufferId: data_bufid,
                Offset: (i * buf_len) as u32,
                Length: buf_len as u32,
            });
            addr_descs.push(RIO_BUF {
                BufferId: addr_bufid,
                Offset: (i * ADDR_SLOT) as u32,
                Length: ADDR_SLOT as u32,
            });
        }

        let core = Arc::new(RioCore {
            _sock: sock,
            rio,
            cq,
            send_cq,
            rq,
            event,
            data_bufid,
            addr_bufid,
            data,
            _addr: addr,
            data_ptr,
            addr_ptr,
            data_descs,
            addr_descs,
            buf_len,
            rq_mu: std::sync::Mutex::new(0),
            send_data_bufid,
            send_addr_bufid,
            _send_data: send_data,
            _send_addr: send_addr,
            send_data_ptr,
            send_addr_ptr,
        });

        // 5. Post all receives, then arm the first completion notification.
        for i in 0..NSLOTS {
            core.post_recv(i)?;
        }
        core.arm_notify()?;
        Ok(core)
    }

    /// Arms the CQ to signal `event` on the next completion. Must be re-armed
    /// after each notification (RIONotify is one-shot).
    fn arm_notify(&self) -> io::Result<()> {
        let notify = self.rio.RIONotify.unwrap();
        let r = unsafe { notify(self.cq) };
        if r != 0 {
            return Err(io::Error::other(format!("RIONotify failed: {r}")));
        }
        Ok(())
    }

    /// Posts (or re-posts) the receive for slot `idx`, capturing the remote
    /// address into the slot's address scratch. Holds `rq_mu` for the duration:
    /// RIO RQ submits are not thread-safe and the feedback thread also submits.
    fn post_recv(&self, idx: usize) -> io::Result<()> {
        let receive_ex = self.rio.RIOReceiveEx.unwrap();
        let _g = self.rq_mu.lock().unwrap();
        let ok = unsafe {
            receive_ex(
                self.rq,
                &self.data_descs[idx],
                1,
                ptr::null(),           // local address (unused)
                &self.addr_descs[idx], // remote address scratch
                ptr::null(),           // control context
                ptr::null(),           // flags
                0,
                idx as *const core::ffi::c_void, // request context = slot index
            )
        };
        if ok == 0 {
            return Err(io::Error::other(format!(
                "RIOReceiveEx failed (slot {idx}, wsa {})",
                unsafe { WSAGetLastError() }
            )));
        }
        Ok(())
    }

    /// Sends `buf` to `peer` on the RIO socket via RIOSendEx (the feedback /NACK
    /// path). A RIO-registered socket cannot use the standard `send_to`, so all
    /// outbound traffic must go through RIO. Uses a small ring of registered send
    /// buffers; completions are drained and skipped by the harvester (sentinel
    /// context). Holds `rq_mu` to serialise the RQ submit against receive
    /// re-posts.
    fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize> {
        let len = buf.len().min(self.buf_len);
        let send_ex = self.rio.RIOSendEx.unwrap();
        let mut guard = self.rq_mu.lock().unwrap();

        // Reap completed sends from the dedicated send CQ before posting another.
        // This keeps outstanding sends bounded (so the ring slot we are about to
        // reuse is free) and keeps the send CQ from ever filling. Non-blocking;
        // sends complete in microseconds.
        let dequeue = self.rio.RIODequeueCompletion.unwrap();
        let mut scratch: [RIORESULT; SEND_RING] = unsafe { mem::zeroed() };
        loop {
            let n = unsafe { dequeue(self.send_cq, scratch.as_mut_ptr(), SEND_RING as u32) };
            if n == 0 || n == windows_sys::Win32::Networking::WinSock::RIO_CORRUPT_CQ {
                break;
            }
        }

        let slot = *guard as usize;
        *guard = ((slot + 1) % SEND_RING) as u32;

        // Copy payload into the ring's data slot.
        let doff = slot * self.buf_len;
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), self.send_data_ptr.add(doff), len);
        }
        let data_desc = RIO_BUF {
            BufferId: self.send_data_bufid,
            Offset: doff as u32,
            Length: len as u32,
        };

        // Serialise the destination address into the ring's address slot. RIO
        // reads the sockaddr family then the matching struct; the descriptor
        // spans the whole (zeroed) slot, matching the working probe — passing the
        // exact sockaddr length here is rejected with WSAEINVAL (10022).
        let aoff = slot * ADDR_SLOT;
        unsafe {
            ptr::write_bytes(self.send_addr_ptr.add(aoff), 0, ADDR_SLOT);
            write_sockaddr(self.send_addr_ptr.add(aoff), peer);
        }
        let addr_desc = RIO_BUF {
            BufferId: self.send_addr_bufid,
            Offset: aoff as u32,
            Length: ADDR_SLOT as u32,
        };

        let ok = unsafe {
            send_ex(
                self.rq,
                &data_desc,
                1,
                ptr::null(), // local address (unused)
                &addr_desc,  // remote address
                ptr::null(), // control context
                ptr::null(), // flags
                0,
                SEND_CTX as *const core::ffi::c_void,
            )
        };
        drop(guard);
        if ok == 0 {
            return Err(io::Error::other(format!(
                "RIOSendEx failed: wsa {}",
                unsafe { WSAGetLastError() }
            )));
        }
        Ok(len)
    }
}

/// Serialises `peer` into a `SOCKADDR_IN`/`SOCKADDR_IN6` at `dst`, returning the
/// number of bytes written. `dst` must have room for at least [`ADDR_SLOT`].
unsafe fn write_sockaddr(dst: *mut u8, peer: SocketAddr) -> u32 {
    match peer {
        SocketAddr::V4(v4) => {
            let mut sa: SOCKADDR_IN = mem::zeroed();
            sa.sin_family = AF_INET;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.ip().octets());
            ptr::copy_nonoverlapping(
                &sa as *const SOCKADDR_IN as *const u8,
                dst,
                mem::size_of::<SOCKADDR_IN>(),
            );
            mem::size_of::<SOCKADDR_IN>() as u32
        }
        SocketAddr::V6(v6) => {
            let mut sa: SOCKADDR_IN6 = mem::zeroed();
            sa.sin6_family = AF_INET6;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_flowinfo = v6.flowinfo();
            sa.sin6_addr.u.Byte = v6.ip().octets();
            sa.Anonymous.sin6_scope_id = v6.scope_id();
            ptr::copy_nonoverlapping(
                &sa as *const SOCKADDR_IN6 as *const u8,
                dst,
                mem::size_of::<SOCKADDR_IN6>(),
            );
            mem::size_of::<SOCKADDR_IN6>() as u32
        }
    }
}

impl Drop for RioCore {
    fn drop(&mut self) {
        // By teardown the sender has finished (the receiver only drops the
        // engine after the feedback + ingest threads have joined), so no further
        // datagrams arrive and the posted receives are quiescent. Close the
        // completion queue and deregister the buffers; the request queue is freed
        // with the socket. The owned `Box` regions then drop normally.
        unsafe {
            if let Some(close_cq) = self.rio.RIOCloseCompletionQueue {
                close_cq(self.cq);
                close_cq(self.send_cq);
            }
            if let Some(dereg) = self.rio.RIODeregisterBuffer {
                dereg(self.data_bufid);
                dereg(self.addr_bufid);
                dereg(self.send_data_bufid);
                dereg(self.send_addr_bufid);
            }
            if !self.event.is_null() {
                CloseHandle(self.event);
            }
        }
    }
}

/// Cloneable handle for the receiver's feedback/NACK transmits over the RIO
/// socket (see [`RioCore::send_to`]). The standard `UdpSocket::send_to` cannot be
/// used on a RIO-registered socket, so feedback must go through RIO too.
#[derive(Clone)]
pub struct FeedbackSender {
    core: Arc<RioCore>,
}

impl FeedbackSender {
    pub fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.core.send_to(buf, peer)
    }
}

/// Per-socket receive engine (a single RIO request/completion queue pair).
pub struct RecvEngine {
    core: Arc<RioCore>,
}

impl RecvEngine {
    pub fn new(sock: &Arc<UdpSocket>, _workers: usize, buf_len: usize) -> io::Result<Self> {
        Ok(RecvEngine {
            core: RioCore::new(sock, buf_len)?,
        })
    }

    /// Builds the harvesting receiver. The receiver runs one ingest worker on
    /// Windows, so this is called once.
    pub fn worker(&self) -> io::Result<BatchReceiver> {
        Ok(BatchReceiver {
            core: self.core.clone(),
            results: vec![unsafe { mem::zeroed() }; DEQ],
            batch: Vec::with_capacity(DEQ),
            pending: Vec::with_capacity(DEQ),
            armed: true, // RioCore::new armed the first notification
        })
    }

    /// Returns a cloneable handle the feedback thread uses to transmit NACKs /
    /// feedback over the RIO socket. `_sock` is accepted for signature parity
    /// with the non-Windows backends (which send via the `UdpSocket`).
    pub fn feedback_sender(&self, _sock: &Arc<UdpSocket>) -> FeedbackSender {
        FeedbackSender {
            core: self.core.clone(),
        }
    }
}

/// Completion harvester. Exposes the same slot-based API as the Linux
/// `recvmmsg` receiver so the ingest loop stays platform-neutral.
pub struct BatchReceiver {
    core: Arc<RioCore>,
    results: Vec<RIORESULT>,
    batch: Vec<(u32, usize)>, // (slot idx, bytes) for the current harvest
    pending: Vec<u32>,        // slots consumed last harvest, awaiting re-post
    armed: bool,              // is the CQ notification currently armed?
}

// Only ever used by its owning ingest thread.
unsafe impl Send for BatchReceiver {}

impl BatchReceiver {
    /// Harvests up to [`DEQ`] completed receives. Re-posts the previous harvest's
    /// buffers first (done being processed by now). When the queue is empty it
    /// waits briefly on the RIO completion event (re-arming the one-shot
    /// notification as needed) and returns a `WouldBlock` error (treated as an
    /// idle timeout by the ingest loop) if nothing arrives.
    pub fn recv(&mut self, _sock: &UdpSocket) -> io::Result<usize> {
        // Re-post the previous harvest's slots. A re-post can fail transiently
        // (e.g. WSAENOBUFS, 10055, under send/receive RQ pressure during a NACK
        // storm); on failure we MUST keep the slot queued and retry next call,
        // not drop it. Dropping leaks the slot from the fixed pool, and since
        // slots are only ever re-posted from harvested completions, a leaked
        // slot never returns — enough leaks and the pool empties, no completions
        // ever land, and the receiver wedges permanently (OS keeps receiving
        // datagrams it has no buffer for). `retain` keeps the ones that failed.
        let core = &self.core;
        self.pending.retain(|&idx| core.post_recv(idx as usize).is_err());
        self.batch.clear();

        let dequeue = self.core.rio.RIODequeueCompletion.unwrap();
        let mut n = unsafe { dequeue(self.core.cq, self.results.as_mut_ptr(), DEQ as u32) };
        if n == 0 {
            // Nothing pending: arm the one-shot notification (if not already
            // armed), wait briefly for the event, then dequeue what landed.
            if !self.armed {
                self.core.arm_notify()?;
                self.armed = true;
            }
            let w = unsafe { WaitForSingleObject(self.core.event, 25) };
            if w == WAIT_OBJECT_0 {
                self.armed = false; // auto-reset event consumed the notification
                n = unsafe { dequeue(self.core.cq, self.results.as_mut_ptr(), DEQ as u32) };
            }
        }
        if n == windows_sys::Win32::Networking::WinSock::RIO_CORRUPT_CQ {
            return Err(io::Error::other("RIO completion queue corrupt"));
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "rio idle"));
        }
        for k in 0..n as usize {
            let res = &self.results[k];
            // Skip send completions (feedback path): their slot is the send ring,
            // not a receive slot, and must not be re-posted as a receive.
            if res.RequestContext as usize == SEND_CTX {
                continue;
            }
            let idx = res.RequestContext as u32;
            let bytes = res.BytesTransferred as usize;
            // A failed completion reports Status != 0 / 0 bytes; treat as empty
            // (the caller skips it) but still re-post the slot.
            let bytes = if res.Status == 0 { bytes } else { 0 };
            self.batch.push((idx, bytes));
            self.pending.push(idx);
        }
        Ok(self.batch.len())
    }

    pub fn message(&self, i: usize) -> RecvMsg<'_> {
        let (idx, bytes) = self.batch[i];
        let n = bytes.min(self.core.buf_len);
        let off = idx as usize * self.core.buf_len;
        let data = unsafe { std::slice::from_raw_parts(self.core.data_ptr.add(off), n) };
        let addr = unsafe { self.parse_addr(idx) };
        RecvMsg { data, addr }
    }

    /// Mutable view of harvested datagram `i` (for in-place decryption).
    pub fn message_mut(&mut self, i: usize) -> (&mut [u8], Option<SocketAddr>) {
        let (idx, bytes) = self.batch[i];
        let n = bytes.min(self.core.buf_len);
        let off = idx as usize * self.core.buf_len;
        let addr = unsafe { self.parse_addr(idx) };
        let data = unsafe { std::slice::from_raw_parts_mut(self.core.data_ptr.add(off), n) };
        (data, addr)
    }

    /// Parses the captured `SOCKADDR_INET` for slot `idx`.
    unsafe fn parse_addr(&self, idx: u32) -> Option<SocketAddr> {
        let p = self.core.addr_ptr.add(idx as usize * ADDR_SLOT) as *const SOCKADDR_INET;
        let fam = (*p).si_family;
        match fam {
            AF_INET => {
                let sin = &(*p).Ipv4 as *const SOCKADDR_IN;
                let ip = Ipv4Addr::from(u32::from_be((*sin).sin_addr.S_un.S_addr));
                let port = u16::from_be((*sin).sin_port);
                Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            AF_INET6 => {
                let sin6 = &(*p).Ipv6 as *const SOCKADDR_IN6;
                let ip = Ipv6Addr::from((*sin6).sin6_addr.u.Byte);
                let port = u16::from_be((*sin6).sin6_port);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    (*sin6).sin6_flowinfo,
                    (*sin6).Anonymous.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

// Silence "field is never read": `data`/`_addr` exist to own the registered
// regions for the core's lifetime; access goes through the raw pointers.
#[allow(dead_code)]
fn _keep_regions_alive(c: &RioCore) -> (&[u8], usize, usize) {
    (&c.data, c.data_descs.len(), c.addr_descs.len())
}
