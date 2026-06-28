//! Sending data plane: paced injection at the target rate, with retransmissions
//! (lowest sequence first) always sent before new blocks.
//!
//! Thread layout (mirrors the Go goroutines):
//!   - one prefetch thread reads blocks sequentially from disk into pooled PDU
//!     buffers (header + CRC, or AEAD seal) and publishes them in order;
//!   - one feedback thread reads FEEDBACK PDUs, queues NACKs, adopts the target
//!     rate (adaptive), echoes timing ticks, and watches for DONE;
//!   - the calling thread runs the high-precision pacing loop.

use crate::crypto::AeadBox;
use crate::io::BlockSource;
use crate::protocol::*;
use crate::rate::{RateConfig, RateMode};
use crate::stats::Stats;
use crate::sys::{self, BatchSender};
use crate::util::precise_sleep_us;
use crossbeam_channel::{bounded, Receiver, Sender as ChanSender, TryRecvError};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_BATCH: usize = 64;

pub struct SendConfig {
    pub sock: Arc<UdpSocket>,
    /// Receiver UDP addr; `None` => learned from the first packet (START).
    pub peer: Option<SocketAddr>,
    pub source: Arc<dyn BlockSource>,
    pub file_size: i64,
    pub block_size: usize,
    pub total_blocks: u64,
    pub session: u32,
    pub rate: RateConfig,
    pub read_workers: usize,
    pub crypto: Option<Arc<AeadBox>>,
    pub stats: Arc<Stats>,
}

#[derive(Default)]
struct RexQueue {
    heap: BinaryHeap<Reverse<u64>>,
    set: HashSet<u64>,
}

#[derive(Default)]
struct TickState {
    pending: bool,
    val: u64,
    is_net: bool,
    t2: u64,
}

struct Shared {
    sock: Arc<UdpSocket>,
    source: Arc<dyn BlockSource>,
    file_size: i64,
    block_size: usize,
    total_blocks: u64,
    session: u32,
    rate_mode: RateMode,
    crypto: Option<Arc<AeadBox>>,
    stats: Arc<Stats>,

    peer: SocketAddr,
    target_bps: AtomicU64,
    done: AtomicBool,

    rex: Mutex<RexQueue>,
    tick: Mutex<TickState>,
}

struct Prefetched {
    buf: Vec<u8>,
    size: usize,
}

pub struct Sender {
    cfg: SendConfig,
}

impl Sender {
    pub fn new(mut cfg: SendConfig) -> Self {
        if cfg.read_workers == 0 {
            cfg.read_workers = 2;
        }
        let init = if cfg.rate.target_bps == 0 {
            cfg.rate.max_bps
        } else {
            cfg.rate.target_bps
        };
        cfg.stats
            .total_bytes
            .store(cfg.file_size as u64, Ordering::Relaxed);
        cfg.stats
            .total_blocks
            .store(cfg.total_blocks, Ordering::Relaxed);
        cfg.stats.target_rate_bps.store(init, Ordering::Relaxed);
        Sender { cfg }
    }

    fn overhead(&self) -> usize {
        self.cfg.crypto.as_ref().map(|c| c.overhead()).unwrap_or(0)
    }

    /// Runs the transfer, returning once the receiver acknowledges DONE.
    pub fn run(self, stop: &Arc<AtomicBool>) -> io::Result<()> {
        // Learn the receiver's UDP address if not provided (NAT-friendly: the
        // receiver sends START first).
        let peer = match self.cfg.peer {
            Some(p) => p,
            None => wait_for_peer(&self.cfg.sock, stop)?,
        };

        let init = self.cfg.stats.target_rate_bps.load(Ordering::Relaxed);
        let shared = Arc::new(Shared {
            sock: self.cfg.sock.clone(),
            source: self.cfg.source.clone(),
            file_size: self.cfg.file_size,
            block_size: self.cfg.block_size,
            total_blocks: self.cfg.total_blocks,
            session: self.cfg.session,
            rate_mode: self.cfg.rate.mode,
            crypto: self.cfg.crypto.clone(),
            stats: self.cfg.stats.clone(),
            peer,
            target_bps: AtomicU64::new(init),
            done: AtomicBool::new(false),
            rex: Mutex::new(RexQueue::default()),
            tick: Mutex::new(TickState::default()),
        });

        let overhead = self.overhead();
        let buf_len = self.cfg.block_size + DATA_HEADER_SIZE + overhead;

        // Buffer pool + ready queue between the prefetch thread and pacer.
        let (free_tx, free_rx) = bounded::<Vec<u8>>(4096);
        let (ready_tx, ready_rx) = bounded::<Prefetched>(4096);
        for _ in 0..4096 {
            free_tx.send(vec![0u8; buf_len]).unwrap();
        }

        let mut handles = Vec::new();

        // Feedback reader.
        {
            let sh = shared.clone();
            let stop = stop.clone();
            handles.push(std::thread::spawn(move || feedback_loop(&sh, &stop)));
        }

        // Single sequential prefetch reader (preserves global block order on the
        // wire so in-flight blocks are not mistaken for loss).
        if self.cfg.total_blocks > 0 {
            let sh = shared.clone();
            let stop = stop.clone();
            let free_rx = free_rx.clone();
            handles.push(std::thread::spawn(move || {
                prefetch(&sh, 0, sh.total_blocks, &free_rx, &ready_tx, &stop);
            }));
        } else {
            drop(ready_tx); // no producer: ready closes immediately
        }

        let err = pacing_loop(&shared, buf_len, &free_tx, &ready_rx, stop);

        shared.done.store(true, Ordering::Relaxed);
        crate::util::trace("send: done (DONE received / pacing loop exited)");
        for h in handles {
            let _ = h.join();
        }
        err
    }
}

fn wait_for_peer(sock: &UdpSocket, stop: &Arc<AtomicBool>) -> io::Result<SocketAddr> {
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::other("stopped while waiting for receiver"));
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::other("timed out waiting for receiver START"));
        }
        match sock.recv_from(&mut buf) {
            Ok((_, addr)) => return Ok(addr),
            Err(e) if sys::is_timeout(&e) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Reads blocks `[lo, hi)` from disk into pooled PDU buffers (header + CRC, or
/// AEAD seal) and publishes them in order.
fn prefetch(
    sh: &Shared,
    lo: u64,
    hi: u64,
    free_rx: &Receiver<Vec<u8>>,
    ready_tx: &ChanSender<Prefetched>,
    stop: &Arc<AtomicBool>,
) {
    for seq in lo..hi {
        // Borrow a pooled buffer.
        let mut buf = loop {
            if stop.load(Ordering::Relaxed) || sh.done.load(Ordering::Relaxed) {
                return;
            }
            match free_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(b) => break b,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(_) => return,
            }
        };

        let off = seq * sh.block_size as u64;
        let mut plen = sh.block_size;
        let rem = sh.file_size - off as i64;
        if rem < plen as i64 {
            plen = rem as usize;
        }
        if sh
            .source
            .read_exact_at(off, &mut buf[DATA_HEADER_SIZE..DATA_HEADER_SIZE + plen])
            .is_err()
        {
            return;
        }

        let mut flags = 0u8;
        if seq == sh.total_blocks - 1 {
            flags |= FLAG_LAST_BLOCK;
        }
        let crc = if sh.crypto.is_none() {
            crc32c(&buf[DATA_HEADER_SIZE..DATA_HEADER_SIZE + plen])
        } else {
            0
        };
        encode_data_header(
            &mut buf,
            &DataHeader {
                flags,
                payload_len: plen as u16,
                session: sh.session,
                block_seq: seq,
                payload_crc: crc,
                ..Default::default()
            },
        );
        let size = match &sh.crypto {
            Some(c) => c.seal_data(&mut buf, DATA_HEADER_SIZE, plen, seq),
            None => DATA_HEADER_SIZE + plen,
        };

        if ready_tx.send(Prefetched { buf, size }).is_err() {
            return;
        }
    }
}

/// High-precision injector implementing the patent's batch + lag-compensation
/// design with absolute-deadline (self-correcting) scheduling.
fn pacing_loop(
    sh: &Arc<Shared>,
    buf_len: usize,
    free_tx: &ChanSender<Vec<u8>>,
    ready_rx: &Receiver<Prefetched>,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let sock = sh.sock.clone();
    let mut bs = BatchSender::new(&sock, sh.peer, 1024);

    let mut rex_scratch: Vec<Vec<u8>> = Vec::new();
    let mut new_bufs: Vec<Vec<u8>> = Vec::with_capacity(MAX_BATCH);

    let pacing = std::env::var_os("GIRTH_PACE").is_some_and(|v| v == "1");

    let mut cur_rate = 0u64;
    let mut ipd_us = 0.0f64;
    let mut batch = 1.0f64;

    let recompute = |rate: u64, cur_rate: &mut u64, ipd_us: &mut f64, batch: &mut f64| {
        let rate = rate.max(1);
        let block_bits = (sh.block_size + DATA_HEADER_SIZE) as f64 * 8.0;
        let ipd = block_bits / rate as f64 * 1e6; // micros per packet
        if ipd < 5000.0 {
            *batch = (5000.0 / ipd) as i64 as f64 + 1.0;
            if *batch > MAX_BATCH as f64 {
                *batch = MAX_BATCH as f64;
            }
            *ipd_us = block_bits * *batch / rate as f64 * 1e6;
        } else {
            *batch = 1.0;
            *ipd_us = ipd;
        }
        *cur_rate = rate;
        if pacing {
            sys::set_max_pacing_rate(&sock, rate + rate / 16);
        }
    };
    recompute(
        sh.target_bps.load(Ordering::Relaxed),
        &mut cur_rate,
        &mut ipd_us,
        &mut batch,
    );

    let mut new_done = false;
    let mut next_deadline = now_micros() as f64;
    let mut first_flush_logged = false;
    let mut all_injected_logged = false;

    loop {
        if sh.done.load(Ordering::Relaxed) {
            return Ok(());
        }
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::other("sender stopped"));
        }

        let r = sh.target_bps.load(Ordering::Relaxed);
        if r != cur_rate {
            recompute(r, &mut cur_rate, &mut ipd_us, &mut batch);
        }

        // Build one batch: retransmissions first (lowest seq), then new blocks.
        let to_send = batch as usize;
        bs.reset();
        new_bufs.clear();
        let mut rex_idx = 0usize;
        let mut rex_bytes = 0u64;
        let mut new_bytes = 0u64;
        let mut rex_n = 0usize;
        let mut new_n = 0usize;
        let mut built = 0usize;

        while built < to_send {
            if let Some(seq) = pop_retransmit(sh) {
                if rex_idx == rex_scratch.len() {
                    rex_scratch.push(vec![0u8; buf_len]);
                }
                if let Some(n) = fill_retransmit(sh, &mut rex_scratch[rex_idx], seq) {
                    attach_tick(sh, &mut rex_scratch[rex_idx]);
                    bs.add(&rex_scratch[rex_idx][..n]);
                    rex_bytes += n as u64;
                    rex_n += 1;
                    rex_idx += 1;
                    built += 1;
                }
                continue;
            }
            if new_done {
                break;
            }
            match ready_rx.try_recv() {
                Ok(mut item) => {
                    attach_tick(sh, &mut item.buf);
                    bs.add(&item.buf[..item.size]);
                    new_bytes += item.size as u64;
                    new_n += 1;
                    new_bufs.push(item.buf);
                    built += 1;
                }
                Err(TryRecvError::Empty) => {
                    built = to_send; // nothing ready; flush and retry next tick
                }
                Err(TryRecvError::Disconnected) => {
                    new_done = true;
                }
            }
        }

        // One syscall sends the whole batch.
        bs.flush();
        if !first_flush_logged && (rex_n > 0 || new_n > 0) {
            first_flush_logged = true;
            crate::util::trace("send: first data batch flushed");
        }
        if rex_n > 0 {
            sh.stats
                .retrans_sent
                .fetch_add(rex_n as u64, Ordering::Relaxed);
            sh.stats
                .packets_sent
                .fetch_add(rex_n as u64, Ordering::Relaxed);
            sh.stats.bytes_sent.fetch_add(rex_bytes, Ordering::Relaxed);
        }
        if new_n > 0 {
            sh.stats
                .packets_sent
                .fetch_add(new_n as u64, Ordering::Relaxed);
            sh.stats.bytes_sent.fetch_add(new_bytes, Ordering::Relaxed);
        }
        for b in new_bufs.drain(..) {
            let _ = free_tx.send(b);
        }

        // Phase 2: all new blocks injected. Announce FIN until DONE.
        if new_done && rex_len(sh) == 0 {
            if !all_injected_logged {
                all_injected_logged = true;
                crate::util::trace("send: all new blocks injected (entering FIN/rex phase)");
            }
            send_fin(sh);
        }

        // Absolute-deadline pacing.
        next_deadline += ipd_us;
        let now = now_micros() as f64;
        if now < next_deadline {
            precise_sleep_us(next_deadline - now);
        } else if now - next_deadline > 100.0 * ipd_us {
            next_deadline = now; // fell too far behind; resynchronise
        }
    }
}

fn fill_retransmit(sh: &Shared, buf: &mut [u8], seq: u64) -> Option<usize> {
    let off = seq * sh.block_size as u64;
    let mut plen = sh.block_size;
    let rem = sh.file_size - off as i64;
    if rem < plen as i64 {
        plen = rem as usize;
    }
    if plen == 0 || (rem <= 0) {
        return None;
    }
    sh.source
        .read_exact_at(off, &mut buf[DATA_HEADER_SIZE..DATA_HEADER_SIZE + plen])
        .ok()?;
    let mut flags = FLAG_RETRANSMIT;
    if seq == sh.total_blocks - 1 {
        flags |= FLAG_LAST_BLOCK;
    }
    let crc = if sh.crypto.is_none() {
        crc32c(&buf[DATA_HEADER_SIZE..DATA_HEADER_SIZE + plen])
    } else {
        0
    };
    encode_data_header(
        buf,
        &DataHeader {
            flags,
            payload_len: plen as u16,
            session: sh.session,
            block_seq: seq,
            rex_index: seq as i64,
            payload_crc: crc,
            ..Default::default()
        },
    );
    Some(match &sh.crypto {
        Some(c) => c.seal_data(buf, DATA_HEADER_SIZE, plen, seq),
        None => DATA_HEADER_SIZE + plen,
    })
}

/// Stamps a pending echo tick into a DATA PDU header if one is waiting. For
/// network ("N") ticks the sender's own processing delay (now - T2) is added so
/// the receiver measures network-only RTT.
fn attach_tick(sh: &Shared, buf: &mut [u8]) {
    let mut t = sh.tick.lock().unwrap();
    if !t.pending {
        return;
    }
    let tick = t.val;
    let is_net = t.is_net;
    let t2 = t.t2;
    t.pending = false;
    drop(t);

    let mut echo = tick;
    let mut flags = buf[1] | FLAG_HAS_TICK;
    if is_net {
        flags |= FLAG_TICK_N;
        echo = tick + (now_micros() - t2);
    } else {
        flags &= !FLAG_TICK_N;
    }
    buf[1] = flags;
    put_echo_tick(buf, echo);
}

fn send_fin(sh: &Shared) {
    let mut b = [0u8; 16];
    let n = encode_fin(&mut b, sh.session, sh.total_blocks);
    let _ = sh.sock.send_to(&b[..n], sh.peer);
}

/// Reads FEEDBACK PDUs: records the timing tick, queues NACKs, adopts the
/// receiver's target rate (adaptive), and watches for DONE.
fn feedback_loop(sh: &Shared, stop: &Arc<AtomicBool>) {
    let mut buf = [0u8; 2048];
    loop {
        if sh.done.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
            return;
        }
        let n = match sh.sock.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(e) if sys::is_timeout(&e) => continue,
            Err(_) => return,
        };
        if pdu_type(&buf[..n]) != PDU_FEEDBACK {
            continue;
        }
        let t2 = now_micros();
        let Some((fh, nacks)) = decode_feedback(&buf[..n]) else {
            continue;
        };
        if fh.session != sh.session {
            continue;
        }

        {
            let mut t = sh.tick.lock().unwrap();
            t.pending = true;
            t.val = fh.tick;
            t.is_net = fh.tick_is_network;
            t.t2 = t2;
        }

        if !nacks.is_empty() {
            sh.stats
                .nacks_recv
                .fetch_add(nacks.len() as u64, Ordering::Relaxed);
            push_retransmits(sh, &nacks);
        }

        if sh.rate_mode == RateMode::Adaptive && fh.target_rate > 0 {
            sh.target_bps.store(fh.target_rate, Ordering::Relaxed);
            sh.stats
                .target_rate_bps
                .store(fh.target_rate, Ordering::Relaxed);
        }
        sh.stats.hi_contig.store(fh.hi_contig, Ordering::Relaxed);

        if fh.done {
            sh.done.store(true, Ordering::Relaxed);
            return;
        }
    }
}

// --- retransmit queue -------------------------------------------------------

fn push_retransmits(sh: &Shared, nacks: &[NackEntry]) {
    let mut q = sh.rex.lock().unwrap();
    for n in nacks {
        if q.set.insert(n.block_seq) {
            q.heap.push(Reverse(n.block_seq));
        }
    }
    sh.stats
        .rex_queue_len
        .store(q.set.len() as i64, Ordering::Relaxed);
}

fn pop_retransmit(sh: &Shared) -> Option<u64> {
    let mut q = sh.rex.lock().unwrap();
    let Reverse(seq) = q.heap.pop()?;
    q.set.remove(&seq);
    sh.stats
        .rex_queue_len
        .store(q.set.len() as i64, Ordering::Relaxed);
    Some(seq)
}

fn rex_len(sh: &Shared) -> usize {
    sh.rex.lock().unwrap().heap.len()
}
