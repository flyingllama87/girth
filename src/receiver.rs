//! Receiving data plane. The per-packet ingest path (parallel across cores)
//! does only order-independent work — integrity check, atomic bitmap set, RTT
//! tick, and staging. All loss detection and NACK scheduling lives in the
//! single feedback thread, which scans the bitmap on a real-time RTO basis,
//! making loss detection immune to in-flight reordering. A single in-order
//! flusher writes blocks to disk strictly at the advancing frontier so the
//! on-disk pattern stays sequential regardless of arrival order.

use crate::crypto::AeadBox;
use crate::io::BlockSink;
use crate::losstracker::{LossScanner, RecvBitmap};
use crate::protocol::*;
use crate::rate::{RateConfig, RateController, RttEstimator};
use crate::stats::Stats;
use crate::sys::{self, BatchReceiver};
use crate::util::num_cpu;
use crossbeam_channel::{bounded, Receiver, Sender as ChanSender};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct RecvConfig {
    pub sock: Arc<UdpSocket>,
    pub sink: Arc<dyn BlockSink>,
    pub file_size: i64,
    pub block_size: usize,
    pub total_blocks: u64,
    pub session: u32,
    pub read_workers: usize,
    pub rate: RateConfig,
    pub crypto: Option<Arc<AeadBox>>,
    pub feedback_interval_us: u32,
    pub net_tick_interval_us: u32,
    pub max_nacks_per_pdu: usize,
    pub stats: Arc<Stats>,
    /// For client-pull only: the sender's data address. The receiver must send
    /// START here to bootstrap the flow (the sender waits for it). This goes via
    /// the platform feedback path, since the RIO data socket on Windows cannot
    /// use the standard `send_to`. `None` for the server-side push receiver,
    /// which learns its peer passively from the first inbound DATA.
    pub start_peer: Option<SocketAddr>,
}

struct RttState {
    path: RttEstimator,
    net: RttEstimator,
    rate: RateController,
}

struct Shared {
    sock: Arc<UdpSocket>,
    sink: Arc<dyn BlockSink>,
    file_size: i64,
    block_size: usize,
    total_blocks: u64,
    session: u32,
    crypto: Option<Arc<AeadBox>>,
    feedback_interval_us: u32,
    net_tick_interval_us: u32,
    max_nacks_per_pdu: usize,
    stats: Arc<Stats>,
    start_peer: Option<SocketAddr>,

    bm: Arc<RecvBitmap>,
    ready_bm: Arc<RecvBitmap>,
    max_seen: AtomicU64,
    seen_any: AtomicBool,
    all_sent: AtomicBool,
    done: AtomicBool,

    peer: Mutex<Option<SocketAddr>>,
    rtt: Mutex<RttState>,

    stage: Mutex<HashMap<u64, Vec<u8>>>,
    free_tx: ChanSender<Vec<u8>>,
    free_rx: Receiver<Vec<u8>>,
    flush_tx: ChanSender<()>,
    flush_rx: Receiver<()>,
}

pub struct Receiver_ {
    sh: Arc<Shared>,
    read_workers: usize,
}

/// Builds a receiver from `cfg`.
pub fn new_receiver(mut cfg: RecvConfig) -> Receiver_ {
    if cfg.read_workers == 0 {
        cfg.read_workers = num_cpu();
    }
    // Windows uses a single ingest worker: the RIO receive engine (sys::rio)
    // drains the completion queue without per-packet syscalls, so one thread
    // keeps well ahead of the path, and a single owner means the RIO queues need
    // no locking.
    #[cfg(target_os = "windows")]
    {
        cfg.read_workers = 1;
    }
    if cfg.feedback_interval_us == 0 {
        cfg.feedback_interval_us = 5000;
    }
    if cfg.net_tick_interval_us == 0 {
        cfg.net_tick_interval_us = 10000;
    }
    if cfg.max_nacks_per_pdu == 0 {
        cfg.max_nacks_per_pdu = 90; // keeps feedback PDU under a 1500B MTU
    }

    // Staging pool to absorb the out-of-order window (~96 MiB), capped so memory
    // stays bounded on small hosts; blocks beyond it fall back to direct writes.
    let mut depth = (96 << 20) / cfg.block_size;
    if cfg.total_blocks > 0 && depth as u64 > cfg.total_blocks {
        depth = cfg.total_blocks as usize;
    }
    if depth < 1 {
        depth = 1;
    }
    let (free_tx, free_rx) = bounded::<Vec<u8>>(depth);
    crate::util::trace("recv: building stage pool");
    for _ in 0..depth {
        free_tx.send(Vec::with_capacity(cfg.block_size)).unwrap();
    }
    crate::util::trace("recv: stage pool built");
    let (flush_tx, flush_rx) = bounded::<()>(1);

    cfg.stats
        .total_bytes
        .store(cfg.file_size as u64, Ordering::Relaxed);
    cfg.stats
        .total_blocks
        .store(cfg.total_blocks, Ordering::Relaxed);
    cfg.stats
        .target_rate_bps
        .store(cfg.rate.target_bps, Ordering::Relaxed);

    let sh = Arc::new(Shared {
        sock: cfg.sock,
        sink: cfg.sink,
        file_size: cfg.file_size,
        block_size: cfg.block_size,
        total_blocks: cfg.total_blocks,
        session: cfg.session,
        crypto: cfg.crypto,
        feedback_interval_us: cfg.feedback_interval_us,
        net_tick_interval_us: cfg.net_tick_interval_us,
        max_nacks_per_pdu: cfg.max_nacks_per_pdu,
        stats: cfg.stats,
        start_peer: cfg.start_peer,
        bm: Arc::new(RecvBitmap::new(cfg.total_blocks)),
        ready_bm: Arc::new(RecvBitmap::new(cfg.total_blocks)),
        max_seen: AtomicU64::new(0),
        seen_any: AtomicBool::new(false),
        all_sent: AtomicBool::new(false),
        done: AtomicBool::new(false),
        peer: Mutex::new(None),
        rtt: Mutex::new(RttState {
            path: RttEstimator::new(),
            net: RttEstimator::new(),
            rate: RateController::new(cfg.rate),
        }),
        stage: Mutex::new(HashMap::with_capacity(depth)),
        free_tx,
        free_rx,
        flush_tx,
        flush_rx,
    });
    Receiver_ {
        sh,
        read_workers: cfg.read_workers,
    }
}

impl Receiver_ {
    /// Blocks until the transfer completes or `stop` fires.
    pub fn run(self, stop: &Arc<AtomicBool>) -> io::Result<()> {
        let sh = self.sh;

        let mut handles = Vec::new();

        // Build the receive engine first: on Windows it owns the RIO socket and
        // also provides the feedback transmit path (the RIO socket cannot use the
        // standard send_to), so the feedback thread needs a handle from it.
        let mut ingest_handles = Vec::new();
        // On Linux/portable the engine is per-worker recvmmsg/recv_from; on
        // Windows it is a RIO registered-I/O receive engine (see sys::rio).
        let buf_len = sh.block_size + DATA_HEADER_SIZE + 64;
        let engine = sys::RecvEngine::new(&sh.sock, self.read_workers, buf_len)?;
        let fb = engine.feedback_sender(&sh.sock);

        // Client-pull bootstrap: the sender waits for a START before injecting
        // any DATA. Send it via the feedback path (RIOSendEx on Windows) — the
        // RIO data socket cannot use the standard `send_to`. Keep nudging until
        // the first DATA arrives, in case the START is lost on the wire.
        if let Some(peer) = sh.start_peer {
            let mut sb = [0u8; 8];
            let n = encode_start(&mut sb, sh.session);
            for _ in 0..5 {
                let _ = fb.send_to(&sb[..n], peer);
            }
            let sh = sh.clone();
            let stop = stop.clone();
            let fb = fb.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    std::thread::sleep(Duration::from_millis(200));
                    if stop.load(Ordering::Relaxed)
                        || sh.stats.packets_recv.load(Ordering::Relaxed) > 0
                    {
                        return;
                    }
                    let _ = fb.send_to(&sb[..n], peer);
                }
            }));
        }

        {
            let sh = sh.clone();
            let stop = stop.clone();
            let fb = fb.clone();
            handles.push(std::thread::spawn(move || feedback_loop(&sh, &stop, fb)));
        }
        {
            let sh = sh.clone();
            let stop = stop.clone();
            handles.push(std::thread::spawn(move || writeback_loop(&sh, &stop)));
        }
        // Flusher outlives ingest so staged blocks are written before the CRC
        // check; it is joined separately.
        let flusher = {
            let sh = sh.clone();
            let stop = stop.clone();
            std::thread::spawn(move || flusher_loop(&sh, &stop))
        };

        for _ in 0..self.read_workers {
            let br = engine.worker()?;
            let sh = sh.clone();
            let stop = stop.clone();
            ingest_handles.push(std::thread::spawn(move || ingest_loop(&sh, &stop, br)));
        }

        // Wait for completion / stop.
        while !sh.done.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(5));
        }

        crate::util::trace("recv: done detected, joining feedback/aux");
        // Join the feedback thread first: it delivers the DONE notification to
        // the sender (8 feedback PDUs) and, for a zero-length transfer, must
        // observe the peer address that ingest learns from the FIN.
        for h in handles {
            let _ = h.join();
        }
        crate::util::trace("recv: aux joined, joining ingest");
        // Ingest exits promptly: it re-checks `done` at the top of its loop, and
        // the sender's end-of-transfer packet dribble keeps recvmmsg returning
        // (so it does not idle out a full SO_RCVTIMEO before noticing `done`).
        for h in ingest_handles {
            let _ = h.join();
        }
        // All harvesters are gone; tear down the receive engine (on Windows this
        // cancels and drains the posted IOCP receives before freeing buffers; on
        // Linux/portable the engine carries no resources).
        #[allow(clippy::drop_non_drop)]
        drop(engine);
        crate::util::trace("recv: ingest joined, draining flusher");
        // Ingest has stopped; let the flusher write any remaining staged blocks.
        signal_flush(&sh);
        let _ = flusher.join();
        crate::util::trace("recv: flusher joined (run returning)");

        if sh.stats.hi_contig.load(Ordering::Relaxed) != sh.total_blocks {
            return Err(io::Error::other(format!(
                "receiver stopped before completion ({}/{} blocks)",
                sh.stats.hi_contig.load(Ordering::Relaxed),
                sh.total_blocks
            )));
        }
        Ok(())
    }
}

fn signal_flush(sh: &Shared) {
    let _ = sh.flush_tx.try_send(());
}

/// Writes received blocks to disk strictly in ascending (frontier) order, so
/// the on-disk write pattern is sequential regardless of arrival order or
/// retransmissions.
fn flusher_loop(sh: &Shared, stop: &Arc<AtomicBool>) {
    let bs = sh.block_size as u64;
    let total = sh.total_blocks;
    let mut write_front = 0u64;
    while write_front < total {
        let mut progressed = false;
        while write_front < total && sh.ready_bm.is_set(write_front) {
            let seq = write_front;
            let staged = sh.stage.lock().unwrap().remove(&seq);
            if let Some(buf) = staged {
                if let Err(e) = sh.sink.write_all_at(seq * bs, &buf) {
                    crate::log::error(&format!("recv: write error at block {}: {}", seq, e));
                }
                let _ = sh.free_tx.send(buf);
            }
            write_front += 1;
            progressed = true;
        }
        if write_front >= total {
            return;
        }
        if progressed {
            continue;
        }
        // Frontier blocked on a not-yet-received hole; wait for arrivals.
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let _ = sh.flush_rx.recv_timeout(Duration::from_millis(2));
    }
}

/// Kicks asynchronous writeback across the active (possibly holey) window so the
/// page cache never hits vm.dirty_ratio and stalls `WriteAt` in the ingest path.
fn writeback_loop(sh: &Shared, stop: &Arc<AtomicBool>) {
    if sh.total_blocks == 0 || std::env::var_os("GIRTH_NOWB").is_some() {
        return;
    }
    let bs = sh.block_size as i64;
    let mut prefix: i64 = 0;
    loop {
        if stop.load(Ordering::Relaxed) || sh.done.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
        let mut hi_w = (sh.max_seen.load(Ordering::Relaxed) as i64 + 1) * bs;
        if hi_w > sh.file_size {
            hi_w = sh.file_size;
        }
        if hi_w > prefix {
            sh.sink.sync_range(prefix, hi_w - prefix);
        }
        let c = sh.stats.hi_contig.load(Ordering::Relaxed) as i64 * bs;
        if c > prefix {
            prefix = c;
        }
    }
}

/// Reads and processes DATA/FIN PDUs. Multiple run in parallel, each harvesting
/// many datagrams per receive (recvmmsg on Linux, batched IOCP completions on
/// Windows).
fn ingest_loop(sh: &Shared, stop: &Arc<AtomicBool>, mut br: BatchReceiver) {
    loop {
        if stop.load(Ordering::Relaxed) || sh.done.load(Ordering::Relaxed) {
            return;
        }
        let n = match br.recv(&sh.sock) {
            Ok(n) => n,
            Err(e) if sys::is_timeout(&e) => {
                if sh.done.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                    return;
                }
                continue;
            }
            Err(e) => {
                eprintln!("girth [ingest-fatal] receive worker exiting: {e}");
                return;
            }
        };
        for i in 0..n {
            let (data, addr) = br.message_mut(i);
            if data.is_empty() {
                continue;
            }
            learn_peer(sh, addr);
            sh.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
            sh.stats
                .bytes_recv
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            handle_packet(sh, data);
        }
    }
}

fn learn_peer(sh: &Shared, addr: Option<SocketAddr>) {
    if let Some(a) = addr {
        let mut p = sh.peer.lock().unwrap();
        if p.is_none() {
            *p = Some(a);
        }
    }
}

fn handle_packet(sh: &Shared, pkt: &mut [u8]) {
    match pdu_type(pkt) {
        PDU_FIN => {
            if pkt.len() >= 16 {
                sh.all_sent.store(true, Ordering::Relaxed);
            }
            return;
        }
        PDU_DATA => {}
        _ => return,
    }

    let Some(h) = decode_data_header(pkt) else {
        return;
    };
    if h.session != sh.session {
        return;
    }

    let plen = h.payload_len as usize;
    let payload_start = DATA_HEADER_SIZE;
    let payload_ok_len;
    if let Some(crypto) = &sh.crypto {
        // Decrypt in place; auth failure is indistinguishable from corruption.
        match crypto.open_data(&mut pkt[payload_start..], plen, h.block_seq) {
            Some(n) => payload_ok_len = n,
            None => {
                sh.stats.corrupt_recv.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    } else {
        if payload_start + plen > pkt.len() {
            return;
        }
        let crc = crc32c(&pkt[payload_start..payload_start + plen]);
        if crc != h.payload_crc {
            sh.stats.corrupt_recv.fetch_add(1, Ordering::Relaxed);
            return;
        }
        payload_ok_len = plen;
    }

    if h.flags & FLAG_HAS_TICK != 0 {
        apply_tick(sh, &h);
    }

    sh.seen_any.store(true, Ordering::Relaxed);
    sh.max_seen.fetch_max(h.block_seq, Ordering::Relaxed);

    if !sh.bm.set_and_test(h.block_seq) {
        sh.stats.dup_recv.fetch_add(1, Ordering::Relaxed);
        return;
    }
    sh.stats
        .payload_recv
        .fetch_add(payload_ok_len as u64, Ordering::Relaxed);
    sh.stats.blocks_written.fetch_add(1, Ordering::Relaxed);

    let seq = h.block_seq;
    let payload = &pkt[payload_start..payload_start + payload_ok_len];

    // Stage for in-order (sequential) disk write if a pooled buffer is free.
    // ready_bm is set last so the flusher never advances past an unstaged block.
    match sh.free_rx.try_recv() {
        Ok(mut buf) => {
            buf.clear();
            buf.extend_from_slice(payload);
            sh.stage.lock().unwrap().insert(seq, buf);
            sh.ready_bm.set_and_test(seq);
            signal_flush(sh);
        }
        Err(_) => {
            // Stage pool exhausted: write directly (possible backward seek,
            // bounded to the overflow case).
            let off = seq * sh.block_size as u64;
            if let Err(e) = sh.sink.write_all_at(off, payload) {
                crate::log::error(&format!("recv: write error at block {}: {}", seq, e));
                return;
            }
            sh.ready_bm.set_and_test(seq);
            signal_flush(sh);
        }
    }
}

/// Converts an echoed timing tick into an RTT sample.
fn apply_tick(sh: &Shared, h: &DataHeader) {
    let sample = now_micros() as f64 - h.echo_tick as f64;
    if !(0.0..=60e6).contains(&sample) {
        return;
    }
    let mut rtt = sh.rtt.lock().unwrap();
    if h.flags & FLAG_TICK_N != 0 {
        rtt.net.sample(sample);
        sh.stats
            .srtt_net_us
            .store(rtt.net.srtt as u64, Ordering::Relaxed);
        sh.stats
            .base_rtt_us
            .store(rtt.net.min_rtt as u64, Ordering::Relaxed);
    } else {
        let rto = rtt.path.sample(sample);
        sh.stats
            .srtt_path_us
            .store(rtt.path.srtt as u64, Ordering::Relaxed);
        sh.stats.rto_us.store(rto as u64, Ordering::Relaxed);
    }
}

/// Owns all loss detection. Each tick it advances the contiguous mark, scans
/// for new holes, collects due retransmit requests, and emits a FEEDBACK PDU.
fn feedback_loop(sh: &Shared, stop: &Arc<AtomicBool>, fb: sys::FeedbackSender) {
    let interval = Duration::from_micros(sh.feedback_interval_us as u64);
    let mut scanner = LossScanner::new(sh.bm.clone(), sh.total_blocks);
    let mut buf = vec![0u8; FEEDBACK_HEADER_SIZE + sh.max_nacks_per_pdu * NACK_ENTRY_SIZE];
    let mut last_net_tick = 0u64;
    let mut done_sends = 0;
    let mut seen_logged = false;
    let mut rtt_logged = false;
    let mut allsent_logged = false;

    // Fire on a fixed wall-clock cadence, matching Go's `time.Ticker`: the
    // period stays at `interval` regardless of how long the loop body takes,
    // so the adaptive rate controller is advanced once per real interval (a
    // plain sleep-at-top would stretch the period by the body's work time,
    // under-clocking the ramp). Missed ticks are dropped, not bunched up.
    let mut next = Instant::now() + interval;

    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let now_i = Instant::now();
        if next > now_i {
            std::thread::sleep(next - now_i);
        }
        next += interval;
        // If the body overran one or more intervals, realign to "now" instead
        // of replaying a burst of catch-up ticks (Ticker drop semantics).
        let after = Instant::now();
        if next <= after {
            next = after + interval;
        }

        let now = now_micros() as f64;
        let (path_rto, srtt_net, base_net, target) = {
            let mut rtt = sh.rtt.lock().unwrap();
            let path_rto = rtt.path.rto();
            let srtt_net = rtt.net.srtt;
            let base_net = rtt.net.min_rtt;
            let target = rtt.rate.update(srtt_net, base_net);
            (path_rto, srtt_net, base_net, target)
        };
        let _ = (srtt_net, base_net);
        sh.stats.target_rate_bps.store(target, Ordering::Relaxed);

        let hi = scanner.advance();
        let mut ms = sh.max_seen.load(Ordering::Relaxed);
        if sh.all_sent.load(Ordering::Relaxed) && sh.total_blocks > 0 {
            ms = sh.total_blocks - 1;
        }
        if !seen_logged && sh.seen_any.load(Ordering::Relaxed) {
            seen_logged = true;
            crate::util::trace("recv: first data seen");
        }
        if !rtt_logged && srtt_net > 0.0 {
            rtt_logged = true;
            crate::util::trace(&format!(
                "recv: rtt established (srtt_net={:.0}us path_rto={:.0}us)",
                srtt_net, path_rto
            ));
        }
        if !allsent_logged && sh.all_sent.load(Ordering::Relaxed) {
            allsent_logged = true;
            crate::util::trace(&format!("recv: FIN/all_sent seen (hi_contig={})", hi));
        }
        if sh.seen_any.load(Ordering::Relaxed) || sh.all_sent.load(Ordering::Relaxed) {
            scanner.scan_holes(ms, now, path_rto);
        }
        let complete = scanner.completed();
        sh.stats.hi_contig.store(hi, Ordering::Relaxed);
        sh.stats
            .rex_queue_len
            .store(scanner.pending_count() as i64, Ordering::Relaxed);

        let peer = match *sh.peer.lock().unwrap() {
            Some(p) => p,
            None => continue,
        };

        // Throttle NACK volume to the sender's per-interval resend capacity.
        let block_bits = (sh.block_size + DATA_HEADER_SIZE) as f64 * 8.0;
        let mut nack_cap = sh.max_nacks_per_pdu;
        if target > 0 && block_bits > 0.0 {
            let mut per_interval =
                (target as f64 / block_bits * (sh.feedback_interval_us as f64 / 1e6)) as usize;
            if per_interval < 1 {
                per_interval = 1;
            }
            if per_interval < nack_cap {
                nack_cap = per_interval;
            }
        }
        let due = scanner.collect_due(now, path_rto, nack_cap);

        let cur_now = now_micros();
        let mut is_net = false;
        if cur_now - last_net_tick >= sh.net_tick_interval_us as u64 {
            is_net = true;
            last_net_tick = cur_now;
        }

        let nacks: Vec<NackEntry> = due
            .iter()
            .map(|&s| NackEntry {
                block_seq: s,
                rex_index: s as i64,
            })
            .collect();
        let fh = FeedbackHeader {
            tick_is_network: is_net,
            session: sh.session,
            tick: now_micros(),
            target_rate: target,
            hi_contig: hi,
            done: complete,
            ..Default::default()
        };
        let nn = encode_feedback(&mut buf, &fh, &nacks);
        if fb.send_to(&buf[..nn], peer).is_ok() && !nacks.is_empty() {
            sh.stats
                .nacks_sent
                .fetch_add(nacks.len() as u64, Ordering::Relaxed);
        }

        if complete {
            done_sends += 1;
            if done_sends >= 8 {
                crate::util::trace("recv: complete (8 done feedbacks sent)");
                sh.done.store(true, Ordering::Relaxed);
                return;
            }
        }
    }
}
