//! Atomically-updated counters/gauges shared between the data-plane threads and
//! the periodic reporter. The hot path only does cheap atomic adds; gauges
//! (rates, RTTs) are written by a single owner thread and read by the reporter.

use std::io::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Stats {
    // Counters (monotonic).
    pub bytes_sent: AtomicU64,
    pub packets_sent: AtomicU64,
    pub retrans_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub packets_recv: AtomicU64,
    pub payload_recv: AtomicU64,
    pub dup_recv: AtomicU64,
    pub corrupt_recv: AtomicU64,
    pub nacks_sent: AtomicU64,
    pub nacks_recv: AtomicU64,
    pub blocks_written: AtomicU64,

    // Gauges (current values; single-writer).
    pub target_rate_bps: AtomicU64,
    pub srtt_path_us: AtomicU64,
    pub srtt_net_us: AtomicU64,
    pub base_rtt_us: AtomicU64,
    pub rto_us: AtomicU64,
    pub rex_queue_len: AtomicI64,
    pub hi_contig: AtomicU64,

    // Transfer descriptors.
    pub total_bytes: AtomicU64,
    pub total_blocks: AtomicU64,

    start: Instant,
}

#[derive(Clone, Copy)]
struct Snapshot {
    t: Instant,
    bytes_sent: u64,
    bytes_recv: u64,
    payload_recv: u64,
}

fn mbps(delta_bytes: u64, dt: f64) -> f64 {
    delta_bytes as f64 * 8.0 / 1e6 / dt
}

fn pct(a: u64, b: u64) -> f64 {
    if b == 0 {
        0.0
    } else {
        a as f64 / b as f64 * 100.0
    }
}

fn qdelay_ms(srtt_net: u64, base: u64) -> f64 {
    if srtt_net < base {
        0.0
    } else {
        (srtt_net - base) as f64 / 1000.0
    }
}

pub fn human_bytes(b: u64) -> String {
    const UNIT: u64 = 1024;
    if b < UNIT {
        return format!("{} B", b);
    }
    let mut div = UNIT;
    let mut exp = 0usize;
    let mut n = b / UNIT;
    while n >= UNIT {
        div *= UNIT;
        exp += 1;
        n /= UNIT;
    }
    let prefix = ['K', 'M', 'G', 'T', 'P', 'E'][exp];
    format!("{:.2} {}iB", b as f64 / div as f64, prefix)
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            bytes_sent: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            retrans_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            payload_recv: AtomicU64::new(0),
            dup_recv: AtomicU64::new(0),
            corrupt_recv: AtomicU64::new(0),
            nacks_sent: AtomicU64::new(0),
            nacks_recv: AtomicU64::new(0),
            blocks_written: AtomicU64::new(0),
            target_rate_bps: AtomicU64::new(0),
            srtt_path_us: AtomicU64::new(0),
            srtt_net_us: AtomicU64::new(0),
            base_rtt_us: AtomicU64::new(0),
            rto_us: AtomicU64::new(0),
            rex_queue_len: AtomicI64::new(0),
            hi_contig: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            total_blocks: AtomicU64::new(0),
            start: Instant::now(),
        }
    }
}

impl Stats {
    pub fn new() -> Arc<Stats> {
        Arc::new(Stats::default())
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn snap(&self) -> Snapshot {
        Snapshot {
            t: Instant::now(),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            payload_recv: self.payload_recv.load(Ordering::Relaxed),
        }
    }

    /// Periodically writes a parseable `key=value` line to stderr until `stop`
    /// is set. `role` is "send" or "recv". Polls `stop` at fine granularity so
    /// a long report interval never delays shutdown.
    pub fn run_reporter(
        self: &Arc<Self>,
        role: &str,
        interval: Duration,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let slice = Duration::from_millis(50).min(interval);
        let mut prev = self.snap();
        let mut last = Instant::now();
        loop {
            std::thread::sleep(slice);
            if stop.load(Ordering::Relaxed) {
                return;
            }
            if last.elapsed() < interval {
                continue;
            }
            let cur = self.snap();
            let mut dt = cur.t.duration_since(prev.t).as_secs_f64();
            if dt <= 0.0 {
                dt = interval.as_secs_f64();
            }
            let line = self.format_line(role, dt, &prev, &cur);
            let _ = writeln!(std::io::stderr(), "{}", line);
            prev = cur;
            last = Instant::now();
        }
    }

    fn format_line(&self, role: &str, dt: f64, prev: &Snapshot, cur: &Snapshot) -> String {
        let el = self.elapsed().as_secs_f64();
        if role == "send" {
            return format!(
                "t={:.1} role=send wire_mbps={:.1} target_mbps={:.1} pkts={} retrans={} nacks_in={} rexq={} hicontig={}/{}",
                el,
                mbps(cur.bytes_sent - prev.bytes_sent, dt),
                self.target_rate_bps.load(Ordering::Relaxed) as f64 / 1e6,
                self.packets_sent.load(Ordering::Relaxed),
                self.retrans_sent.load(Ordering::Relaxed),
                self.nacks_recv.load(Ordering::Relaxed),
                self.rex_queue_len.load(Ordering::Relaxed),
                self.hi_contig.load(Ordering::Relaxed),
                self.total_blocks.load(Ordering::Relaxed),
            );
        }
        let pr = self.packets_recv.load(Ordering::Relaxed);
        let loss = if pr > 0 {
            self.dup_recv.load(Ordering::Relaxed) as f64 / pr as f64 * 100.0
        } else {
            0.0
        };
        let srtt_net = self.srtt_net_us.load(Ordering::Relaxed);
        let base = self.base_rtt_us.load(Ordering::Relaxed);
        format!(
            "t={:.1} role=recv wire_mbps={:.1} goodput_mbps={:.1} pkts={} dup={}({:.2}%) corrupt={} nacks_out={} losstab={} \
srtt_path_ms={:.1} srtt_net_ms={:.1} base_ms={:.1} rto_ms={:.1} qdelay_ms={:.1} target_mbps={:.1} hicontig={}/{}",
            el,
            mbps(cur.bytes_recv - prev.bytes_recv, dt),
            mbps(cur.payload_recv - prev.payload_recv, dt),
            pr,
            self.dup_recv.load(Ordering::Relaxed), loss,
            self.corrupt_recv.load(Ordering::Relaxed),
            self.nacks_sent.load(Ordering::Relaxed),
            self.rex_queue_len.load(Ordering::Relaxed),
            self.srtt_path_us.load(Ordering::Relaxed) as f64 / 1000.0,
            srtt_net as f64 / 1000.0,
            base as f64 / 1000.0,
            self.rto_us.load(Ordering::Relaxed) as f64 / 1000.0,
            qdelay_ms(srtt_net, base),
            self.target_rate_bps.load(Ordering::Relaxed) as f64 / 1e6,
            self.hi_contig.load(Ordering::Relaxed),
            self.total_blocks.load(Ordering::Relaxed),
        )
    }

    /// Final human-readable one-line report.
    pub fn summary(&self, role: &str) -> String {
        let mut el = self.elapsed().as_secs_f64();
        if el <= 0.0 {
            el = 1e-9;
        }
        if role == "send" {
            return format!(
                "girth send complete: {} in {:.2}s (wire {:.1} Mbps) | pkts={} retrans={} ({:.2}%) nacks_in={}",
                human_bytes(self.total_bytes.load(Ordering::Relaxed)),
                el,
                self.bytes_sent.load(Ordering::Relaxed) as f64 * 8.0 / 1e6 / el,
                self.packets_sent.load(Ordering::Relaxed),
                self.retrans_sent.load(Ordering::Relaxed),
                pct(self.retrans_sent.load(Ordering::Relaxed), self.packets_sent.load(Ordering::Relaxed)),
                self.nacks_recv.load(Ordering::Relaxed),
            );
        }
        format!(
            "girth recv complete: {} in {:.2}s (goodput {:.1} Mbps, wire {:.1} Mbps) | pkts={} dup={} ({:.2}%) corrupt={} nacks_out={}",
            human_bytes(self.total_bytes.load(Ordering::Relaxed)),
            el,
            self.payload_recv.load(Ordering::Relaxed) as f64 * 8.0 / 1e6 / el,
            self.bytes_recv.load(Ordering::Relaxed) as f64 * 8.0 / 1e6 / el,
            self.packets_recv.load(Ordering::Relaxed),
            self.dup_recv.load(Ordering::Relaxed),
            pct(self.dup_recv.load(Ordering::Relaxed), self.packets_recv.load(Ordering::Relaxed)),
            self.corrupt_recv.load(Ordering::Relaxed),
            self.nacks_sent.load(Ordering::Relaxed),
        )
    }
}
