//! Atomically-updated counters/gauges shared between the data-plane threads and
//! the periodic reporter. The hot path only does cheap atomic adds; gauges
//! (rates, RTTs) are written by a single owner thread and read by the reporter.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A point-in-time copy of transfer counters and derived progress values.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub elapsed: Duration,
    pub total_bytes: u64,
    pub total_blocks: u64,
    pub block_size: u64,
    pub bytes_sent: u64,
    pub packets_sent: u64,
    pub retrans_sent: u64,
    pub bytes_recv: u64,
    pub packets_recv: u64,
    pub payload_recv: u64,
    pub dup_recv: u64,
    pub corrupt_recv: u64,
    pub nacks_sent: u64,
    pub nacks_recv: u64,
    pub blocks_written: u64,
    pub target_rate_bps: u64,
    pub srtt_path_us: u64,
    pub srtt_net_us: u64,
    pub base_rtt_us: u64,
    pub rto_us: u64,
    pub rex_queue_len: i64,
    pub hi_contig: u64,
    pub progress_bytes: u64,
    pub progress_blocks: u64,
    pub percent_complete: f64,
    pub retrans_percent: f64,
    pub duplicate_percent: f64,
    pub queue_delay_us: u64,
    pub average_send_wire_mbps: f64,
    pub average_recv_wire_mbps: f64,
    pub average_recv_goodput_mbps: f64,
}

impl StatsSnapshot {
    fn delta_secs(&self, prev: &StatsSnapshot) -> f64 {
        self.elapsed
            .checked_sub(prev.elapsed)
            .map(|d| d.as_secs_f64())
            .filter(|d| *d > 0.0)
            .unwrap_or(1e-9)
    }

    pub fn send_wire_mbps_since(&self, prev: &StatsSnapshot) -> f64 {
        mbps(
            self.bytes_sent.saturating_sub(prev.bytes_sent),
            self.delta_secs(prev),
        )
    }

    pub fn recv_wire_mbps_since(&self, prev: &StatsSnapshot) -> f64 {
        mbps(
            self.bytes_recv.saturating_sub(prev.bytes_recv),
            self.delta_secs(prev),
        )
    }

    pub fn recv_goodput_mbps_since(&self, prev: &StatsSnapshot) -> f64 {
        mbps(
            self.payload_recv.saturating_sub(prev.payload_recv),
            self.delta_secs(prev),
        )
    }
}

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
    pub block_size: AtomicU64,

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
            block_size: AtomicU64::new(0),
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

    pub fn snapshot(&self) -> StatsSnapshot {
        let elapsed = self.elapsed();
        let elapsed_secs = elapsed.as_secs_f64().max(1e-9);
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);
        let total_blocks = self.total_blocks.load(Ordering::Relaxed);
        let block_size = self.block_size.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let packets_sent = self.packets_sent.load(Ordering::Relaxed);
        let retrans_sent = self.retrans_sent.load(Ordering::Relaxed);
        let bytes_recv = self.bytes_recv.load(Ordering::Relaxed);
        let packets_recv = self.packets_recv.load(Ordering::Relaxed);
        let payload_recv = self.payload_recv.load(Ordering::Relaxed);
        let dup_recv = self.dup_recv.load(Ordering::Relaxed);
        let corrupt_recv = self.corrupt_recv.load(Ordering::Relaxed);
        let nacks_sent = self.nacks_sent.load(Ordering::Relaxed);
        let nacks_recv = self.nacks_recv.load(Ordering::Relaxed);
        let blocks_written = self.blocks_written.load(Ordering::Relaxed);
        let target_rate_bps = self.target_rate_bps.load(Ordering::Relaxed);
        let srtt_path_us = self.srtt_path_us.load(Ordering::Relaxed);
        let srtt_net_us = self.srtt_net_us.load(Ordering::Relaxed);
        let base_rtt_us = self.base_rtt_us.load(Ordering::Relaxed);
        let rto_us = self.rto_us.load(Ordering::Relaxed);
        let rex_queue_len = self.rex_queue_len.load(Ordering::Relaxed);
        let hi_contig = self.hi_contig.load(Ordering::Relaxed);
        let progress_blocks = hi_contig.max(blocks_written).min(total_blocks);
        let progress_bytes = if payload_recv > 0 {
            payload_recv.min(total_bytes)
        } else if total_bytes > 0 && block_size > 0 {
            progress_blocks.saturating_mul(block_size).min(total_bytes)
        } else {
            0
        };
        let percent_complete = if total_bytes > 0 {
            progress_bytes as f64 / total_bytes as f64 * 100.0
        } else if total_blocks == 0 {
            100.0
        } else {
            0.0
        };
        let queue_delay_us = srtt_net_us.saturating_sub(base_rtt_us);
        StatsSnapshot {
            elapsed,
            total_bytes,
            total_blocks,
            block_size,
            bytes_sent,
            packets_sent,
            retrans_sent,
            bytes_recv,
            packets_recv,
            payload_recv,
            dup_recv,
            corrupt_recv,
            nacks_sent,
            nacks_recv,
            blocks_written,
            target_rate_bps,
            srtt_path_us,
            srtt_net_us,
            base_rtt_us,
            rto_us,
            rex_queue_len,
            hi_contig,
            progress_bytes,
            progress_blocks,
            percent_complete,
            retrans_percent: pct(retrans_sent, packets_sent),
            duplicate_percent: pct(dup_recv, packets_recv),
            queue_delay_us,
            average_send_wire_mbps: mbps(bytes_sent, elapsed_secs),
            average_recv_wire_mbps: mbps(bytes_recv, elapsed_secs),
            average_recv_goodput_mbps: mbps(payload_recv, elapsed_secs),
        }
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
            crate::log::info(&line);
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
