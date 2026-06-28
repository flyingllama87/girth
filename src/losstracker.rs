//! Concurrent received-block bitmap + single-threaded loss scanner.

use crate::rate::RTT_PREC_US;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

/// A concurrent received-block bitmap. The per-packet ingest path only ever
/// sets bits (an order-independent, commutative operation), so it is safe and
/// fast to update from many threads without a global lock.
pub struct RecvBitmap {
    words: Vec<AtomicU64>,
    #[allow(dead_code)]
    total: u64,
}

impl RecvBitmap {
    pub fn new(total: u64) -> Self {
        let n = total.div_ceil(64) as usize;
        let mut words = Vec::with_capacity(n);
        for _ in 0..n {
            words.push(AtomicU64::new(0));
        }
        RecvBitmap { words, total }
    }

    /// Atomically marks `seq` received and reports whether this was the first
    /// time (`false` => duplicate).
    #[inline]
    pub fn set_and_test(&self, seq: u64) -> bool {
        let w = &self.words[(seq >> 6) as usize];
        let mask = 1u64 << (seq & 63);
        let prev = w.fetch_or(mask, Ordering::AcqRel);
        prev & mask == 0
    }

    #[inline]
    pub fn is_set(&self, seq: u64) -> bool {
        self.words[(seq >> 6) as usize].load(Ordering::Acquire) & (1u64 << (seq & 63)) != 0
    }
}

#[derive(PartialEq, Eq)]
struct HeapItem {
    due: u64,
    seq: u64,
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Order by due time, then seq (deterministic tie-break).
        self.due.cmp(&other.due).then(self.seq.cmp(&other.seq))
    }
}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Detects missing blocks and schedules retransmission requests. Owned
/// exclusively by the receiver's single feedback thread, so it needs no
/// locking. Detection is decoupled from packet ingest: because ingest only
/// sets bits, by the time the scanner runs all blocks actually received so far
/// are visible — so transient in-flight reordering can never be mistaken for
/// loss. A block is only NACKed after it has been missing for one RTO of real
/// elapsed time (the patent's "wait one RTO" rule).
pub struct LossScanner {
    bm: std::sync::Arc<RecvBitmap>,
    total: u64,
    hi_contig: u64,
    next_scan: u64, // next seq to examine for holes
    pending: HashSet<u64>,
    heap: BinaryHeap<Reverse<HeapItem>>,
}

impl LossScanner {
    pub fn new(bm: std::sync::Arc<RecvBitmap>, total: u64) -> Self {
        LossScanner {
            bm,
            total,
            hi_contig: 0,
            next_scan: 0,
            pending: HashSet::new(),
            heap: BinaryHeap::new(),
        }
    }

    /// Moves the contiguous high-water mark forward and drops pending entries
    /// that have since been filled. Returns the number of contiguous blocks.
    pub fn advance(&mut self) -> u64 {
        while self.hi_contig < self.total && self.bm.is_set(self.hi_contig) {
            self.pending.remove(&self.hi_contig);
            self.hi_contig += 1;
        }
        self.hi_contig
    }

    /// Records newly-missing blocks in `[next_scan, max_seen]` and schedules
    /// their first retransmit request at `now+rto+precision`.
    pub fn scan_holes(&mut self, mut max_seen: u64, now: f64, rto: f64) {
        if self.total == 0 {
            return;
        }
        if max_seen >= self.total {
            max_seen = self.total - 1;
        }
        let due = (now + rto + RTT_PREC_US) as u64;
        let mut seq = self.next_scan;
        while seq <= max_seen {
            if !self.bm.is_set(seq) && self.pending.insert(seq) {
                self.heap.push(Reverse(HeapItem { seq, due }));
            }
            seq += 1;
        }
        if max_seen + 1 > self.next_scan {
            self.next_scan = max_seen + 1;
        }
    }

    /// Returns up to `max` sequence numbers whose retransmit request is due,
    /// rescheduling each so the request repeats every RTO until it arrives.
    pub fn collect_due(&mut self, now: f64, rto: f64, max: usize) -> Vec<u64> {
        let mut out = Vec::new();
        let re_due = (now + rto + RTT_PREC_US) as u64;
        while out.len() < max {
            let Some(Reverse(top)) = self.heap.peek() else {
                break;
            };
            if top.due as f64 > now {
                break;
            }
            let Reverse(top) = self.heap.pop().unwrap();
            if !self.pending.contains(&top.seq) {
                continue;
            }
            if self.bm.is_set(top.seq) {
                self.pending.remove(&top.seq);
                continue;
            }
            out.push(top.seq);
            self.heap.push(Reverse(HeapItem {
                seq: top.seq,
                due: re_due,
            }));
        }
        out
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn completed(&self) -> bool {
        self.hi_contig == self.total
    }
}
