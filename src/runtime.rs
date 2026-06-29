use crate::stats::{Stats, StatsSnapshot};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

const PHASE_QUEUED: u8 = 0;
const PHASE_CONNECTING: u8 = 1;
const PHASE_TRANSFERRING: u8 = 2;
const PHASE_VERIFYING: u8 = 3;
const PHASE_COMPLETE: u8 = 4;
const PHASE_FAILED: u8 = 5;
const PAUSED_RATE_BPS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferPhase {
    Queued,
    Connecting,
    Transferring,
    Verifying,
    Complete,
    Failed,
}

impl TransferPhase {
    fn as_u8(self) -> u8 {
        match self {
            TransferPhase::Queued => PHASE_QUEUED,
            TransferPhase::Connecting => PHASE_CONNECTING,
            TransferPhase::Transferring => PHASE_TRANSFERRING,
            TransferPhase::Verifying => PHASE_VERIFYING,
            TransferPhase::Complete => PHASE_COMPLETE,
            TransferPhase::Failed => PHASE_FAILED,
        }
    }

    fn from_u8(v: u8) -> TransferPhase {
        match v {
            PHASE_CONNECTING => TransferPhase::Connecting,
            PHASE_TRANSFERRING => TransferPhase::Transferring,
            PHASE_VERIFYING => TransferPhase::Verifying,
            PHASE_COMPLETE => TransferPhase::Complete,
            PHASE_FAILED => TransferPhase::Failed,
            _ => TransferPhase::Queued,
        }
    }
}

#[derive(Default)]
pub struct TransferControl {
    rate_limit_bps: AtomicU64,
    paused: AtomicBool,
    cancelled: AtomicBool,
}

impl TransferControl {
    pub fn new() -> TransferControl {
        TransferControl::default()
    }

    pub fn set_rate_limit(&self, bps: Option<u64>) {
        self.rate_limit_bps
            .store(bps.unwrap_or(0), Ordering::Relaxed);
    }

    pub fn rate_limit_bps(&self) -> Option<u64> {
        match self.rate_limit_bps.load(Ordering::Relaxed) {
            0 => None,
            n => Some(n),
        }
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub(crate) fn effective_rate_bps(&self, base: u64) -> u64 {
        if self.is_paused() {
            return PAUSED_RATE_BPS.min(base.max(1));
        }
        match self.rate_limit_bps() {
            Some(limit) => base.min(limit.max(1)),
            None => base,
        }
    }
}

pub struct TransferHandle {
    stats: Arc<Stats>,
    control: Arc<TransferControl>,
    phase: AtomicU8,
    last_error: Mutex<Option<String>>,
}

impl Default for TransferHandle {
    fn default() -> Self {
        TransferHandle {
            stats: Stats::new(),
            control: Arc::new(TransferControl::new()),
            phase: AtomicU8::new(PHASE_QUEUED),
            last_error: Mutex::new(None),
        }
    }
}

impl TransferHandle {
    pub fn new() -> Arc<TransferHandle> {
        Arc::new(TransferHandle::default())
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    pub fn phase(&self) -> TransferPhase {
        TransferPhase::from_u8(self.phase.load(Ordering::Relaxed))
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    pub fn set_rate_limit(&self, bps: Option<u64>) {
        self.control.set_rate_limit(bps);
    }

    pub fn rate_limit_bps(&self) -> Option<u64> {
        self.control.rate_limit_bps()
    }

    pub fn pause(&self) {
        self.control.pause();
    }

    pub fn resume(&self) {
        self.control.resume();
    }

    pub fn is_paused(&self) -> bool {
        self.control.is_paused()
    }

    pub fn cancel(&self) {
        self.control.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.control.is_cancelled()
    }

    pub(crate) fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    pub(crate) fn control(&self) -> Arc<TransferControl> {
        self.control.clone()
    }

    pub(crate) fn set_phase(&self, phase: TransferPhase) {
        if phase != TransferPhase::Failed {
            *self.last_error.lock().unwrap() = None;
        }
        self.phase.store(phase.as_u8(), Ordering::Relaxed);
    }

    pub(crate) fn set_failed(&self, err: impl ToString) {
        *self.last_error.lock().unwrap() = Some(err.to_string());
        self.phase.store(PHASE_FAILED, Ordering::Relaxed);
    }
}
