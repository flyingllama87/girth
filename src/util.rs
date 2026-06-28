//! Small shared helpers: CPU count and the high-precision pacing sleep.

use crate::protocol::now_micros;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub fn num_cpu() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

static TRACE_START: OnceLock<Instant> = OnceLock::new();

/// Emits a timestamped startup/endgame milestone when `GIRTH_TRACE` is set.
/// No-op (single env probe) otherwise. The clock zeroes on the first call.
#[inline]
pub fn trace(msg: &str) {
    if std::env::var_os("GIRTH_TRACE").is_some() {
        let start = TRACE_START.get_or_init(Instant::now);
        eprintln!("[trace +{:.3}s] {}", start.elapsed().as_secs_f64(), msg);
    }
}

/// Bounds the tail duration we busy-spin (instead of sleeping) to achieve
/// sub-millisecond pacing precision despite coarse OS sleep granularity.
const SPIN_THRESHOLD_US: f64 = 150.0;

/// Sleeps for approximately `us` microseconds: coarsely for the bulk of the
/// duration, then busy-spins a short tail (min(150us, 5% of the interval)) to
/// keep pacing precise. The absolute-deadline scheduler in the pacing loop
/// corrects any residual jitter.
#[inline]
pub fn precise_sleep_us(us: f64) {
    if us <= 0.0 {
        return;
    }
    let mut spin = us * 0.05;
    if spin > SPIN_THRESHOLD_US {
        spin = SPIN_THRESHOLD_US;
    }
    let deadline = now_micros() + us as u64;
    if us > spin {
        std::thread::sleep(Duration::from_micros((us - spin) as u64));
    }
    while now_micros() < deadline {
        std::hint::spin_loop();
    }
}
