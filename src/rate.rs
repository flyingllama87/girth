//! Predictive RTT estimation (Jacobson-style SRTT/VRTT -> RTO) and the
//! injection-rate controller (fixed, or FAST-TCP-like delay-based adaptive).
//! All values in microseconds / bits-per-second, matching the Go code exactly.

const RTT_GAIN: f64 = 0.125; // 1/8
const RTT_ATTEN_K: f64 = 4.0;
const RTT_RTO_K: f64 = 4.0;
/// Measurement precision (1ms) added to due times.
pub const RTT_PREC_US: f64 = 1000.0;
const DEF_MIN_RTO_US: f64 = 2000.0; // floor RTO 2ms (loopback / LAN)
const DEF_MAX_RTO_US: f64 = 4.0e6; // ceil RTO 4s

/// Recursive RTT estimator:
///   err   = sample - srtt
///   srtt += gain * err                 (gain = 1/8)
///   vrtt += (|err| - vrtt) / attenK    (attenK = 4)
///   rto   = srtt + rtoK * vrtt         (rtoK = 4), range-bounded
pub struct RttEstimator {
    pub srtt: f64,
    pub vrtt: f64,
    pub min_rtt: f64, // base RTT: smallest sample seen
    have_any: bool,
    min_rto: f64,
    max_rto: f64,
}

impl RttEstimator {
    pub fn new() -> Self {
        RttEstimator {
            srtt: 0.0,
            vrtt: 0.0,
            min_rtt: 0.0,
            have_any: false,
            min_rto: DEF_MIN_RTO_US,
            max_rto: DEF_MAX_RTO_US,
        }
    }

    /// Feeds a new RTT measurement (micros) and returns the updated RTO.
    pub fn sample(&mut self, mut rtt: f64) -> f64 {
        if rtt < 0.0 {
            rtt = 0.0;
        }
        if !self.have_any {
            self.srtt = rtt;
            self.vrtt = rtt / 2.0;
            self.min_rtt = rtt;
            self.have_any = true;
        } else {
            let err = rtt - self.srtt;
            self.srtt += RTT_GAIN * err;
            self.vrtt += (err.abs() - self.vrtt) / RTT_ATTEN_K;
            if rtt < self.min_rtt {
                self.min_rtt = rtt;
            }
        }
        self.rto()
    }

    pub fn rto(&self) -> f64 {
        (self.srtt + RTT_RTO_K * self.vrtt).clamp(self.min_rto, self.max_rto)
    }

    pub fn seed(&mut self, srtt_us: u64, min_rtt_us: u64) {
        if srtt_us == 0 {
            return;
        }
        self.srtt = srtt_us as f64;
        self.vrtt = (srtt_us as f64 / 4.0).max(1.0);
        self.min_rtt = if min_rtt_us == 0 {
            srtt_us as f64
        } else {
            min_rtt_us.min(srtt_us) as f64
        };
        self.have_any = true;
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// --- Rate control -----------------------------------------------------------

/// Selects the injection-rate policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateMode {
    /// Constant target injection rate (predictable transfer time; the primary
    /// mode for dedicated LFN links).
    Fixed,
    /// Delay-based equation control (FAST-TCP-like): ramps toward available
    /// bandwidth and backs off as queuing delay builds.
    Adaptive,
}

#[derive(Debug, Clone, Copy)]
pub struct RateConfig {
    pub mode: RateMode,
    pub target_bps: u64,
    pub min_bps: u64,
    pub max_bps: u64,
    /// Adaptation factor `a` (bits/sec) from patent Eq.2; sets the equilibrium
    /// operating point rate ~= alpha / (1 - base/srtt). Adaptive mode only.
    pub alpha: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateWarmStart {
    pub rate_bps: u64,
    pub srtt_net_us: u64,
    pub base_rtt_us: u64,
}

impl RateWarmStart {
    pub fn is_empty(self) -> bool {
        self.rate_bps == 0 && self.srtt_net_us == 0 && self.base_rtt_us == 0
    }
}

/// Computes the target injection rate. In adaptive mode it applies patent Eq.2:
///   rate_{i+1} = 0.5 * (rate_i*BaseAvg + rate_i + a)
///   BaseAvg    = 1                 if base<5ms and srtt<20ms
///              = base / srtt       otherwise   (<=1 when queuing present)
pub struct RateController {
    cfg: RateConfig,
    rate: f64, // bits/sec
}

impl RateController {
    pub fn new(mut cfg: RateConfig) -> Self {
        if cfg.min_bps == 0 {
            cfg.min_bps = 64 * 1000; // 64 Kbps floor
        }
        if cfg.max_bps == 0 {
            cfg.max_bps = 10_000_000_000; // 10 Gbps ceiling
        }
        if cfg.alpha == 0.0 {
            cfg.alpha = 30_000_000.0; // 30 Mbit default adaptation factor
        }
        let mut start = cfg.target_bps as f64;
        if cfg.mode == RateMode::Adaptive {
            if start == 0.0 || start > cfg.max_bps as f64 {
                start = cfg.max_bps as f64;
            }
            start *= 0.05;
            if start < cfg.min_bps as f64 {
                start = cfg.min_bps as f64;
            }
        }
        RateController { cfg, rate: start }
    }

    /// Recomputes the target given smoothed network RTT and base RTT (micros).
    pub fn update(&mut self, srtt_net_us: f64, base_us: f64) -> u64 {
        if self.cfg.mode == RateMode::Fixed {
            self.rate = self.cfg.target_bps as f64;
            return self.rate as u64;
        }
        if srtt_net_us <= 0.0 {
            return self.rate as u64;
        }
        let mut base_avg = 1.0;
        if !(base_us < 5000.0 && srtt_net_us < 20000.0) {
            base_avg = (base_us / srtt_net_us).clamp(0.0, 1.0);
        }
        self.rate = 0.5 * (self.rate * base_avg + self.rate + self.cfg.alpha);
        self.rate = self
            .rate
            .clamp(self.cfg.min_bps as f64, self.cfg.max_bps as f64);
        self.rate as u64
    }

    pub fn set_rate(&mut self, rate_bps: u64) {
        if rate_bps == 0 {
            return;
        }
        self.rate = (rate_bps as f64).clamp(self.cfg.min_bps as f64, self.cfg.max_bps as f64);
    }
}
