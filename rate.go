package girth

// rttEstimator implements the predictive (recursive) round-trip estimator
// described in the FASP patents: a Jacobson-style smoothed RTT (SRTT) and RTT
// variance (VRTT), used to derive a retransmit timeout (RTO) that is "neither
// too early (hurting stability) nor too late (hurting efficiency)".
//
//	err   = sample - srtt
//	srtt += gain * err                 (gain = 1/8)
//	vrtt += (|err| - vrtt) / attenK    (attenK = 4)
//	rto   = srtt + rtoK * vrtt         (rtoK = 4), range-bounded
//
// All values are in microseconds.
type rttEstimator struct {
	srtt    float64
	vrtt    float64
	minRTT  float64 // base RTT: smallest sample seen
	haveAny bool

	minRTO float64
	maxRTO float64
}

const (
	rttGain     = 0.125 // 1/8
	rttAttenK   = 4.0
	rttRtoK     = 4.0
	rttPrecUs   = 1000.0 // measurement precision (1ms) added to due times
	defMinRTOus = 2000.0 // floor RTO 2ms (loopback / LAN)
	defMaxRTOus = 4.0e6  // ceil RTO 4s
)

func newRTTEstimator() *rttEstimator {
	return &rttEstimator{minRTO: defMinRTOus, maxRTO: defMaxRTOus}
}

// sample feeds a new RTT measurement (micros) and returns the updated RTO.
func (e *rttEstimator) sample(rtt float64) float64 {
	if rtt < 0 {
		rtt = 0
	}
	if !e.haveAny {
		e.srtt = rtt
		e.vrtt = rtt / 2
		e.minRTT = rtt
		e.haveAny = true
	} else {
		err := rtt - e.srtt
		e.srtt += rttGain * err
		a := err
		if a < 0 {
			a = -a
		}
		e.vrtt += (a - e.vrtt) / rttAttenK
		if rtt < e.minRTT {
			e.minRTT = rtt
		}
	}
	return e.rto()
}

func (e *rttEstimator) rto() float64 {
	rto := e.srtt + rttRtoK*e.vrtt
	if rto < e.minRTO {
		rto = e.minRTO
	}
	if rto > e.maxRTO {
		rto = e.maxRTO
	}
	return rto
}

// --- Rate control -----------------------------------------------------------

// RateMode selects the injection-rate policy.
type RateMode int

const (
	// RateFixed holds a constant target injection rate (predictable transfer
	// time; the primary mode for dedicated LFN links).
	RateFixed RateMode = iota
	// RateAdaptive uses delay-based equation control (FAST-TCP-like): it ramps
	// toward available bandwidth and backs off as queuing delay builds, so it
	// fills unused capacity yet stays stable and roughly TCP-friendly under
	// congestion.
	RateAdaptive
)

// RateConfig parameterises a rateController.
type RateConfig struct {
	Mode      RateMode
	TargetBps uint64 // initial/fixed target (bits/sec)
	MinBps    uint64
	MaxBps    uint64
	// Alpha is the adaptation factor `a` (bits/sec) from patent Eq.2. It sets
	// the equilibrium operating point: rate ~= alpha / (1 - base/srtt), i.e.
	// larger alpha => more aggressive (tolerates more queuing). Only used in
	// adaptive mode.
	Alpha float64
}

// rateController computes the target injection rate. In adaptive mode it
// applies patent Eq.2:
//
//	rate_{i+1} = 0.5 * (rate_i*BaseAvg + rate_i + a)
//	BaseAvg    = 1                 if base<5ms and srtt<20ms
//	           = base / srtt       otherwise   (<=1 when queuing present)
//
// At equilibrium (rate_{i+1}=rate_i) this gives rate = a / (1 - base/srtt),
// matching patent Eq.3 (x = alpha*RTT/(srtt-base)).
type rateController struct {
	cfg  RateConfig
	rate float64 // bits/sec
}

func newRateController(cfg RateConfig) *rateController {
	if cfg.MinBps == 0 {
		cfg.MinBps = 64 * 1000 // 64 Kbps floor
	}
	if cfg.MaxBps == 0 {
		cfg.MaxBps = 10_000_000_000 // 10 Gbps ceiling
	}
	if cfg.Alpha == 0 {
		cfg.Alpha = 30_000_000 // 30 Mbit default adaptation factor
	}
	start := float64(cfg.TargetBps)
	if cfg.Mode == RateAdaptive {
		// Start modestly and let the equation ramp (slow-start-ish).
		if start == 0 || start > float64(cfg.MaxBps) {
			start = float64(cfg.MaxBps)
		}
		start = start * 0.05
		if start < float64(cfg.MinBps) {
			start = float64(cfg.MinBps)
		}
	}
	return &rateController{cfg: cfg, rate: start}
}

// update recomputes the target given the smoothed network RTT and base RTT
// (micros). For fixed mode the target is constant. Returns bits/sec.
func (rc *rateController) update(srttNetUs, baseUs float64) uint64 {
	if rc.cfg.Mode == RateFixed {
		rc.rate = float64(rc.cfg.TargetBps)
		return uint64(rc.rate)
	}
	if srttNetUs <= 0 {
		return uint64(rc.rate)
	}
	baseAvg := 1.0
	if !(baseUs < 5000 && srttNetUs < 20000) {
		baseAvg = baseUs / srttNetUs
		if baseAvg > 1 {
			baseAvg = 1
		}
		if baseAvg < 0 {
			baseAvg = 0
		}
	}
	rc.rate = 0.5 * (rc.rate*baseAvg + rc.rate + rc.cfg.Alpha)
	if rc.rate < float64(rc.cfg.MinBps) {
		rc.rate = float64(rc.cfg.MinBps)
	}
	if rc.rate > float64(rc.cfg.MaxBps) {
		rc.rate = float64(rc.cfg.MaxBps)
	}
	return uint64(rc.rate)
}
