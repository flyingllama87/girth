package girth

import (
	"encoding/binary"
	"net"
	"runtime"
	"time"
)

func numCPU() int { return runtime.NumCPU() }

// isTimeout reports whether err is a network timeout (deadline) error.
func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func putU64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }

// spinThresholdUs bounds the tail duration we busy-spin (instead of sleeping)
// to achieve sub-millisecond pacing precision despite coarse OS sleep
// granularity. The spin is also capped at a small fraction of each interval
// (see preciseSleepUs) so that short inter-batch gaps — produced by small
// sendmmsg batches at high rates — do not burn a core spinning.
const spinThresholdUs = 150.0

// preciseSleepUs sleeps for approximately us microseconds. It sleeps coarsely
// for the bulk of the duration and busy-spins a short tail to keep pacing
// precise. The spin tail is min(spinThresholdUs, 5% of the interval), so it is
// always a small fraction of CPU time regardless of batch cadence — and the
// absolute-deadline scheduler in the pacing loop corrects any residual jitter.
func preciseSleepUs(us float64) {
	if us <= 0 {
		return
	}
	spin := us * 0.05
	if spin > spinThresholdUs {
		spin = spinThresholdUs
	}
	deadline := nowMicros() + uint64(us)
	if us > spin {
		time.Sleep(time.Duration(us-spin) * time.Microsecond)
	}
	for nowMicros() < deadline {
		// brief spin
	}
}
