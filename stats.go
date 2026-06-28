package girth

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// Stats holds atomically-updated counters and gauges shared between the data
// plane goroutines and the periodic reporter. It is designed so that the hot
// path only does cheap atomic adds; gauges (rates, RTTs) are written by the
// single owner goroutine and read by the reporter.
type Stats struct {
	// Counters (monotonic).
	BytesSent     atomic.Uint64 // payload + header bytes written to UDP (sender)
	PacketsSent   atomic.Uint64
	RetransSent   atomic.Uint64 // retransmitted DATA PDUs sent
	BytesRecv     atomic.Uint64 // payload + header bytes read from UDP (receiver)
	PacketsRecv   atomic.Uint64
	PayloadRecv   atomic.Uint64 // useful (first-time) payload bytes written to disk
	DupRecv       atomic.Uint64 // duplicate blocks received
	CorruptRecv   atomic.Uint64 // CRC failures
	NacksSent     atomic.Uint64 // retransmission requests emitted (receiver)
	NacksRecv     atomic.Uint64 // retransmission requests received (sender)
	BlocksWritten atomic.Uint64

	// Gauges (current values; single-writer).
	TargetRateBps atomic.Uint64 // current injection target (bits/sec)
	SrttPathUs    atomic.Uint64 // smoothed path RTT (micros)
	SrttNetUs     atomic.Uint64 // smoothed network RTT (micros)
	BaseRttUs     atomic.Uint64 // minimum (base) network RTT (micros)
	RtoUs         atomic.Uint64 // current retransmit timeout (micros)
	RexQueueLen   atomic.Int64  // outstanding retransmissions (sender queue / receiver loss table)
	HiContig      atomic.Uint64 // contiguous blocks completed

	// Transfer descriptors.
	TotalBytes  atomic.Uint64
	TotalBlocks atomic.Uint64

	start time.Time
}

// NewStats returns a Stats with the start time set.
func NewStats() *Stats {
	return &Stats{start: time.Now()}
}

// Elapsed returns time since the stats object was created.
func (s *Stats) Elapsed() time.Duration { return time.Since(s.start) }

// snapshot is an immutable copy used to compute deltas between reports.
type snapshot struct {
	t           time.Time
	bytesSent   uint64
	bytesRecv   uint64
	payloadRecv uint64
}

func (s *Stats) snap() snapshot {
	return snapshot{
		t:           time.Now(),
		bytesSent:   s.BytesSent.Load(),
		bytesRecv:   s.BytesRecv.Load(),
		payloadRecv: s.PayloadRecv.Load(),
	}
}

// Reporter periodically writes a parseable key=value line to w until stop is
// closed. role is "send" or "recv". The format is intentionally machine-
// friendly (space-separated key=value) for the live-testing stage.
func (s *Stats) Reporter(w io.Writer, role string, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	prev := s.snap()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			cur := s.snap()
			dt := cur.t.Sub(prev.t).Seconds()
			if dt <= 0 {
				dt = interval.Seconds()
			}
			line := s.formatLine(role, dt, prev, cur)
			fmt.Fprintln(w, line)
			prev = cur
		}
	}
}

func mbps(deltaBytes uint64, dt float64) float64 {
	return float64(deltaBytes) * 8 / 1e6 / dt
}

func (s *Stats) formatLine(role string, dt float64, prev, cur snapshot) string {
	el := s.Elapsed().Seconds()
	if role == "send" {
		return fmt.Sprintf(
			"t=%.1f role=send wire_mbps=%.1f target_mbps=%.1f pkts=%d retrans=%d nacks_in=%d rexq=%d hicontig=%d/%d",
			el,
			mbps(cur.bytesSent-prev.bytesSent, dt),
			float64(s.TargetRateBps.Load())/1e6,
			s.PacketsSent.Load(),
			s.RetransSent.Load(),
			s.NacksRecv.Load(),
			s.RexQueueLen.Load(),
			s.HiContig.Load(), s.TotalBlocks.Load(),
		)
	}
	// receiver
	loss := 0.0
	if pr := s.PacketsRecv.Load(); pr > 0 {
		loss = float64(s.DupRecv.Load()) / float64(pr) * 100
	}
	return fmt.Sprintf(
		"t=%.1f role=recv wire_mbps=%.1f goodput_mbps=%.1f pkts=%d dup=%d(%.2f%%) corrupt=%d nacks_out=%d losstab=%d "+
			"srtt_path_ms=%.1f srtt_net_ms=%.1f base_ms=%.1f rto_ms=%.1f qdelay_ms=%.1f target_mbps=%.1f hicontig=%d/%d",
		el,
		mbps(cur.bytesRecv-prev.bytesRecv, dt),
		mbps(cur.payloadRecv-prev.payloadRecv, dt),
		s.PacketsRecv.Load(),
		s.DupRecv.Load(), loss,
		s.CorruptRecv.Load(),
		s.NacksSent.Load(),
		s.RexQueueLen.Load(),
		float64(s.SrttPathUs.Load())/1000,
		float64(s.SrttNetUs.Load())/1000,
		float64(s.BaseRttUs.Load())/1000,
		float64(s.RtoUs.Load())/1000,
		qdelayMs(s.SrttNetUs.Load(), s.BaseRttUs.Load()),
		float64(s.TargetRateBps.Load())/1e6,
		s.HiContig.Load(), s.TotalBlocks.Load(),
	)
}

func qdelayMs(srttNet, base uint64) float64 {
	if srttNet < base {
		return 0
	}
	return float64(srttNet-base) / 1000
}

// Summary returns a final human-readable multi-line report.
func (s *Stats) Summary(role string) string {
	el := s.Elapsed().Seconds()
	if el <= 0 {
		el = 1e-9
	}
	if role == "send" {
		return fmt.Sprintf(
			"girth send complete: %s in %.2fs (wire %.1f Mbps) | pkts=%d retrans=%d (%.2f%%) nacks_in=%d",
			humanBytes(s.TotalBytes.Load()), el,
			float64(s.BytesSent.Load())*8/1e6/el,
			s.PacketsSent.Load(), s.RetransSent.Load(),
			pct(s.RetransSent.Load(), s.PacketsSent.Load()),
			s.NacksRecv.Load(),
		)
	}
	return fmt.Sprintf(
		"girth recv complete: %s in %.2fs (goodput %.1f Mbps, wire %.1f Mbps) | pkts=%d dup=%d (%.2f%%) corrupt=%d nacks_out=%d",
		humanBytes(s.TotalBytes.Load()), el,
		float64(s.PayloadRecv.Load())*8/1e6/el,
		float64(s.BytesRecv.Load())*8/1e6/el,
		s.PacketsRecv.Load(), s.DupRecv.Load(),
		pct(s.DupRecv.Load(), s.PacketsRecv.Load()),
		s.CorruptRecv.Load(), s.NacksSent.Load(),
	)
}

func pct(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
