package girth

import (
	"math"
	"testing"
)

func TestDataHeaderRoundTrip(t *testing.T) {
	in := dataHeader{
		flags:      flagRetransmit | flagHasTick | flagTickN | flagLastBlock,
		payloadLen: 1400,
		session:    0xDEADBEEF,
		blockSeq:   0x0123456789ABCDEF,
		echoTick:   123456789,
		rexIndex:   42,
		payloadCRC: 0xCAFEBABE,
	}
	buf := make([]byte, DataHeaderSize+int(in.payloadLen))
	encodeDataHeader(buf, in)
	out, ok := decodeDataHeader(buf)
	if !ok {
		t.Fatal("decode failed")
	}
	if out != in {
		t.Fatalf("roundtrip mismatch\n in=%+v\nout=%+v", in, out)
	}
}

func TestFeedbackRoundTrip(t *testing.T) {
	in := feedbackHeader{
		tickIsNetwork: true,
		session:       7,
		tick:          999,
		targetRate:    250_000_000,
		hiContig:      12345,
		done:          true,
	}
	nacks := []nackEntry{{1, 1}, {5, 5}, {99999, 99999}}
	buf := make([]byte, feedbackHeaderSize+len(nacks)*nackEntrySize)
	n := encodeFeedback(buf, in, nacks)
	out, gotNacks, ok := decodeFeedback(buf[:n])
	if !ok {
		t.Fatal("decode failed")
	}
	if out.tickIsNetwork != in.tickIsNetwork || out.session != in.session ||
		out.tick != in.tick || out.targetRate != in.targetRate ||
		out.hiContig != in.hiContig || out.done != in.done {
		t.Fatalf("header mismatch\n in=%+v\nout=%+v", in, out)
	}
	if len(gotNacks) != len(nacks) {
		t.Fatalf("nack count: got %d want %d", len(gotNacks), len(nacks))
	}
	for i := range nacks {
		if gotNacks[i] != nacks[i] {
			t.Fatalf("nack[%d]: got %+v want %+v", i, gotNacks[i], nacks[i])
		}
	}
}

func TestCRC32CDetectsCorruption(t *testing.T) {
	data := []byte("the quick brown fox")
	c := crc32c(data)
	data[0] ^= 0xFF
	if crc32c(data) == c {
		t.Fatal("crc did not change on corruption")
	}
}

func TestRTTEstimatorConvergesAndBounds(t *testing.T) {
	e := newRTTEstimator()
	const target = 280000.0 // 280 ms in micros (Brisbane<->London)
	var rto float64
	for i := 0; i < 200; i++ {
		rto = e.sample(target)
	}
	if math.Abs(e.srtt-target) > target*0.01 {
		t.Fatalf("srtt did not converge: got %.0f want ~%.0f", e.srtt, target)
	}
	if rto < e.srtt {
		t.Fatalf("rto %.0f should be >= srtt %.0f", rto, e.srtt)
	}
	// minRTT should track the smallest sample.
	e.sample(100000)
	if e.minRTT != 100000 {
		t.Fatalf("minRTT: got %.0f want 100000", e.minRTT)
	}
}

func TestAdaptiveRateEquilibrium(t *testing.T) {
	// At equilibrium the patent's Eq.2 settles at rate = alpha / (1 - base/srtt).
	cfg := RateConfig{Mode: RateAdaptive, TargetBps: 1_000_000, MaxBps: 100_000_000_000,
		MinBps: 1000, Alpha: 30_000_000}
	rc := newRateController(cfg)
	base := 100000.0 // 100ms
	srtt := 110000.0 // 110ms => 10ms queuing
	var rate uint64
	for i := 0; i < 5000; i++ {
		rate = rc.update(srtt, base)
	}
	want := cfg.Alpha / (1 - base/srtt)
	if math.Abs(float64(rate)-want)/want > 0.05 {
		t.Fatalf("equilibrium rate: got %d want ~%.0f", rate, want)
	}
}

func TestFixedRateConstant(t *testing.T) {
	cfg := RateConfig{Mode: RateFixed, TargetBps: 500_000_000}
	rc := newRateController(cfg)
	for i := 0; i < 100; i++ {
		if got := rc.update(200000, 100000); got != cfg.TargetBps {
			t.Fatalf("fixed rate drifted: %d", got)
		}
	}
}

func TestLossScannerDetectAndCancel(t *testing.T) {
	const total = 1000
	bm := newRecvBitmap(total)
	s := newLossScanner(bm, total)

	// Receive 0..499 and 600 (gap 500..599, plus 601..599 none).
	for i := uint64(0); i <= 499; i++ {
		bm.setAndTest(i)
	}
	bm.setAndTest(600)

	now := 1_000_000.0
	rto := 10000.0 // 10ms
	s.advance()
	s.scanHoles(600, now, rto)
	if s.pendingCount() != 100 { // 500..599
		t.Fatalf("pending: got %d want 100", s.pendingCount())
	}
	// Nothing is due yet (due = now+rto+prec).
	if due := s.collectDue(now, rto, 1000); len(due) != 0 {
		t.Fatalf("nothing should be due yet, got %d", len(due))
	}
	// After RTO elapses, all 100 become due.
	later := now + rto + rttPrecUs + 1
	due := s.collectDue(later, rto, 1000)
	if len(due) != 100 {
		t.Fatalf("due: got %d want 100", len(due))
	}
	if due[0] != 500 {
		t.Fatalf("lowest due seq: got %d want 500", due[0])
	}
	// Fill the gap; advancing should clear pending and complete contiguity.
	for i := uint64(500); i <= 600; i++ {
		bm.setAndTest(i)
	}
	for i := uint64(601); i < total; i++ {
		bm.setAndTest(i)
	}
	s.advance()
	if !s.completed() {
		t.Fatal("scanner should be completed")
	}
}

func TestRecvBitmapDuplicateDetection(t *testing.T) {
	bm := newRecvBitmap(128)
	if !bm.setAndTest(65) {
		t.Fatal("first set should be firstTime")
	}
	if bm.setAndTest(65) {
		t.Fatal("second set should be duplicate")
	}
	if !bm.isSet(65) || bm.isSet(64) {
		t.Fatal("bitmap state wrong")
	}
}

func TestNumBlocks(t *testing.T) {
	cases := []struct {
		size   int64
		bs     int
		blocks uint64
	}{
		{0, 1400, 0},
		{1, 1400, 1},
		{1400, 1400, 1},
		{1401, 1400, 2},
		{1234567, 1400, 882},
	}
	for _, c := range cases {
		if got := numBlocks(c.size, c.bs); got != c.blocks {
			t.Fatalf("numBlocks(%d,%d)=%d want %d", c.size, c.bs, got, c.blocks)
		}
	}
}
