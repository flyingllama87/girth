package girth

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

// RecvConfig configures a receiving data-plane session.
type RecvConfig struct {
	Conn        *net.UDPConn // bound UDP socket
	File        *os.File     // destination file, pre-sized to FileSize
	FileSize    int64
	BlockSize   int
	TotalBlocks uint64
	Session     uint32
	ReadWorkers int // UDP ingest goroutines (default: NumCPU)
	Rate        RateConfig
	Crypto      *aeadBox // data-plane AEAD; nil => cleartext

	FeedbackIntervalUs int // base NACK/tick cadence (default 5000)
	NetTickIntervalUs  int // network-RTT tick cadence (default 10000)
	MaxNacksPerPDU     int // cap entries per feedback PDU (default 90)

	Stats *Stats
	Log   *log.Logger
}

// Receiver runs the receiving side of a transfer until the file is complete.
//
// Design: the per-packet ingest path (parallel across cores) does only
// order-independent work — CRC check, atomic bitmap set, disk write, RTT tick.
// All loss detection and NACK scheduling lives in the single feedback
// goroutine, which scans the bitmap on a real-time RTO basis. This keeps the
// hot path lock-free and makes loss detection immune to in-flight reordering.
type Receiver struct {
	cfg RecvConfig

	bm      *recvBitmap
	maxSeen atomic.Uint64
	seenAny atomic.Bool

	rttMu   sync.Mutex
	pathEst *rttEstimator
	netEst  *rttEstimator
	rateCtl *rateController

	peer    atomic.Pointer[net.UDPAddr]
	allSent atomic.Bool // sender signalled FIN

	// In-order disk writes. Retransmitted blocks arrive ~1 RTT late — by which
	// point the write frontier has advanced ~1 BDP — so writing in arrival
	// order means a backward seek per retransmit: random I/O that on cloud block
	// storage runs ~40x slower than sequential and stalls ingest into a loss
	// storm. Instead ingest stages out-of-order blocks in a bounded RAM pool and
	// a single flusher writes strictly at the advancing frontier (sequential).
	// If the stage pool is exhausted (a long stall under heavy loss) ingest
	// falls back to writing the block directly. readyBm marks a block as
	// staged-or-written so the flusher never races ahead of an in-flight stage.
	stageMu    sync.Mutex
	stage      map[uint64][]byte
	freeBufs   chan []byte
	readyBm    *recvBitmap
	writeFront uint64        // next block the flusher will write (flusher-owned)
	flushSig   chan struct{} // wake the flusher when new blocks arrive

	done      chan struct{}
	closeOnce sync.Once
}

// NewReceiver builds a Receiver from cfg.
func NewReceiver(cfg RecvConfig) *Receiver {
	if cfg.ReadWorkers <= 0 {
		cfg.ReadWorkers = numCPU()
	}
	if cfg.FeedbackIntervalUs <= 0 {
		cfg.FeedbackIntervalUs = 5000
	}
	if cfg.NetTickIntervalUs <= 0 {
		cfg.NetTickIntervalUs = 10000
	}
	if cfg.MaxNacksPerPDU <= 0 {
		cfg.MaxNacksPerPDU = 90 // keeps feedback PDU under a 1500B MTU
	}
	if cfg.Log == nil {
		cfg.Log = log.New(os.Stderr, "girth-recv ", log.LstdFlags|log.Lmicroseconds)
	}
	r := &Receiver{
		cfg:     cfg,
		bm:      newRecvBitmap(cfg.TotalBlocks),
		pathEst: newRTTEstimator(),
		netEst:  newRTTEstimator(),
		rateCtl: newRateController(cfg.Rate),
		done:    make(chan struct{}),
	}
	// Size the staging pool to absorb the out-of-order window (received-ahead
	// blocks while a hole waits for retransmission) — ~96 MiB. Blocks beyond it
	// fall back to direct writes. Capped so memory stays bounded on small hosts.
	depth := (96 << 20) / cfg.BlockSize
	if cfg.TotalBlocks > 0 && uint64(depth) > cfg.TotalBlocks {
		depth = int(cfg.TotalBlocks)
	}
	if depth < 1 {
		depth = 1
	}
	r.stage = make(map[uint64][]byte, depth)
	r.freeBufs = make(chan []byte, depth)
	for i := 0; i < depth; i++ {
		r.freeBufs <- make([]byte, cfg.BlockSize)
	}
	r.readyBm = newRecvBitmap(cfg.TotalBlocks)
	r.flushSig = make(chan struct{}, 1)
	cfg.Stats.TotalBytes.Store(uint64(cfg.FileSize))
	cfg.Stats.TotalBlocks.Store(cfg.TotalBlocks)
	cfg.Stats.TargetRateBps.Store(cfg.Rate.TargetBps)
	return r
}

// Run blocks until the transfer completes or stop fires.
func (r *Receiver) Run(stop <-chan struct{}) error {
	if r.cfg.TotalBlocks == 0 {
		r.markDone()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); r.feedbackLoop(stop) }()

	wg.Add(1)
	go func() { defer wg.Done(); r.writebackLoop(stop) }()

	// Single in-order flusher drains staged blocks to disk sequentially. It
	// outlives ingest so blocks still staged at completion are written before
	// the CRC check.
	var flusherWg sync.WaitGroup
	flusherWg.Add(1)
	go func() { defer flusherWg.Done(); r.flusherLoop(stop) }()

	for i := 0; i < r.cfg.ReadWorkers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.ingestLoop(stop) }()
	}

	select {
	case <-r.done:
	case <-stop:
	}

	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = r.cfg.Conn.SetReadDeadline(time.Now())
	}()
	wg.Wait()
	// Ingest has stopped; let the flusher write any remaining staged blocks.
	r.signalFlush()
	flusherWg.Wait()

	if r.cfg.Stats.HiContig.Load() != r.cfg.TotalBlocks {
		return fmt.Errorf("receiver stopped before completion (%d/%d blocks)",
			r.cfg.Stats.HiContig.Load(), r.cfg.TotalBlocks)
	}
	return nil
}

func (r *Receiver) signalFlush() {
	select {
	case r.flushSig <- struct{}{}:
	default:
	}
}

// flusherLoop writes received blocks to disk strictly in ascending (frontier)
// order, so the on-disk write pattern is sequential regardless of arrival order
// or retransmissions. Staged blocks are written and their buffers recycled;
// blocks written directly by ingest (stage-pool exhausted) are simply skipped
// here since they are already durable.
func (r *Receiver) flusherLoop(stop <-chan struct{}) {
	bs := int64(r.cfg.BlockSize)
	total := r.cfg.TotalBlocks
	for r.writeFront < total {
		// Advance over every contiguous ready block.
		progressed := false
		for r.writeFront < total && r.readyBm.isSet(r.writeFront) {
			seq := r.writeFront
			r.stageMu.Lock()
			buf, staged := r.stage[seq]
			if staged {
				delete(r.stage, seq)
			}
			r.stageMu.Unlock()
			if staged {
				if _, err := r.cfg.File.WriteAt(buf, int64(seq)*bs); err != nil {
					r.cfg.Log.Printf("write error at block %d: %v", seq, err)
				}
				r.freeBufs <- buf[:cap(buf)]
			}
			r.writeFront++
			progressed = true
		}
		if r.writeFront >= total {
			return
		}
		if progressed {
			continue
		}
		// Frontier is blocked on a not-yet-received hole; wait for arrivals.
		select {
		case <-r.flushSig:
		case <-stop:
			return
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func (r *Receiver) markDone() { r.closeOnce.Do(func() { close(r.done) }) }

// writebackLoop keeps the page cache from filling with dirty pages, which would
// otherwise hit the kernel's vm.dirty_ratio limit and make WriteAt block
// synchronously in the ingest path — stalling the UDP drain and forcing the
// socket to drop packets (a self-inflicted loss storm). Every tick it asks the
// kernel to start (asynchronous, non-blocking) writeback with sync_file_range.
//
// Crucially it flushes the whole active window — from the durable prefix up to
// the highest block *received* (maxSeen) — NOT just the contiguous frontier.
// Under loss the contiguous frontier stalls on a missing block while blocks
// keep arriving ahead of it; flushing only the prefix would let those pile up
// as dirty pages without bound. sync_file_range writes the dirty pages in the
// window and harmlessly skips the holes (refilled by retransmits, flushed next
// tick). The disk sustains far more than the network rate, so dirty stays low
// and WriteAt never blocks.
//
// We deliberately do NOT evict pages with fadvise(DONTNEED): girth's blocks are
// not page-aligned, so writing into an evicted page would force a synchronous
// read-modify-write that stalls ingest. Best-effort; a no-op on tmpfs.
func (r *Receiver) writebackLoop(stop <-chan struct{}) {
	if r.cfg.TotalBlocks == 0 || os.Getenv("GIRTH_NOWB") != "" {
		return
	}
	bs := int64(r.cfg.BlockSize)
	var prefix int64 // bytes below this are contiguous and already flushed

	flush := func() {
		hiW := int64(r.maxSeen.Load()+1) * bs
		if hiW > r.cfg.FileSize {
			hiW = r.cfg.FileSize
		}
		if hiW > prefix {
			// Kick async writeback across the active (possibly holey) window.
			platformSyncFileRangeWrite(r.cfg.File, prefix, hiW-prefix)
		}
		// Advance the durable prefix to the contiguous frontier; the region
		// above it stays "active" and is re-flushed next tick until its holes
		// fill in and the frontier sweeps past.
		if c := int64(r.cfg.Stats.HiContig.Load()) * bs; c > prefix {
			prefix = c
		}
	}

	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-r.done:
			return
		case <-t.C:
			flush()
		}
	}
}

// ingestLoop reads and processes DATA/FIN PDUs. Multiple run in parallel.
// It uses recvmmsg (via ipv4.PacketConn.ReadBatch) to pull many datagrams per
// syscall, which raises the socket-drain rate and keeps the kernel receive
// buffer from overflowing during arrival bursts. Falls back to single reads if
// batched receive is unavailable.
func (r *Receiver) ingestLoop(stop <-chan struct{}) {
	const batch = 32
	bufLen := r.cfg.BlockSize + DataHeaderSize + 64
	msgs := make([]ipv4.Message, batch)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, bufLen)}
	}
	pc := ipv4.NewPacketConn(r.cfg.Conn)
	useBatch := os.Getenv("GIRTH_NOBATCH") == ""

	for {
		select {
		case <-stop:
			return
		default:
		}

		if useBatch {
			n, err := pc.ReadBatch(msgs, 0)
			if err != nil {
				if isTimeout(err) {
					select {
					case <-r.done:
						return
					case <-stop:
						return
					default:
						continue
					}
				}
				// Batched receive is unsupported on this platform/socket
				// (e.g. Windows): fall back to single reads instead of
				// aborting the ingest loop. Mirrors batchSender's fallback.
				useBatch = false
				continue
			}
			for i := 0; i < n; i++ {
				m := &msgs[i]
				if m.N == 0 {
					continue
				}
				if r.peer.Load() == nil {
					if ua, ok := m.Addr.(*net.UDPAddr); ok {
						r.peer.CompareAndSwap(nil, ua)
					}
				}
				r.cfg.Stats.PacketsRecv.Add(1)
				r.cfg.Stats.BytesRecv.Add(uint64(m.N))
				r.handlePacket(m.Buffers[0][:m.N])
			}
			continue
		}

		// Single-read fallback.
		n, addr, err := r.cfg.Conn.ReadFromUDP(msgs[0].Buffers[0])
		if err != nil {
			if isTimeout(err) {
				select {
				case <-r.done:
					return
				case <-stop:
					return
				default:
					continue
				}
			}
			return
		}
		if r.peer.Load() == nil {
			r.peer.CompareAndSwap(nil, addr)
		}
		r.cfg.Stats.PacketsRecv.Add(1)
		r.cfg.Stats.BytesRecv.Add(uint64(n))
		r.handlePacket(msgs[0].Buffers[0][:n])
	}
}

func (r *Receiver) handlePacket(pkt []byte) {
	switch pduType(pkt) {
	case pduFin:
		if len(pkt) >= 16 {
			r.allSent.Store(true)
		}
		return
	case pduData:
	default:
		return
	}

	h, ok := decodeDataHeader(pkt)
	if !ok || h.session != r.cfg.Session {
		return
	}
	payload := pkt[DataHeaderSize:]
	if r.cfg.Crypto != nil {
		// Decrypt in place. Authentication failure (forged/corrupt/tampered)
		// is indistinguishable from a bad packet and is dropped as corrupt.
		pt, ok := r.cfg.Crypto.openData(payload, int(h.payloadLen), h.blockSeq)
		if !ok {
			r.cfg.Stats.CorruptRecv.Add(1)
			return
		}
		payload = pt
	} else {
		if int(h.payloadLen) > len(payload) {
			return
		}
		payload = payload[:h.payloadLen]
		if crc32c(payload) != h.payloadCRC {
			r.cfg.Stats.CorruptRecv.Add(1)
			return
		}
	}

	if h.flags&flagHasTick != 0 {
		r.applyTick(h)
	}

	// Track the highest sequence seen (atomic max) for the loss scanner.
	r.seenAny.Store(true)
	for {
		old := r.maxSeen.Load()
		if h.blockSeq <= old {
			break
		}
		if r.maxSeen.CompareAndSwap(old, h.blockSeq) {
			break
		}
	}

	if !r.bm.setAndTest(h.blockSeq) {
		r.cfg.Stats.DupRecv.Add(1)
		return
	}
	r.cfg.Stats.PayloadRecv.Add(uint64(len(payload)))
	r.cfg.Stats.BlocksWritten.Add(1)

	seq := h.blockSeq
	// Stage for in-order (sequential) disk write if a pooled buffer is free.
	// readyBm is set last so the flusher never advances past a block whose data
	// is not yet staged or written.
	select {
	case buf := <-r.freeBufs:
		n := copy(buf[:cap(buf)], payload)
		r.stageMu.Lock()
		r.stage[seq] = buf[:n]
		r.stageMu.Unlock()
		r.readyBm.setAndTest(seq)
		r.signalFlush()
	default:
		// Stage pool exhausted (long stall under heavy loss): write directly.
		// This may be a backward seek, but it is bounded to the overflow case.
		off := int64(seq) * int64(r.cfg.BlockSize)
		if _, err := r.cfg.File.WriteAt(payload, off); err != nil {
			r.cfg.Log.Printf("write error at block %d: %v", seq, err)
			return
		}
		r.readyBm.setAndTest(seq)
		r.signalFlush()
	}
}

// applyTick converts an echoed timing tick into an RTT sample.
func (r *Receiver) applyTick(h dataHeader) {
	sample := float64(nowMicros()) - float64(h.echoTick)
	if sample < 0 || sample > 60e6 {
		return
	}
	r.rttMu.Lock()
	if h.flags&flagTickN != 0 {
		r.netEst.sample(sample)
		r.cfg.Stats.SrttNetUs.Store(uint64(r.netEst.srtt))
		r.cfg.Stats.BaseRttUs.Store(uint64(r.netEst.minRTT))
	} else {
		rto := r.pathEst.sample(sample)
		r.cfg.Stats.SrttPathUs.Store(uint64(r.pathEst.srtt))
		r.cfg.Stats.RtoUs.Store(uint64(rto))
	}
	r.rttMu.Unlock()
}

// feedbackLoop owns all loss detection. Each tick it advances the contiguous
// mark, scans for new holes, collects due retransmit requests, and emits a
// FEEDBACK PDU with NACKs, a timing tick, the target rate, progress and done.
func (r *Receiver) feedbackLoop(stop <-chan struct{}) {
	interval := time.Duration(r.cfg.FeedbackIntervalUs) * time.Microsecond
	t := time.NewTicker(interval)
	defer t.Stop()

	scanner := newLossScanner(r.bm, r.cfg.TotalBlocks)
	buf := make([]byte, feedbackHeaderSize+r.cfg.MaxNacksPerPDU*nackEntrySize)
	lastNetTick := uint64(0)
	doneSends := 0

	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}

		now := float64(nowMicros())
		r.rttMu.Lock()
		pathRTO := r.pathEst.rto()
		srttNet := r.netEst.srtt
		baseNet := r.netEst.minRTT
		target := r.rateCtl.update(srttNet, baseNet)
		r.rttMu.Unlock()
		r.cfg.Stats.TargetRateBps.Store(target)

		// Loss detection (single-goroutine, lock-free w.r.t. ingest).
		hi := scanner.advance()
		ms := r.maxSeen.Load()
		if r.allSent.Load() && r.cfg.TotalBlocks > 0 {
			ms = r.cfg.TotalBlocks - 1
		}
		if r.seenAny.Load() || r.allSent.Load() {
			scanner.scanHoles(ms, now, pathRTO)
		}
		complete := scanner.completed()
		r.cfg.Stats.HiContig.Store(hi)
		r.cfg.Stats.RexQueueLen.Store(int64(scanner.pendingCount()))
		if complete {
			r.markDone()
		}

		peer := r.peer.Load()
		if peer == nil {
			continue
		}

		// Throttle NACK volume to the sender's per-interval resend capacity.
		blockBits := float64(r.cfg.BlockSize+DataHeaderSize) * 8
		nackCap := r.cfg.MaxNacksPerPDU
		if target > 0 && blockBits > 0 {
			perInterval := int(float64(target) / blockBits * (float64(r.cfg.FeedbackIntervalUs) / 1e6))
			if perInterval < 1 {
				perInterval = 1
			}
			if perInterval < nackCap {
				nackCap = perInterval
			}
		}
		due := scanner.collectDue(now, pathRTO, nackCap)

		curNow := nowMicros()
		isNet := false
		if curNow-lastNetTick >= uint64(r.cfg.NetTickIntervalUs) {
			isNet = true
			lastNetTick = curNow
		}

		nacks := make([]nackEntry, len(due))
		for i, s := range due {
			nacks[i] = nackEntry{blockSeq: s, rexIndex: int64(s)}
		}
		fh := feedbackHeader{
			tickIsNetwork: isNet,
			session:       r.cfg.Session,
			tick:          nowMicros(),
			targetRate:    target,
			hiContig:      hi,
			done:          complete,
		}
		nn := encodeFeedback(buf, fh, nacks)
		if _, err := r.cfg.Conn.WriteToUDP(buf[:nn], peer); err == nil && len(nacks) > 0 {
			r.cfg.Stats.NacksSent.Add(uint64(len(nacks)))
		}

		if complete {
			doneSends++
			if doneSends >= 8 {
				r.markDone()
				return
			}
		}
	}
}
