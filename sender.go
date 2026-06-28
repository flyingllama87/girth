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

// kernelPacingEnabled reports whether to offload egress pacing to the kernel
// (SO_MAX_PACING_RATE + the fq qdisc). It is OPT-IN (GIRTH_PACE=1) and off by
// default: measurements on a real LFN showed it caps throughput below target
// for no loss benefit, and it requires the non-default fq qdisc. It remains
// available for paths with low-burst-tolerance policers. When enabled we pair
// it with a small socket send buffer so the paced queue adds only a bounded
// amount of latency (a large buffer would inflate RTT into false-loss NACKs).
func kernelPacingEnabled() bool { return os.Getenv("GIRTH_PACE") == "1" }

// setMaxPacingRate sets the kernel egress pacing ceiling for the socket. It is
// a no-op on platforms without an equivalent syscall (see platform_*.go).
func setMaxPacingRate(conn *net.UDPConn, bps uint64) {
	platformSetMaxPacingRate(conn, bps)
}

// SendConfig configures a sending data-plane session.
type SendConfig struct {
	Conn        *net.UDPConn
	Peer        *net.UDPAddr // receiver UDP addr; if nil, learned from first packet (START)
	File        *os.File
	FileSize    int64
	BlockSize   int
	TotalBlocks uint64
	Session     uint32
	Rate        RateConfig
	ReadWorkers int      // prefetch reader goroutines (default 2)
	Crypto      *aeadBox // data-plane AEAD; nil => cleartext
	Stats       *Stats
	Log         *log.Logger
}

// Sender runs the sending side: paced injection at the target rate, with
// retransmissions (lowest sequence first) always sent before new blocks.
type Sender struct {
	cfg SendConfig

	peer atomic.Pointer[net.UDPAddr]

	targetBps atomic.Uint64

	// retransmit queue: min-by-seq, deduplicated.
	rexMu   sync.Mutex
	rexHeap minSeqHeap
	rexSet  map[uint64]struct{}

	// pending timing tick to echo back to the receiver.
	tickMu      sync.Mutex
	tickPending bool
	tickVal     uint64 // receiver T1
	tickIsNet   bool
	tickT2      uint64 // sender clock at feedback receipt

	done      chan struct{}
	closeOnce sync.Once
}

// prefetched is one ready-to-send new-block PDU buffer.
type prefetched struct {
	buf  []byte // full PDU (header + payload)
	size int    // total PDU length
}

// NewSender builds a Sender from cfg.
func NewSender(cfg SendConfig) *Sender {
	if cfg.ReadWorkers <= 0 {
		cfg.ReadWorkers = 2
	}
	if cfg.Log == nil {
		cfg.Log = log.New(os.Stderr, "girth-send ", log.LstdFlags|log.Lmicroseconds)
	}
	s := &Sender{
		cfg:    cfg,
		rexSet: make(map[uint64]struct{}),
		done:   make(chan struct{}),
	}
	if cfg.Peer != nil {
		s.peer.Store(cfg.Peer)
	}
	init := cfg.Rate.TargetBps
	if init == 0 {
		init = cfg.Rate.MaxBps
	}
	s.targetBps.Store(init)
	cfg.Stats.TotalBytes.Store(uint64(cfg.FileSize))
	cfg.Stats.TotalBlocks.Store(cfg.TotalBlocks)
	cfg.Stats.TargetRateBps.Store(init)
	return s
}

// Run performs the transfer, returning nil once the receiver acknowledges DONE.
func (s *Sender) Run(stop <-chan struct{}) error {
	// Learn the receiver's UDP address if not provided (NAT-friendly: the
	// receiver sends a START first).
	if s.peer.Load() == nil {
		if err := s.waitForPeer(stop); err != nil {
			return err
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.feedbackLoop(stop) }()

	// Empty file: nothing to inject; just announce FIN until DONE.
	free := make(chan []byte, 4096)
	ready := make(chan prefetched, 4096)
	bufLen := s.cfg.BlockSize + DataHeaderSize + s.overhead()
	for i := 0; i < cap(free); i++ {
		free <- make([]byte, bufLen)
	}

	var rwg sync.WaitGroup
	if s.cfg.TotalBlocks > 0 {
		// A single sequential reader preserves global block order on the wire
		// (out-of-order injection would make the receiver mistake in-flight
		// blocks for loss and NACK them). Sequential reads are cheap thanks to
		// OS read-ahead and the page cache; the receiver is where we spend
		// cores in parallel. CRC32C is hardware-accelerated and computed here.
		rwg.Add(1)
		go func() { defer rwg.Done(); s.prefetch(0, s.cfg.TotalBlocks, free, ready, stop) }()
	}
	go func() { rwg.Wait(); close(ready) }()

	err := s.pacingLoop(free, ready, stop)

	s.markDone()
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = s.cfg.Conn.SetReadDeadline(time.Now())
	}()
	wg.Wait()
	return err
}

func (s *Sender) markDone() { s.closeOnce.Do(func() { close(s.done) }) }

// overhead is the per-PDU AEAD expansion (tag bytes), 0 when not encrypting.
func (s *Sender) overhead() int {
	if s.cfg.Crypto != nil {
		return s.cfg.Crypto.overhead()
	}
	return 0
}

func (s *Sender) waitForPeer(stop <-chan struct{}) error {
	buf := make([]byte, 2048)
	_ = s.cfg.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer s.cfg.Conn.SetReadDeadline(time.Time{})
	for {
		select {
		case <-stop:
			return fmt.Errorf("stopped while waiting for receiver")
		default:
		}
		n, addr, err := s.cfg.Conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				return fmt.Errorf("timed out waiting for receiver START")
			}
			return err
		}
		_ = n
		s.peer.Store(addr)
		return nil
	}
}

// prefetch reads blocks [lo,hi) from disk into pooled PDU buffers (with headers
// + CRC filled in) and publishes them in order to the ready channel. Note:
// readers cover disjoint ranges, so the global order across readers is only
// approximately sequential — acceptable, since the receiver writes by absolute
// offset and only cares about completeness.
func (s *Sender) prefetch(lo, hi uint64, free chan []byte, ready chan prefetched, stop <-chan struct{}) {
	for seq := lo; seq < hi; seq++ {
		var buf []byte
		select {
		case buf = <-free:
		case <-stop:
			return
		case <-s.done:
			return
		}
		off := int64(seq) * int64(s.cfg.BlockSize)
		plen := s.cfg.BlockSize
		if rem := s.cfg.FileSize - off; rem < int64(plen) {
			plen = int(rem)
		}
		payload := buf[DataHeaderSize : DataHeaderSize+plen]
		if _, err := s.cfg.File.ReadAt(payload, off); err != nil {
			s.cfg.Log.Printf("read error at block %d: %v", seq, err)
			return
		}
		var flags uint8
		if seq == s.cfg.TotalBlocks-1 {
			flags |= flagLastBlock
		}
		// In cleartext mode the header carries a payload CRC32C; in encrypted
		// mode the AEAD tag is the integrity check, so the CRC is left zero.
		var crc uint32
		if s.cfg.Crypto == nil {
			crc = crc32c(payload)
		}
		encodeDataHeader(buf, dataHeader{
			flags:      flags,
			payloadLen: uint16(plen),
			session:    s.cfg.Session,
			blockSeq:   seq,
			payloadCRC: crc,
		})
		size := DataHeaderSize + plen
		if s.cfg.Crypto != nil {
			size = s.cfg.Crypto.sealData(buf, DataHeaderSize, plen, seq)
		}
		select {
		case ready <- prefetched{buf: buf, size: size}:
		case <-stop:
			return
		case <-s.done:
			return
		}
	}
}

// pacingLoop is the high-precision injector. It implements the patent's
// batch + lag-compensation design: packets are grouped into batches sized so
// the inter-batch delay (IPD) is large enough (>=5ms) to absorb OS scheduling
// jitter while keeping the average rate precise. We schedule against an
// absolute deadline (self-correcting) and cap how far we may fall behind so a
// stall cannot produce an unbounded catch-up burst.
func (s *Sender) pacingLoop(free chan []byte, ready chan prefetched, stop <-chan struct{}) error {
	peer := s.peer.Load()
	bufLen := s.cfg.BlockSize + DataHeaderSize + s.overhead()

	// One sendmmsg per batch (instead of one sendto per packet) collapses the
	// dominant per-packet syscall cost — the single-flow sender bottleneck on a
	// fast LFN. The inter-batch IPD is kept large (>=5ms) so burst shape and
	// pacing precision are unchanged; only the cost of emitting a batch drops.
	bs := newBatchSender(s.cfg.Conn, peer, 1024)
	// Scratch buffers for retransmits inside the current batch. WriteBatch is
	// synchronous, so these are safe to reuse on the next batch.
	var rexScratch [][]byte
	// New-block buffers borrowed from the pool this batch; returned after flush.
	newBufs := make([][]byte, 0, 1024)

	var curRate uint64
	var ipdUs, batch float64
	// maxBatch caps how many packets one sendmmsg emits. sendmmsg hands the
	// whole batch to the kernel at once (a line-rate microburst), so an
	// oversized batch overflows downstream buffers and triggers loss. A small
	// cap keeps each burst gentle (~64*1.5KB ≈ 96KB) while still collapsing the
	// per-packet syscall cost ~60x versus one sendto per packet.
	const maxBatch = 64
	pacing := kernelPacingEnabled()
	if pacing {
		// Bound the kernel pacing queue: a small send buffer means the paced
		// backlog can add at most a few ms of latency (well under the RTO), so
		// it cannot inflate the measured RTT into false-loss territory.
		_ = s.cfg.Conn.SetWriteBuffer(2 << 20)
	}
	recompute := func(rate uint64) {
		if rate == 0 {
			rate = 1
		}
		blockBits := float64(s.cfg.BlockSize+DataHeaderSize) * 8
		ipd := blockBits / float64(rate) * 1e6 // micros per packet
		if ipd < 5000 {
			batch = float64(int(5000/ipd) + 1)
			if batch > maxBatch {
				batch = maxBatch
			}
			ipdUs = blockBits * batch / float64(rate) * 1e6
		} else {
			batch = 1
			ipdUs = ipd
		}
		curRate = rate
		if pacing {
			// Pace a touch above the app target so the kernel smooths the
			// per-batch bursts on the wire without ever throttling below target.
			setMaxPacingRate(s.cfg.Conn, rate+rate/16)
		}
	}
	recompute(s.targetBps.Load())

	newDone := false
	nextDeadline := float64(nowMicros())

	for {
		select {
		case <-s.done:
			return nil
		case <-stop:
			return fmt.Errorf("sender stopped")
		default:
		}

		if r := s.targetBps.Load(); r != curRate {
			recompute(r)
		}

		// Build one batch: retransmissions first (lowest seq), then new blocks.
		toSend := int(batch)
		bs.reset()
		newBufs = newBufs[:0]
		rexIdx := 0
		var rexBytes, newBytes uint64
		var rexN, newN int
		built := 0
		for built < toSend {
			if seq, ok := s.popRetransmit(); ok {
				if rexIdx == len(rexScratch) {
					rexScratch = append(rexScratch, make([]byte, bufLen))
				}
				rbuf := rexScratch[rexIdx]
				if n, ok := s.fillRetransmit(rbuf, seq); ok {
					s.attachTick(rbuf)
					bs.add(rbuf[:n])
					rexBytes += uint64(n)
					rexN++
					rexIdx++
					built++
				}
				continue
			}
			if newDone {
				break
			}
			select {
			case item, ok := <-ready:
				if !ok {
					newDone = true
					continue
				}
				s.attachTick(item.buf)
				bs.add(item.buf[:item.size])
				newBufs = append(newBufs, item.buf)
				newBytes += uint64(item.size)
				newN++
				built++
			default:
				// Nothing prefetched yet; flush what we have and retry next tick.
				built = toSend
			}
		}

		// One syscall sends the whole batch.
		bs.flush()
		if rexN > 0 {
			s.cfg.Stats.RetransSent.Add(uint64(rexN))
			s.cfg.Stats.PacketsSent.Add(uint64(rexN))
			s.cfg.Stats.BytesSent.Add(rexBytes)
		}
		if newN > 0 {
			s.cfg.Stats.PacketsSent.Add(uint64(newN))
			s.cfg.Stats.BytesSent.Add(newBytes)
		}
		for _, b := range newBufs {
			free <- b
		}

		// Phase 2: all new blocks injected. Announce FIN until DONE.
		if newDone && s.rexLen() == 0 {
			s.sendFin(peer)
		}

		// Absolute-deadline pacing.
		nextDeadline += ipdUs
		now := float64(nowMicros())
		if now < nextDeadline {
			preciseSleepUs(nextDeadline - now)
		} else if now-nextDeadline > 100*ipdUs {
			// Fell too far behind (e.g. long stall); resynchronise.
			nextDeadline = now
		}
	}
}

// batchSender emits a group of UDP datagrams with a single sendmmsg(2) call via
// golang.org/x/net/ipv4. If the platform/socket cannot do batched writes it
// transparently falls back to per-packet WriteToUDP.
type batchSender struct {
	conn *net.UDPConn
	pc   *ipv4.PacketConn
	peer *net.UDPAddr
	msgs []ipv4.Message
	n    int
	bad  bool // batched write unsupported; use per-packet fallback
}

func newBatchSender(conn *net.UDPConn, peer *net.UDPAddr, capHint int) *batchSender {
	if capHint < 8 {
		capHint = 8
	}
	return &batchSender{
		conn: conn,
		pc:   ipv4.NewPacketConn(conn),
		peer: peer,
		msgs: make([]ipv4.Message, 0, capHint),
		bad:  os.Getenv("GIRTH_NOBATCH") != "", // debug: force per-packet sends
	}
}

func (b *batchSender) reset() { b.n = 0 }

// add appends a datagram (p must stay valid until flush returns).
func (b *batchSender) add(p []byte) {
	if b.n == len(b.msgs) {
		b.msgs = append(b.msgs, ipv4.Message{Buffers: [][]byte{nil}})
	}
	m := &b.msgs[b.n]
	m.Buffers[0] = p
	m.Addr = b.peer
	b.n++
}

// flush sends all queued datagrams and returns the count actually sent.
func (b *batchSender) flush() int {
	if b.n == 0 {
		return 0
	}
	sent := 0
	if !b.bad {
		for sent < b.n {
			k, err := b.pc.WriteBatch(b.msgs[sent:b.n], 0)
			if err != nil {
				b.bad = true // permanently fall back
				break
			}
			if k <= 0 {
				break
			}
			sent += k
		}
	}
	// Per-packet fallback for anything not sent (unsupported or partial).
	for i := sent; i < b.n; i++ {
		if _, err := b.conn.WriteToUDP(b.msgs[i].Buffers[0], b.peer); err == nil {
			sent++
		}
	}
	return sent
}

func (s *Sender) fillRetransmit(buf []byte, seq uint64) (int, bool) {
	off := int64(seq) * int64(s.cfg.BlockSize)
	plen := s.cfg.BlockSize
	if rem := s.cfg.FileSize - off; rem < int64(plen) {
		plen = int(rem)
	}
	if plen <= 0 {
		return 0, false
	}
	payload := buf[DataHeaderSize : DataHeaderSize+plen]
	if _, err := s.cfg.File.ReadAt(payload, off); err != nil {
		return 0, false
	}
	flags := uint8(flagRetransmit)
	if seq == s.cfg.TotalBlocks-1 {
		flags |= flagLastBlock
	}
	var crc uint32
	if s.cfg.Crypto == nil {
		crc = crc32c(payload)
	}
	encodeDataHeader(buf, dataHeader{
		flags:      flags,
		payloadLen: uint16(plen),
		session:    s.cfg.Session,
		blockSeq:   seq,
		rexIndex:   int64(seq),
		payloadCRC: crc,
	})
	if s.cfg.Crypto != nil {
		return s.cfg.Crypto.sealData(buf, DataHeaderSize, plen, seq), true
	}
	return DataHeaderSize + plen, true
}

// attachTick stamps a pending echo tick into a DATA PDU header if one is
// waiting. For network ("N") ticks the sender's own processing delay
// (now - T2) is added so the receiver measures network-only RTT.
func (s *Sender) attachTick(buf []byte) {
	s.tickMu.Lock()
	if !s.tickPending {
		s.tickMu.Unlock()
		return
	}
	tick := s.tickVal
	isNet := s.tickIsNet
	t2 := s.tickT2
	s.tickPending = false
	s.tickMu.Unlock()

	echo := tick
	flags := buf[1] | flagHasTick
	if isNet {
		flags |= flagTickN
		echo = tick + (nowMicros() - t2)
	} else {
		flags &^= flagTickN
	}
	buf[1] = flags
	// echoTick lives at [16:24].
	putU64(buf[16:24], echo)
}

func (s *Sender) sendFin(peer *net.UDPAddr) {
	var b [16]byte
	n := encodeFin(b[:], s.cfg.Session, s.cfg.TotalBlocks)
	_, _ = s.cfg.Conn.WriteToUDP(b[:n], peer)
}

// feedbackLoop reads FEEDBACK PDUs: it records the timing tick, queues NACKs,
// adopts the receiver's target rate (adaptive mode), and watches for DONE.
func (s *Sender) feedbackLoop(stop <-chan struct{}) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-s.done:
			return
		case <-stop:
			return
		default:
		}
		n, _, err := s.cfg.Conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				select {
				case <-s.done:
					return
				default:
					continue
				}
			}
			return
		}
		if pduType(buf[:n]) != pduFeedback {
			continue
		}
		t2 := nowMicros()
		fh, nacks, ok := decodeFeedback(buf[:n])
		if !ok || fh.session != s.cfg.Session {
			continue
		}

		// Stash the tick to echo on the next outgoing DATA PDU.
		s.tickMu.Lock()
		s.tickPending = true
		s.tickVal = fh.tick
		s.tickIsNet = fh.tickIsNetwork
		s.tickT2 = t2
		s.tickMu.Unlock()

		if len(nacks) > 0 {
			s.cfg.Stats.NacksRecv.Add(uint64(len(nacks)))
			s.pushRetransmits(nacks)
		}

		// Adopt receiver-computed rate in adaptive mode.
		if s.cfg.Rate.Mode == RateAdaptive && fh.targetRate > 0 {
			s.targetBps.Store(fh.targetRate)
			s.cfg.Stats.TargetRateBps.Store(fh.targetRate)
		}
		s.cfg.Stats.HiContig.Store(fh.hiContig)

		if fh.done {
			s.markDone()
			return
		}
	}
}

// --- retransmit queue --------------------------------------------------------

func (s *Sender) pushRetransmits(nacks []nackEntry) {
	s.rexMu.Lock()
	for _, n := range nacks {
		if _, ok := s.rexSet[n.blockSeq]; ok {
			continue
		}
		s.rexSet[n.blockSeq] = struct{}{}
		s.rexHeap.push(n.blockSeq)
	}
	s.cfg.Stats.RexQueueLen.Store(int64(len(s.rexSet)))
	s.rexMu.Unlock()
}

func (s *Sender) popRetransmit() (uint64, bool) {
	s.rexMu.Lock()
	defer s.rexMu.Unlock()
	if s.rexHeap.len() == 0 {
		return 0, false
	}
	seq := s.rexHeap.pop()
	delete(s.rexSet, seq)
	s.cfg.Stats.RexQueueLen.Store(int64(len(s.rexSet)))
	return seq, true
}

func (s *Sender) rexLen() int {
	s.rexMu.Lock()
	defer s.rexMu.Unlock()
	return s.rexHeap.len()
}

// minSeqHeap is a binary min-heap of block sequence numbers, so the sender
// retransmits lowest-numbered blocks first (optimising sequential disk reads
// and receiver sequential writes).
type minSeqHeap struct{ a []uint64 }

func (h *minSeqHeap) len() int { return len(h.a) }
func (h *minSeqHeap) push(v uint64) {
	h.a = append(h.a, v)
	i := len(h.a) - 1
	for i > 0 {
		p := (i - 1) / 2
		if h.a[p] <= h.a[i] {
			break
		}
		h.a[p], h.a[i] = h.a[i], h.a[p]
		i = p
	}
}
func (h *minSeqHeap) pop() uint64 {
	n := len(h.a)
	top := h.a[0]
	h.a[0] = h.a[n-1]
	h.a = h.a[:n-1]
	n--
	i := 0
	for {
		l, r := 2*i+1, 2*i+2
		small := i
		if l < n && h.a[l] < h.a[small] {
			small = l
		}
		if r < n && h.a[r] < h.a[small] {
			small = r
		}
		if small == i {
			break
		}
		h.a[i], h.a[small] = h.a[small], h.a[i]
		i = small
	}
	return top
}
