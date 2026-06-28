package girth

import "sync/atomic"

// recvBitmap is a concurrent received-block bitmap. The per-packet ingest path
// only ever sets bits (an order-independent, commutative operation), so it is
// safe and fast to update from many goroutines without a global lock.
type recvBitmap struct {
	words []atomic.Uint64
	total uint64
}

func newRecvBitmap(total uint64) *recvBitmap {
	return &recvBitmap{words: make([]atomic.Uint64, (total+63)/64), total: total}
}

// setAndTest atomically marks seq received and reports whether this was the
// first time (false => duplicate).
func (b *recvBitmap) setAndTest(seq uint64) (firstTime bool) {
	w := &b.words[seq>>6]
	mask := uint64(1) << (seq & 63)
	for {
		old := w.Load()
		if old&mask != 0 {
			return false
		}
		if w.CompareAndSwap(old, old|mask) {
			return true
		}
	}
}

func (b *recvBitmap) isSet(seq uint64) bool {
	return b.words[seq>>6].Load()&(1<<(seq&63)) != 0
}

// lossScanner detects missing blocks and schedules retransmission requests. It
// is owned exclusively by the receiver's single feedback goroutine, so it needs
// no locking. Detection is decoupled from packet ingest: because ingest only
// sets bits, by the time the scanner runs (every feedback interval) all blocks
// actually received so far are visible — so transient in-flight reordering can
// never be mistaken for loss. A block is only NACKed after it has been missing
// for one RTO of real elapsed time (the patent's "wait one RTO" rule).
type lossScanner struct {
	bm       *recvBitmap
	total    uint64
	hiContig uint64
	nextScan uint64 // next seq to examine for holes
	pending  map[uint64]struct{}
	heap     dueHeap
}

func newLossScanner(bm *recvBitmap, total uint64) *lossScanner {
	return &lossScanner{bm: bm, total: total, pending: make(map[uint64]struct{})}
}

// advance moves the contiguous high-water mark forward and drops pending entries
// that have since been filled. Returns the number of contiguous blocks.
func (s *lossScanner) advance() uint64 {
	for s.hiContig < s.total && s.bm.isSet(s.hiContig) {
		delete(s.pending, s.hiContig)
		s.hiContig++
	}
	return s.hiContig
}

// scanHoles records any newly-missing blocks in [nextScan, maxSeen] and
// schedules their first retransmit request at now+rto+precision. Blocks below
// nextScan that are still missing are already tracked in pending.
func (s *lossScanner) scanHoles(maxSeen uint64, now, rto float64) {
	if s.total == 0 {
		return
	}
	if maxSeen >= s.total {
		maxSeen = s.total - 1
	}
	due := uint64(now + rto + rttPrecUs)
	for seq := s.nextScan; seq <= maxSeen; seq++ {
		if s.bm.isSet(seq) {
			continue
		}
		if _, ok := s.pending[seq]; ok {
			continue
		}
		s.pending[seq] = struct{}{}
		s.heap.push(heapItem{seq: seq, due: due})
	}
	if maxSeen+1 > s.nextScan {
		s.nextScan = maxSeen + 1
	}
}

// collectDue returns up to max sequence numbers whose retransmit request is due,
// rescheduling each so the request repeats every RTO until the block arrives.
func (s *lossScanner) collectDue(now, rto float64, max int) []uint64 {
	var out []uint64
	reDue := uint64(now + rto + rttPrecUs)
	for len(out) < max && s.heap.len() > 0 {
		top := s.heap.peek()
		if float64(top.due) > now {
			break
		}
		s.heap.pop()
		if _, ok := s.pending[top.seq]; !ok {
			continue
		}
		if s.bm.isSet(top.seq) {
			delete(s.pending, top.seq)
			continue
		}
		out = append(out, top.seq)
		s.heap.push(heapItem{seq: top.seq, due: reDue})
	}
	return out
}

func (s *lossScanner) pendingCount() int { return len(s.pending) }

func (s *lossScanner) completed() bool { return s.hiContig == s.total }

// --- due-time min-heap -------------------------------------------------------

type heapItem struct {
	seq uint64
	due uint64
}

type dueHeap struct {
	items []heapItem
}

func (h *dueHeap) len() int       { return len(h.items) }
func (h *dueHeap) peek() heapItem { return h.items[0] }

func (h *dueHeap) push(it heapItem) {
	h.items = append(h.items, it)
	i := len(h.items) - 1
	for i > 0 {
		p := (i - 1) / 2
		if h.items[p].due <= h.items[i].due {
			break
		}
		h.items[p], h.items[i] = h.items[i], h.items[p]
		i = p
	}
}

func (h *dueHeap) pop() heapItem {
	n := len(h.items)
	top := h.items[0]
	h.items[0] = h.items[n-1]
	h.items = h.items[:n-1]
	n--
	i := 0
	for {
		l, r := 2*i+1, 2*i+2
		small := i
		if l < n && h.items[l].due < h.items[small].due {
			small = l
		}
		if r < n && h.items[r].due < h.items[small].due {
			small = r
		}
		if small == i {
			break
		}
		h.items[i], h.items[small] = h.items[small], h.items[i]
		i = small
	}
	return top
}
