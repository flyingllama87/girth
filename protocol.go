package girth

import (
	"encoding/binary"
	"hash/crc32"
	"time"
)

// Wire protocol for girth — a FASP-inspired reliable bulk transfer over UDP.
//
// Two planes:
//   - Control plane (TCP): session setup, file metadata, checksum exchange.
//   - Data plane (UDP): DATA (sender->receiver), FEEDBACK (receiver->sender),
//     START (receiver->sender first contact), FIN (sender->receiver end-of-stream).
//
// The receiver is the "brain": it measures RTT, computes RTO, schedules
// retransmission requests (NACKs), and (in adaptive mode) computes the target
// rate. The sender is "dumb": it paces injection at the target rate, services
// retransmissions before new data, and echoes timing ticks.

const (
	// ProtocolVersion is bumped on incompatible wire changes.
	ProtocolVersion = 1

	// DefaultBlockSize is the UDP payload (bytes) carried per DATA PDU. The
	// total PDU (header + payload + IP/UDP encap) should stay under the path
	// MTU to avoid fragmentation. 1400 keeps us safely under a 1500 MTU.
	DefaultBlockSize = 1400

	// DataHeaderSize is the fixed DATA PDU header length in bytes.
	DataHeaderSize = 36
)

// PDU type byte (first byte of every UDP datagram).
const (
	pduData     = 1
	pduFeedback = 2
	pduStart    = 5
	pduFin      = 4
)

// DATA flags bitfield.
const (
	flagRetransmit = 1 << 0 // this PDU is a retransmission
	flagTickN      = 1 << 1 // tick type: set => network ("N"), clear => path ("P")
	flagHasTick    = 1 << 2 // echoTick field is valid
	flagLastBlock  = 1 << 3 // this is the final block of the file
)

// crcTable is Castagnoli (CRC32C), hardware-accelerated on amd64/arm64.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// crc32c returns the CRC32C of b.
func crc32c(b []byte) uint32 { return crc32.Checksum(b, crcTable) }

// epoch anchors the per-process monotonic clock used for timing ticks. Because
// all RTT math is done as differences (and the one cross-host term is a
// duration), absolute clock offset between hosts cancels out.
var epoch = time.Now()

// nowMicros returns monotonic microseconds since process start.
func nowMicros() uint64 { return uint64(time.Since(epoch).Microseconds()) }

// --- DATA PDU ---------------------------------------------------------------
//
// Layout (little-endian):
//   [0]      type (=1)
//   [1]      flags
//   [2:4]    payloadLen   u16
//   [4:8]    session      u32
//   [8:16]   blockSeq     u64   (0-based block index)
//   [16:24]  echoTick     u64   (valid if flagHasTick; receiver-clock micros)
//   [24:32]  rexIndex     i64   (receiver loss-table index, for O(1) cancel)
//   [32:36]  payloadCRC   u32   (CRC32C of payload)
//   [36:]    payload

type dataHeader struct {
	flags      uint8
	payloadLen uint16
	session    uint32
	blockSeq   uint64
	echoTick   uint64
	rexIndex   int64
	payloadCRC uint32
}

// encodeDataHeader writes the header into buf[:DataHeaderSize].
func encodeDataHeader(buf []byte, h dataHeader) {
	buf[0] = pduData
	buf[1] = h.flags
	binary.LittleEndian.PutUint16(buf[2:4], h.payloadLen)
	binary.LittleEndian.PutUint32(buf[4:8], h.session)
	binary.LittleEndian.PutUint64(buf[8:16], h.blockSeq)
	binary.LittleEndian.PutUint64(buf[16:24], h.echoTick)
	binary.LittleEndian.PutUint64(buf[24:32], uint64(h.rexIndex))
	binary.LittleEndian.PutUint32(buf[32:36], h.payloadCRC)
}

// decodeDataHeader parses a DATA header from buf. ok is false if buf is too
// short or not a DATA PDU.
func decodeDataHeader(buf []byte) (h dataHeader, ok bool) {
	if len(buf) < DataHeaderSize || buf[0] != pduData {
		return h, false
	}
	h.flags = buf[1]
	h.payloadLen = binary.LittleEndian.Uint16(buf[2:4])
	h.session = binary.LittleEndian.Uint32(buf[4:8])
	h.blockSeq = binary.LittleEndian.Uint64(buf[8:16])
	h.echoTick = binary.LittleEndian.Uint64(buf[16:24])
	h.rexIndex = int64(binary.LittleEndian.Uint64(buf[24:32]))
	h.payloadCRC = binary.LittleEndian.Uint32(buf[32:36])
	return h, true
}

// --- FEEDBACK PDU -----------------------------------------------------------
//
// Layout (little-endian):
//   [0]      type (=2)
//   [1]      flags (bit1 => tick type N, else P)
//   [2:4]    nackCount    u16
//   [4:8]    session      u32
//   [8:16]   tick         u64   (sender-echoes this back; receiver-clock micros)
//   [16:24]  targetRate   u64   (bits/sec the receiver requests; 0 => unchanged)
//   [24:32]  hiContig     u64   (#contiguous blocks received from 0)
//   [32]     done         u8    (1 => receiver has the whole file)
//   [33:36]  pad
//   [36:]    nackCount * { blockSeq u64 ; rexIndex i64 }   (16 bytes each)

const feedbackHeaderSize = 36
const nackEntrySize = 16

type feedbackHeader struct {
	tickIsNetwork bool
	nackCount     uint16
	session       uint32
	tick          uint64
	targetRate    uint64
	hiContig      uint64
	done          bool
}

type nackEntry struct {
	blockSeq uint64
	rexIndex int64
}

func encodeFeedback(buf []byte, h feedbackHeader, nacks []nackEntry) int {
	buf[0] = pduFeedback
	var flags uint8
	if h.tickIsNetwork {
		flags |= flagTickN
	}
	buf[1] = flags
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(nacks)))
	binary.LittleEndian.PutUint32(buf[4:8], h.session)
	binary.LittleEndian.PutUint64(buf[8:16], h.tick)
	binary.LittleEndian.PutUint64(buf[16:24], h.targetRate)
	binary.LittleEndian.PutUint64(buf[24:32], h.hiContig)
	if h.done {
		buf[32] = 1
	} else {
		buf[32] = 0
	}
	buf[33], buf[34], buf[35] = 0, 0, 0
	off := feedbackHeaderSize
	for _, n := range nacks {
		binary.LittleEndian.PutUint64(buf[off:off+8], n.blockSeq)
		binary.LittleEndian.PutUint64(buf[off+8:off+16], uint64(n.rexIndex))
		off += nackEntrySize
	}
	return off
}

func decodeFeedback(buf []byte) (h feedbackHeader, nacks []nackEntry, ok bool) {
	if len(buf) < feedbackHeaderSize || buf[0] != pduFeedback {
		return h, nil, false
	}
	h.tickIsNetwork = buf[1]&flagTickN != 0
	h.nackCount = binary.LittleEndian.Uint16(buf[2:4])
	h.session = binary.LittleEndian.Uint32(buf[4:8])
	h.tick = binary.LittleEndian.Uint64(buf[8:16])
	h.targetRate = binary.LittleEndian.Uint64(buf[16:24])
	h.hiContig = binary.LittleEndian.Uint64(buf[24:32])
	h.done = buf[32] == 1
	need := feedbackHeaderSize + int(h.nackCount)*nackEntrySize
	if len(buf) < need {
		return h, nil, false
	}
	if h.nackCount > 0 {
		nacks = make([]nackEntry, h.nackCount)
		off := feedbackHeaderSize
		for i := range nacks {
			nacks[i].blockSeq = binary.LittleEndian.Uint64(buf[off : off+8])
			nacks[i].rexIndex = int64(binary.LittleEndian.Uint64(buf[off+8 : off+16]))
			off += nackEntrySize
		}
	}
	return h, nacks, true
}

// --- START / FIN PDUs -------------------------------------------------------
//
// START (receiver->sender first contact, so the sender learns the receiver's
// UDP address even behind NAT):
//   [0] type (=5) ; [4:8] session u32
//
// FIN (sender->receiver, "I have injected every new block at least once"):
//   [0] type (=4) ; [4:8] session u32 ; [8:16] totalBlocks u64

func encodeStart(buf []byte, session uint32) int {
	buf[0] = pduStart
	buf[1], buf[2], buf[3] = 0, 0, 0
	binary.LittleEndian.PutUint32(buf[4:8], session)
	return 8
}

func encodeFin(buf []byte, session uint32, totalBlocks uint64) int {
	buf[0] = pduFin
	buf[1], buf[2], buf[3] = 0, 0, 0
	binary.LittleEndian.PutUint32(buf[4:8], session)
	binary.LittleEndian.PutUint64(buf[8:16], totalBlocks)
	return 16
}

// pduType returns the type byte (0 if empty).
func pduType(buf []byte) byte {
	if len(buf) == 0 {
		return 0
	}
	return buf[0]
}
