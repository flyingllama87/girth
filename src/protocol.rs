//! Wire protocol: PDU layouts, constants, CRC32C, and the monotonic clock.
//!
//! All multi-byte fields are little-endian, byte-for-byte identical to the Go
//! implementation so the two can interoperate on the wire.

use std::sync::OnceLock;
use std::time::Instant;

/// Bumped on incompatible wire changes.
pub const PROTOCOL_VERSION: i64 = 1;

/// UDP payload (bytes) carried per DATA PDU. The total PDU (header + payload +
/// IP/UDP encap) should stay under the path MTU to avoid fragmentation. 1400
/// keeps us safely under a 1500 MTU.
pub const DEFAULT_BLOCK_SIZE: usize = 1400;

/// Fixed DATA PDU header length in bytes.
pub const DATA_HEADER_SIZE: usize = 36;

// PDU type byte (first byte of every UDP datagram).
pub const PDU_DATA: u8 = 1;
pub const PDU_FEEDBACK: u8 = 2;
pub const PDU_START: u8 = 5;
pub const PDU_FIN: u8 = 4;

// DATA flags bitfield.
pub const FLAG_RETRANSMIT: u8 = 1 << 0; // this PDU is a retransmission
pub const FLAG_TICK_N: u8 = 1 << 1; // tick type: set => network ("N"), clear => path ("P")
pub const FLAG_HAS_TICK: u8 = 1 << 2; // echoTick field is valid
pub const FLAG_LAST_BLOCK: u8 = 1 << 3; // this is the final block of the file

/// CRC32C (Castagnoli), hardware-accelerated on amd64/arm64 — identical value
/// to Go's `crc32.MakeTable(crc32.Castagnoli)`.
#[inline]
pub fn crc32c(b: &[u8]) -> u32 {
    crc32c::crc32c(b)
}

/// Running CRC32C accumulator for the whole-file integrity check.
#[inline]
pub fn crc32c_append(crc: u32, b: &[u8]) -> u32 {
    crc32c::crc32c_append(crc, b)
}

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Monotonic microseconds since process start. All RTT math is done as
/// differences (and the one cross-host term is a duration), so absolute clock
/// offset between hosts cancels out.
#[inline]
pub fn now_micros() -> u64 {
    epoch().elapsed().as_micros() as u64
}

// --- little-endian helpers --------------------------------------------------

#[inline]
fn put_u16(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u32(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u64(b: &mut [u8], v: u64) {
    b[..8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn get_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
#[inline]
fn get_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
#[inline]
fn get_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Writes the 8-byte LE echo tick at the DATA header's tick slot. Exposed for
/// the sender's `attach_tick`, which stamps it into an already-built PDU.
#[inline]
pub fn put_echo_tick(buf: &mut [u8], v: u64) {
    put_u64(&mut buf[16..24], v);
}

// --- DATA PDU ---------------------------------------------------------------
//
// Layout (little-endian):
//   [0]      type (=1)
//   [1]      flags
//   [2:4]    payloadLen   u16
//   [4:8]    session      u32
//   [8:16]   blockSeq     u64   (0-based block index)
//   [16:24]  echoTick     u64   (valid if FLAG_HAS_TICK; receiver-clock micros)
//   [24:32]  rexIndex     i64   (receiver loss-table index, for O(1) cancel)
//   [32:36]  payloadCRC   u32   (CRC32C of payload)
//   [36:]    payload

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataHeader {
    pub flags: u8,
    pub payload_len: u16,
    pub session: u32,
    pub block_seq: u64,
    pub echo_tick: u64,
    pub rex_index: i64,
    pub payload_crc: u32,
}

/// Writes the header into `buf[..DATA_HEADER_SIZE]`.
pub fn encode_data_header(buf: &mut [u8], h: &DataHeader) {
    buf[0] = PDU_DATA;
    buf[1] = h.flags;
    put_u16(&mut buf[2..4], h.payload_len);
    put_u32(&mut buf[4..8], h.session);
    put_u64(&mut buf[8..16], h.block_seq);
    put_u64(&mut buf[16..24], h.echo_tick);
    put_u64(&mut buf[24..32], h.rex_index as u64);
    put_u32(&mut buf[32..36], h.payload_crc);
}

/// Parses a DATA header. Returns `None` if `buf` is too short or not a DATA PDU.
pub fn decode_data_header(buf: &[u8]) -> Option<DataHeader> {
    if buf.len() < DATA_HEADER_SIZE || buf[0] != PDU_DATA {
        return None;
    }
    Some(DataHeader {
        flags: buf[1],
        payload_len: get_u16(&buf[2..4]),
        session: get_u32(&buf[4..8]),
        block_seq: get_u64(&buf[8..16]),
        echo_tick: get_u64(&buf[16..24]),
        rex_index: get_u64(&buf[24..32]) as i64,
        payload_crc: get_u32(&buf[32..36]),
    })
}

// --- FEEDBACK PDU -----------------------------------------------------------
//
// Layout (little-endian):
//   [0]      type (=2)
//   [1]      flags (bit1 => tick type N, else P)
//   [2:4]    nackCount    u16
//   [4:8]    session      u32
//   [8:16]   tick         u64
//   [16:24]  targetRate   u64
//   [24:32]  hiContig     u64
//   [32]     done         u8
//   [33:36]  pad
//   [36:]    nackCount * { blockSeq u64 ; rexIndex i64 }   (16 bytes each)

pub const FEEDBACK_HEADER_SIZE: usize = 36;
pub const NACK_ENTRY_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, Default)]
pub struct FeedbackHeader {
    pub tick_is_network: bool,
    pub nack_count: u16,
    pub session: u32,
    pub tick: u64,
    pub target_rate: u64,
    pub hi_contig: u64,
    pub done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackEntry {
    pub block_seq: u64,
    pub rex_index: i64,
}

/// Encodes a feedback header followed by `nacks`, returning total length.
pub fn encode_feedback(buf: &mut [u8], h: &FeedbackHeader, nacks: &[NackEntry]) -> usize {
    buf[0] = PDU_FEEDBACK;
    let mut flags = 0u8;
    if h.tick_is_network {
        flags |= FLAG_TICK_N;
    }
    buf[1] = flags;
    put_u16(&mut buf[2..4], nacks.len() as u16);
    put_u32(&mut buf[4..8], h.session);
    put_u64(&mut buf[8..16], h.tick);
    put_u64(&mut buf[16..24], h.target_rate);
    put_u64(&mut buf[24..32], h.hi_contig);
    buf[32] = if h.done { 1 } else { 0 };
    buf[33] = 0;
    buf[34] = 0;
    buf[35] = 0;
    let mut off = FEEDBACK_HEADER_SIZE;
    for n in nacks {
        put_u64(&mut buf[off..off + 8], n.block_seq);
        put_u64(&mut buf[off + 8..off + 16], n.rex_index as u64);
        off += NACK_ENTRY_SIZE;
    }
    off
}

/// Decodes a feedback PDU. Returns `None` on a malformed/short buffer.
pub fn decode_feedback(buf: &[u8]) -> Option<(FeedbackHeader, Vec<NackEntry>)> {
    if buf.len() < FEEDBACK_HEADER_SIZE || buf[0] != PDU_FEEDBACK {
        return None;
    }
    let mut h = FeedbackHeader {
        tick_is_network: buf[1] & FLAG_TICK_N != 0,
        nack_count: get_u16(&buf[2..4]),
        session: get_u32(&buf[4..8]),
        tick: get_u64(&buf[8..16]),
        target_rate: get_u64(&buf[16..24]),
        hi_contig: get_u64(&buf[24..32]),
        done: buf[32] == 1,
    };
    let need = FEEDBACK_HEADER_SIZE + h.nack_count as usize * NACK_ENTRY_SIZE;
    if buf.len() < need {
        return None;
    }
    let mut nacks = Vec::with_capacity(h.nack_count as usize);
    let mut off = FEEDBACK_HEADER_SIZE;
    for _ in 0..h.nack_count {
        nacks.push(NackEntry {
            block_seq: get_u64(&buf[off..off + 8]),
            rex_index: get_u64(&buf[off + 8..off + 16]) as i64,
        });
        off += NACK_ENTRY_SIZE;
    }
    // Keep nack_count consistent with the parsed vector length.
    h.nack_count = nacks.len() as u16;
    Some((h, nacks))
}

// --- START / FIN PDUs -------------------------------------------------------

/// START (receiver->sender first contact). Returns bytes written.
pub fn encode_start(buf: &mut [u8], session: u32) -> usize {
    buf[0] = PDU_START;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    put_u32(&mut buf[4..8], session);
    8
}

/// FIN (sender->receiver, "I have injected every new block at least once").
pub fn encode_fin(buf: &mut [u8], session: u32, total_blocks: u64) -> usize {
    buf[0] = PDU_FIN;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    put_u32(&mut buf[4..8], session);
    put_u64(&mut buf[8..16], total_blocks);
    16
}

/// Returns the type byte (0 if empty).
#[inline]
pub fn pdu_type(buf: &[u8]) -> u8 {
    if buf.is_empty() {
        0
    } else {
        buf[0]
    }
}

/// Number of fixed-size blocks for a file of `size` bytes.
pub fn num_blocks(size: i64, block_size: usize) -> u64 {
    if size <= 0 {
        return 0;
    }
    (size as u64).div_ceil(block_size as u64)
}
