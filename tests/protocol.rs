//! Wire-protocol, RTT, rate, and loss-scanner unit tests (ported from the Go
//! `protocol_test.go`).

use girth::losstracker::{LossScanner, RecvBitmap};
use girth::protocol::*;
use girth::rate::{RateConfig, RateController, RateMode, RttEstimator};
use std::sync::Arc;

#[test]
fn data_header_round_trip() {
    let in_h = DataHeader {
        flags: FLAG_RETRANSMIT | FLAG_HAS_TICK | FLAG_TICK_N | FLAG_LAST_BLOCK,
        payload_len: 1400,
        session: 0xDEADBEEF,
        block_seq: 0x0123456789ABCDEF,
        echo_tick: 123456789,
        rex_index: 42,
        payload_crc: 0xCAFEBABE,
    };
    let mut buf = vec![0u8; DATA_HEADER_SIZE + in_h.payload_len as usize];
    encode_data_header(&mut buf, &in_h);
    let out = decode_data_header(&buf).expect("decode failed");
    assert_eq!(out, in_h);
}

#[test]
fn feedback_round_trip() {
    let in_h = FeedbackHeader {
        tick_is_network: true,
        session: 7,
        tick: 999,
        target_rate: 250_000_000,
        hi_contig: 12345,
        done: true,
        ..Default::default()
    };
    let nacks = vec![
        NackEntry {
            block_seq: 1,
            rex_index: 1,
        },
        NackEntry {
            block_seq: 5,
            rex_index: 5,
        },
        NackEntry {
            block_seq: 99999,
            rex_index: 99999,
        },
    ];
    let mut buf = vec![0u8; FEEDBACK_HEADER_SIZE + nacks.len() * NACK_ENTRY_SIZE];
    let n = encode_feedback(&mut buf, &in_h, &nacks);
    let (out, got_nacks) = decode_feedback(&buf[..n]).expect("decode failed");
    assert_eq!(out.tick_is_network, in_h.tick_is_network);
    assert_eq!(out.session, in_h.session);
    assert_eq!(out.tick, in_h.tick);
    assert_eq!(out.target_rate, in_h.target_rate);
    assert_eq!(out.hi_contig, in_h.hi_contig);
    assert_eq!(out.done, in_h.done);
    assert_eq!(got_nacks, nacks);
}

#[test]
fn start_and_fin_round_trip_with_session() {
    let mut start = [0u8; 8];
    let n = encode_start(&mut start, 0x1122_3344);
    assert_eq!(n, 8);
    assert_eq!(decode_start(&start), Some(0x1122_3344));
    assert_eq!(decode_start(&start[..7]), None);

    let mut fin = [0u8; 16];
    let n = encode_fin(&mut fin, 0x5566_7788, 12345);
    assert_eq!(n, 16);
    assert_eq!(decode_fin(&fin), Some((0x5566_7788, 12345)));
    assert_eq!(decode_fin(&fin[..15]), None);
}

#[test]
fn crc32c_detects_corruption() {
    let mut data = b"the quick brown fox".to_vec();
    let c = crc32c(&data);
    data[0] ^= 0xFF;
    assert_ne!(crc32c(&data), c);
}

#[test]
fn rtt_estimator_converges_and_bounds() {
    let mut e = RttEstimator::new();
    const TARGET: f64 = 280000.0; // 280 ms in micros
    let mut rto = 0.0;
    for _ in 0..200 {
        rto = e.sample(TARGET);
    }
    assert!((e.srtt - TARGET).abs() <= TARGET * 0.01, "srtt={}", e.srtt);
    assert!(rto >= e.srtt);
    e.sample(100000.0);
    assert_eq!(e.min_rtt, 100000.0);
}

#[test]
fn rtt_estimator_can_be_seeded() {
    let mut e = RttEstimator::new();
    e.seed(120_000, 90_000);

    assert_eq!(e.srtt, 120_000.0);
    assert_eq!(e.min_rtt, 90_000.0);
    assert!(e.rto() >= e.srtt);

    e.sample(100_000.0);
    assert!(e.srtt < 120_000.0);
    assert_eq!(e.min_rtt, 90_000.0);
}

#[test]
fn adaptive_rate_equilibrium() {
    let cfg = RateConfig {
        mode: RateMode::Adaptive,
        target_bps: 1_000_000,
        max_bps: 100_000_000_000,
        min_bps: 1000,
        alpha: 30_000_000.0,
    };
    let mut rc = RateController::new(cfg);
    let base = 100000.0;
    let srtt = 110000.0;
    let mut rate = 0;
    for _ in 0..5000 {
        rate = rc.update(srtt, base);
    }
    let want = cfg.alpha / (1.0 - base / srtt);
    assert!(
        (rate as f64 - want).abs() / want <= 0.05,
        "rate={} want={}",
        rate,
        want
    );
}

#[test]
fn adaptive_rate_can_be_warm_started() {
    let cfg = RateConfig {
        mode: RateMode::Adaptive,
        target_bps: 1_000_000,
        max_bps: 10_000_000,
        min_bps: 1000,
        alpha: 30_000_000.0,
    };
    let mut rc = RateController::new(cfg);
    rc.set_rate(50_000_000);

    assert_eq!(rc.update(0.0, 0.0), 10_000_000);
}

#[test]
fn fixed_rate_constant() {
    let cfg = RateConfig {
        mode: RateMode::Fixed,
        target_bps: 500_000_000,
        min_bps: 0,
        max_bps: 0,
        alpha: 0.0,
    };
    let mut rc = RateController::new(cfg);
    for _ in 0..100 {
        assert_eq!(rc.update(200000.0, 100000.0), 500_000_000);
    }
}

#[test]
fn loss_scanner_detect_and_cancel() {
    const TOTAL: u64 = 1000;
    let bm = Arc::new(RecvBitmap::new(TOTAL));
    let mut s = LossScanner::new(bm.clone(), TOTAL);

    for i in 0..=499u64 {
        bm.set_and_test(i);
    }
    bm.set_and_test(600);

    let now = 1_000_000.0;
    let rto = 10000.0;
    s.advance();
    s.scan_holes(600, now, rto);
    assert_eq!(s.pending_count(), 100); // 500..599

    assert_eq!(s.collect_due(now, rto, 1000).len(), 0); // nothing due yet

    let later = now + rto + girth::rate::RTT_PREC_US + 1.0;
    let due = s.collect_due(later, rto, 1000);
    assert_eq!(due.len(), 100);
    assert_eq!(due[0], 500);

    for i in 500..=600u64 {
        bm.set_and_test(i);
    }
    for i in 601..TOTAL {
        bm.set_and_test(i);
    }
    s.advance();
    assert!(s.completed());
}

#[test]
fn recv_bitmap_duplicate_detection() {
    let bm = RecvBitmap::new(128);
    assert!(bm.set_and_test(65));
    assert!(!bm.set_and_test(65));
    assert!(bm.is_set(65));
    assert!(!bm.is_set(64));
}

#[test]
fn num_blocks_cases() {
    let cases = [
        (0i64, 1400usize, 0u64),
        (1, 1400, 1),
        (1400, 1400, 1),
        (1401, 1400, 2),
        (1234567, 1400, 882),
    ];
    for (size, bs, blocks) in cases {
        assert_eq!(num_blocks(size, bs), blocks, "num_blocks({size},{bs})");
    }
}

// --- decoder negative tests (P0-2: no panics on malformed/short input) -------

#[test]
fn decoders_reject_malformed_without_panicking() {
    // Empty / truncated buffers of every length below the header size.
    for n in 0..DATA_HEADER_SIZE {
        assert!(decode_data_header(&vec![PDU_DATA; n]).is_none());
    }
    for n in 0..FEEDBACK_HEADER_SIZE {
        assert!(decode_feedback(&vec![PDU_FEEDBACK; n]).is_none());
    }

    // Right length but wrong type byte.
    assert!(decode_data_header(&[0xFE; DATA_HEADER_SIZE]).is_none());
    assert!(decode_feedback(&[0xFE; FEEDBACK_HEADER_SIZE]).is_none());

    // Feedback header claiming more NACK entries than the buffer can hold must
    // be rejected rather than reading out of bounds.
    let mut fb = vec![0u8; FEEDBACK_HEADER_SIZE];
    fb[0] = PDU_FEEDBACK;
    fb[2] = 0xFF; // nack_count low byte = 255, far more than present
    fb[3] = 0xFF;
    assert!(decode_feedback(&fb).is_none());

    // pdu_type on an empty slice is well-defined (0), not a panic.
    assert_eq!(pdu_type(&[]), 0);
}

#[test]
fn decoders_accept_well_formed_after_negatives() {
    // Sanity: a valid header still decodes (guards against an over-strict fix).
    let mut buf = vec![0u8; DATA_HEADER_SIZE];
    encode_data_header(
        &mut buf,
        &DataHeader {
            payload_len: 0,
            session: 7,
            block_seq: 3,
            ..Default::default()
        },
    );
    let h = decode_data_header(&buf).expect("valid header decodes");
    assert_eq!(h.session, 7);
    assert_eq!(h.block_seq, 3);
}
