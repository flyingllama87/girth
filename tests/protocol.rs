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
