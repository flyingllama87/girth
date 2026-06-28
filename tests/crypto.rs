//! Data-plane crypto tests (ported from the Go `crypto_test.go`).

use girth::crypto::*;
use girth::protocol::DATA_HEADER_SIZE;
use std::sync::Arc;

fn pair_boxes(cipher_name: &str) -> (AeadBox, AeadBox) {
    let (cpriv, cpub) = gen_keypair();
    let (spriv, spub) = gen_keypair();
    const SESSION: u32 = 0xABCD1234;
    let client = derive_aead(&cpriv, &spub, SESSION, cipher_name).unwrap();
    let server = derive_aead(&spriv, &cpub, SESSION, cipher_name).unwrap();
    (client, server)
}

/// Seals `plaintext` into a fresh PDU-shaped buffer and returns the payload
/// region (ciphertext || tag), mirroring the Go `sealCopy`.
fn seal_copy(b: &AeadBox, plaintext: &[u8], seq: u64) -> Vec<u8> {
    let mut buf = vec![0u8; DATA_HEADER_SIZE + plaintext.len() + AEAD_TAG_LEN];
    buf[DATA_HEADER_SIZE..DATA_HEADER_SIZE + plaintext.len()].copy_from_slice(plaintext);
    let size = b.seal_data(&mut buf, DATA_HEADER_SIZE, plaintext.len(), seq);
    assert_eq!(size, DATA_HEADER_SIZE + plaintext.len() + AEAD_TAG_LEN);
    buf[DATA_HEADER_SIZE..size].to_vec()
}

#[test]
fn aead_round_trip_both_suites() {
    for name in [CIPHER_AES_GCM, CIPHER_CHACHA] {
        let (client, server) = pair_boxes(name);
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let mut payload = seal_copy(&client, plaintext, 42);
        assert_ne!(
            &payload[..plaintext.len()],
            &plaintext[..],
            "{name}: not encrypted"
        );
        let n = server
            .open_data(&mut payload, plaintext.len(), 42)
            .expect("open failed");
        assert_eq!(&payload[..n], &plaintext[..], "{name}");
    }
}

#[test]
fn aead_rejects_tampering() {
    let (client, server) = pair_boxes(CIPHER_AES_GCM);
    let plaintext = b"sensitive bytes";

    let mut payload = seal_copy(&client, plaintext, 7);
    payload[0] ^= 0xFF;
    assert!(server.open_data(&mut payload, plaintext.len(), 7).is_none());

    let mut payload = seal_copy(&client, plaintext, 7);
    let last = payload.len() - 1;
    payload[last] ^= 0xFF;
    assert!(server.open_data(&mut payload, plaintext.len(), 7).is_none());

    // Wrong block sequence (nonce mismatch) must fail authentication.
    let mut payload = seal_copy(&client, plaintext, 7);
    assert!(server.open_data(&mut payload, plaintext.len(), 8).is_none());
}

#[test]
fn aead_wrong_key_fails() {
    let (client, _) = pair_boxes(CIPHER_CHACHA);
    let (_, other) = pair_boxes(CIPHER_CHACHA);
    let mut payload = seal_copy(&client, b"payload", 1);
    assert!(other.open_data(&mut payload, b"payload".len(), 1).is_none());
}

#[test]
fn aead_empty_payload() {
    let (client, server) = pair_boxes(CIPHER_AES_GCM);
    let mut payload = seal_copy(&client, b"", 0);
    let n = server
        .open_data(&mut payload, 0, 0)
        .expect("empty roundtrip failed");
    assert_eq!(n, 0);
}

#[test]
fn choose_cipher_cases() {
    let aes = CIPHER_AES_GCM.to_string();
    let cha = CIPHER_CHACHA.to_string();
    let cases: Vec<(Vec<String>, Vec<String>, &str)> = vec![
        (
            vec![aes.clone(), cha.clone()],
            vec![cha.clone(), aes.clone()],
            CIPHER_AES_GCM,
        ),
        (
            vec![cha.clone(), aes.clone()],
            vec![aes.clone()],
            CIPHER_AES_GCM,
        ),
        (vec![aes.clone()], vec![cha.clone()], ""),
        (
            vec![cha.clone(), aes.clone()],
            vec![cha.clone(), aes.clone()],
            CIPHER_CHACHA,
        ),
    ];
    for (i, (prefer, peer, want)) in cases.iter().enumerate() {
        assert_eq!(choose_cipher(prefer, peer), *want, "case {i}");
    }
}

#[test]
fn server_negotiation_no_encrypt() {
    let (enc, _, _, b) = negotiate_crypto_server(false, &[], &[], 1).unwrap();
    assert!(!enc);
    assert!(b.is_none());
}

#[test]
fn client_crypto_fails_closed() {
    // User wanted encryption but server declined -> must error, not downgrade.
    assert!(client_crypto(true, false, &[], 0, "", None).is_err());
}

#[test]
fn full_handshake_negotiation_round_trip() {
    // Client requests encryption; server negotiates and both derive a matching
    // key that can seal/open across the boundary.
    let (cpriv, cpub) = gen_keypair();
    let session = 0x1122_3344u32;
    let (enc, cipher, spub, sbox) =
        negotiate_crypto_server(true, &local_ciphers(), &cpub, session).unwrap();
    assert!(enc);
    let sbox = sbox.unwrap();
    let cbox: Arc<AeadBox> = client_crypto(true, true, &spub, session, &cipher, Some(&cpriv))
        .unwrap()
        .unwrap();

    let mut payload = seal_copy(&cbox, b"hello over the wire", 9);
    let n = sbox
        .open_data(&mut payload, b"hello over the wire".len(), 9)
        .unwrap();
    assert_eq!(&payload[..n], b"hello over the wire");
}
