//! Optional confidentiality + integrity for the data plane.
//!
//! Key agreement runs over the (cleartext) TCP control channel: each side sends
//! an ephemeral X25519 public key, both compute the shared ECDH secret, and
//! HKDF-SHA256 derives the symmetric data key. Ephemeral keys give forward
//! secrecy. Each DATA payload is sealed with an AEAD (AES-256-GCM where the CPU
//! has AES instructions, else ChaCha20-Poly1305). The nonce is derived from the
//! globally-unique block sequence number (already in the cleartext header), so
//! it is never transmitted and a retransmit re-seals identically. The 16-byte
//! tag replaces the per-packet CRC in encrypted mode (whole-file CRC32C is
//! still verified end to end).
//!
//! Wire-compatible with the Go implementation: identical X25519/HKDF derivation
//! (salt = LE session id, info = `"girth data key <cipher>"`) and identical
//! ciphertext||tag layout.

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

/// Cipher suite identifiers exchanged in the handshake.
pub const CIPHER_AES_GCM: &str = "aes-256-gcm";
pub const CIPHER_CHACHA: &str = "chacha20-poly1305";

pub const AEAD_KEY_LEN: usize = 32; // 256-bit key for both suites
pub const AEAD_NONCE_LEN: usize = 12; // 96-bit nonce for both suites
pub const AEAD_TAG_LEN: usize = 16; // 128-bit tag for both suites

/// Reports whether the CPU has native AES instructions (AES-NI on x86, the
/// ARMv8 Cryptographic Extension on arm64). When present AES-GCM is faster;
/// otherwise ChaCha20-Poly1305 is preferred.
pub fn aes_hardware() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// This host's supported suites in preference order.
pub fn local_ciphers() -> Vec<String> {
    if aes_hardware() {
        vec![CIPHER_AES_GCM.into(), CIPHER_CHACHA.into()]
    } else {
        vec![CIPHER_CHACHA.into(), CIPHER_AES_GCM.into()]
    }
}

/// Picks the first suite in our preference order that the peer also supports.
/// Returns `""` if there is no common suite.
pub fn choose_cipher(prefer: &[String], peer: &[String]) -> String {
    for c in prefer {
        if peer.iter().any(|p| p == c) {
            return c.clone();
        }
    }
    String::new()
}

/// Returns the local cipher list when `enc`, else `None` (so the handshake JSON
/// omits it, matching Go's `omitempty`).
pub fn ciphers_if(enc: bool) -> Option<Vec<String>> {
    if enc {
        Some(local_ciphers())
    } else {
        None
    }
}

/// A negotiated AEAD for the data plane. The underlying cipher is safe for
/// concurrent seal/open, so parallel ingest threads decrypt simultaneously and
/// prefetch/retransmit encrypt concurrently.
// The two suites differ in size (AES-GCM carries a GHASH table); both live for
// the whole transfer and are hit on the hot path, so we keep them inline rather
// than boxing.
#[allow(clippy::large_enum_variant)]
pub enum AeadBox {
    Aes(Aes256Gcm),
    Cha(ChaCha20Poly1305),
}

fn block_nonce(seq: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    // bytes [0:4] are a zero/domain prefix; the unique part is the 64-bit seq.
    n[4..].copy_from_slice(&seq.to_le_bytes());
    n
}

impl AeadBox {
    fn new(name: &str, key: &[u8]) -> Result<AeadBox, String> {
        if key.len() != AEAD_KEY_LEN {
            return Err(format!("girth: bad key length {}", key.len()));
        }
        let k = GenericArray::from_slice(key);
        match name {
            CIPHER_AES_GCM => Ok(AeadBox::Aes(Aes256Gcm::new(k))),
            CIPHER_CHACHA => Ok(AeadBox::Cha(ChaCha20Poly1305::new(k))),
            _ => Err(format!("girth: unknown cipher {:?}", name)),
        }
    }

    pub fn overhead(&self) -> usize {
        AEAD_TAG_LEN
    }

    pub fn name(&self) -> &'static str {
        match self {
            AeadBox::Aes(_) => CIPHER_AES_GCM,
            AeadBox::Cha(_) => CIPHER_CHACHA,
        }
    }

    /// Encrypts `plen` plaintext bytes at `buf[hdr_len..hdr_len+plen]` in place,
    /// appending the 16-byte tag, and returns the total PDU length
    /// (`hdr_len + plen + tag`). The header (`buf[..hdr_len]`) is untouched so
    /// the cleartext routing fields stay readable. `buf` must have capacity for
    /// the tag.
    pub fn seal_data(&self, buf: &mut [u8], hdr_len: usize, plen: usize, seq: u64) -> usize {
        let nonce = block_nonce(seq);
        let nonce = GenericArray::from_slice(&nonce);
        let tag = {
            let pt = &mut buf[hdr_len..hdr_len + plen];
            match self {
                AeadBox::Aes(c) => c.encrypt_in_place_detached(nonce, &[], pt),
                AeadBox::Cha(c) => c.encrypt_in_place_detached(nonce, &[], pt),
            }
            .expect("AEAD seal failed")
        };
        buf[hdr_len + plen..hdr_len + plen + AEAD_TAG_LEN].copy_from_slice(tag.as_slice());
        hdr_len + plen + AEAD_TAG_LEN
    }

    /// Decrypts a DATA payload (ciphertext followed by tag) in place. `plen` is
    /// the plaintext length from the header. Returns the plaintext length on
    /// success, or `None` on authentication failure / short buffer.
    pub fn open_data(&self, payload: &mut [u8], plen: usize, seq: u64) -> Option<usize> {
        let ct_len = plen + AEAD_TAG_LEN;
        if ct_len > payload.len() {
            return None;
        }
        let nonce = block_nonce(seq);
        let nonce = GenericArray::from_slice(&nonce);
        let (ct, tag_bytes) = payload[..ct_len].split_at_mut(plen);
        let tag = GenericArray::from_slice(tag_bytes);
        let res = match self {
            AeadBox::Aes(c) => c.decrypt_in_place_detached(nonce, &[], ct, tag),
            AeadBox::Cha(c) => c.decrypt_in_place_detached(nonce, &[], ct, tag),
        };
        res.ok().map(|_| plen)
    }
}

/// Creates an ephemeral X25519 keypair; the returned bytes are the 32-byte
/// public key to put on the wire.
pub fn gen_keypair() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    (secret, public.to_bytes())
}

/// Completes the handshake: computes the X25519 shared secret with the peer's
/// public key and derives the session AEAD via HKDF-SHA256, salted with the
/// session id and bound to the negotiated cipher name. Both ends run this with
/// mirrored keys and arrive at the same symmetric key.
pub fn derive_aead(
    priv_key: &StaticSecret,
    peer_pub: &[u8],
    session: u32,
    cipher_name: &str,
) -> Result<AeadBox, String> {
    let pub_arr: [u8; 32] = peer_pub
        .try_into()
        .map_err(|_| "girth: bad peer public key".to_string())?;
    let peer = PublicKey::from(pub_arr);
    let secret = priv_key.diffie_hellman(&peer);

    let salt = session.to_le_bytes();
    let info = format!("girth data key {}", cipher_name);
    let hk = Hkdf::<Sha256>::new(Some(&salt), secret.as_bytes());
    let mut key = [0u8; AEAD_KEY_LEN];
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|e| format!("girth: HKDF failed: {e}"))?;
    AeadBox::new(cipher_name, &key)
}

/// Server side of key exchange for a hello requesting encryption. Returns
/// `(enabled, cipher_name, our_pubkey, box)`. If the client did not request
/// encryption it returns a disabled result with no box.
#[allow(clippy::type_complexity)]
pub fn negotiate_crypto_server(
    encrypt: bool,
    peer_ciphers: &[String],
    peer_pub: &[u8],
    session: u32,
) -> Result<(bool, String, Vec<u8>, Option<Arc<AeadBox>>), String> {
    if !encrypt {
        return Ok((false, String::new(), Vec::new(), None));
    }
    let cipher_name = choose_cipher(&local_ciphers(), peer_ciphers);
    if cipher_name.is_empty() {
        return Err("no common cipher suite".into());
    }
    let (priv_key, pub_key) = gen_keypair();
    let aead = derive_aead(&priv_key, peer_pub, session, &cipher_name)?;
    Ok((true, cipher_name, pub_key.to_vec(), Some(Arc::new(aead))))
}

/// Client side of key exchange from the server's ack fields. Fails closed: if
/// the user asked for encryption but the server did not enable it, that is an
/// error rather than a silent downgrade to cleartext.
pub fn client_crypto(
    want: bool,
    server_encrypt: bool,
    server_pub: &[u8],
    session: u32,
    cipher: &str,
    priv_key: Option<&StaticSecret>,
) -> Result<Option<Arc<AeadBox>>, String> {
    if !server_encrypt {
        if want {
            return Err("server declined encryption".into());
        }
        return Ok(None);
    }
    let Some(priv_key) = priv_key else {
        return Err("server enabled encryption unexpectedly".into());
    };
    if !want {
        return Err("server enabled encryption unexpectedly".into());
    }
    Ok(Some(Arc::new(derive_aead(
        priv_key, server_pub, session, cipher,
    )?)))
}
