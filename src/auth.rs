//! Control-plane authentication.
//!
//! The scheme here is a **pre-shared-key (PSK) proof of possession** that also
//! **binds the ephemeral X25519 keys** exchanged for encryption, closing the
//! man-in-the-middle window on the cleartext TCP control channel:
//!
//!   * The PSK (the "token") is a shared secret and is **never put on the wire**.
//!     The client proves possession by sending `HMAC-SHA256(token, transcript)`.
//!   * The client transcript covers `version | mode | name | size | client_pub`,
//!     so a MITM cannot swap the client's ephemeral public key without the token.
//!   * The server replies with `HMAC-SHA256(token, session | server_pub |
//!     client_mac)`, authenticating itself and binding its own ephemeral key and
//!     the session id. The client verifies it, giving mutual authentication.
//!
//! The server learns the *expected* token from its `Authorizer` callback (which
//! also performs object-level authorization), so the secret stays server-side.
//!
//! Replay protection beyond the session-bound MACs is out of scope here. Hosted
//! deployments should pair this with their normal authenticated control/session
//! layer or use short-lived per-transfer tokens.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const DOMAIN_CLIENT: &[u8] = b"girth-auth-client-v1";
const DOMAIN_SERVER: &[u8] = b"girth-auth-server-v1";

fn mac_new(token: &[u8]) -> HmacSha256 {
    // HMAC accepts a key of any length.
    HmacSha256::new_from_slice(token).expect("HMAC accepts any key length")
}

/// The client's proof of possession, binding the request fields and the client's
/// ephemeral public key (empty when not encrypting).
pub fn client_mac(
    token: &[u8],
    version: i64,
    mode: &str,
    name: &str,
    size: i64,
    client_pub: &[u8],
) -> Vec<u8> {
    let mut m = mac_new(token);
    m.update(DOMAIN_CLIENT);
    m.update(&version.to_le_bytes());
    m.update(mode.as_bytes());
    m.update(&[0]);
    m.update(name.as_bytes());
    m.update(&[0]);
    m.update(&size.to_le_bytes());
    m.update(client_pub);
    m.finalize().into_bytes().to_vec()
}

/// The server's reply MAC, authenticating the server and binding the negotiated
/// session id, the server's ephemeral public key, and the client's proof.
pub fn server_mac(token: &[u8], session: u32, server_pub: &[u8], client_mac: &[u8]) -> Vec<u8> {
    let mut m = mac_new(token);
    m.update(DOMAIN_SERVER);
    m.update(&session.to_le_bytes());
    m.update(server_pub);
    m.update(client_mac);
    m.finalize().into_bytes().to_vec()
}

/// Constant-time verification of a previously computed MAC against the expected
/// inputs. Returns true on a match.
pub fn verify_client_mac(
    token: &[u8],
    version: i64,
    mode: &str,
    name: &str,
    size: i64,
    client_pub: &[u8],
    presented: &[u8],
) -> bool {
    let mut m = mac_new(token);
    m.update(DOMAIN_CLIENT);
    m.update(&version.to_le_bytes());
    m.update(mode.as_bytes());
    m.update(&[0]);
    m.update(name.as_bytes());
    m.update(&[0]);
    m.update(&size.to_le_bytes());
    m.update(client_pub);
    m.verify_slice(presented).is_ok()
}

/// Constant-time verification of the server's reply MAC.
pub fn verify_server_mac(
    token: &[u8],
    session: u32,
    server_pub: &[u8],
    client_mac: &[u8],
    presented: &[u8],
) -> bool {
    let mut m = mac_new(token);
    m.update(DOMAIN_SERVER);
    m.update(&session.to_le_bytes());
    m.update(server_pub);
    m.update(client_mac);
    m.verify_slice(presented).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_mac_roundtrip_and_binding() {
        let token = b"s3cr3t";
        let pk = [9u8; 32];
        let mac = client_mac(token, 1, "send", "obj", 100, &pk);
        assert!(verify_client_mac(token, 1, "send", "obj", 100, &pk, &mac));
        // Wrong token, wrong field, or swapped key all fail.
        assert!(!verify_client_mac(
            b"other", 1, "send", "obj", 100, &pk, &mac
        ));
        assert!(!verify_client_mac(token, 1, "send", "obj", 101, &pk, &mac));
        assert!(!verify_client_mac(
            token, 1, "send", "obj", 100, &[1u8; 32], &mac
        ));
        assert!(!verify_client_mac(token, 1, "recv", "obj", 100, &pk, &mac));
    }

    #[test]
    fn server_mac_roundtrip() {
        let token = b"s3cr3t";
        let cmac = client_mac(token, 1, "recv", "obj", 0, &[]);
        let spub = [7u8; 32];
        let smac = server_mac(token, 42, &spub, &cmac);
        assert!(verify_server_mac(token, 42, &spub, &cmac, &smac));
        assert!(!verify_server_mac(token, 43, &spub, &cmac, &smac));
        assert!(!verify_server_mac(b"nope", 42, &spub, &cmac, &smac));
    }
}
