//! Control plane (TCP): session negotiation, file metadata, integrity checksum,
//! and X25519 public-key exchange. Length-prefixed JSON, byte-compatible with
//! the Go implementation (LE u32 length prefix; camelCase fields; `omitempty`;
//! base64 `[]byte`).

use crate::protocol::DEFAULT_BLOCK_SIZE;
use crate::rate::{RateConfig, RateMode};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Direction of the bulk transfer relative to the client.
pub const MODE_SEND: &str = "send"; // client pushes a file to the server
pub const MODE_RECV: &str = "recv"; // client pulls a file from the server

fn is_false(b: &bool) -> bool {
    !*b
}

/// base64 (standard, padded) serialization for optional byte fields, matching
/// Go's `encoding/json` `[]byte` handling.
mod b64opt {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_str(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => STANDARD
                .decode(s.as_bytes())
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// The client's opening control message.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    pub version: i64,
    pub mode: String,
    pub name: String,
    pub size: i64,
    pub block_size: i64,
    pub rate_bps: u64,
    pub max_bps: u64,
    pub adaptive: bool,
    pub alpha_bps: u64,
    pub crc32c: u32,

    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypt: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<Vec<String>>,
    #[serde(default, with = "b64opt", skip_serializing_if = "Option::is_none")]
    pub pub_key: Option<Vec<u8>>,

    /// PSK proof of possession: `HMAC-SHA256(token, transcript)` binding the
    /// request fields and the client's ephemeral public key. Absent when
    /// the client is not authenticating. The token itself is never sent.
    #[serde(default, with = "b64opt", skip_serializing_if = "Option::is_none")]
    pub auth_mac: Option<Vec<u8>>,
}

/// The server's reply.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Ack {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub err: String,
    pub udp_port: i64,
    pub session: u32,
    pub size: i64,
    pub crc32c: u32,
    pub name: String,

    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypt: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cipher: String,
    #[serde(default, with = "b64opt", skip_serializing_if = "Option::is_none")]
    pub pub_key: Option<Vec<u8>>,

    /// Set when the server requires a PSK and the client did not present a valid
    /// proof, so the client can distinguish "auth needed" from other failures.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auth_required: bool,
    /// The server's reply MAC, authenticating the server and binding the session
    /// id and the server's ephemeral public key.
    #[serde(default, with = "b64opt", skip_serializing_if = "Option::is_none")]
    pub auth_mac: Option<Vec<u8>>,
}

/// Writes a length-prefixed JSON value to the control connection.
pub fn write_json<T: Serialize>(c: &mut TcpStream, v: &T) -> io::Result<()> {
    c.set_write_timeout(Some(Duration::from_secs(30)))?;
    let b = serde_json::to_vec(v).map_err(io::Error::other)?;
    let len = b.len() as u32;
    c.write_all(&len.to_le_bytes())?;
    c.write_all(&b)?;
    c.flush()
}

/// Reads a length-prefixed JSON value from the control connection.
pub fn read_json<T: for<'de> Deserialize<'de>>(c: &mut TcpStream) -> io::Result<T> {
    c.set_read_timeout(Some(Duration::from_secs(120)))?;
    let mut lenbuf = [0u8; 4];
    c.read_exact(&mut lenbuf)?;
    let n = u32::from_le_bytes(lenbuf) as usize;
    if n > (1 << 20) {
        return Err(io::Error::other(format!(
            "control message too large: {}",
            n
        )));
    }
    let mut b = vec![0u8; n];
    c.read_exact(&mut b)?;
    serde_json::from_slice(&b).map_err(io::Error::other)
}

/// User-tunable knobs shared by client and server.
#[derive(Debug, Clone)]
pub struct TransferParams {
    pub block_size: usize,
    pub rate_bps: u64,
    pub max_bps: u64,
    pub adaptive: bool,
    pub alpha_bps: u64,
    pub read_workers: usize,
    pub feedback_interval_us: u32,
    pub net_tick_interval_us: u32,
    pub report_interval: Duration,
    pub verbose: bool,
    pub encrypt: bool,
}

/// Sensible defaults (matching the Go `DefaultParams`).
pub fn default_params() -> TransferParams {
    TransferParams {
        block_size: DEFAULT_BLOCK_SIZE,
        rate_bps: 100_000_000, // 100 Mbps
        max_bps: 10_000_000_000,
        adaptive: false,
        alpha_bps: 30_000_000,
        read_workers: 0, // 0 => auto
        feedback_interval_us: 5000,
        net_tick_interval_us: 10000,
        report_interval: Duration::from_secs(1),
        verbose: false,
        encrypt: false,
    }
}

impl TransferParams {
    pub fn rate_config(&self, target: u64) -> RateConfig {
        RateConfig {
            mode: if self.adaptive {
                RateMode::Adaptive
            } else {
                RateMode::Fixed
            },
            target_bps: target,
            min_bps: 0,
            max_bps: self.max_bps,
            alpha: self.alpha_bps as f64,
        }
    }
}

pub fn basename(p: &str) -> String {
    std::path::Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string())
}
