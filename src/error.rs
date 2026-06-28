//! Typed, classifiable errors for the library API.
//!
//! The CLI and the in-process transfer functions previously surfaced every
//! failure as an `io::Error` with a string message. `GirthError` classifies the
//! cases that drive retry/fail decisions: transient path conditions (`Timeout`)
//! are retryable; `AuthDenied` / `NotFound` / `VersionMismatch` / `Integrity`
//! are terminal.

use std::fmt;
use std::io;

/// A classified transfer error.
#[derive(Debug)]
#[non_exhaustive]
pub enum GirthError {
    /// The control or data plane timed out (retryable).
    Timeout,
    /// The caller's cancellation flag fired.
    Stopped,
    /// The peer/authorizer rejected the session's auth token (terminal).
    AuthDenied,
    /// The requested object does not exist on the server (terminal).
    NotFound,
    /// Protocol version mismatch between peers (terminal).
    VersionMismatch,
    /// End-to-end CRC32C mismatch — the moved bytes are corrupt (terminal).
    Integrity,
    /// A malformed control message or peer protocol violation (terminal).
    Protocol(String),
    /// An underlying I/O error (socket, source, or sink).
    Io(io::Error),
}

impl GirthError {
    /// Reports whether retrying the transfer (on girth, or via a fallback) is
    /// sensible. Only transient conditions are retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(self, GirthError::Timeout)
    }

    /// Classifies a server's `Ack.err` rejection string into a typed error.
    /// The strings are produced by this crate's server, so the matching is
    /// stable; unknown text falls back to `Protocol`.
    pub fn from_server_err(msg: &str) -> GirthError {
        let m = msg.to_ascii_lowercase();
        if m.contains("version mismatch") {
            GirthError::VersionMismatch
        } else if m.contains("auth") || m.contains("denied") || m.contains("unauthorized") {
            GirthError::AuthDenied
        } else if m.contains("no such file") || m.contains("not found") || m.contains("notfound") {
            GirthError::NotFound
        } else {
            GirthError::Protocol(msg.to_string())
        }
    }
}

impl fmt::Display for GirthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GirthError::Timeout => write!(f, "transfer timed out"),
            GirthError::Stopped => write!(f, "transfer cancelled"),
            GirthError::AuthDenied => write!(f, "authentication denied"),
            GirthError::NotFound => write!(f, "object not found"),
            GirthError::VersionMismatch => write!(f, "protocol version mismatch"),
            GirthError::Integrity => write!(f, "integrity check failed (crc32c mismatch)"),
            GirthError::Protocol(s) => write!(f, "protocol error: {s}"),
            GirthError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for GirthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GirthError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for GirthError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => GirthError::Timeout,
            io::ErrorKind::NotFound => GirthError::NotFound,
            _ => GirthError::Io(e),
        }
    }
}

/// Convenience: turn a `GirthError` back into an `io::Error` for the few places
/// (CLI parity, legacy callers) that still want one.
impl From<GirthError> for io::Error {
    fn from(e: GirthError) -> Self {
        match e {
            GirthError::Io(io) => io,
            other => io::Error::other(other.to_string()),
        }
    }
}
