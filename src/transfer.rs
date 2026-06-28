//! Top-level orchestration: client push/pull and the server, wiring the control
//! handshake (TCP) to the data plane (UDP).
//!
//! The high-level functions come in two flavours:
//!   - `client_send` / `client_recv`: file-backed convenience wrappers for the
//!     CLI (move a path to/from disk), returning a [`GirthError`].
//!   - `client_send_from` / `client_recv_into`: library APIs to move bytes
//!     to/from any [`BlockSource`] / [`BlockSink`] (e.g. in-memory `MemSource` /
//!     `MemSink`), with caller-owned cancellation + [`Stats`], an optional PSK
//!     auth token, and no process-global side effects or stderr output.

use crate::auth;
use crate::control::*;
use crate::crypto::{ciphers_if, client_crypto, gen_keypair, negotiate_crypto_server};
use crate::error::GirthError;
use crate::io::{source_crc32c, BlockSink, BlockSource, FileSink, FileSource};
use crate::protocol::{num_blocks, PROTOCOL_VERSION};
use crate::receiver::{new_receiver, RecvConfig};
use crate::sender::{SendConfig, Sender};
use crate::stats::Stats;
use crate::sys::{local_udp_port, new_udp_socket};
use std::fs::{File, OpenOptions};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use x25519_dalek::StaticSecret;

fn is_dir(p: &str) -> bool {
    Path::new(p).is_dir()
}

/// Resolves the data-plane UDP peer from the control address + negotiated port.
fn resolve_peer(server_addr: &str, udp_port: i64) -> io::Result<SocketAddr> {
    let host = match server_addr.rfind(':') {
        Some(i) => &server_addr[..i],
        None => server_addr,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let target = format!("{}:{}", host, udp_port);
    target
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other(format!("cannot resolve peer {}", target)))
}

/// Binds a server data socket, honouring an optional bounded UDP port range so a
/// firewalled/NAT'd host can expose a known range instead of "all UDP ports".
/// `None` => an ephemeral port (`:0`), as before.
fn bind_data_socket(range: &Option<RangeInclusive<u16>>, rio: bool) -> io::Result<UdpSocket> {
    match range {
        None => new_udp_socket(0, rio),
        Some(r) => {
            let mut last_err =
                io::Error::new(io::ErrorKind::AddrNotAvailable, "no free port in UDP range");
            for port in r.clone() {
                match new_udp_socket(port, rio) {
                    Ok(s) => return Ok(s),
                    Err(e) => last_err = e,
                }
            }
            Err(last_err)
        }
    }
}

fn spawn_reporter(
    stats: &Arc<Stats>,
    role: &'static str,
    interval: Duration,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let s = stats.clone();
    let st = stop.clone();
    let h = std::thread::spawn(move || s.run_reporter(role, interval, st));
    (stop, h)
}

/// Normalizes a server listen address, accepting the Go-style `:port` shorthand
/// (and an entirely empty host) by binding the IPv4 wildcard `0.0.0.0`.
fn normalize_listen_addr(addr: &str) -> String {
    let a = addr.trim();
    match a.rfind(':') {
        Some(i) if a[..i].is_empty() => format!("0.0.0.0{}", a),
        None if !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()) => {
            format!("0.0.0.0:{}", a)
        }
        _ => a.to_string(),
    }
}

fn connect_control(server_addr: &str) -> io::Result<TcpStream> {
    let addr = server_addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("cannot resolve server"))?;
    let c = TcpStream::connect_timeout(&addr, Duration::from_secs(15))?;
    c.set_nodelay(true).ok();
    Ok(c)
}

/// Maps a server rejection `Ack` to a typed error.
fn reject_error(a: &Ack) -> GirthError {
    if a.auth_required {
        GirthError::AuthDenied
    } else {
        GirthError::from_server_err(&a.err)
    }
}

// --- client send ------------------------------------------------------------

/// Pushes `local_path` to the girth server (file-backed CLI convenience).
pub fn client_send(
    server_addr: &str,
    local_path: &str,
    p: &TransferParams,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let source = Arc::new(FileSource::open(local_path)?);
    let stats = Stats::new();
    let (rep_stop, rep_h) = spawn_reporter(&stats, "send", p.report_interval);
    let res = send_core(
        server_addr,
        source,
        &basename(local_path),
        p,
        stats.clone(),
        None,
        stop,
    );
    rep_stop.store(true, Ordering::Relaxed);
    let _ = rep_h.join();
    res
}

/// Pushes the bytes of `source` to the server as object `name`.
/// `progress` lets the caller observe live counters; `auth_token` is the PSK
/// shared with the server's authorizer (`None` for an unauthenticated server).
#[allow(clippy::too_many_arguments)]
pub fn client_send_from(
    server_addr: &str,
    source: Arc<dyn BlockSource>,
    name: &str,
    p: &TransferParams,
    progress: Option<Arc<Stats>>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let stats = progress.unwrap_or_default();
    send_core(server_addr, source, name, p, stats, auth_token, stop)
}

fn send_core(
    server_addr: &str,
    source: Arc<dyn BlockSource>,
    name: &str,
    p: &TransferParams,
    stats: Arc<Stats>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let size = source.len() as i64;
    let crc = source_crc32c(source.as_ref())?;

    let mut tcp = connect_control(server_addr)?;

    let (priv_key, pub_key): (Option<StaticSecret>, Option<Vec<u8>>) = if p.encrypt {
        let (sk, pk) = gen_keypair();
        (Some(sk), Some(pk.to_vec()))
    } else {
        (None, None)
    };
    let client_pub = pub_key.as_deref().unwrap_or(&[]);
    let auth_mac = auth_token
        .map(|t| auth::client_mac(t, PROTOCOL_VERSION, MODE_SEND, name, size, client_pub));

    write_json(
        &mut tcp,
        &Hello {
            version: PROTOCOL_VERSION,
            mode: MODE_SEND.into(),
            name: name.to_string(),
            size,
            block_size: p.block_size as i64,
            rate_bps: p.rate_bps,
            max_bps: p.max_bps,
            adaptive: p.adaptive,
            alpha_bps: p.alpha_bps,
            crc32c: crc,
            encrypt: p.encrypt,
            ciphers: ciphers_if(p.encrypt),
            pub_key,
            auth_mac: auth_mac.clone(),
        },
    )?;
    let a: Ack = read_json(&mut tcp)?;
    if !a.ok {
        return Err(reject_error(&a));
    }
    verify_server_auth(auth_token, auth_mac.as_deref(), &a)?;

    let crypto = client_crypto(
        p.encrypt,
        a.encrypt,
        a.pub_key.as_deref().unwrap_or(&[]),
        a.session,
        &a.cipher,
        priv_key.as_ref(),
    )
    .map_err(GirthError::Protocol)?;

    let peer = resolve_peer(server_addr, a.udp_port)?;
    let conn = Arc::new(new_udp_socket(0, false)?);

    let snd = Sender::new(SendConfig {
        sock: conn,
        peer: Some(peer),
        source,
        file_size: size,
        block_size: p.block_size,
        total_blocks: num_blocks(size, p.block_size),
        session: a.session,
        rate: p.rate_config(p.rate_bps),
        read_workers: p.read_workers,
        crypto,
        stats: stats.clone(),
    });
    snd.run(&stop)?;
    crate::log::info(&stats.summary("send"));
    Ok(())
}

// --- client recv ------------------------------------------------------------

/// Pulls `remote_name` from the server into `out_path` (file-backed CLI helper).
pub fn client_recv(
    server_addr: &str,
    remote_name: &str,
    out_path: &str,
    p: &TransferParams,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let mut out = out_path.to_string();
    if out.is_empty() || is_dir(&out) {
        out = Path::new(&out)
            .join(basename(remote_name))
            .to_string_lossy()
            .into_owned();
    }
    let sink = Arc::new(FileSink::create(&out)?);
    let stats = Stats::new();
    let (rep_stop, rep_h) = spawn_reporter(&stats, "recv", p.report_interval);
    let res = recv_core(server_addr, remote_name, sink, p, stats.clone(), None, stop);
    rep_stop.store(true, Ordering::Relaxed);
    let _ = rep_h.join();
    res
}

/// Pulls object `name` from the server into `sink`.
#[allow(clippy::too_many_arguments)]
pub fn client_recv_into(
    server_addr: &str,
    name: &str,
    sink: Arc<dyn BlockSink>,
    p: &TransferParams,
    progress: Option<Arc<Stats>>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let stats = progress.unwrap_or_default();
    recv_core(server_addr, name, sink, p, stats, auth_token, stop)
}

fn recv_core(
    server_addr: &str,
    name: &str,
    sink: Arc<dyn BlockSink>,
    p: &TransferParams,
    stats: Arc<Stats>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let mut tcp = connect_control(server_addr)?;

    let (priv_key, pub_key): (Option<StaticSecret>, Option<Vec<u8>>) = if p.encrypt {
        let (sk, pk) = gen_keypair();
        (Some(sk), Some(pk.to_vec()))
    } else {
        (None, None)
    };
    let client_pub = pub_key.as_deref().unwrap_or(&[]);
    let auth_mac =
        auth_token.map(|t| auth::client_mac(t, PROTOCOL_VERSION, MODE_RECV, name, 0, client_pub));

    write_json(
        &mut tcp,
        &Hello {
            version: PROTOCOL_VERSION,
            mode: MODE_RECV.into(),
            name: name.to_string(),
            size: 0,
            block_size: p.block_size as i64,
            rate_bps: p.rate_bps,
            max_bps: p.max_bps,
            adaptive: p.adaptive,
            alpha_bps: p.alpha_bps,
            crc32c: 0,
            encrypt: p.encrypt,
            ciphers: ciphers_if(p.encrypt),
            pub_key,
            auth_mac: auth_mac.clone(),
        },
    )?;
    let a: Ack = read_json(&mut tcp)?;
    if !a.ok {
        return Err(reject_error(&a));
    }
    verify_server_auth(auth_token, auth_mac.as_deref(), &a)?;

    let crypto = client_crypto(
        p.encrypt,
        a.encrypt,
        a.pub_key.as_deref().unwrap_or(&[]),
        a.session,
        &a.cipher,
        priv_key.as_ref(),
    )
    .map_err(GirthError::Protocol)?;

    sink.allocate(a.size.max(0) as u64)?;

    let peer = resolve_peer(server_addr, a.udp_port)?;
    let conn = Arc::new(new_udp_socket(0, true)?);

    let rcv = new_receiver(RecvConfig {
        sock: conn,
        sink: sink.clone(),
        file_size: a.size,
        block_size: p.block_size,
        total_blocks: num_blocks(a.size, p.block_size),
        session: a.session,
        read_workers: p.read_workers,
        rate: p.rate_config(p.rate_bps),
        crypto,
        feedback_interval_us: p.feedback_interval_us,
        net_tick_interval_us: p.net_tick_interval_us,
        max_nacks_per_pdu: 0,
        stats: stats.clone(),
        start_peer: Some(peer),
    });
    rcv.run(&stop)?;
    sink.finalize()?;

    // A CRC mismatch is a hard error, not just a log line.
    if let Some(got) = sink.read_crc32c()? {
        if got != a.crc32c {
            return Err(GirthError::Integrity);
        }
        crate::log::info(&format!("integrity OK (crc32c={:08x})", got));
    }
    crate::log::info(&stats.summary("recv"));
    Ok(())
}

/// When we authenticated, the server must prove possession
/// of the same PSK (binding the session id and its ephemeral key), or we treat
/// the session as denied — this is what closes the MITM on the server's pubkey.
fn verify_server_auth(
    auth_token: Option<&[u8]>,
    client_mac: Option<&[u8]>,
    a: &Ack,
) -> Result<(), GirthError> {
    let (Some(token), Some(cmac)) = (auth_token, client_mac) else {
        return Ok(());
    };
    let server_pub = a.pub_key.as_deref().unwrap_or(&[]);
    match &a.auth_mac {
        Some(smac) if auth::verify_server_mac(token, a.session, server_pub, cmac, smac) => Ok(()),
        _ => Err(GirthError::AuthDenied),
    }
}

// --- server -----------------------------------------------------------------

/// Context passed to a [`Server`] authorizer for each incoming control
/// connection, before any data flows.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Transfer direction requested by the client (`"send"` or `"recv"`).
    pub mode: String,
    /// The object (basename) the client wants to read or write.
    pub name: String,
    /// The client's control-connection address.
    pub peer_addr: SocketAddr,
}

/// Server authorization + token-lookup hook.
///
/// Given the request context, it returns the **expected PSK (token) bytes** to
/// verify the client's proof against, or `Err(reason)` to deny the request
/// outright. The secret never leaves the server. Object-level access control
/// (may *this* identity read/write *this* name?) lives here too: return `Err`.
pub type Authorizer = Arc<dyn Fn(&AuthContext) -> Result<Vec<u8>, String> + Send + Sync>;

/// A verified client identity, carried into the handler so the server's reply
/// MAC can bind the session id and its ephemeral key.
struct AuthState {
    token: Vec<u8>,
    client_mac: Vec<u8>,
}

/// Accepts control connections and runs the negotiated transfers.
pub struct Server {
    pub addr: String,
    pub dir: String,
    pub params: TransferParams,
    /// Optional PSK authorizer. `None` => open server (any client may
    /// read/write any basename in `dir`); this must be an explicit choice.
    pub authorizer: Option<Authorizer>,
    /// Optional bounded UDP data-plane port range. `None` => ephemeral.
    pub udp_port_range: Option<RangeInclusive<u16>>,
}

impl Server {
    /// An open server (no auth, ephemeral UDP ports). Add auth / a port range
    /// with [`Server::with_authorizer`] / [`Server::with_udp_port_range`].
    pub fn new(addr: impl Into<String>, dir: impl Into<String>, params: TransferParams) -> Server {
        Server {
            addr: addr.into(),
            dir: dir.into(),
            params,
            authorizer: None,
            udp_port_range: None,
        }
    }

    pub fn with_authorizer(mut self, authorizer: Authorizer) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    pub fn with_udp_port_range(mut self, range: RangeInclusive<u16>) -> Self {
        self.udp_port_range = Some(range);
        self
    }

    /// Runs until `stop` is set.
    pub fn listen_and_serve(&self, stop: Arc<AtomicBool>) -> io::Result<()> {
        let ln = TcpListener::bind(normalize_listen_addr(&self.addr))?;
        ln.set_nonblocking(true)?;
        crate::log::info(&format!(
            "server: listening on {} (control/TCP), serving dir {}",
            ln.local_addr()?,
            self.dir
        ));
        let mut workers = Vec::new();
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match ln.accept() {
                Ok((c, _addr)) => {
                    c.set_nonblocking(false).ok();
                    let dir = self.dir.clone();
                    let params = self.params.clone();
                    let authorizer = self.authorizer.clone();
                    let udp_range = self.udp_port_range.clone();
                    let stop = stop.clone();
                    workers.push(std::thread::spawn(move || {
                        if let Err(e) =
                            handle_conn(c, &dir, &params, &authorizer, &udp_range, &stop)
                        {
                            crate::log::error(&format!("server: transfer error: {}", e));
                        }
                    }));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn ack_err(c: &mut TcpStream, err: impl Into<String>, auth_required: bool) {
    let _ = write_json(
        c,
        &Ack {
            err: err.into(),
            auth_required,
            ..Default::default()
        },
    );
}

fn handle_conn(
    mut c: TcpStream,
    dir: &str,
    params: &TransferParams,
    authorizer: &Option<Authorizer>,
    udp_range: &Option<RangeInclusive<u16>>,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let peer_addr = c.peer_addr()?;
    let mut h: Hello = read_json(&mut c)?;
    if h.version != PROTOCOL_VERSION {
        ack_err(&mut c, "protocol version mismatch", false);
        return Ok(());
    }
    if h.block_size <= 0 {
        h.block_size = params.block_size as i64;
    }
    let session: u32 = rand_u32();
    let mut p = params.clone();
    p.block_size = h.block_size as usize;
    p.adaptive = h.adaptive;
    if h.alpha_bps > 0 {
        p.alpha_bps = h.alpha_bps;
    }
    if h.rate_bps > 0 {
        p.rate_bps = h.rate_bps;
    }
    if h.max_bps > 0 {
        p.max_bps = h.max_bps;
    }

    // Verify the client's PSK proof before anything else.
    let auth_state = match authorizer {
        Some(authz) => {
            let ctx = AuthContext {
                mode: h.mode.clone(),
                name: h.name.clone(),
                peer_addr,
            };
            let token = match authz(&ctx) {
                Ok(t) => t,
                Err(reason) => {
                    ack_err(&mut c, format!("auth denied: {reason}"), true);
                    return Ok(());
                }
            };
            let Some(presented) = h.auth_mac.as_deref() else {
                ack_err(&mut c, "auth required", true);
                return Ok(());
            };
            let client_pub = h.pub_key.as_deref().unwrap_or(&[]);
            if !auth::verify_client_mac(
                &token, h.version, &h.mode, &h.name, h.size, client_pub, presented,
            ) {
                ack_err(&mut c, "auth denied", true);
                return Ok(());
            }
            Some(AuthState {
                token,
                client_mac: presented.to_vec(),
            })
        }
        None => None,
    };

    match h.mode.as_str() {
        MODE_SEND => recv_from_client(c, h, session, &p, dir, udp_range, auth_state, stop),
        MODE_RECV => send_to_client(c, h, session, &p, dir, udp_range, auth_state, stop),
        _ => {
            ack_err(&mut c, "unknown mode", false);
            Ok(())
        }
    }
}

/// Client pushes a file; server is the data receiver.
#[allow(clippy::too_many_arguments)]
fn recv_from_client(
    mut c: TcpStream,
    h: Hello,
    session: u32,
    p: &TransferParams,
    dir: &str,
    udp_range: &Option<RangeInclusive<u16>>,
    auth_state: Option<AuthState>,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let out_path = Path::new(dir).join(basename(&h.name));
    let f = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&out_path)
    {
        Ok(f) => f,
        Err(e) => {
            ack_err(&mut c, e.to_string(), false);
            return Ok(());
        }
    };
    let sink = Arc::new(FileSink::from_file(f));
    if let Err(e) = sink.allocate(h.size.max(0) as u64) {
        ack_err(&mut c, e.to_string(), false);
        return Ok(());
    }
    let conn = Arc::new(bind_data_socket(udp_range, true)?);

    let (enc, cipher_name, pub_key, crypto) = match negotiate_crypto_server(
        h.encrypt,
        h.ciphers.as_deref().unwrap_or(&[]),
        h.pub_key.as_deref().unwrap_or(&[]),
        session,
    ) {
        Ok(v) => v,
        Err(e) => {
            ack_err(&mut c, e, false);
            return Ok(());
        }
    };
    let server_auth_mac = auth_state
        .as_ref()
        .map(|a| auth::server_mac(&a.token, session, &pub_key, &a.client_mac));
    write_json(
        &mut c,
        &Ack {
            ok: true,
            udp_port: local_udp_port(&conn) as i64,
            session,
            name: h.name.clone(),
            encrypt: enc,
            cipher: cipher_name.clone(),
            pub_key: (!pub_key.is_empty()).then_some(pub_key),
            auth_mac: server_auth_mac,
            ..Default::default()
        },
    )?;
    if enc {
        crate::log::info(&format!(
            "server: encryption enabled ({}) for {:?}",
            cipher_name, h.name
        ));
    }

    let stats = Stats::new();
    let (rep_stop, rep_h) = spawn_reporter(&stats, "recv", p.report_interval);

    let rcv = new_receiver(RecvConfig {
        sock: conn,
        sink: sink.clone(),
        file_size: h.size,
        block_size: p.block_size,
        total_blocks: num_blocks(h.size, p.block_size),
        session,
        read_workers: p.read_workers,
        rate: p.rate_config(h.rate_bps),
        crypto,
        feedback_interval_us: p.feedback_interval_us,
        net_tick_interval_us: p.net_tick_interval_us,
        max_nacks_per_pdu: 0,
        stats: stats.clone(),
        start_peer: None,
    });
    crate::log::info(&format!(
        "server: recv {:?} ({} blocks) from peer",
        h.name,
        num_blocks(h.size, p.block_size)
    ));
    let res = rcv.run(stop);
    rep_stop.store(true, Ordering::Relaxed);
    let _ = rep_h.join();
    crate::log::info(&stats.summary("recv"));
    res?;
    sink.finalize()?;

    // Server-side integrity is a hard error, not just a log line.
    if let Some(got) = sink.read_crc32c()? {
        if got != h.crc32c {
            return Err(io::Error::other(format!(
                "integrity failure {:?}: crc got={:08x} want={:08x}",
                h.name, got, h.crc32c
            )));
        }
        crate::log::info(&format!(
            "server: integrity OK {:?} (crc32c={:08x})",
            h.name, got
        ));
    }
    Ok(())
}

/// Client pulls a file; server is the data sender.
#[allow(clippy::too_many_arguments)]
fn send_to_client(
    mut c: TcpStream,
    h: Hello,
    session: u32,
    p: &TransferParams,
    dir: &str,
    udp_range: &Option<RangeInclusive<u16>>,
    auth_state: Option<AuthState>,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let in_path = Path::new(dir).join(basename(&h.name));
    let f = match File::open(&in_path) {
        Ok(f) => f,
        Err(e) => {
            ack_err(&mut c, e.to_string(), false);
            return Ok(());
        }
    };
    let source = match FileSource::from_file(f) {
        Ok(s) => s,
        Err(e) => {
            ack_err(&mut c, e.to_string(), false);
            return Ok(());
        }
    };
    let size = source.len() as i64;
    let crc = match source_crc32c(&source) {
        Ok(v) => v,
        Err(e) => {
            ack_err(&mut c, e.to_string(), false);
            return Ok(());
        }
    };
    let source = Arc::new(source);
    let conn = Arc::new(bind_data_socket(udp_range, false)?);

    let (enc, cipher_name, pub_key, crypto) = match negotiate_crypto_server(
        h.encrypt,
        h.ciphers.as_deref().unwrap_or(&[]),
        h.pub_key.as_deref().unwrap_or(&[]),
        session,
    ) {
        Ok(v) => v,
        Err(e) => {
            ack_err(&mut c, e, false);
            return Ok(());
        }
    };
    let server_auth_mac = auth_state
        .as_ref()
        .map(|a| auth::server_mac(&a.token, session, &pub_key, &a.client_mac));
    write_json(
        &mut c,
        &Ack {
            ok: true,
            udp_port: local_udp_port(&conn) as i64,
            session,
            size,
            crc32c: crc,
            name: h.name.clone(),
            encrypt: enc,
            cipher: cipher_name.clone(),
            pub_key: (!pub_key.is_empty()).then_some(pub_key),
            auth_mac: server_auth_mac,
            ..Default::default()
        },
    )?;
    if enc {
        crate::log::info(&format!(
            "server: encryption enabled ({}) for {:?}",
            cipher_name, h.name
        ));
    }

    let stats = Stats::new();
    let (rep_stop, rep_h) = spawn_reporter(&stats, "send", p.report_interval);

    let snd = Sender::new(SendConfig {
        sock: conn,
        peer: None, // learned from the receiver's START
        source,
        file_size: size,
        block_size: p.block_size,
        total_blocks: num_blocks(size, p.block_size),
        session,
        rate: p.rate_config(h.rate_bps),
        read_workers: p.read_workers,
        crypto,
        stats: stats.clone(),
    });
    crate::log::info(&format!(
        "server: send {:?} ({} blocks) to peer",
        h.name,
        num_blocks(size, p.block_size)
    ));
    let res = snd.run(stop);
    rep_stop.store(true, Ordering::Relaxed);
    let _ = rep_h.join();
    crate::log::info(&stats.summary("send"));
    res
}

fn rand_u32() -> u32 {
    use rand_core::RngCore;
    rand_core::OsRng.next_u32()
}

#[cfg(test)]
mod tests {
    use super::normalize_listen_addr;

    #[test]
    fn listen_addr_shorthand() {
        assert_eq!(normalize_listen_addr(":7400"), "0.0.0.0:7400");
        assert_eq!(normalize_listen_addr("7400"), "0.0.0.0:7400");
        assert_eq!(normalize_listen_addr("0.0.0.0:7400"), "0.0.0.0:7400");
        assert_eq!(normalize_listen_addr("127.0.0.1:7400"), "127.0.0.1:7400");
        assert_eq!(normalize_listen_addr("[::]:7400"), "[::]:7400");
        assert_eq!(normalize_listen_addr("[::1]:7400"), "[::1]:7400");
    }
}
