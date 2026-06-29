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
use crate::rate::RateWarmStart;
use crate::receiver::{new_receiver, RecvConfig};
use crate::runtime::{TransferHandle, TransferPhase};
use crate::sender::{SendConfig, Sender};
use crate::stats::Stats;
use crate::sys::{local_udp_port, new_udp_socket};
use std::fs::{File, OpenOptions};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use x25519_dalek::StaticSecret;

pub type SourceResolver = Arc<dyn Fn(&str) -> io::Result<Arc<dyn BlockSource>> + Send + Sync>;
pub type SinkResolver = Arc<dyn Fn(&str) -> io::Result<Arc<dyn BlockSink>> + Send + Sync>;

fn is_dir(p: &str) -> bool {
    Path::new(p).is_dir()
}

fn served_object_name(name: &str) -> io::Result<String> {
    let b = basename(name);
    if b.is_empty() || b == "." || b == ".." || b.contains('/') || b.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid object name",
        ));
    }
    Ok(b)
}

#[cfg(unix)]
fn apply_no_follow(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn apply_no_follow(_opts: &mut OpenOptions) {}

#[cfg(not(unix))]
fn reject_symlink_candidate(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => {
            Err(io::Error::other("refusing to follow served-object symlink"))
        }
        Ok(_) | Err(_) => Ok(()),
    }
}

#[cfg(unix)]
fn reject_symlink_candidate(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn open_served_source(dir: &str, name: &str) -> io::Result<File> {
    let path = Path::new(dir).join(name);
    reject_symlink_candidate(&path)?;
    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_no_follow(&mut opts);
    let f = opts.open(&path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "served object is not a regular file",
        ));
    }
    Ok(f)
}

fn open_served_sink(dir: &str, name: &str) -> io::Result<File> {
    let path = Path::new(dir).join(name);
    reject_symlink_candidate(&path)?;
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    apply_no_follow(&mut opts);
    let f = opts.open(&path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "served object is not a regular file",
        ));
    }
    Ok(f)
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

fn mark_phase(handle: Option<&Arc<TransferHandle>>, phase: TransferPhase) {
    if let Some(h) = handle {
        h.set_phase(phase);
    }
}

fn mark_result<T>(
    handle: Option<&Arc<TransferHandle>>,
    res: Result<T, GirthError>,
) -> Result<T, GirthError> {
    match &res {
        Ok(_) => {}
        Err(e) => {
            if let Some(h) = handle {
                h.set_failed(e);
            }
        }
    }
    res
}

fn warm_from_hello(h: &Hello) -> Option<RateWarmStart> {
    if !h.adaptive {
        return None;
    }
    let warm = RateWarmStart {
        rate_bps: h.warm_rate_bps,
        srtt_net_us: h.warm_srtt_net_us,
        base_rtt_us: h.warm_base_rtt_us,
    };
    (!warm.is_empty()).then_some(warm)
}

fn warm_for_params(p: &TransferParams, warm: Option<RateWarmStart>) -> Option<RateWarmStart> {
    if !p.adaptive {
        return None;
    }
    warm.filter(|w| !w.is_empty())
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
        None,
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
    send_core(
        server_addr,
        source,
        name,
        p,
        stats,
        None,
        None,
        auth_token,
        stop,
    )
}

/// Pushes `source` with a caller-owned [`TransferHandle`] for snapshots,
/// lifecycle state, cancellation, pause/resume, and live rate limits.
#[allow(clippy::too_many_arguments)]
pub fn client_send_from_with_handle(
    server_addr: &str,
    source: Arc<dyn BlockSource>,
    name: &str,
    p: &TransferParams,
    handle: Arc<TransferHandle>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let stats = handle.stats();
    let res = send_core(
        server_addr,
        source,
        name,
        p,
        stats,
        Some(handle.clone()),
        None,
        auth_token,
        stop,
    );
    mark_result(Some(&handle), res)
}

#[allow(clippy::too_many_arguments)]
fn send_core(
    server_addr: &str,
    source: Arc<dyn BlockSource>,
    name: &str,
    p: &TransferParams,
    stats: Arc<Stats>,
    handle: Option<Arc<TransferHandle>>,
    warm_start: Option<RateWarmStart>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    mark_phase(handle.as_ref(), TransferPhase::Connecting);
    let mut tcp = connect_control(server_addr)?;
    send_core_with_stream(
        &mut tcp,
        server_addr,
        source,
        name,
        p,
        stats,
        handle,
        warm_start,
        auth_token,
        stop,
    )
}

#[allow(clippy::too_many_arguments)]
fn send_core_with_stream(
    tcp: &mut TcpStream,
    server_addr: &str,
    source: Arc<dyn BlockSource>,
    name: &str,
    p: &TransferParams,
    stats: Arc<Stats>,
    handle: Option<Arc<TransferHandle>>,
    warm_start: Option<RateWarmStart>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let size = source.len() as i64;
    let crc = source_crc32c(source.as_ref())?;

    let (priv_key, pub_key): (Option<StaticSecret>, Option<Vec<u8>>) = if p.encrypt {
        let (sk, pk) = gen_keypair();
        (Some(sk), Some(pk.to_vec()))
    } else {
        (None, None)
    };
    let client_pub = pub_key.as_deref().unwrap_or(&[]);
    let auth_mac = auth_token
        .map(|t| auth::client_mac(t, PROTOCOL_VERSION, MODE_SEND, name, size, client_pub));
    let warm_start = warm_for_params(p, warm_start);
    let warm = warm_start.unwrap_or_default();

    write_json(
        tcp,
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
            warm_rate_bps: warm.rate_bps,
            warm_srtt_net_us: warm.srtt_net_us,
            warm_base_rtt_us: warm.base_rtt_us,
            encrypt: p.encrypt,
            ciphers: ciphers_if(p.encrypt),
            pub_key,
            auth_mac: auth_mac.clone(),
        },
    )?;
    let a: Ack = read_json(tcp)?;
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

    mark_phase(handle.as_ref(), TransferPhase::Transferring);
    let snd = Sender::new(SendConfig {
        sock: conn,
        peer: Some(peer),
        expected_peer_ip: Some(peer.ip()),
        source,
        file_size: size,
        block_size: p.block_size,
        total_blocks: num_blocks(size, p.block_size),
        session: a.session,
        rate: p.rate_config(p.rate_bps),
        read_workers: p.read_workers,
        crypto,
        stats: stats.clone(),
        control: handle.as_ref().map(|h| h.control()),
        warm_start,
    });
    snd.run(&stop)?;
    crate::log::info(&stats.summary("send"));
    mark_phase(handle.as_ref(), TransferPhase::Complete);
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
    let res = recv_core(
        server_addr,
        remote_name,
        sink,
        p,
        stats.clone(),
        None,
        None,
        None,
        stop,
    );
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
    recv_core(
        server_addr,
        name,
        sink,
        p,
        stats,
        None,
        None,
        auth_token,
        stop,
    )
}

/// Pulls `name` into `sink` with a caller-owned [`TransferHandle`] for
/// snapshots, lifecycle state, cancellation, pause/resume, and live rate limits.
#[allow(clippy::too_many_arguments)]
pub fn client_recv_into_with_handle(
    server_addr: &str,
    name: &str,
    sink: Arc<dyn BlockSink>,
    p: &TransferParams,
    handle: Arc<TransferHandle>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let stats = handle.stats();
    let res = recv_core(
        server_addr,
        name,
        sink,
        p,
        stats,
        Some(handle.clone()),
        None,
        auth_token,
        stop,
    );
    mark_result(Some(&handle), res)
}

/// A persistent client session that reuses the underlying TCP control channel
/// across multiple file pushes/pulls to avoid handshake latency.
pub struct ClientSession {
    server_addr: String,
    tcp: Mutex<Option<TcpStream>>,
    warm_start: Mutex<RateWarmStart>,
}

impl ClientSession {
    pub fn connect(server_addr: impl Into<String>) -> io::Result<ClientSession> {
        let addr = server_addr.into();
        let stream = connect_control(&addr)?;
        Ok(ClientSession {
            server_addr: addr,
            tcp: Mutex::new(Some(stream)),
            warm_start: Mutex::new(RateWarmStart::default()),
        })
    }

    pub fn new(server_addr: impl Into<String>) -> ClientSession {
        ClientSession {
            server_addr: server_addr.into(),
            tcp: Mutex::new(None),
            warm_start: Mutex::new(RateWarmStart::default()),
        }
    }

    pub fn rate_warm_start(&self) -> RateWarmStart {
        *self.warm_start.lock().unwrap()
    }

    fn get_or_connect(&self) -> io::Result<TcpStream> {
        let mut lock = self.tcp.lock().unwrap();
        if let Some(stream) = lock.take() {
            Ok(stream)
        } else {
            connect_control(&self.server_addr)
        }
    }

    fn put_stream(&self, stream: TcpStream) {
        let mut lock = self.tcp.lock().unwrap();
        *lock = Some(stream);
    }

    fn warm_for(&self, p: &TransferParams) -> Option<RateWarmStart> {
        warm_for_params(p, Some(*self.warm_start.lock().unwrap()))
    }

    fn record_warm_start(&self, p: &TransferParams, stats: &Stats) {
        if !p.adaptive {
            return;
        }
        let snap = stats.snapshot();
        let mut warm = self.warm_start.lock().unwrap();
        if snap.target_rate_bps > 0 {
            warm.rate_bps = snap.target_rate_bps;
        }
        if snap.srtt_net_us > 0 {
            warm.srtt_net_us = snap.srtt_net_us;
        }
        if snap.base_rtt_us > 0 {
            warm.base_rtt_us = snap.base_rtt_us;
        }
    }

    pub fn send_from(
        &self,
        source: Arc<dyn BlockSource>,
        name: &str,
        p: &TransferParams,
        progress: Option<Arc<Stats>>,
        auth_token: Option<&[u8]>,
        stop: Arc<AtomicBool>,
    ) -> Result<(), GirthError> {
        let mut stream = self.get_or_connect().map_err(GirthError::Io)?;
        let stats = progress.unwrap_or_default();
        let warm_start = self.warm_for(p);
        match send_core_with_stream(
            &mut stream,
            &self.server_addr,
            source,
            name,
            p,
            stats.clone(),
            None,
            warm_start,
            auth_token,
            stop,
        ) {
            Ok(()) => {
                self.record_warm_start(p, &stats);
                self.put_stream(stream);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_from_with_handle(
        &self,
        source: Arc<dyn BlockSource>,
        name: &str,
        p: &TransferParams,
        handle: Arc<TransferHandle>,
        auth_token: Option<&[u8]>,
        stop: Arc<AtomicBool>,
    ) -> Result<(), GirthError> {
        mark_phase(Some(&handle), TransferPhase::Connecting);
        let mut stream = self.get_or_connect().map_err(GirthError::Io)?;
        let stats = handle.stats();
        let warm_start = self.warm_for(p);
        let res = send_core_with_stream(
            &mut stream,
            &self.server_addr,
            source,
            name,
            p,
            stats.clone(),
            Some(handle.clone()),
            warm_start,
            auth_token,
            stop,
        );
        let res = mark_result(Some(&handle), res);
        if res.is_ok() {
            self.record_warm_start(p, &stats);
            self.put_stream(stream);
        }
        res
    }

    pub fn recv_into(
        &self,
        name: &str,
        sink: Arc<dyn BlockSink>,
        p: &TransferParams,
        progress: Option<Arc<Stats>>,
        auth_token: Option<&[u8]>,
        stop: Arc<AtomicBool>,
    ) -> Result<(), GirthError> {
        let mut stream = self.get_or_connect().map_err(GirthError::Io)?;
        let stats = progress.unwrap_or_default();
        let warm_start = self.warm_for(p);
        match recv_core_with_stream(
            &mut stream,
            &self.server_addr,
            name,
            sink,
            p,
            stats.clone(),
            None,
            warm_start,
            auth_token,
            stop,
        ) {
            Ok(()) => {
                self.record_warm_start(p, &stats);
                self.put_stream(stream);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recv_into_with_handle(
        &self,
        name: &str,
        sink: Arc<dyn BlockSink>,
        p: &TransferParams,
        handle: Arc<TransferHandle>,
        auth_token: Option<&[u8]>,
        stop: Arc<AtomicBool>,
    ) -> Result<(), GirthError> {
        mark_phase(Some(&handle), TransferPhase::Connecting);
        let mut stream = self.get_or_connect().map_err(GirthError::Io)?;
        let stats = handle.stats();
        let warm_start = self.warm_for(p);
        let res = recv_core_with_stream(
            &mut stream,
            &self.server_addr,
            name,
            sink,
            p,
            stats.clone(),
            Some(handle.clone()),
            warm_start,
            auth_token,
            stop,
        );
        let res = mark_result(Some(&handle), res);
        if res.is_ok() {
            self.record_warm_start(p, &stats);
            self.put_stream(stream);
        }
        res
    }
}

#[allow(clippy::too_many_arguments)]
fn recv_core(
    server_addr: &str,
    name: &str,
    sink: Arc<dyn BlockSink>,
    p: &TransferParams,
    stats: Arc<Stats>,
    handle: Option<Arc<TransferHandle>>,
    warm_start: Option<RateWarmStart>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    mark_phase(handle.as_ref(), TransferPhase::Connecting);
    let mut tcp = connect_control(server_addr)?;
    recv_core_with_stream(
        &mut tcp,
        server_addr,
        name,
        sink,
        p,
        stats,
        handle,
        warm_start,
        auth_token,
        stop,
    )
}

#[allow(clippy::too_many_arguments)]
fn recv_core_with_stream(
    tcp: &mut TcpStream,
    server_addr: &str,
    name: &str,
    sink: Arc<dyn BlockSink>,
    p: &TransferParams,
    stats: Arc<Stats>,
    handle: Option<Arc<TransferHandle>>,
    warm_start: Option<RateWarmStart>,
    auth_token: Option<&[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<(), GirthError> {
    let (priv_key, pub_key): (Option<StaticSecret>, Option<Vec<u8>>) = if p.encrypt {
        let (sk, pk) = gen_keypair();
        (Some(sk), Some(pk.to_vec()))
    } else {
        (None, None)
    };
    let client_pub = pub_key.as_deref().unwrap_or(&[]);
    let auth_mac =
        auth_token.map(|t| auth::client_mac(t, PROTOCOL_VERSION, MODE_RECV, name, 0, client_pub));
    let warm_start = warm_for_params(p, warm_start);
    let warm = warm_start.unwrap_or_default();

    write_json(
        tcp,
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
            warm_rate_bps: warm.rate_bps,
            warm_srtt_net_us: warm.srtt_net_us,
            warm_base_rtt_us: warm.base_rtt_us,
            encrypt: p.encrypt,
            ciphers: ciphers_if(p.encrypt),
            pub_key,
            auth_mac: auth_mac.clone(),
        },
    )?;
    let a: Ack = read_json(tcp)?;
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

    mark_phase(handle.as_ref(), TransferPhase::Transferring);
    let rcv = new_receiver(RecvConfig {
        sock: conn,
        sink: sink.clone(),
        file_size: a.size,
        block_size: p.block_size,
        total_blocks: num_blocks(a.size, p.block_size),
        session: a.session,
        expected_peer_ip: Some(peer.ip()),
        read_workers: p.read_workers,
        rate: p.rate_config(p.rate_bps),
        crypto,
        feedback_interval_us: p.feedback_interval_us,
        net_tick_interval_us: p.net_tick_interval_us,
        max_nacks_per_pdu: 0,
        stats: stats.clone(),
        control: handle.as_ref().map(|h| h.control()),
        warm_start,
        start_peer: Some(peer),
    });
    rcv.run(&stop)?;
    mark_phase(handle.as_ref(), TransferPhase::Verifying);
    sink.finalize()?;

    // A CRC mismatch is a hard error, not just a log line.
    if let Some(got) = sink.read_crc32c()? {
        if got != a.crc32c {
            return Err(GirthError::Integrity);
        }
        crate::log::info(&format!("integrity OK (crc32c={:08x})", got));
    }
    crate::log::info(&stats.summary("recv"));
    mark_phase(handle.as_ref(), TransferPhase::Complete);
    Ok(())
}

/// When we authenticated, the server must prove possession
/// of the same PSK (binding the session id and its ephemeral key), or we treat
/// the session as denied - this is what closes the MITM on the server's pubkey.
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

/// Server-side caps applied to peer-controlled handshake values before any file
/// allocation or UDP data-plane setup occurs.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    pub max_object_size: u64,
    pub min_block_size: usize,
    pub max_block_size: usize,
    pub max_rate_bps: u64,
    pub max_alpha_bps: u64,
    pub max_concurrent_connections: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        ServerLimits {
            max_object_size: 1 << 40, // 1 TiB
            min_block_size: 256,
            max_block_size: 65_455, // DATA header + AEAD tag fit in one UDP payload
            max_rate_bps: 100_000_000_000, // 100 Gbps
            max_alpha_bps: 100_000_000_000,
            max_concurrent_connections: 256,
        }
    }
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
    pub limits: ServerLimits,
    pub source_resolver: Option<SourceResolver>,
    pub sink_resolver: Option<SinkResolver>,
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
            limits: ServerLimits::default(),
            source_resolver: None,
            sink_resolver: None,
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

    pub fn with_limits(mut self, limits: ServerLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_source_resolver(mut self, resolver: SourceResolver) -> Self {
        self.source_resolver = Some(resolver);
        self
    }

    pub fn with_sink_resolver(mut self, resolver: SinkResolver) -> Self {
        self.sink_resolver = Some(resolver);
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
        let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let h = workers.swap_remove(i);
                    let _ = h.join();
                } else {
                    i += 1;
                }
            }
            match ln.accept() {
                Ok((c, _addr)) => {
                    if active.load(Ordering::Relaxed) >= self.limits.max_concurrent_connections {
                        drop(c);
                        continue;
                    }
                    active.fetch_add(1, Ordering::Relaxed);
                    c.set_nonblocking(false).ok();
                    let dir = self.dir.clone();
                    let params = self.params.clone();
                    let authorizer = self.authorizer.clone();
                    let udp_range = self.udp_port_range.clone();
                    let limits = self.limits.clone();
                    let source_resolver = self.source_resolver.clone();
                    let sink_resolver = self.sink_resolver.clone();
                    let stop = stop.clone();
                    let active = active.clone();
                    workers.push(std::thread::spawn(move || {
                        if let Err(e) = handle_conn(
                            c,
                            &dir,
                            &params,
                            &authorizer,
                            &udp_range,
                            &limits,
                            &source_resolver,
                            &sink_resolver,
                            &stop,
                        ) {
                            crate::log::error(&format!("server: transfer error: {}", e));
                        }
                        active.fetch_sub(1, Ordering::Relaxed);
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

const MAX_WARM_RTT_US: u64 = 60_000_000;

fn validate_hello_limits(h: &Hello, limits: &ServerLimits) -> Result<(), String> {
    match h.mode.as_str() {
        MODE_SEND | MODE_RECV => {}
        _ => return Err("unknown mode".into()),
    }
    if h.size < 0 {
        return Err("negative size".into());
    }
    if h.mode == MODE_SEND && h.size as u64 > limits.max_object_size {
        return Err(format!(
            "object too large: {} > {}",
            h.size, limits.max_object_size
        ));
    }
    if h.block_size <= 0 {
        return Err("invalid block size".into());
    }
    let block_size = h.block_size as usize;
    if block_size < limits.min_block_size || block_size > limits.max_block_size {
        return Err(format!(
            "block size out of range: {} (allowed {}..={})",
            block_size, limits.min_block_size, limits.max_block_size
        ));
    }
    if h.rate_bps > limits.max_rate_bps {
        return Err(format!(
            "rate too high: {} > {}",
            h.rate_bps, limits.max_rate_bps
        ));
    }
    if h.max_bps > limits.max_rate_bps {
        return Err(format!(
            "max rate too high: {} > {}",
            h.max_bps, limits.max_rate_bps
        ));
    }
    if h.warm_rate_bps > limits.max_rate_bps {
        return Err(format!(
            "warm rate too high: {} > {}",
            h.warm_rate_bps, limits.max_rate_bps
        ));
    }
    if h.warm_srtt_net_us > MAX_WARM_RTT_US || h.warm_base_rtt_us > MAX_WARM_RTT_US {
        return Err(format!(
            "warm RTT too high: srtt={} base={} max={}",
            h.warm_srtt_net_us, h.warm_base_rtt_us, MAX_WARM_RTT_US
        ));
    }
    if h.warm_srtt_net_us > 0 && h.warm_base_rtt_us > 0 && h.warm_base_rtt_us > h.warm_srtt_net_us {
        return Err("warm base RTT exceeds warm SRTT".into());
    }
    if h.alpha_bps > limits.max_alpha_bps {
        return Err(format!(
            "alpha too high: {} > {}",
            h.alpha_bps, limits.max_alpha_bps
        ));
    }
    if h.max_bps > 0 && h.rate_bps > h.max_bps {
        return Err("rate exceeds max rate".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_conn(
    mut c: TcpStream,
    dir: &str,
    params: &TransferParams,
    authorizer: &Option<Authorizer>,
    udp_range: &Option<RangeInclusive<u16>>,
    limits: &ServerLimits,
    source_resolver: &Option<SourceResolver>,
    sink_resolver: &Option<SinkResolver>,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let peer_addr = c.peer_addr()?;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let h: Hello = match read_json(&mut c) {
            Ok(h) => h,
            Err(e)
                if e.kind() == io::ErrorKind::UnexpectedEof
                    || e.kind() == io::ErrorKind::ConnectionReset =>
            {
                break
            }
            Err(e) => return Err(e),
        };
        if h.version != PROTOCOL_VERSION {
            ack_err(&mut c, "protocol version mismatch", false);
            return Ok(());
        }
        if let Err(e) = validate_hello_limits(&h, limits) {
            ack_err(&mut c, e, false);
            return Ok(());
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
            MODE_SEND => recv_from_client(
                &mut c,
                h,
                session,
                &p,
                dir,
                peer_addr,
                limits,
                udp_range,
                sink_resolver,
                auth_state,
                stop,
            )?,
            MODE_RECV => send_to_client(
                &mut c,
                h,
                session,
                &p,
                dir,
                peer_addr,
                limits,
                udp_range,
                source_resolver,
                auth_state,
                stop,
            )?,
            _ => {
                ack_err(&mut c, "unknown mode", false);
                break;
            }
        }
    }
    Ok(())
}

/// Client pushes a file; server is the data receiver.
#[allow(clippy::too_many_arguments)]
fn recv_from_client(
    c: &mut TcpStream,
    h: Hello,
    session: u32,
    p: &TransferParams,
    dir: &str,
    peer_addr: SocketAddr,
    _limits: &ServerLimits,
    udp_range: &Option<RangeInclusive<u16>>,
    sink_resolver: &Option<SinkResolver>,
    auth_state: Option<AuthState>,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let object_name = match served_object_name(&h.name) {
        Ok(n) => n,
        Err(e) => {
            ack_err(c, e.to_string(), false);
            return Ok(());
        }
    };
    let sink: Arc<dyn BlockSink> = if let Some(ref resolver) = sink_resolver {
        match resolver(&object_name) {
            Ok(s) => s,
            Err(e) => {
                ack_err(c, e.to_string(), false);
                return Ok(());
            }
        }
    } else {
        let f = match open_served_sink(dir, &object_name) {
            Ok(f) => f,
            Err(e) => {
                ack_err(c, e.to_string(), false);
                return Ok(());
            }
        };
        Arc::new(FileSink::from_file(f))
    };
    if let Err(e) = sink.allocate(h.size.max(0) as u64) {
        ack_err(c, e.to_string(), false);
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
            ack_err(c, e, false);
            return Ok(());
        }
    };
    let server_auth_mac = auth_state
        .as_ref()
        .map(|a| auth::server_mac(&a.token, session, &pub_key, &a.client_mac));
    write_json(
        c,
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
        expected_peer_ip: Some(peer_addr.ip()),
        read_workers: p.read_workers,
        rate: p.rate_config(h.rate_bps),
        crypto,
        feedback_interval_us: p.feedback_interval_us,
        net_tick_interval_us: p.net_tick_interval_us,
        max_nacks_per_pdu: 0,
        stats: stats.clone(),
        control: None,
        warm_start: warm_from_hello(&h),
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
    c: &mut TcpStream,
    h: Hello,
    session: u32,
    p: &TransferParams,
    dir: &str,
    peer_addr: SocketAddr,
    limits: &ServerLimits,
    udp_range: &Option<RangeInclusive<u16>>,
    source_resolver: &Option<SourceResolver>,
    auth_state: Option<AuthState>,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let object_name = match served_object_name(&h.name) {
        Ok(n) => n,
        Err(e) => {
            ack_err(c, e.to_string(), false);
            return Ok(());
        }
    };
    let source: Arc<dyn BlockSource> = if let Some(ref resolver) = source_resolver {
        match resolver(&object_name) {
            Ok(s) => s,
            Err(e) => {
                ack_err(c, e.to_string(), false);
                return Ok(());
            }
        }
    } else {
        let f = match open_served_source(dir, &object_name) {
            Ok(f) => f,
            Err(e) => {
                ack_err(c, e.to_string(), false);
                return Ok(());
            }
        };
        match FileSource::from_file(f) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                ack_err(c, e.to_string(), false);
                return Ok(());
            }
        }
    };
    let source_len = source.len();
    if source_len > limits.max_object_size {
        ack_err(
            c,
            format!(
                "object too large: {} > {}",
                source_len, limits.max_object_size
            ),
            false,
        );
        return Ok(());
    }
    if source_len > i64::MAX as u64 {
        ack_err(c, "object too large for protocol size field", false);
        return Ok(());
    }
    let size = source_len as i64;
    let crc = match source_crc32c(source.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            ack_err(c, e.to_string(), false);
            return Ok(());
        }
    };
    let conn = Arc::new(bind_data_socket(udp_range, false)?);

    let (enc, cipher_name, pub_key, crypto) = match negotiate_crypto_server(
        h.encrypt,
        h.ciphers.as_deref().unwrap_or(&[]),
        h.pub_key.as_deref().unwrap_or(&[]),
        session,
    ) {
        Ok(v) => v,
        Err(e) => {
            ack_err(c, e, false);
            return Ok(());
        }
    };
    let server_auth_mac = auth_state
        .as_ref()
        .map(|a| auth::server_mac(&a.token, session, &pub_key, &a.client_mac));
    write_json(
        c,
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
        expected_peer_ip: Some(peer_addr.ip()),
        source,
        file_size: size,
        block_size: p.block_size,
        total_blocks: num_blocks(size, p.block_size),
        session,
        rate: p.rate_config(h.rate_bps),
        read_workers: p.read_workers,
        crypto,
        stats: stats.clone(),
        control: None,
        warm_start: warm_from_hello(&h),
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
