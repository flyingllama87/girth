//! Top-level orchestration: client push/pull and the server, wiring the control
//! handshake (TCP) to the data plane (UDP).

use crate::control::*;
use crate::crypto::{ciphers_if, client_crypto, gen_keypair, negotiate_crypto_server};
use crate::protocol::{crc32c_append, num_blocks, PROTOCOL_VERSION};
use crate::receiver::{new_receiver, RecvConfig};
use crate::sender::{SendConfig, Sender};
use crate::stats::Stats;
use crate::sys::{local_udp_port, new_udp_socket};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use x25519_dalek::StaticSecret;

/// Computes the whole-file CRC32C for the end-to-end integrity check.
fn file_crc32c(f: &mut File) -> io::Result<u32> {
    f.seek(SeekFrom::Start(0))?;
    let mut crc = 0u32;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        crc = crc32c_append(crc, &buf[..n]);
    }
    Ok(crc)
}

/// Sizes the receive file to `size`, preferring fallocate (real blocks) over a
/// sparse file so scattered retransmit writes are plain overwrites.
fn prepare_dest_file(f: &File, size: i64) -> io::Result<()> {
    if size > 0 && crate::sys::fallocate(f, size).is_ok() {
        return Ok(());
    }
    f.set_len(size.max(0) as u64)
}

fn is_dir(p: &str) -> bool {
    Path::new(p).is_dir()
}

/// Resolves the data-plane UDP peer from the control address + negotiated port.
fn resolve_peer(server_addr: &str, udp_port: i64) -> io::Result<std::net::SocketAddr> {
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
        // Empty host before the port, e.g. ":7400" -> "0.0.0.0:7400".
        Some(i) if a[..i].is_empty() => format!("0.0.0.0{}", a),
        // No colon at all: treat the whole thing as a bare port.
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

/// Pushes `local_path` to the girth server at `server_addr` (host:port).
pub fn client_send(
    server_addr: &str,
    local_path: &str,
    p: &TransferParams,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut f = File::open(local_path)?;
    let size = f.metadata()?.len() as i64;
    let crc = file_crc32c(&mut f)?;

    let mut tcp = connect_control(server_addr)?;

    let (priv_key, pub_key): (Option<StaticSecret>, Option<Vec<u8>>) = if p.encrypt {
        let (sk, pk) = gen_keypair();
        (Some(sk), Some(pk.to_vec()))
    } else {
        (None, None)
    };

    write_json(
        &mut tcp,
        &Hello {
            version: PROTOCOL_VERSION,
            mode: MODE_SEND.into(),
            name: basename(local_path),
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
        },
    )?;
    let a: Ack = read_json(&mut tcp)?;
    if !a.ok {
        return Err(io::Error::other(format!(
            "server rejected transfer: {}",
            a.err
        )));
    }
    let crypto = client_crypto(
        p.encrypt,
        a.encrypt,
        a.pub_key.as_deref().unwrap_or(&[]),
        a.session,
        &a.cipher,
        priv_key.as_ref(),
    )
    .map_err(io::Error::other)?;

    let peer = resolve_peer(server_addr, a.udp_port)?;
    let conn = Arc::new(new_udp_socket(0, false)?);

    let stats = Stats::new();
    let (rep_stop, rep_h) = spawn_reporter(&stats, "send", p.report_interval);

    let snd = Sender::new(SendConfig {
        sock: conn,
        peer: Some(peer),
        file: Arc::new(f),
        file_size: size,
        block_size: p.block_size,
        total_blocks: num_blocks(size, p.block_size),
        session: a.session,
        rate: p.rate_config(p.rate_bps),
        read_workers: p.read_workers,
        crypto,
        stats: stats.clone(),
    });
    let res = snd.run(&stop);

    rep_stop.store(true, Ordering::Relaxed);
    let _ = rep_h.join();
    eprintln!("{}", stats.summary("send"));
    res
}

/// Pulls `remote_name` from the server into `out_path`.
pub fn client_recv(
    server_addr: &str,
    remote_name: &str,
    out_path: &str,
    p: &TransferParams,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut tcp = connect_control(server_addr)?;

    let (priv_key, pub_key): (Option<StaticSecret>, Option<Vec<u8>>) = if p.encrypt {
        let (sk, pk) = gen_keypair();
        (Some(sk), Some(pk.to_vec()))
    } else {
        (None, None)
    };

    write_json(
        &mut tcp,
        &Hello {
            version: PROTOCOL_VERSION,
            mode: MODE_RECV.into(),
            name: remote_name.into(),
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
        },
    )?;
    let a: Ack = read_json(&mut tcp)?;
    if !a.ok {
        return Err(io::Error::other(format!(
            "server rejected transfer: {}",
            a.err
        )));
    }
    let crypto = client_crypto(
        p.encrypt,
        a.encrypt,
        a.pub_key.as_deref().unwrap_or(&[]),
        a.session,
        &a.cipher,
        priv_key.as_ref(),
    )
    .map_err(io::Error::other)?;

    let mut out = out_path.to_string();
    if out.is_empty() || is_dir(&out) {
        out = Path::new(&out)
            .join(basename(remote_name))
            .to_string_lossy()
            .into_owned();
    }
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&out)?;
    prepare_dest_file(&f, a.size)?;

    let peer = resolve_peer(server_addr, a.udp_port)?;
    let conn = Arc::new(new_udp_socket(0, true)?);

    let stats = Stats::new();
    let (rep_stop, rep_h) = spawn_reporter(&stats, "recv", p.report_interval);

    // The receiver bootstraps the flow by sending START to `peer` (the sender
    // waits for it). That is done inside the receiver via the feedback path, not
    // here: on Windows `conn` is a RIO-registered socket that cannot use the
    // standard `send_to`, so START must go through RIOSendEx.
    let rcv = new_receiver(RecvConfig {
        sock: conn,
        file: Arc::new(f),
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
    let res = rcv.run(&stop);

    rep_stop.store(true, Ordering::Relaxed);
    let _ = rep_h.join();
    eprintln!("{}", stats.summary("recv"));
    res?;

    // End-to-end integrity check.
    let mut check = File::open(&out)?;
    if let Ok(got) = file_crc32c(&mut check) {
        if got != a.crc32c {
            return Err(io::Error::other(format!(
                "INTEGRITY FAILURE: crc32c got={:08x} want={:08x}",
                got, a.crc32c
            )));
        }
        eprintln!("integrity OK (crc32c={:08x})", got);
    }
    Ok(())
}

/// Accepts control connections and runs the negotiated transfers.
pub struct Server {
    pub addr: String,
    pub dir: String,
    pub params: TransferParams,
}

impl Server {
    /// Runs until `stop` is set.
    pub fn listen_and_serve(&self, stop: Arc<AtomicBool>) -> io::Result<()> {
        let ln = TcpListener::bind(normalize_listen_addr(&self.addr))?;
        ln.set_nonblocking(true)?;
        eprintln!(
            "girth-srv: listening on {} (control/TCP), serving dir {}",
            ln.local_addr()?,
            self.dir
        );
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
                    let stop = stop.clone();
                    workers.push(std::thread::spawn(move || {
                        if let Err(e) = handle_conn(c, &dir, &params, &stop) {
                            eprintln!("girth-srv: transfer error: {}", e);
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

fn handle_conn(
    mut c: TcpStream,
    dir: &str,
    params: &TransferParams,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let mut h: Hello = read_json(&mut c)?;
    if h.version != PROTOCOL_VERSION {
        let _ = write_json(
            &mut c,
            &Ack {
                err: "protocol version mismatch".into(),
                ..Default::default()
            },
        );
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

    match h.mode.as_str() {
        MODE_SEND => recv_from_client(c, h, session, &p, dir, stop),
        MODE_RECV => send_to_client(c, h, session, &p, dir, stop),
        _ => {
            let _ = write_json(
                &mut c,
                &Ack {
                    err: "unknown mode".into(),
                    ..Default::default()
                },
            );
            Ok(())
        }
    }
}

/// Client pushes a file; server is the data receiver.
fn recv_from_client(
    mut c: TcpStream,
    h: Hello,
    session: u32,
    p: &TransferParams,
    dir: &str,
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
            let _ = write_json(
                &mut c,
                &Ack {
                    err: e.to_string(),
                    ..Default::default()
                },
            );
            return Ok(());
        }
    };
    if let Err(e) = prepare_dest_file(&f, h.size) {
        let _ = write_json(
            &mut c,
            &Ack {
                err: e.to_string(),
                ..Default::default()
            },
        );
        return Ok(());
    }
    let conn = Arc::new(new_udp_socket(0, true)?);

    let (enc, cipher_name, pub_key, crypto) = match negotiate_crypto_server(
        h.encrypt,
        h.ciphers.as_deref().unwrap_or(&[]),
        h.pub_key.as_deref().unwrap_or(&[]),
        session,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = write_json(
                &mut c,
                &Ack {
                    err: e,
                    ..Default::default()
                },
            );
            return Ok(());
        }
    };
    write_json(
        &mut c,
        &Ack {
            ok: true,
            udp_port: local_udp_port(&conn) as i64,
            session,
            name: h.name.clone(),
            encrypt: enc,
            cipher: cipher_name.clone(),
            pub_key: if pub_key.is_empty() {
                None
            } else {
                Some(pub_key)
            },
            ..Default::default()
        },
    )?;
    if enc {
        eprintln!(
            "girth-srv: encryption enabled ({}) for {:?}",
            cipher_name, h.name
        );
    }

    let stats = Stats::new();
    let (rep_stop, rep_h) = spawn_reporter(&stats, "recv", p.report_interval);

    let rcv = new_receiver(RecvConfig {
        sock: conn,
        file: Arc::new(f),
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
        // Server-side push receiver: learns its peer from the first inbound DATA;
        // the client (sender) drives the flow, so no bootstrap START is needed.
        start_peer: None,
    });
    eprintln!(
        "girth-srv: recv {:?} ({} blocks) from peer",
        h.name,
        num_blocks(h.size, p.block_size)
    );
    let res = rcv.run(stop);
    rep_stop.store(true, Ordering::Relaxed);
    let _ = rep_h.join();
    eprintln!("{}", stats.summary("recv"));
    res?;

    if let Ok(mut check) = File::open(&out_path) {
        if let Ok(got) = file_crc32c(&mut check) {
            if got != h.crc32c {
                eprintln!(
                    "girth-srv: INTEGRITY FAILURE {:?}: crc got={:08x} want={:08x}",
                    h.name, got, h.crc32c
                );
            } else {
                eprintln!("girth-srv: integrity OK {:?} (crc32c={:08x})", h.name, got);
            }
        }
    }
    Ok(())
}

/// Client pulls a file; server is the data sender.
fn send_to_client(
    mut c: TcpStream,
    h: Hello,
    session: u32,
    p: &TransferParams,
    dir: &str,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let in_path = Path::new(dir).join(basename(&h.name));
    let mut f = match File::open(&in_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = write_json(
                &mut c,
                &Ack {
                    err: e.to_string(),
                    ..Default::default()
                },
            );
            return Ok(());
        }
    };
    let size = f.metadata()?.len() as i64;
    let crc = match file_crc32c(&mut f) {
        Ok(v) => v,
        Err(e) => {
            let _ = write_json(
                &mut c,
                &Ack {
                    err: e.to_string(),
                    ..Default::default()
                },
            );
            return Ok(());
        }
    };
    let conn = Arc::new(new_udp_socket(0, false)?);

    let (enc, cipher_name, pub_key, crypto) = match negotiate_crypto_server(
        h.encrypt,
        h.ciphers.as_deref().unwrap_or(&[]),
        h.pub_key.as_deref().unwrap_or(&[]),
        session,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = write_json(
                &mut c,
                &Ack {
                    err: e,
                    ..Default::default()
                },
            );
            return Ok(());
        }
    };
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
            pub_key: if pub_key.is_empty() {
                None
            } else {
                Some(pub_key)
            },
            ..Default::default()
        },
    )?;
    if enc {
        eprintln!(
            "girth-srv: encryption enabled ({}) for {:?}",
            cipher_name, h.name
        );
    }

    let stats = Stats::new();
    let (rep_stop, rep_h) = spawn_reporter(&stats, "send", p.report_interval);

    let snd = Sender::new(SendConfig {
        sock: conn,
        peer: None, // learned from the receiver's START
        file: Arc::new(f),
        file_size: size,
        block_size: p.block_size,
        total_blocks: num_blocks(size, p.block_size),
        session,
        rate: p.rate_config(h.rate_bps),
        read_workers: p.read_workers,
        crypto,
        stats: stats.clone(),
    });
    eprintln!(
        "girth-srv: send {:?} ({} blocks) to peer",
        h.name,
        num_blocks(size, p.block_size)
    );
    let res = snd.run(stop);
    rep_stop.store(true, Ordering::Relaxed);
    let _ = rep_h.join();
    eprintln!("{}", stats.summary("send"));
    res
}

// The server's serving directory is threaded through `handle_conn`.

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
