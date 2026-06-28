//! Tests for the library-facing surface: in-memory source/sink, PSK auth, hard
//! CRC failure, bounded UDP port range, typed errors, and safe concurrent
//! in-process transfers.

use girth::{
    client_recv_into, client_send_from, default_params, AuthContext, Authorizer, BlockSink,
    GirthError, MemSink, MemSource, Server, TransferParams,
};
use rand_core::{OsRng, RngCore};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct TestServer {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn start(srv: Server) -> TestServer {
    let addr = srv.addr.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let handle = std::thread::spawn(move || {
        let _ = srv.listen_and_serve(st);
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if TcpStream::connect(&addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    TestServer {
        addr,
        stop,
        handle: Some(handle),
    }
}

fn free_addr() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = ln.local_addr().unwrap().to_string();
    drop(ln);
    a
}

fn base_params() -> TransferParams {
    let mut p = default_params();
    p.rate_bps = 400_000_000;
    p.report_interval = Duration::from_secs(3600);
    p
}

fn never_stop() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// Push from RAM and pull back into RAM, no temp files, several sizes.
#[test]
fn in_memory_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let srv = start(Server::new(
        free_addr(),
        dir.path().to_string_lossy(),
        p.clone(),
    ));

    for size in [0usize, 1, 1500, 1 << 20, 3 << 20] {
        let name = format!("mem{size}");
        let data = random_bytes(size);

        client_send_from(
            &srv.addr,
            Arc::new(MemSource::new(data.clone())),
            &name,
            &p,
            None,
            None,
            never_stop(),
        )
        .unwrap_or_else(|e| panic!("mem push size={size}: {e}"));

        let sink = Arc::new(MemSink::new());
        client_recv_into(&srv.addr, &name, sink.clone(), &p, None, None, never_stop())
            .unwrap_or_else(|e| panic!("mem pull size={size}: {e}"));
        assert_eq!(sink.to_vec(), data, "mem round-trip size={size}");
    }
}

/// Caller-supplied Stats is populated, and two transfers run concurrently in one
/// process without interfering.
#[test]
fn injectable_stats_and_concurrent_transfers() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let srv = start(Server::new(
        free_addr(),
        dir.path().to_string_lossy(),
        p.clone(),
    ));
    let addr = srv.addr.clone();

    let run = |name: &str| {
        let name = name.to_string();
        let addr = addr.clone();
        let p = p.clone();
        std::thread::spawn(move || {
            let data = random_bytes(2 << 20);
            let progress = girth::Stats::new();
            client_send_from(
                &addr,
                Arc::new(MemSource::new(data.clone())),
                &name,
                &p,
                Some(progress.clone()),
                None,
                never_stop(),
            )
            .unwrap();
            assert!(progress.bytes_sent.load(Ordering::Relaxed) > 0);

            let sink = Arc::new(MemSink::new());
            client_recv_into(&addr, &name, sink.clone(), &p, None, None, never_stop()).unwrap();
            assert_eq!(sink.to_vec(), data);
        })
    };
    let a = run("concA");
    let b = run("concB");
    a.join().unwrap();
    b.join().unwrap();
}

fn psk_authorizer(expected: &'static [u8]) -> Authorizer {
    Arc::new(move |_ctx: &AuthContext| Ok(expected.to_vec()))
}

/// A correct token succeeds; a wrong or missing token is denied with the typed
/// `AuthDenied` error.
#[test]
fn auth_required_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let token: &[u8] = b"correct horse battery staple";
    let srv = start(
        Server::new(free_addr(), dir.path().to_string_lossy(), p.clone())
            .with_authorizer(psk_authorizer(token)),
    );

    let data = random_bytes(64 << 10);

    // Correct token: push then pull succeed and round-trip.
    client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(data.clone())),
        "secret",
        &p,
        None,
        Some(token),
        never_stop(),
    )
    .expect("authed push");
    let sink = Arc::new(MemSink::new());
    client_recv_into(
        &srv.addr,
        "secret",
        sink.clone(),
        &p,
        None,
        Some(token),
        never_stop(),
    )
    .expect("authed pull");
    assert_eq!(sink.to_vec(), data);

    // Wrong token: denied.
    let err = client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(data.clone())),
        "secret",
        &p,
        None,
        Some(b"wrong token"),
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::AuthDenied), "got {err:?}");

    // No token at all: denied.
    let err = client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(data)),
        "secret",
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::AuthDenied), "got {err:?}");
}

/// An authorizer can deny a specific object.
#[test]
fn authorizer_can_deny_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let authz: Authorizer = Arc::new(|ctx: &AuthContext| {
        if ctx.name == "allowed" {
            Ok(b"tok".to_vec())
        } else {
            Err("not permitted".into())
        }
    });
    let srv = start(
        Server::new(free_addr(), dir.path().to_string_lossy(), p.clone()).with_authorizer(authz),
    );

    let err = client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(random_bytes(1024))),
        "blocked",
        &p,
        None,
        Some(b"tok"),
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::AuthDenied), "got {err:?}");
}

/// A sink that silently corrupts a block makes the transfer fail with the
/// typed `Integrity` error instead of returning a "successful" wrong result.
#[test]
fn crc_mismatch_is_a_hard_error() {
    struct CorruptingSink(MemSink);
    impl BlockSink for CorruptingSink {
        fn allocate(&self, len: u64) -> std::io::Result<()> {
            self.0.allocate(len)
        }
        fn write_all_at(&self, off: u64, buf: &[u8]) -> std::io::Result<()> {
            let mut b = buf.to_vec();
            if !b.is_empty() {
                b[0] ^= 0xff; // flip a bit so the end-to-end CRC will not match
            }
            self.0.write_all_at(off, &b)
        }
        fn read_crc32c(&self) -> std::io::Result<Option<u32>> {
            self.0.read_crc32c()
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let srv = start(Server::new(
        free_addr(),
        dir.path().to_string_lossy(),
        p.clone(),
    ));

    client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(random_bytes(8192))),
        "obj",
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap();

    let err = client_recv_into(
        &srv.addr,
        "obj",
        Arc::new(CorruptingSink(MemSink::new())),
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::Integrity), "got {err:?}");
}

/// A server constrained to a bounded UDP port range still transfers.
#[test]
fn bounded_udp_port_range() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let srv = start(
        Server::new(free_addr(), dir.path().to_string_lossy(), p.clone())
            .with_udp_port_range(41400..=41450),
    );

    let data = random_bytes(512 << 10);
    client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(data.clone())),
        "ranged",
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap();
    let sink = Arc::new(MemSink::new());
    client_recv_into(
        &srv.addr,
        "ranged",
        sink.clone(),
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap();
    assert_eq!(sink.to_vec(), data);
}

/// A traversal-style object name is reduced to its basename and
/// can never write outside the served directory.
#[test]
fn object_name_cannot_escape_served_dir() {
    let parent = tempfile::tempdir().unwrap();
    let served = parent.path().join("served");
    std::fs::create_dir(&served).unwrap();
    let p = base_params();
    let srv = start(Server::new(
        free_addr(),
        served.to_string_lossy(),
        p.clone(),
    ));

    let data = random_bytes(4096);
    client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(data.clone())),
        "../escapee",
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap();

    // Landed inside the served dir under its basename, not in the parent.
    assert!(served.join("escapee").exists());
    assert!(!parent.path().join("escapee").exists());
    assert_eq!(std::fs::read(served.join("escapee")).unwrap(), data);
}

/// Pulling a nonexistent object yields the typed `NotFound`.
#[test]
fn missing_object_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let srv = start(Server::new(
        free_addr(),
        dir.path().to_string_lossy(),
        p.clone(),
    ));

    let err = client_recv_into(
        &srv.addr,
        "does-not-exist",
        Arc::new(MemSink::new()),
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::NotFound), "got {err:?}");
}
