//! Tests for the embedder-facing surface added for Lore: in-memory source/sink
//! (P0-1), PSK auth (P0-3), hard CRC failure (P1-1), bounded UDP port range
//! (P1-2), typed errors (P1-3), and safe concurrent in-process transfers (P0-2).

use girth::{
    client_recv_into, client_recv_into_with_handle, client_send_from, client_send_from_with_handle,
    default_params, AuthContext, Authorizer, BlockSink, ClientSession, FileSink, GirthError,
    MemSink, MemSource, Server, ServerLimits, TransferHandle, TransferParams, TransferPhase,
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

/// P0-1: push from RAM and pull back into RAM, no temp files, several sizes.
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

/// P0-2: caller-supplied Stats is populated, and two transfers run concurrently
/// in one process without interfering.
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

/// P0-3: a correct token succeeds; a wrong or missing token is denied (and the
/// error is the typed `AuthDenied`, P1-3).
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

/// P0-3: an authorizer that denies a specific object (object-level authz).
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

/// P1-1: a sink that silently corrupts a block makes the transfer fail with the
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

/// P1-2: a server constrained to a bounded UDP port range still transfers.
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

/// P0-3 hardening: a traversal-style object name is reduced to its basename and
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

#[cfg(unix)]
#[test]
fn served_symlink_is_refused() {
    use std::os::unix::fs::symlink;

    let parent = tempfile::tempdir().unwrap();
    let served = parent.path().join("served");
    std::fs::create_dir(&served).unwrap();
    let outside = parent.path().join("outside");
    std::fs::write(&outside, b"outside").unwrap();
    symlink(&outside, served.join("link")).unwrap();

    let p = base_params();
    let srv = start(Server::new(
        free_addr(),
        served.to_string_lossy(),
        p.clone(),
    ));

    let err = client_recv_into(
        &srv.addr,
        "link",
        Arc::new(MemSink::new()),
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::Protocol(_)), "got {err:?}");

    let err = client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(b"overwrite".to_vec())),
        "link",
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::Protocol(_)), "got {err:?}");
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
}

#[test]
fn shorter_overwrite_truncates_stale_tail() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("object");
    std::fs::write(&path, b"old-long-content").unwrap();

    let sink = FileSink::create(path.to_str().unwrap()).unwrap();
    sink.allocate(3).unwrap();
    sink.write_all_at(0, b"new").unwrap();
    sink.finalize().unwrap();

    assert_eq!(std::fs::read(path).unwrap(), b"new");
}

#[test]
fn server_rejects_out_of_range_handshake_values() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = base_params();
    p.block_size = 128;
    let srv = start(
        Server::new(free_addr(), dir.path().to_string_lossy(), p.clone()).with_limits(
            ServerLimits {
                min_block_size: 256,
                ..ServerLimits::default()
            },
        ),
    );

    let err = client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(random_bytes(1024))),
        "too-small-block",
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::Protocol(_)), "got {err:?}");
}

/// P1-3: pulling a nonexistent object yields the typed `NotFound`.
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

#[test]
fn persistent_session_multiple_transfers() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let srv = start(Server::new(
        free_addr(),
        dir.path().to_string_lossy(),
        p.clone(),
    ));

    let session = ClientSession::connect(&srv.addr).unwrap();
    let data1 = random_bytes(64 << 10);
    let data2 = random_bytes(128 << 10);

    session
        .send_from(
            Arc::new(MemSource::new(data1.clone())),
            "file1",
            &p,
            None,
            None,
            never_stop(),
        )
        .unwrap();

    session
        .send_from(
            Arc::new(MemSource::new(data2.clone())),
            "file2",
            &p,
            None,
            None,
            never_stop(),
        )
        .unwrap();

    let sink1 = Arc::new(MemSink::new());
    session
        .recv_into("file1", sink1.clone(), &p, None, None, never_stop())
        .unwrap();
    assert_eq!(sink1.to_vec(), data1);

    let sink2 = Arc::new(MemSink::new());
    session
        .recv_into("file2", sink2.clone(), &p, None, None, never_stop())
        .unwrap();
    assert_eq!(sink2.to_vec(), data2);
}

#[test]
fn persistent_session_records_adaptive_rate_warm_start() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = base_params();
    p.adaptive = true;
    p.rate_bps = 500_000_000;
    p.max_bps = 1_000_000_000;
    let srv = start(Server::new(
        free_addr(),
        dir.path().to_string_lossy(),
        p.clone(),
    ));

    let session = ClientSession::connect(&srv.addr).unwrap();
    assert!(session.rate_warm_start().is_empty());

    session
        .send_from(
            Arc::new(MemSource::new(random_bytes(512 << 10))),
            "warm1",
            &p,
            None,
            None,
            never_stop(),
        )
        .unwrap();

    let warm = session.rate_warm_start();
    assert!(warm.rate_bps > 0, "warm start was not recorded: {warm:?}");
    assert!(warm.rate_bps <= p.max_bps);

    session
        .send_from(
            Arc::new(MemSource::new(random_bytes(512 << 10))),
            "warm2",
            &p,
            None,
            None,
            never_stop(),
        )
        .unwrap();
    assert!(session.rate_warm_start().rate_bps > 0);
}

#[test]
fn trait_based_server_streaming() {
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    let p = base_params();
    let store: Arc<StdMutex<HashMap<String, Arc<MemSink>>>> =
        Arc::new(StdMutex::new(HashMap::new()));
    let store_clone = store.clone();

    let sink_resolver = Arc::new(move |name: &str| -> std::io::Result<Arc<dyn BlockSink>> {
        let sink = Arc::new(MemSink::new());
        store_clone
            .lock()
            .unwrap()
            .insert(name.to_string(), sink.clone());
        Ok(sink)
    });

    let store_read = store.clone();
    let source_resolver = Arc::new(
        move |name: &str| -> std::io::Result<Arc<dyn girth::BlockSource>> {
            let lock = store_read.lock().unwrap();
            if let Some(sink) = lock.get(name) {
                let data = sink.to_vec();
                Ok(Arc::new(MemSource::new(data)))
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "not found in memory store",
                ))
            }
        },
    );

    let srv = start(
        Server::new(free_addr(), "/nonexistent_dummy_dir", p.clone())
            .with_sink_resolver(sink_resolver)
            .with_source_resolver(source_resolver),
    );

    let data = random_bytes(100 << 10);
    client_send_from(
        &srv.addr,
        Arc::new(MemSource::new(data.clone())),
        "ram_object",
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap();

    let recvd = Arc::new(MemSink::new());
    client_recv_into(
        &srv.addr,
        "ram_object",
        recvd.clone(),
        &p,
        None,
        None,
        never_stop(),
    )
    .unwrap();

    assert_eq!(recvd.to_vec(), data);
}

#[test]
fn transfer_handle_reports_lifecycle_and_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let srv = start(Server::new(
        free_addr(),
        dir.path().to_string_lossy(),
        p.clone(),
    ));
    let data = random_bytes(2 << 20);

    let send_handle = TransferHandle::new();
    send_handle.set_rate_limit(Some(200_000_000));
    assert_eq!(send_handle.rate_limit_bps(), Some(200_000_000));
    client_send_from_with_handle(
        &srv.addr,
        Arc::new(MemSource::new(data.clone())),
        "handled",
        &p,
        send_handle.clone(),
        None,
        never_stop(),
    )
    .expect("handled send");
    assert_eq!(send_handle.phase(), TransferPhase::Complete);
    assert_eq!(send_handle.last_error(), None);
    let send_snap = send_handle.snapshot();
    assert_eq!(send_snap.total_bytes, data.len() as u64);
    assert_eq!(send_snap.block_size, p.block_size as u64);
    assert!(send_snap.bytes_sent > 0);
    assert!(send_snap.percent_complete >= 99.0);

    let sink = Arc::new(MemSink::new());
    let recv_handle = TransferHandle::new();
    recv_handle.pause();
    assert!(recv_handle.is_paused());
    recv_handle.resume();
    client_recv_into_with_handle(
        &srv.addr,
        "handled",
        sink.clone(),
        &p,
        recv_handle.clone(),
        None,
        never_stop(),
    )
    .expect("handled recv");
    assert_eq!(recv_handle.phase(), TransferPhase::Complete);
    assert_eq!(recv_handle.last_error(), None);
    assert_eq!(sink.to_vec(), data);
    let recv_snap = recv_handle.snapshot();
    assert_eq!(recv_snap.payload_recv, data.len() as u64);
    assert_eq!(recv_snap.progress_bytes, data.len() as u64);
    assert!(recv_snap.percent_complete >= 99.0);
}

#[test]
fn transfer_handle_records_auth_failure() {
    let dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let token: &[u8] = b"secret";
    let srv = start(
        Server::new(free_addr(), dir.path().to_string_lossy(), p.clone())
            .with_authorizer(psk_authorizer(token)),
    );

    let handle = TransferHandle::new();
    let err = client_send_from_with_handle(
        &srv.addr,
        Arc::new(MemSource::new(random_bytes(1024))),
        "denied",
        &p,
        handle.clone(),
        Some(b"wrong"),
        never_stop(),
    )
    .unwrap_err();
    assert!(matches!(err, GirthError::AuthDenied), "got {err:?}");
    assert_eq!(handle.phase(), TransferPhase::Failed);
    assert!(handle
        .last_error()
        .is_some_and(|e| e.contains("authentication denied")));
}
