//! End-to-end push/pull tests over loopback (ported from `e2e_test.go`).

use girth::{client_recv, client_send, default_params, Server, TransferParams};
use rand_core::{OsRng, RngCore};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
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

fn start_test_server(dir: &Path, p: TransferParams) -> TestServer {
    // Pick a free port, then reuse it (matches the Go test).
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    drop(ln);

    let stop = Arc::new(AtomicBool::new(false));
    let srv = Server {
        addr: addr.clone(),
        dir: dir.to_string_lossy().into_owned(),
        params: p,
    };
    let st = stop.clone();
    let handle = std::thread::spawn(move || {
        let _ = srv.listen_and_serve(st);
    });

    // Wait for the listener to come up.
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

fn make_random_file(path: &Path, size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    OsRng.fill_bytes(&mut data);
    fs::write(path, &data).unwrap();
    data
}

fn never_stop() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

fn base_params() -> TransferParams {
    let mut p = default_params();
    p.rate_bps = 400_000_000;
    p.report_interval = Duration::from_secs(3600); // silence reporter in tests
    p
}

#[test]
fn end_to_end_push_pull() {
    let sizes = [0usize, 1, 1500, 1 << 20, 5 << 20];
    let srv_dir = tempfile::tempdir().unwrap();
    let cli_dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let server = start_test_server(srv_dir.path(), p.clone());

    for size in sizes {
        let name = format!("f{size}.bin");
        let src = cli_dir.path().join(&name);
        let want = make_random_file(&src, size);

        // PUSH: client -> server.
        client_send(&server.addr, src.to_str().unwrap(), &p, never_stop())
            .unwrap_or_else(|e| panic!("push size={size}: {e}"));
        let got = fs::read(srv_dir.path().join(&name)).unwrap();
        assert_eq!(got, want, "push size={size} content mismatch");

        // PULL: server -> client.
        let out = cli_dir.path().join(format!("pulled_{name}"));
        client_recv(&server.addr, &name, out.to_str().unwrap(), &p, never_stop())
            .unwrap_or_else(|e| panic!("pull size={size}: {e}"));
        let got2 = fs::read(&out).unwrap();
        assert_eq!(got2, want, "pull size={size} content mismatch");
    }
}

#[test]
fn end_to_end_encrypted() {
    let sizes = [0usize, 1, 1500, 1 << 20, 5 << 20];
    let srv_dir = tempfile::tempdir().unwrap();
    let cli_dir = tempfile::tempdir().unwrap();
    let mut p = base_params();
    p.encrypt = true;
    let server = start_test_server(srv_dir.path(), p.clone());

    for size in sizes {
        let name = format!("enc{size}.bin");
        let src = cli_dir.path().join(&name);
        let want = make_random_file(&src, size);

        client_send(&server.addr, src.to_str().unwrap(), &p, never_stop())
            .unwrap_or_else(|e| panic!("encrypted push size={size}: {e}"));
        let got = fs::read(srv_dir.path().join(&name)).unwrap();
        assert_eq!(got, want, "encrypted push size={size} mismatch");

        let out = cli_dir.path().join(format!("pulled_{name}"));
        client_recv(&server.addr, &name, out.to_str().unwrap(), &p, never_stop())
            .unwrap_or_else(|e| panic!("encrypted pull size={size}: {e}"));
        let got2 = fs::read(&out).unwrap();
        assert_eq!(got2, want, "encrypted pull size={size} mismatch");
    }
}

#[test]
fn end_to_end_plaintext_still_works() {
    let srv_dir = tempfile::tempdir().unwrap();
    let cli_dir = tempfile::tempdir().unwrap();
    let p = base_params();
    let server = start_test_server(srv_dir.path(), p.clone());

    let src = cli_dir.path().join("plain.bin");
    let want = make_random_file(&src, 2 << 20);
    client_send(&server.addr, src.to_str().unwrap(), &p, never_stop()).unwrap();
    let got = fs::read(srv_dir.path().join("plain.bin")).unwrap();
    assert_eq!(got, want);
}

#[test]
fn end_to_end_adaptive() {
    let srv_dir = tempfile::tempdir().unwrap();
    let cli_dir = tempfile::tempdir().unwrap();
    let mut p = base_params();
    p.adaptive = true;
    p.rate_bps = 20_000_000;
    p.max_bps = 800_000_000;
    p.alpha_bps = 50_000_000;
    let server = start_test_server(srv_dir.path(), p.clone());

    let src = cli_dir.path().join("adaptive.bin");
    let want = make_random_file(&src, 8 << 20);
    client_send(&server.addr, src.to_str().unwrap(), &p, never_stop()).unwrap();
    let got = fs::read(srv_dir.path().join("adaptive.bin")).unwrap();
    assert_eq!(got, want);
}
