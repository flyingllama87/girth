# GIRTH

girth is a Rust library and CLI for fast bulk file transfer over Long Fat Networks: high bandwidth, high round-trip time links where normal single-stream TCP leaves most of the pipe empty.

It is inspired by Aspera FASP's core transport idea: use a reliable control channel for setup, move bulk data over paced UDP, and let the receiver drive loss recovery with NACKs. Reliability is separate from rate control, so a lost packet does not collapse the sender's congestion window the way it can with a single TCP flow. The packet pacer is delay based instead of the more common loss based pacers, allowing one to fill a LFN and recover from transient network speed drops.

The project *was* AI-assisted (Opus 4.8 High reasoning). However, the project was tested and compared repeatedly to other solutions to ensure real performance over LFNs on both Linux and Windows.

## Status

- Library crate: `girth`
- CLI binary: `girth`
- Runtime model: blocking OS threads, no async runtime
- Designed to spread load over multiple cores
- Control plane: length-prefixed JSON over TCP
- Data plane: UDP DATA/FEEDBACK/START/FIN PDUs
- Optional data encryption: X25519 + HKDF + AES-256-GCM or ChaCha20-Poly1305
- File-backed CLI plus in-memory `BlockSource` / `BlockSink` APIs
- Linux has recvmmsg/sendmmsg batching backend 
- Windows has a RIO receive/send backend
- Original Go implementation is available on the `go` branch

## Simple Example

Build the CLI:

```sh
cargo build --release
```

On the machine that will receive or serve files:

```sh
target/release/girth server -addr :7400 -dir /data
```

Push a file to it:

```sh
target/release/girth send -rate 800 ./bigfile.bin server.example:7400
```

Pull a file from it:

```sh
target/release/girth recv -rate 800 server.example:7400 bigfile.bin ./bigfile.bin
```

Add `-encrypt` on client commands if you want encrypted DATA payloads.

## Network Requirements

girth uses two network paths:

| Channel | Protocol | Direction | Purpose |
|---|---|---|---|
| Control | TCP | client to server | handshake, file metadata, negotiated UDP port, optional key exchange |
| Data | UDP | bidirectional | file DATA, receiver START, FEEDBACK/NACKs, FIN |

The server always needs an inbound TCP control port. The default CLI port is `7400`, set with `girth server -addr :7400`.

For each transfer, the receiver binds a UDP data socket and advertises that port over the TCP control channel. With the CLI/server defaults this is an ephemeral UDP port. That is fine on open hosts, but firewalls need to allow the UDP data port as well as the TCP control port.

For library servers, use `Server::with_udp_port_range(start..=end)` to constrain the UDP data ports to a firewall-friendly range. Open inbound TCP on the control port and inbound UDP on that range.

Pull mode is NAT-friendly for a receiver behind NAT/CGNAT: the receiver dials the server's TCP control port and sends the first UDP START packet out to the server, creating the NAT mapping before data starts flowing.

## Build And Test

```sh
cargo build --release
cargo test
cargo clippy --all-targets
cargo fmt --check
```

## CLI

Common flags:

| Flag | Meaning |
|---|---|
| `-rate <Mbps>` | fixed target send rate |
| `-max <Mbps>` | adaptive-mode ceiling |
| `-adaptive` | enable delay-based adaptive rate control |
| `-encrypt` | encrypt DATA payloads |
| `-block <bytes>` | UDP payload size, default 1400 |
| `-workers <n>` | receiver ingest workers, 0 means auto |
| `-fb <us>` | feedback/NACK interval |
| `-report <ms>` | stats report interval |

For LFN transfers, fixed `-rate` is usually the right first choice. Adaptive mode exists, but long, bursty public-internet paths can make any delay controller oscillate.

## Library Use

File-backed transfer:

```rust
use girth::{client_recv, client_send, default_params};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

let stop = Arc::new(AtomicBool::new(false));

let mut params = default_params();
params.rate_bps = 800_000_000;
params.encrypt = true;

client_send("server.example:7400", "bigfile.bin", &params, stop.clone())?;
client_recv("server.example:7400", "bigfile.bin", "./out.bin", &params, stop)?;

# Ok::<(), girth::GirthError>(())
```

In-memory transfer APIs are also available for applications that already have bytes in memory and do not want to stage through temporary files:

```rust
use girth::{client_send_from, default_params, MemSource, Stats};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

let source = Arc::new(MemSource::new(b"payload".to_vec()));
let stats = Some(Stats::new());
let stop = Arc::new(AtomicBool::new(false));
let params = default_params();

client_send_from(
    "server.example:7400",
    source,
    "object.bin",
    &params,
    stats,
    None,
    stop,
)?;

# Ok::<(), girth::GirthError>(())
```

As a Git dependency:

```toml
[dependencies]
girth = { git = "https://github.com/flyingllama87/girth" }
```

## Benchmarks

The main benchmark path was Sydney to London over public cloud (Digital Ocean) VMs using the public paths (i.e. internet), about 264 ms RTT, using a 2 GB file with end-to-end integrity checks. Socket buffers were raised to 128 MiB on the hosts for the high-BDP tests. iPerf put the link at 1.7 Gbps.

| Tool / mode | Goodput | Notes |
|---|---:|---|
| girth, Rust main | 1816 Mbps | fastest run in the benchmark set |
| FASP fixed-rate | 1726 Mbps | very fast, sender near one core |
| multi-tcp BBR x16 | 1451 Mbps | parallel TCP |
| lfn-send | ~1200 Mbps | older loss-based UDP/TCP tool |
| QUIC/BBR | 1052 Mbps | CPU-bound in userspace |
| UDT tuned | ~1010 Mbps | one core at peaks |
| bbcp x8 | ~784 Mbps | parallel TCP |
| GridFTP | ~758 Mbps | server one-core bound |
| HPN-SSH | 707 Mbps | single TCP stream with tuned buffers |

Windows RIO testing on a Sydney to Windows path, about 259 ms RTT, moved a 1 GiB file at 1753.5 Mbps cleartext with 0 loss.

All quoted file-transfer results were verified with whole-file integrity checks.

## OS Tuning (Linux)

High-rate UDP needs real socket buffers. One BDP at 1.5 Gbps and 264 ms RTT is about 50 MB.

```sh
sudo sysctl -w net.core.rmem_max=268435456 net.core.wmem_max=268435456
```

girth requests large socket buffers, but linux caps those requests. If the caps are tiny, the transfer still works, but the kernel will drop bursts that girth then has to retransmit.

## OS Tuning (Windows)

No tuning is needed on Windows.

## Current Gaps / TODO

- Add CI for Linux Rust tests, clippy, and format checks.
- Add release artifacts.
- Add multi-file transfer or directory packing.
- Publish a crate once the public API is stable enough to support semver.
- UDP holepunching allowing p2p xfer with central broker.

## License

MIT.
