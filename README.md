# girth

girth is a Rust library and CLI for fast bulk file transfer over Long Fat
Networks: high bandwidth, high round-trip time links where normal single-stream
TCP leaves most of the pipe empty.

It uses a TCP control channel for setup and a paced UDP data plane for file data.
Reliability is receiver-driven with NACKs, so loss recovery is separate from rate
control. The current Rust implementation is the primary public implementation.
The original Go implementation is kept on the `go` branch.

The project was AI-assisted with Opus 4.8 High reasoning. The code was not judged
by vibes: it was validated with loopback tests, Rust/Go wire-compatibility tests,
and real performance runs over LFNs.

## Status

- Library crate: `girth`
- CLI binary: `girth`
- Runtime model: blocking OS threads, no async runtime
- Data plane: UDP DATA/FEEDBACK/START/FIN PDUs
- Control plane: length-prefixed JSON over TCP
- Optional data encryption: X25519 + HKDF + AES-256-GCM or ChaCha20-Poly1305
- Tested on Linux; Windows has a RIO receive/send backend on the Rust branch
- Go wire-compatible implementation available on the `go` branch

## Why

On a long path, throughput is bounded by bytes in flight divided by RTT. A
single TCP flow with default socket buffers can get stuck far below the link
capacity, and loss can collapse its congestion window.

girth takes the FASP-style approach:

- Send file data over UDP at a paced target rate.
- Let the receiver track missing blocks and request retransmission.
- Keep rate control separate from reliability.
- Write received blocks to disk in order, so retransmits do not turn the disk
  path into random I/O.

This is meant for big files across long links, not tiny RPCs or directory sync.

## Build

```sh
cargo build --release
cargo test
cargo clippy --all-targets
cargo fmt --check
```

The CLI ends up at `target/release/girth`.

## CLI

Run a server:

```sh
girth server -addr :7400 -dir /data
```

Push a file to the server:

```sh
girth send -rate 800 bigfile.bin server.example:7400
```

Pull a file from the server:

```sh
girth recv -rate 800 server.example:7400 bigfile.bin ./bigfile.bin
```

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

For LFN transfers, fixed `-rate` is usually the right first choice. Adaptive mode
exists, but long, bursty public-internet paths can make any delay controller
oscillate.

## Library Use

```rust
use girth::{client_recv, client_send, default_params, Server};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

let stop = Arc::new(AtomicBool::new(false));

let mut params = default_params();
params.rate_bps = 800_000_000;
params.encrypt = true;

client_send("server.example:7400", "bigfile.bin", &params, stop.clone())?;
client_recv("server.example:7400", "bigfile.bin", "./out.bin", &params, stop)?;

# Ok::<(), std::io::Error>(())
```

As a Git dependency:

```toml
[dependencies]
girth = { git = "https://github.com/flyingllama87/girth" }
```

## Benchmarks

The main benchmark path was Sydney to London over public cloud VMs, about 264 ms
RTT, using a real 2 GB file with end-to-end integrity checks. Socket buffers were
raised to 128 MiB on the hosts for the high-BDP tests.

| Tool / mode | Goodput | Notes |
|---|---:|---|
| girth, Go branch | 1816 Mbps | fastest run in the benchmark set |
| girth, Rust main | 1627 Mbps | Rust port, encrypted fixed-rate run, 0 retransmits |
| libfasp fixed-rate | 1726 Mbps | very fast, sender near one core |
| multi-tcp BBR x16 | 1451 Mbps | parallel TCP |
| lfn-send | ~1200 Mbps | older loss-based UDP/TCP tool |
| QUIC/BBR | 1052 Mbps | CPU-bound in userspace |
| UDT tuned | ~1010 Mbps | one core at peaks |
| bbcp x8 | ~784 Mbps | parallel TCP |
| GridFTP | ~758 Mbps | server one-core bound |
| fathom | 759 Mbps | one-core bound |
| HPN-SSH | 707 Mbps | single TCP stream with tuned buffers |

Rust girth also worked through a real CGNAT home path:

| Scenario | Goodput | Notes |
|---|---:|---|
| London to Brisbane home pull | 424 Mbps | receiver behind CGNAT dials out |
| Brisbane home to London push | 41.4 Mbps | saturated the tested uplink |

Windows RIO testing on a Sydney to Windows path, about 259 ms RTT, moved a 1 GiB
file at 1753.5 Mbps cleartext with 0 loss. A Rust RIO client pulling from the Go
server reached 1362.5 Mbps, confirming cross-implementation wire compatibility
on that path.

All quoted file-transfer results were verified with whole-file integrity checks.

## OS Tuning

High-rate UDP needs real socket buffers. One BDP at 1.5 Gbps and 264 ms RTT is
about 50 MB.

```sh
sudo sysctl -w net.core.rmem_max=268435456 net.core.wmem_max=268435456
```

girth requests large socket buffers, but the OS caps those requests. If the caps
are tiny, the transfer still works, but the kernel will drop bursts that girth
then has to retransmit.

## Public Branches

- `main`: Rust implementation, primary public code.
- `go`: original Go implementation.
- `lore-embedding`: Rust branch with embedding-oriented APIs for Lore, including
  in-memory sources/sinks and control-plane auth work.

## Current Gaps

- Pick and document a stable public API policy before publishing a crate.
- Add CI for Linux Rust tests, clippy, and format checks.
- Add release artifacts or install instructions if users should fetch binaries
  rather than build from source.
- Add multi-file transfer or directory packing if that becomes a goal.

## License

MIT.
