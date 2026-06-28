# Lessons from building girth

Hard-won notes from writing a high-rate reliable-UDP file-transfer tool for long
fat networks (LFNs). Most of these cost real time to learn. They are ordered
roughly by how much grief they caused, not by how clever they sound.

## 0. The meta-lesson: measure the *system*, not just your code

The single biggest time sink on this project was a "loss storm" I spent four
disk-path rewrites chasing. The real cause was **leftover memory pressure on the
test box** (700 MB stranded in `/dev/shm` plus page cache on a 2 GB VM) starving
the writer. The same code ran clean once RAM was freed.

The disk fixes were still worthwhile, but the *collapse* was a test-environment
artifact. Lessons:

- **Before blaming your code, snapshot the environment**: `free -m`, `df`,
  `/proc/pressure/{cpu,io,memory}`, `nstat`, qdisc, socket buffer limits. Do this
  *first*, every run, not after a day of edits.
- **A shared cloud path is not a fixed baseline.** Ours swung 0.65–1.5 Gbps
  minute to minute. If you change code and the number moves, you may be measuring
  the weather. Re-baseline the path (iperf3) immediately before and after.
- **Change one variable at a time** and keep a log of (commit, env state,
  result). I conflated path changes with code changes more than once.

## 1. Reliable UDP at line rate is a disk problem as much as a network problem

The thing that actually limited goodput was not the network — it was **write
ordering on the receiver.**

- Retransmitted packets arrive ~1 RTT late, so if you write blocks in *arrival*
  order you issue a backward seek of ~1 BDP for every retransmit. That converts
  sequential writes into random I/O. On our cloud disk: ~858 MB/s sequential vs
  ~57 MB/s random. The writer falls behind, iowait climbs, the ingest goroutine
  stalls, the kernel UDP receive buffer overflows, and you get a *loss storm that
  looks like a network problem but is self-inflicted.*
- Fix: an **in-order flusher**. A single goroutine writes strictly at the
  advancing byte frontier; out-of-order blocks stage in a bounded RAM pool until
  the gap fills. Now the disk only ever sees sequential writes.
- **`fallocate` the destination up front.** Sparse allocate-on-write causes
  metadata stalls mid-transfer at exactly the wrong moment.
- Stream dirty pages out with `sync_file_range(SYNC_FILE_RANGE_WRITE)` so
  writeback is smooth instead of a cliff at `close()`. **Do not** use
  `fadvise(DONTNEED)` aggressively — it caused read-modify-write stalls for us.
- Decouple "received" from "durable." Receipt logic works on a bitmap in memory;
  durability is a separate, sequential, lagging process.

## 2. Batching syscalls is essential — but a batch is a burst

`recvmmsg`/`sendmmsg` cut per-packet syscall overhead ~60× and were the main CPU
win. But:

- **A full-size send batch handed to the NIC is a line-rate microburst** that
  overruns switch buffers and the receiver's socket buffer. Cap the batch
  (`maxBatch=64` for us) and keep honoring your pacing deadline *between*
  batches. Batching is an efficiency tool, not a license to dump.
- Always keep a per-packet fallback path (we gate it with `GIRTH_NOBATCH=1`).
  Batched socket APIs have platform quirks; you want an escape hatch for
  debugging and for portability.

## 3. Pacing must use absolute deadlines, not sleep(interval)

The first pacer did `send; sleep(packet_interval)`. Every scheduling jitter and
syscall cost is *added* to the interval, so you systematically under-send — or,
if you "catch up," you over-send in bursts. Track an **absolute next-send
deadline** and advance it by the interval regardless of when you actually woke.
Sleep until the deadline; spin the last sliver for precision
(we spin `min(150µs, 5% of interval)`).

## 4. Make the receiver the brain

Put RTT estimation, RTO, loss detection, and rate feedback **on the receiver**.
The sender just paces, retransmits-first, and echoes timestamps. Reasons:

- The receiver is the only party that *knows* what arrived. Loss/duplication
  decisions belong where the ground truth is.
- It keeps the sender's hot path trivial and branch-light (it does almost nothing
  but fill packets and write to the socket).
- One feedback goroutine scanning a bitmap on an RTO cadence is far cheaper and
  saner than per-packet ack bookkeeping.

## 5. Keep the per-packet path commutative and lock-light

Anything you do per packet at 750k packets/s must be cheap and order-independent:
set a bit in a bitmap, copy payload to a staging buffer, advance a counter. Push
everything that requires a global view (loss scanning, rate decisions) onto a
*separate, infrequent* goroutine. Per-packet locks or per-packet allocation will
quietly become your bottleneck on a single core long before the network does.

## 6. Don't fight the kernel's defaults without proof

- **Kernel pacing** (`SO_MAX_PACING_RATE` + `fq` qdisc) sounded ideal and was a
  net *loss*: it capped throughput (733→673 Mbps) for no loss benefit, and the
  `fq` queue inflated RTT enough to trigger false-loss in our delay logic. We made
  it opt-in and off by default. Default `fq_codel` beat it.
- Raise `rmem_max`/`wmem_max` and *actually request* large `SO_RCVBUF`/`SO_SNDBUF`
  (64 MiB here) — this genuinely matters on LFNs because one BDP at 1.5 Gbps ×
  264 ms ≈ 50 MB in flight. But beyond "big enough to hold a BDP plus slack,"
  more buffer just adds latency.
- Every kernel knob is a hypothesis. A/B test it on the real path or leave it
  alone.

## 7. Instrument everything, in the units that matter

We could only diagnose the storm because we had: retrans %, dup %, corrupt count,
nacks in/out, *and* `nstat` `UdpRcvbufErrors`/`UdpInErrors`. The killer insight
was that **rcvbuf drops ≈ nacks during a storm** — proof the loss was the
receiver's own socket overflowing, not the network.

- Distinguish **wire rate** (bytes on the network, includes retransmits) from
  **goodput** (useful bytes delivered). Reporting only one hides duplication
  overhead or hides loss.
- Correlate app metrics with OS counters (`pidstat`, `mpstat`, `nstat`,
  `/proc/pressure`). The bug is often in the gap between them.

## 8. Verify correctness independently of your own counters

"0% retrans" means nothing if a byte landed in the wrong place. We hashed both
ends (SHA-256) and CRC32C'd every block (hardware Castagnoli). A reliable
transfer tool whose only proof of correctness is its own bookkeeping is just a
fast way to corrupt files confidently.

## 9. Single-core ceilings sneak up on you

Go makes concurrency easy and a single goroutine bottleneck easy to miss. One
pacing goroutine caps single-flow throughput regardless of core count; we hit
~1.9 Gbps on loopback purely from that. Know which goroutine is your serial
chokepoint *before* you need more, and design the wire format (block + offset,
reassembly bitmap) so you can add parallel sub-flows later without redesigning.

## 10. Operational footguns are real lessons too

- **Backgrounding a server over SSH (`&`) hangs interactive tooling.** Use
  `systemd-run --unit=... --collect` and start/check in separate calls.
- **`pkill -f "yourbinary"` can match your own SSH shell and kill your session.**
  Use named units (`systemctl stop`) or exact matches (`pkill -x`).
- An open file handle blocks redeploy (`scp` "dest open" failure) — stop the
  service before copying the binary.

These aren't about protocols, but a tool you can't operate safely is a tool you
can't test, and untested is unshipped.

---

### The short version

Reliable high-rate UDP is mostly **flow-of-bytes engineering at three queues you
don't control**: the NIC/qdisc, the kernel socket buffer, and the disk
writeback. Loss is usually one of *your* queues overflowing, not the network.
Pace with absolute deadlines, batch syscalls but cap the burst, write to disk
strictly in order, put the intelligence on the receiver, keep the hot path
dumb, prove correctness out-of-band, and **check the environment before you
blame the code.**
