# MTU, fragmentation, and block size

How the data-block size interacts with the path MTU, what it costs you to get it
wrong, and how to measure the path MTU and detect fragmentation. All numbers below
are measured on the Sydney↔London VPS pair (RTT ~264 ms, 1500 B path MTU).

## TL;DR

- girth sends one UDP datagram per data block: **`36 B header + block payload`**
  on top of UDP(8)+IP(20). Default `-block 1400` ⇒ a **1464 B IP packet**, safely
  under a 1500 MTU.
- **Keep the whole IP packet ≤ the path MTU.** If you exceed it, the datagram
  fragments (or is dropped), and because **losing one IP fragment loses the whole
  block**, retransmits explode.
- girth does **not** set the DF bit or do path-MTU discovery. It relies on you
  keeping the block under the MTU. The safe default is 1400; the max that exactly
  fills a 1500 MTU is **`-block 1436`** (plain) / ~**1420** (with `-encrypt`).
- Filling the MTU (1436 vs 1400) uses **~2.6 % fewer packets** for the same bytes —
  a small goodput/CPU win that only matters when you are packets-per-second bound.

## Packet math

```
IP packet size = 20 (IPv4) + 8 (UDP) + 36 (girth DATA header) + block_payload
               = 64 + block_payload
```

| `-block` | IP packet | vs 1500 MTU | Notes |
|---:|---:|---|---|
| 1400 (default) | 1464 B | fits | conservative; ~36 B of MTU left unused |
| **1436** | **1500 B** | **exactly fits** | max payload, no fragmentation |
| 1437+ | 1501+ B | **over** | fragments or is dropped |
| 4000 | 4064 B | 2.7× over | fragments into 3 IP fragments per block |

With `-encrypt`, each packet also carries an AEAD tag (X25519 + AES-GCM /
ChaCha20-Poly1305), so subtract ~16 B: use **`-block 1420`** to stay at 1500.

> Other movers differ in header size: libfasp uses a 16 B header, so its
> MTU-filling block is ~1456. Always recompute `MTU − IP − UDP − protocol_header`.

## Why getting it wrong hurts (measured)

Three 2 GB transfers at a fixed `-rate 1500`, with IP fragmentation counters
sampled before/after on each end:

| Config | IP packet | Packets for 2 GB | Retransmits | Sender `IpFragCreates` Δ | Recv `IpReasmReqds` Δ |
|---|---:|---:|---:|---:|---:|
| `-block 1400` (default) | 1464 B | 1,535,613 | 0.11 % | 0 | 0 |
| `-block 1436` (fills MTU) | 1500 B | 1,495,480 | **0.00 %** | 0 | 0 |
| `-block 4000` (oversized) | 4064 B | 659,403 | **18.58 %** | **1,976,018** | 1,614,562 |

Takeaways:

- **1400 and 1436 do not fragment** (`Δ = 0` on both ends). 1436 fills the MTU and
  used 2.6 % fewer packets with the *lowest* retransmit count.
- **1436 → 1437 is a cliff, not a slope.** One byte over the path MTU and every
  packet fragments.
- **Oversizing is catastrophic.** At `-block 4000` each block becomes 3 IP
  fragments; lose any one and the whole block is lost, so retransmits jumped to
  **18.58 %** and the fragmentation counters lit up with ~2 M events. Throughput
  only survived here because the path was clean and the rate was capped; on a
  lossier path this is a collapse.
- Because girth doesn't set DF, an oversized datagram **fragments silently** rather
  than failing fast. If a *tunnel* on the path has a smaller MTU and also drops/DF
  the fragments, you instead get a **PMTU black hole**: packets vanish and
  throughput stalls with no obvious error.

## Is there free performance in tuning the MTU?

A little, and only sometimes:

- **Per-packet overhead at 1400 is ~3.8 %** (64 B IP/UDP/girth framing + 14 B
  Ethernet per ~1478 B frame). Moving to 1436 reclaims ~2–3 %.
- That gain is **real only when the bottleneck is packets-per-second** (CPU,
  syscalls, interrupts, NIC pps). When the path is bandwidth/weather-bound (as our
  ~1.6–1.8 Gbit LFN was), the wire rate is unchanged and you only see the lower
  packet count.
- The big win — **jumbo frames (9000)** — is unavailable across the public internet
  / cross-region. It typically exists only inside a single datacenter/VPC. On our
  Sydney↔London path the measured PMTU is 1500 (see below), so 9000 is off the
  table.

So: hardcoding 1400 leaves ~2–3 % on the table versus probing the path and filling
it, but it buys robustness against fragmentation and PMTU black holes. The
principled fix is to probe once and set `block = pmtu − headers` (and set DF), which
girth does not yet do.

## How to measure the path MTU

### 1. DF ping sweep (no tooling beyond `ping`)
`ping -M do` sets the Don't-Fragment bit; `-s N` sets the **ICMP payload**, so the
IP packet is `N + 28`. Find the largest `N` that succeeds:

```sh
for s in 1372 1422 1448 1472 1473 1500; do
  ping -M do -s $s -c1 -W2 <peer-ip> >/dev/null 2>&1 \
    && echo "payload $s (IP $((s+28))) OK" \
    || echo "payload $s (IP $((s+28))) FAIL"
done
# OK at 1472 (IP 1500), FAIL at 1473 (IP 1501)  =>  path MTU = 1500
```

### 2. `tracepath` (reports PMTU directly, finds the limiting hop)
```sh
tracepath -n <peer-ip>
# ... Resume: pmtu 1500 hops 9 back 9
```

### 3. Interface / route MTU
```sh
ip link show            # device MTU (the local link ceiling)
ip route get <peer-ip>  # 'mtu N' if the route pins one; else uses device MTU
```

Then set girth: `block = pmtu − 20 − 8 − 36` (plain) or `− 16` more (encrypted).
For a 1500 PMTU that is **`-block 1436`** (plain) / **`-block 1420`** (encrypted).

## How to detect fragmentation (on a live transfer)

The kernel keeps cumulative IP fragmentation counters. **Snapshot them before and
after a transfer and diff** — the absolute values are useless because they
accumulate since boot (and are easily dominated by other tools; tsunami-udp's 32 KB
default blocks, for example, generate millions of fragments).

Counters that matter:

| Counter | Where | Meaning |
|---|---|---|
| `IpFragCreates` | sender | datagrams the sender split into fragments |
| `IpReasmReqds` | receiver | fragments the receiver had to reassemble |
| `IpReasmFails` | receiver | reassembly timeouts/failures (lost a fragment) |
| `UdpRcvbufErrors` / `UdpInErrors` | receiver | socket-buffer overflow / UDP drops |

Delta method:

```sh
getc(){ ssh "$1" "nstat -az 2>/dev/null | awk '/$2/{print \$2}'"; }

s0=$(getc SENDER IpFragCreates);  r0=$(getc RECEIVER IpReasmReqds)
#  ... run the transfer ...
s1=$(getc SENDER IpFragCreates);  r1=$(getc RECEIVER IpReasmReqds)
echo "sender FragCreates Δ=$((s1-s0))   receiver ReasmReqds Δ=$((r1-r0))"
#  Δ = 0   -> no fragmentation (good)
#  Δ > 0   -> blocks are fragmenting; reduce -block below the PMTU
```

`nstat` (without `-a`) also resets its own baseline per invocation, so
`nstat -z` before and `nstat` after a run shows just the delta. The raw counters
also live in `/proc/net/snmp` (the `Ip:` line) if `nstat` isn't installed.

A second, direct check is to watch the wire with `tcpdump` and confirm packet sizes
and the DF flag:
```sh
tcpdump -ni any udp and host <peer> -c 5 -v   # look at 'length' and 'flags [DF]'
```

## Recommendation

- Leave `-block 1400` as the safe default for unknown paths.
- On a known clean path with a verified 1500 PMTU, use **`-block 1436`** (plain) /
  **`-block 1420`** (encrypted) for ~2.6 % fewer packets.
- Never set `-block` above `PMTU − headers`; one byte over fragments every packet.
- Future work: have girth probe the PMTU at handshake (DF-ping or
  `IP_MTU_DISCOVER`/`IP_MTU`) and auto-pick the block size, and set DF so an
  undersized tunnel surfaces as a fast error instead of a silent loss storm.
