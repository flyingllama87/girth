#!/usr/bin/env bash
#
# girth LFN (long fat network) emulation harness — the bridge to live testing.
#
#   sudo ./scripts/lfn_netem.sh [rtt_ms] [rate_mbit] [loss_pct]
#
# Emulates a Brisbane<->London-style path on loopback using tc/netem:
#   - default 280 ms RTT, 1000 Mbit bottleneck, 0.1% random loss
# then runs a girth transfer over it so you can watch the RTT/RTO/rate-control
# instrumentation behave under realistic delay before deploying to real VPSes.
#
# REQUIRES ROOT (tc). It modifies the loopback qdisc and restores it on exit.
#
# NOTE: also raise socket buffers for high BDP:
#   sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728
#
#   high-BDP example: 280ms * 1Gbit = 35 MB in flight => buffers must exceed that.
set -euo pipefail

RTT_MS="${1:-280}"
RATE_MBIT="${2:-1000}"
LOSS_PCT="${3:-0.1}"
HALF=$(( RTT_MS / 2 ))

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="/tmp/girth-lfn"
PORT=7450
BIN="$WORK/girth"
DEV=lo

if [ "$(id -u)" -ne 0 ]; then echo "must run as root (tc)"; exit 1; fi

mkdir -p "$WORK/srv" "$WORK/cli"
go -C "$ROOT" build -o "$BIN" ./cmd/girth
[ -f "$WORK/cli/test.bin" ] || head -c 104857600 /dev/urandom > "$WORK/cli/test.bin"  # 100 MiB

echo "==> applying netem: ${RTT_MS}ms RTT, ${RATE_MBIT}Mbit, ${LOSS_PCT}% loss on $DEV"
tc qdisc del dev "$DEV" root 2>/dev/null || true
# delay HALF each direction (loopback traverses the qdisc both ways => full RTT)
tc qdisc add dev "$DEV" root netem delay "${HALF}ms" rate "${RATE_MBIT}mbit" loss "${LOSS_PCT}%"

restore() {
  echo "==> restoring $DEV qdisc"
  tc qdisc del dev "$DEV" root 2>/dev/null || true
  kill -9 "${SRV:-0}" 2>/dev/null || true
}
trap restore EXIT

echo "==> current buffers:"; sysctl net.core.rmem_max net.core.wmem_max 2>/dev/null || true

"$BIN" server -addr "127.0.0.1:$PORT" -dir "$WORK/srv" -report 1000 >"$WORK/srv.log" 2>&1 &
SRV=$!
sleep 0.5

echo "==> transferring 100 MiB at ${RATE_MBIT}Mbit target over the emulated LFN"
rm -f "$WORK/srv/test.bin"
"$BIN" send -rate "$RATE_MBIT" -report 1000 "$WORK/cli/test.bin" "127.0.0.1:$PORT" 2>&1 | sed 's/^/  send: /'

echo "==> receiver instrumentation:"
grep "role=recv" "$WORK/srv.log" | sed 's/^/  /'
grep complete "$WORK/srv.log" | sed 's/^/  /'
cmp -s "$WORK/cli/test.bin" "$WORK/srv/test.bin" && echo "INTEGRITY OK" || echo "INTEGRITY FAILURE"
