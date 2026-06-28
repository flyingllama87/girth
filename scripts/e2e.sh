#!/usr/bin/env bash
#
# girth local end-to-end test + performance sweep.
#
#   ./scripts/e2e.sh [workdir]
#
# Builds girth, runs a functional correctness matrix (edge cases + both
# directions, integrity-verified), then a throughput sweep across target rates.
# Pure loopback, no root required — though raising socket buffers (see TUNING
# below) dramatically reduces loss at multi-hundred-Mbps rates.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-/tmp/girth-e2e}"
PORT=7440
BIN="$WORK/girth"

mkdir -p "$WORK/srv" "$WORK/cli" "$WORK/pulled"
echo "==> building girth"
go -C "$ROOT" build -o "$BIN" ./cmd/girth

echo "==> socket buffer limits (raise for high-rate tests):"
sysctl net.core.rmem_max net.core.wmem_max 2>/dev/null || true
echo "    TUNING (needs root): sudo sysctl -w net.core.rmem_max=67108864 net.core.wmem_max=67108864"

cleanup() { kill -9 "${SRV:-0}" 2>/dev/null || true; }
trap cleanup EXIT

"$BIN" server -addr "127.0.0.1:$PORT" -dir "$WORK/srv" -report 0 >"$WORK/srv.log" 2>&1 &
SRV=$!
sleep 0.5

echo
echo "=== functional correctness (push + pull, integrity-verified) ==="
mkfile() { head -c "$2" /dev/urandom > "$1"; }
: > "$WORK/cli/empty.bin"
printf 'x' > "$WORK/cli/one.bin"
mkfile "$WORK/cli/odd.bin" 1234567
mkfile "$WORK/cli/m10.bin" 10000000

fail=0
for f in empty.bin one.bin odd.bin m10.bin; do
  rm -f "$WORK/srv/$f" "$WORK/pulled/$f"
  "$BIN" send -rate 300 -report 0 "$WORK/cli/$f" "127.0.0.1:$PORT" >/dev/null 2>&1
  cmp -s "$WORK/cli/$f" "$WORK/srv/$f" && echo "  PUSH $f  OK" || { echo "  PUSH $f  FAIL"; fail=1; }
  "$BIN" recv -rate 300 -report 0 "127.0.0.1:$PORT" "$f" "$WORK/pulled/$f" >/dev/null 2>&1
  cmp -s "$WORK/cli/$f" "$WORK/pulled/$f" && echo "  PULL $f  OK" || { echo "  PULL $f  FAIL"; fail=1; }
done

echo
echo "=== throughput sweep (50 MiB, fixed rate) ==="
mkfile "$WORK/cli/sweep.bin" 52428800
for rate in 100 300 600 1000 2000; do
  rm -f "$WORK/srv/sweep.bin"
  "$BIN" send -rate $rate -report 0 "$WORK/cli/sweep.bin" "127.0.0.1:$PORT" >"$WORK/send.log" 2>&1
  sleep 0.5
  echo "  --- target ${rate} Mbps ---"
  echo "    send: $(grep 'send complete' "$WORK/send.log" | sed 's/girth send complete: //')"
  echo "    recv: $(grep 'recv complete' "$WORK/srv.log" | tail -1 | sed 's/girth recv complete: //')"
done

echo
[ $fail -eq 0 ] && echo "RESULT: ALL FUNCTIONAL TESTS PASSED" || { echo "RESULT: FAILURES"; exit 1; }
