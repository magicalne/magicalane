#!/usr/bin/env bash
# suites: regression
# transports: any
# regression: server-side UDP-flow teardown + memory retention under
#   churn (issue #29). Two pins, both failing pre-fix:
#   1) FD pin (deterministic): every UDP-magic flow used to pin its
#      socket + 64KiB buffer for the full 60s FLOW_IDLE after the
#      client left (poll_shutdown did not abort the spawned recv) —
#      fd count climbed +1/flow (2000 flows -> ~1800 fds: the
#      production "all transports wedged, box alive" fd-exhaustion).
#      Fixed by abort-abort-on-shutdown in src/udp/mod.rs +
#      src/dns/mod.rs. Assert: fd count stays near baseline.
#   2) RSS pin: the same scenario grew the server ~58 kB/flow
#      (+116 MB / 2000 flows pre-fix). Fixed teardown + periodic
#      malloc_trim (src/mem.rs) keep growth bounded. Assert: total
#      growth over the window <= 8 MB (post-fix measured ~1.6 MB).
#
# Standalone:   env/verify.sh 031-reg-server-mem-churn
# A/B:          MGL_REG_TRIM_SECS=0 ... -> still passes (trim is a
#               mitigation); a PRE-FIX binary fails both asserts.
set -uo pipefail

TESTS_DIR="${TESTS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
source "$TESTS_DIR/helpers.sh"

# Own port base + work dir: safe alongside a running lab / long soak.
export MGL_SOAK_PORT_BASE=1000
# Trim every 2s (production default 60s; accelerated for the window).
# MGL_REG_TRIM_SECS=0 emulates a no-trim binary (mitigation off).
export MAGICALANE_MEM_TRIM_SECS="${MGL_REG_TRIM_SECS:-2}"
# Exercise the UDP magic relay (server-side UdpFramedStream churn).
export MGL_SOAK_TARGET="magicalane-udp:1"
export MGL_SOAK_MAGIC=udp

BATCHES=10
BATCH_SIZE=200
MAX_FD=20          # baseline is ~10 (listener + std fds)
MAX_GROWTH_KB=8192

"$ENV_DIR/soak.sh" --transports quic --mode stream \
    --batches "$BATCHES" --batch-size "$BATCH_SIZE" --concurrency 8 \
    --settle 3 >/dev/null 2>&1 || fail "soak harness itself failed (see env/soak-base1000/*.log)"

pairs="$ENV_DIR/soak-base1000/pairs-quic.txt"
[ -s "$pairs" ] || fail "no soak samples produced (see env/soak-base1000/*.log)"

# Freshness: samples must be from THIS run.
samples=$(grep -c '^batch=' "$pairs")
[ "$samples" -eq "$BATCHES" ] || fail "expected $BATCHES batches, got $samples (stale samples?)"
expected_ok=$((BATCHES * BATCH_SIZE))
last_ok=$(grep '^batch=' "$pairs" | tail -1 | grep -oE 'ok=[0-9]+' | cut -d= -f2)
[ "$last_ok" -ge "$expected_ok" ] || fail "only $last_ok/$expected_ok flows drove — harness under-ran"

# Pin 1: fd count (deterministic; pre-fix: ~1800 for this volume).
last_fd=$(grep '^batch=' "$pairs" | tail -1 | grep -oE 'fd=[0-9]+' | cut -d= -f2)
if [ "$last_fd" -le "$MAX_FD" ]; then
    pass "udp-flow fds released at teardown (fd=$last_fd <= $MAX_FD)"
else
    fail "server fd count $last_fd > $MAX_FD after $expected_ok udp flows — teardown retention regression (issue #29)"
fi

# Pin 2: bounded RSS growth (pre-fix: ~116 MB over this window).
rss_warm=$(grep -oE 'rss_kb=[0-9]+' "$pairs" | sed -n '3p' | cut -d= -f2)
rss_last=$(grep -oE 'rss_kb=[0-9]+' "$pairs" | tail -1 | cut -d= -f2)
[ -n "$rss_warm" ] && [ -n "$rss_last" ] || fail "could not parse RSS series"
growth=$((rss_last - rss_warm))
if [ "$growth" -le "$MAX_GROWTH_KB" ]; then
    pass "server RSS bounded under churn (growth ${growth}kB <= ${MAX_GROWTH_KB}kB)"
else
    fail "server RSS grew ${growth}kB > ${MAX_GROWTH_KB}kB under churn — memory retention regression (issue #29)"
fi
