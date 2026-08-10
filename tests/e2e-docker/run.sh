#!/usr/bin/env bash
# Vault p2p sync — Docker full e2e orchestrator.
#
#   ./run.sh            build + run the whole scenario sequence
#   ./run.sh --no-build reuse the existing image
#
# Builds the image, brings up sso + device-a/b/c, drives the six scenarios
# across real containers via `docker compose exec`, prints a PASS/FAIL/SKIP
# table, and always tears the stack down (-v). Exits non-zero on any FAIL.
# Safe to re-run.
set -uo pipefail

cd "$(dirname "$0")"
COMPOSE="docker compose"
LISTEN_PORT=7000

# ── result table ─────────────────────────────────────────────────────────────
declare -a NAMES STATES
record() { NAMES+=("$1"); STATES+=("$2"); }
fail_count=0

pass() { echo "  ✓ $1" >&2; record "$1" PASS; }
skip() { echo "  ~ $1  (SKIP: ${2:-})" >&2; record "$1" SKIP; }
fail() { echo "  ✗ $1  ($2)" >&2; record "$1" FAIL; fail_count=$((fail_count+1)); }

# Run a scenario step in a device; echo its stdout. Non-zero exit is the
# caller's to interpret.
sx() { local dev=$1; shift; $COMPOSE exec -T "$dev" /app/e2e/scenario.sh "$@"; }
# grep the RESULT token out of a step's output.
result_of() { grep -oE 'RESULT: .*' | sed 's/^RESULT: //'; }

cleanup() {
  echo "▸ tearing down (compose down -v)" >&2
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "▸ pre-clean any prior stack" >&2
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true

if [ "${1:-}" != "--no-build" ]; then
  echo "▸ building image (first build pulls node:22 + apt installs; be patient)" >&2
  $COMPOSE build >/tmp/e2e-build.log 2>&1 || { echo "BUILD FAILED — see /tmp/e2e-build.log" >&2; tail -30 /tmp/e2e-build.log >&2; exit 1; }
fi

echo "▸ starting stack" >&2
$COMPOSE up -d >/tmp/e2e-up.log 2>&1 || { echo "UP FAILED" >&2; cat /tmp/e2e-up.log >&2; exit 1; }

# Wait for the sso healthcheck to pass (compose depends_on handles ordering, but
# device idles independently — poll the sso from device-a to be sure).
echo "▸ waiting for SSO to be healthy" >&2
for _ in $(seq 1 60); do
  if sx device-a bash -lc 'curl -fsS http://127.0.0.1:5050/.well-known/openid-configuration >/dev/null 2>&1 && echo ok' 2>/dev/null | grep -q ok; then
    break
  fi
  sleep 1
done

# ── Scenario 1: setup (all three devices) ────────────────────────────────────
echo "▸ Scenario 1: setup (bootstrap + auth vs dev-sso + vault init)" >&2
setup_ok=1
for dev in device-a device-b device-c; do
  if out=$(sx "$dev" setup 2>&1) && echo "$out" | grep -q 'RESULT: ownerSub='; then
    :
  else
    echo "    $dev setup output: $out" >&2
    setup_ok=0
  fi
done
# Assert all three share ONE owner (fixed sub from dev-sso).
subs=$(for d in device-a device-b device-c; do sx "$d" status-sub; done | sort -u | grep -c .)
n_subs=$subs
subs=$(sx device-a status-sub)
if [ "$setup_ok" = 1 ] && [ "$n_subs" = 1 ] && [ -n "$subs" ]; then
  pass "setup: 3 devices bootstrapped, one shared owner ($subs)"
else
  fail "setup" "setup_ok=$setup_ok distinct_owners=$n_subs"
fi

# Cache device jkts.
JKT_A=$(sx device-a jkt); JKT_B=$(sx device-b jkt); JKT_C=$(sx device-c jkt)

# ── Scenario 2: transfer (A→B, 2 creds) ──────────────────────────────────────
echo "▸ Scenario 2: transfer (A adds 2 creds, B syncs from A)" >&2
sx device-a add-cred api-a bearer api.example.com mock-token-a1 >/dev/null
sx device-a add-cred svc-b basic svc.example.com admin:mock-basic-a1 >/dev/null
sx device-a listen "$LISTEN_PORT" 1 >/dev/null
b_sync=$(sx device-b sync-peer "device-a:$LISTEN_PORT" | result_of)
set_a=$(sx device-a creds); set_b=$(sx device-b creds)
sx device-a stop-listen >/dev/null
if [ "$b_sync" = "sync-ok=true" ] && [ "$set_a" = "$set_b" ] && [ -n "$set_a" ]; then
  pass "transfer: B mirrors A ($set_b)"
else
  fail "transfer" "b_sync=$b_sync A=[$set_a] B=[$set_b]"
fi

# ── Scenario 3: beacon discovery (best-effort) ───────────────────────────────
echo "▸ Scenario 3: beacon discovery (best-effort; SKIP if multicast unavailable)" >&2
sx device-a listen "$LISTEN_PORT" 1 >/dev/null
beacon=$(sx device-b sync-beacon | result_of)
sx device-a stop-listen >/dev/null
case "$beacon" in
  beacon=synced)  pass "beacon: B discovered A via multicast" ;;
  beacon=nopeers) skip "beacon" "multicast unavailable on this host/Docker" ;;
  *)              skip "beacon" "no peers / $beacon" ;;
esac

# ── Scenario 4: headless approval (C, no autoapprove on A's listener) ─────────
# Run BEFORE the conflict scenario ON PURPOSE. agent-id's sync trust model
# (documented in tests/test-sync-e2e.mjs) only accepts a RELAYED op if the
# receiver has already pinned that op's AUTHOR. Right now A's oplog is entirely
# A-authored (api-a, svc-b), so once C pins A on its approved retry it can
# accept all of A's ops. Introducing B-authored ops (the conflict scenario)
# BEFORE C joins would make C's single-peer join legitimately fail with
# unknown-author — a real property of the model, not a bug — and would need C
# to also directly pin B. Keeping headless first models the natural "new device
# joins, gets approved, pulls the current vault" story with one peer.
echo "▸ Scenario 4: headless approval (A listens WITHOUT autoapprove; C first-contact refused)" >&2
sx device-a listen "$LISTEN_PORT" 0 >/dev/null    # A: autoapprove OFF → headless path
c_first=$(sx device-c sync-peer-headless "device-a:$LISTEN_PORT" | result_of)
c_creds_before=$(sx device-c creds)
peer_jkt=$(sx device-a peer-jkt-from-log)
if echo "$c_first" | grep -q 'sync-ok=false' && [ -z "$c_creds_before" ] && [ -n "$peer_jkt" ]; then
  # Operator approves C on A out-of-band. The running listener holds an
  # in-memory vault snapshot from when it started, so the preapproval only
  # takes effect on its NEXT session — restart the listener before C retries
  # (this mirrors the real "add device, then it connects again" flow).
  sx device-a devices-add "$peer_jkt" >/dev/null
  sx device-a stop-listen >/dev/null
  sx device-a listen "$LISTEN_PORT" 0 >/dev/null
  c_retry=$(sx device-c sync-peer "device-a:$LISTEN_PORT" | result_of)
  c_creds_after=$(sx device-c creds)
  a_creds=$(sx device-a creds)
  sx device-a stop-listen >/dev/null
  if [ "$c_retry" = "sync-ok=true" ] && [ "$c_creds_after" = "$a_creds" ] && [ -n "$c_creds_after" ]; then
    pass "headless: first contact refused, approved via 'devices add', retry synced ($c_creds_after)"
  else
    fail "headless-retry" "c_retry=$c_retry C=[$c_creds_after] A=[$a_creds]"
  fi
else
  sx device-a stop-listen >/dev/null
  fail "headless-refusal" "c_first=$c_first creds_before=[$c_creds_before] jkt=[$peer_jkt]"
fi

# ── Scenario 5: conflict (concurrent edit, journaled, resolve --restore) ──────
echo "▸ Scenario 5: conflict (A & B edit same name to different values)" >&2
# Listener is stopped. Both add the same name concurrently.
sx device-a add-cred conflict bearer conflict.example.com value-from-A >/dev/null
sx device-b add-cred conflict bearer conflict.example.com value-from-B >/dev/null
sx device-a listen "$LISTEN_PORT" 1 >/dev/null
sx device-b sync-peer "device-a:$LISTEN_PORT" >/dev/null
sx device-a stop-listen >/dev/null
val_a=$(sx device-a show-value conflict); val_b=$(sx device-b show-value conflict)
conf_a=$(sx device-a conflicts); conf_b=$(sx device-b conflicts)
if [ "$val_a" = "$val_b" ] && [ -n "$val_a" ] && { [ "${conf_a:-0}" -gt 0 ] || [ "${conf_b:-0}" -gt 0 ]; }; then
  # The deterministic fold picked a winner; the OTHER value is the loser.
  winner_val=$val_a
  loser_val=value-from-A; [ "$winner_val" = "value-from-A" ] && loser_val=value-from-B
  # Restore on a side that journaled the conflict (prefer A, the listener).
  restore_side=device-a; [ "${conf_a:-0}" -gt 0 ] || restore_side=device-b
  sx "$restore_side" resolve-restore conflict >/dev/null
  # One re-sync propagates the restored (causally-later) edit everywhere.
  # The restoring side listens; the other pulls.
  other_side=device-b; [ "$restore_side" = device-b ] && other_side=device-a
  sx "$restore_side" listen "$LISTEN_PORT" 1 >/dev/null
  sx "$other_side" sync-peer "$restore_side:$LISTEN_PORT" >/dev/null
  sx "$restore_side" stop-listen >/dev/null
  rval_a=$(sx device-a show-value conflict); rval_b=$(sx device-b show-value conflict)
  if [ "$rval_a" = "$rval_b" ] && [ "$rval_a" = "$loser_val" ]; then
    pass "conflict: converged ($winner_val), journaled, restored '$loser_val' won everywhere"
  else
    fail "conflict-resolve" "restored A=[$rval_a] B=[$rval_b] expected=[$loser_val]"
  fi
else
  fail "conflict" "A=[$val_a] B=[$val_b] conf_a=$conf_a conf_b=$conf_b"
fi

# ── Scenario 6: revoke (A revokes B; B re-sync refused; A data intact) ────────
echo "▸ Scenario 6: revoke (A revokes B, B re-sync refused, A unchanged)" >&2
a_before=$(sx device-a creds)
sx device-a revoke "$JKT_B" >/dev/null
sx device-a listen "$LISTEN_PORT" 0 >/dev/null    # autoapprove OFF so B can't re-pin trivially
b_resync=$(sx device-b sync-peer-headless "device-a:$LISTEN_PORT" | result_of)
sx device-a stop-listen >/dev/null
a_after=$(sx device-a creds)
if echo "$b_resync" | grep -q 'sync-ok=false' && [ "$a_before" = "$a_after" ]; then
  pass "revoke: B refused after revoke, A data intact"
else
  fail "revoke" "b_resync=$b_resync A_before=[$a_before] A_after=[$a_after]"
fi

# ── Report ───────────────────────────────────────────────────────────────────
echo "" >&2
echo "══════════════════════════ RESULTS ══════════════════════════" >&2
printf '  %-16s %s\n' "SCENARIO" "STATE" >&2
for i in "${!NAMES[@]}"; do
  printf '  %-16s %s\n' "$(echo "${NAMES[$i]}" | cut -d: -f1)" "${STATES[$i]}" >&2
done
echo "══════════════════════════════════════════════════════════════" >&2

if [ "$fail_count" -gt 0 ]; then
  echo "RESULT: $fail_count scenario(s) FAILED" >&2
  exit 1
fi
echo "RESULT: all scenarios PASS/SKIP" >&2
exit 0
