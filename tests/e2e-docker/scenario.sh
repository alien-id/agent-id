#!/usr/bin/env bash
# In-container scenario step runner.
#
#   scenario.sh <step> [args...]
#
# Invoked from the host via `docker compose exec <device> /app/e2e/scenario.sh …`.
# Each step is a small, assertive unit; the host run.sh orchestrates ordering
# across containers and tallies PASS/FAIL/SKIP. Steps print machine-readable
# `RESULT: <token>` lines the host greps, and exit non-zero on assertion failure.
set -uo pipefail
source /app/e2e/lib.sh

SSO_URL=${SSO_ISSUER_URL:-http://127.0.0.1:5050}
PROVIDER=dev-fixture-provider
LISTEN_LOG=/state/listen.log
LISTEN_PID=/state/listen.pid

step=${1:-}; shift || true

# ── helpers for the persistent listener ──────────────────────────────────────
start_listener() { # start_listener <port> [autoapprove=1]
  local port=$1 aa=${2:-1}
  : >"$LISTEN_LOG"
  # device-entry.sh already neutralised /dev/tty so hasTty() is false → with
  # autoapprove OFF the listener takes the headless approval-required path
  # (logs the peer jkt, never prompts). stdin from /dev/null is belt-and-braces.
  AGENT_ID_SYNC_AUTOAPPROVE="$aa" $VAULT sync --listen --port "$port" --label "$DEVICE" \
    >"$LISTEN_LOG" 2>&1 </dev/null &
  echo $! >"$LISTEN_PID"
  wait_log "$LISTEN_LOG" "Sync listener on port" listener
  log "listener up on :$port (autoapprove=$aa)"
}
stop_listener() {
  [ -f "$LISTEN_PID" ] || return 0
  kill "$(cat "$LISTEN_PID")" 2>/dev/null || true
  rm -f "$LISTEN_PID"
  log "listener stopped"
}

case "$step" in

  # 1. setup: socat is already up (entrypoint). bootstrap → vault init → assert.
  setup)
    wait_http "$SSO_URL/.well-known/openid-configuration" SSO
    # /state is a tmpfs mountpoint — clear its CONTENTS, not the mount itself.
    rm -rf /state/* 2>/dev/null || true; mkdir -p /state
    $CORE bootstrap --provider-address "$PROVIDER" --sso-url "$SSO_URL" \
      --timeout-sec 15 --poll-interval-ms 300 >/state/bootstrap.json 2>/state/bootstrap.err \
      || die "bootstrap failed: $(cat /state/bootstrap.err)"
    sub=$($CORE status 2>/dev/null | jget 'j.ownerSub||""')
    [ -n "$sub" ] || die "no owner session / ownerSub after bootstrap"
    $VAULT init >/state/init.json 2>/state/init.err || die "vault init failed: $(cat /state/init.err)"
    jkt=$($VAULT sync status 2>/dev/null >/dev/null; cat /state/bootstrap.json | jget 'j.jkt')
    log "bootstrapped owner=$sub jkt=$jkt"
    echo "RESULT: ownerSub=$sub jkt=$jkt"
    ;;

  jkt)   # print this device's own agent jkt
    cat /state/bootstrap.json | jget 'j.jkt'; echo
    ;;

  status-sub) # print this device's owner sub
    $CORE status 2>/dev/null | jget 'j.ownerSub||""'; echo
    ;;

  add-cred) # add-cred <name> <type> <domain> <value|user:pass>
    name=$1 type=$2 domain=$3 val=${4:-}
    case "$type" in
      bearer)
        E2E_V="$val" $VAULT add --name "$name" --type bearer --domains "$domain" --value-env E2E_V \
          >/dev/null || die "add bearer $name failed" ;;
      basic)
        user=${val%%:*}; pass=${val#*:}
        E2E_P="$pass" $VAULT add --name "$name" --type basic --domains "$domain" \
          --username "$user" --password-env E2E_P >/dev/null || die "add basic $name failed" ;;
      *) die "unsupported cred type $type" ;;
    esac
    log "added $name ($type)"
    echo "RESULT: added $name:$type"
    ;;

  listen)        start_listener "$1" "${2:-1}"; echo "RESULT: listening" ;;
  stop-listen)   stop_listener; echo "RESULT: stopped" ;;

  # sync to an explicit peer with autoapprove. args: <peer host:port>
  sync-peer)
    peer=$1
    out=$(AGENT_ID_SYNC_AUTOAPPROVE=1 $VAULT sync --peer "$peer" --label "$DEVICE" 2>/state/sync.err)
    ok=$(echo "$out" | jget 'j.ok'); echo "$out" >/state/sync.json
    err=$(echo "$out" | jget '(j.results&&j.results[0]&&(j.results[0].error||j.results[0].code))||j.error||""')
    log "sync-peer $peer -> ok=$ok ${err:+err=$err}"
    echo "RESULT: sync-ok=$ok${err:+ err=$err}"
    ;;

  # sync WITHOUT autoapprove (headless path under test on the LISTENER side).
  # The initiator still needs to approve the listener; we let the initiator use
  # its own autoapprove only. args: <peer host:port>
  sync-peer-headless)
    peer=$1
    out=$(AGENT_ID_SYNC_AUTOAPPROVE=1 $VAULT sync --peer "$peer" --label "$DEVICE" 2>/state/sync.err)
    ok=$(echo "$out" | jget 'j.ok'); echo "$out" >/state/sync.json
    code=$(echo "$out" | jget '(j.results&&j.results[0]&&j.results[0].code)||""')
    log "sync-peer-headless $peer -> ok=$ok code=$code"
    echo "RESULT: sync-ok=$ok code=$code"
    ;;

  # best-effort beacon sync (no --peer). PASS on ok, SKIP if no peers found.
  sync-beacon)
    out=$(AGENT_ID_SYNC_AUTOAPPROVE=1 $VAULT sync --label "$DEVICE" --timeout-ms 4000 2>/state/beacon.err) || true
    ok=$(echo "$out" | jget 'j.ok||false' 2>/dev/null || echo false)
    err=$(cat /state/beacon.err 2>/dev/null; echo "$out")
    if [ "$ok" = "true" ]; then echo "RESULT: beacon=synced"
    elif echo "$err" | grep -qi "no sync peers found"; then echo "RESULT: beacon=nopeers"
    else echo "RESULT: beacon=error"; fi
    ;;

  creds)   cred_set; echo ;;                       # print "name:type,name:type,..."
  show)    $VAULT show --name "$1" 2>/dev/null ;;   # raw JSON of one cred

  # print the value of a cred (for conflict winner comparison). `show` nests the
  # record under `credential`; bearer/basic values are visible (not sealed).
  show-value)
    $VAULT show --name "$1" 2>/dev/null | jget 'j.credential && (j.credential.value!=null?j.credential.value:(j.credential.username+":"+(j.credential.password||"")))'
    echo ;;

  conflicts) # count of journaled conflicts
    $VAULT sync status 2>/dev/null | jget 'j.conflicts.length'; echo ;;

  conflict-names)
    $VAULT sync status 2>/dev/null | jget 'j.conflicts.map(c=>c.name).join(",")'; echo ;;

  # grep A's listener log for the approval-required jkt of the most recent peer.
  peer-jkt-from-log)
    # protocol.mjs message: "... sync devices add --jkt <jkt>"
    grep -oE 'sync devices add --jkt [A-Za-z0-9_-]+' "$LISTEN_LOG" | tail -1 | awk '{print $NF}'
    ;;

  devices-add) # preapprove a peer jkt on this (listener) device
    $VAULT sync devices add --jkt "$1" >/dev/null || die "devices add failed"
    log "preapproved jkt $1"
    echo "RESULT: added-device $1"
    ;;

  resolve-restore) # resolve --name <n> --restore on the journaling side
    $VAULT sync resolve --name "$1" --restore >/dev/null || die "resolve --restore failed"
    log "restored losing version of $1"
    echo "RESULT: restored $1"
    ;;

  revoke) # revoke a peer jkt
    out=$($VAULT sync revoke --jkt "$1" 2>/dev/null)
    ok=$(echo "$out" | jget 'j.ok')
    log "revoke $1 -> ok=$ok"
    echo "RESULT: revoke-ok=$ok"
    ;;

  listener-log) cat "$LISTEN_LOG" 2>/dev/null || true ;;

  *) die "unknown scenario step: $step" ;;
esac
