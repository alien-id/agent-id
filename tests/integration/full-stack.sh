#!/usr/bin/env bash
# tests/integration/full-stack.sh — end-to-end against local dev-sso + demo-service.
#
# Spawns:
#   - examples/dev-sso.mjs       on :5050   (DPoP-cutover-aware OIDC, auto-approves)
#   - examples/demo-service.mjs  on :3141   (well-known manifest + AgentID verifier)
#
# Drives the agent CLI through the full bootstrap and call sequence:
#   init → auth → bind → discover-service → service-support → auth-header → call → refresh → call
#
# Asserts each step and exits non-zero on the first failure. Logs are kept in
# /tmp/dev-sso.log and /tmp/demo.log for postmortem when something breaks.
#
# Usage:   bash tests/integration/full-stack.sh
# CI:      INTEGRATION=1 bash tests/integration/full-stack.sh

set -euo pipefail

cd "$(dirname "$0")/../.."

SSO_PORT=${SSO_PORT:-5050}
DEMO_PORT=${DEMO_PORT:-3141}
STATE_DIR=${STATE_DIR:-/tmp/agent-id-integration}
PROVIDER=${PROVIDER:-dev-fixture-provider}

cli() {
  # Usage: cli <command> [flags...]
  # `--state-dir` is forwarded to every command so all CLI invocations
  # share the same scratch state directory under STATE_DIR.
  local cmd=$1 ; shift
  node skills/alien-agent-id/cli.mjs "$cmd" --state-dir "$STATE_DIR" "$@"
}

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
blue()   { printf '\033[34m%s\033[0m\n' "$*"; }

cleanup() {
  local code=$?
  [[ -n "${SSO_PID:-}"  ]] && kill "$SSO_PID"  2>/dev/null || true
  [[ -n "${DEMO_PID:-}" ]] && kill "$DEMO_PID" 2>/dev/null || true
  if (( code != 0 )); then
    red "FAILED. dev-sso log:"   ; tail -20 /tmp/dev-sso.log 2>/dev/null || true
    red       "demo-service log:"; tail -20 /tmp/demo.log    2>/dev/null || true
  fi
  exit "$code"
}
trap cleanup EXIT INT TERM

# Reset agent state for a deterministic run.
rm -rf "$STATE_DIR" && mkdir -p "$STATE_DIR"

blue "▸ Starting dev-sso on :$SSO_PORT"
node examples/dev-sso.mjs --port "$SSO_PORT" --verbose >/tmp/dev-sso.log 2>&1 &
SSO_PID=$!

blue "▸ Starting demo-service on :$DEMO_PORT"
node examples/demo-service.mjs --port "$DEMO_PORT" --verbose >/tmp/demo.log 2>&1 &
DEMO_PID=$!

# Wait for both servers to accept connections.
for i in {1..30}; do
  if curl -fsS "http://127.0.0.1:$SSO_PORT/.well-known/openid-configuration"  >/dev/null 2>&1 && \
     curl -fsS "http://127.0.0.1:$DEMO_PORT/.well-known/alien-agent-id.json" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

assert() {
  local label=$1 ; shift
  if "$@"; then green "  ✓ $label"; else red "  ✗ $label"; exit 1; fi
}

blue "▸ Step 1: init"
cli init >/tmp/integ.init.json
assert "fingerprint produced" \
  bash -c 'jq -e ".fingerprint | type == \"string\"" /tmp/integ.init.json >/dev/null'

blue "▸ Step 2: auth (begin OIDC, dpop_jkt advertised)"
cli auth --provider-address "$PROVIDER" --sso-url "http://127.0.0.1:$SSO_PORT" >/tmp/integ.auth.json
assert "polling_code returned" \
  bash -c 'jq -e ".pollingCode | type == \"string\"" /tmp/integ.auth.json >/dev/null'

blue "▸ Step 3: bind (poll → exchange → verify cnf.jkt)"
cli bind --timeout-sec 10 --poll-interval-ms 500 >/tmp/integ.bind.json
assert "binding created"  \
  bash -c 'jq -e ".bindingId" /tmp/integ.bind.json >/dev/null'
assert "fingerprint matches init" \
  bash -c 'test "$(jq -r .fingerprint /tmp/integ.init.json)" = "$(jq -r .fingerprint /tmp/integ.bind.json)"'

blue "▸ Step 4: status reports bound"
cli status >/tmp/integ.status.json
assert "bound==true" \
  bash -c 'jq -e ".bound == true" /tmp/integ.status.json >/dev/null'

blue "▸ Step 5: discover-service (well-known fetch)"
cli discover-service --url "http://127.0.0.1:$DEMO_PORT" --allow-insecure >/tmp/integ.discover.json
assert "manifest version 1" \
  bash -c 'jq -e ".manifest.version == 1" /tmp/integ.discover.json >/dev/null'
assert "manifest auth.scheme is AgentID" \
  bash -c '[[ "$(jq -r .manifest.auth.scheme /tmp/integ.discover.json)" = "AgentID" ]]'
assert "api.base under same authority" \
  bash -c '[[ "$(jq -r .manifest.api.base /tmp/integ.discover.json)" =~ http://127.0.0.1:$DEMO_PORT ]]'

blue "▸ Step 6: service-support (meta-tag probe)"
cli service-support --url "http://127.0.0.1:$DEMO_PORT" --allow-insecure >/tmp/integ.support.json
assert "supported v1" \
  bash -c '[[ "$(jq -r .version /tmp/integ.support.json)" = "v1" ]]'

blue "▸ Step 7: auth-header --raw → call /api/v1/whoami"
HDR=$(cli auth-header --raw)
HTTP_CODE=$(curl -s -o /tmp/integ.whoami.json -w '%{http_code}' -H "$HDR" "http://127.0.0.1:$DEMO_PORT/api/v1/whoami")
assert "service returns 200" bash -c "[[ '$HTTP_CODE' = '200' ]]"
assert "agent_fingerprint matches" \
  bash -c 'test "$(jq -r .agent_fingerprint /tmp/integ.whoami.json)" = "$(jq -r .fingerprint /tmp/integ.bind.json)"'

blue "▸ Step 8: tampered token → 401"
TAMP="${HDR:0:30}$([[ ${HDR:30:1} = Z ]] && echo Y || echo Z)${HDR:31}"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$TAMP" "http://127.0.0.1:$DEMO_PORT/api/v1/whoami")
assert "tampered → 401"  bash -c "[[ '$CODE' = '401' ]]"

blue "▸ Step 9: bare token (no scheme) → 401"
RAW="${HDR#Authorization: AgentID }"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: $RAW" "http://127.0.0.1:$DEMO_PORT/api/v1/whoami")
assert "bare → 401"  bash -c "[[ '$CODE' = '401' ]]"

blue "▸ Step 10: refresh (DPoP-bound, sticky cnf.jkt)"
cli refresh >/tmp/integ.refresh.json
assert "refresh ok" \
  bash -c 'jq -e ".ok == true" /tmp/integ.refresh.json >/dev/null'

blue "▸ Step 11: post-refresh, service call still 200"
HDR2=$(cli auth-header --raw)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$HDR2" "http://127.0.0.1:$DEMO_PORT/api/v1/whoami")
assert "post-refresh → 200"  bash -c "[[ '$CODE' = '200' ]]"

green ""
green "All 11 integration steps passed."
