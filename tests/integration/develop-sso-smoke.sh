#!/usr/bin/env bash
# tests/integration/develop-sso-smoke.sh — full end-to-end verification of
# agent-id 3.0.0 against the real Alien develop SSO at sso.develop.alien-api.com.
#
# Walks: discovery → init → auth → mock-callback approval → bind →
#        auth-header → call local demo-service.
#
# Uses the develop dev-portal's published mock-callback signature
# (developer-portal/src/app/api/mock-callback/route.ts) to bypass the
# Alien App's signing step, so this runs CI-friendly without a phone.
#
# Usage:    bash tests/integration/develop-sso-smoke.sh
# Override: STATE_DIR / SSO_URL / PROVIDER / SHORTENER / DEMO_PORT
#           BIND_TIMEOUT_SEC / SUPER_OPTIMISTIC

set -euo pipefail

cd "$(dirname "$0")/../.."

STATE_DIR=${STATE_DIR:-/tmp/agent-id-develop-smoke}
SSO_URL=${SSO_URL:-https://sso.develop.alien-api.com}
PROVIDER=${PROVIDER:-00000001040000000000000100000000}
SHORTENER=${SHORTENER:-https://s.develop.alien.app}
DEMO_PORT=${DEMO_PORT:-3141}
BIND_TIMEOUT_SEC=${BIND_TIMEOUT_SEC:-10}

# Hardcoded mock signature, copied verbatim from
# developer-portal/src/app/api/mock-callback/route.ts. Public test
# fixture; fine to commit.
MOCK_SESSION_ADDRESS="00000001010000000000000200000000"
MOCK_SESSION_SEED="tcCQpxmvM7C4VnZXCuSgCa4fFIyZhkDp"
MOCK_SESSION_SIG="E9BBDA7EE84B022A35E8A9007224BCF5653B5D996C15C5F6550B4BDEA99E4562A2DEE30D365E6B186218DF240161CC6E9EB36B409703E9EACCEDD4B989D0EA0F"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
blue()   { printf '\033[34m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

cleanup() {
  local code=$?
  [[ -n "${DEMO_PID:-}" ]] && kill "$DEMO_PID" 2>/dev/null || true
  if (( code != 0 )); then red "FAILED."; fi
  exit "$code"
}
trap cleanup EXIT INT TERM

assert() {
  local label=$1 ; shift
  if "$@"; then green "  ✓ $label"; else red "  ✗ $label"; exit 1; fi
}

rm -rf "$STATE_DIR" && mkdir -p "$STATE_DIR"

blue "▸ Verify external SSO advertises DPoP cutover"
curl -fsS "$SSO_URL/.well-known/openid-configuration" \
  | jq -e '(.claims_supported | index("cnf") != null)
           and ((.dpop_signing_alg_values_supported // []) | index("EdDSA") != null)' \
  >/dev/null
assert "advertises cnf + EdDSA" true

blue "▸ Step 1: init (agent keypair)"
node plugins/agent-id-core/bin/cli.mjs init --state-dir "$STATE_DIR" >/tmp/dsm.init.json
assert "fingerprint produced" \
  bash -c 'jq -e ".fingerprint | type == \"string\"" /tmp/dsm.init.json >/dev/null'

blue "▸ Step 2: auth (begin OIDC, dpop_jkt + Origin: http://localhost)"
node plugins/agent-id-core/bin/cli.mjs auth --state-dir "$STATE_DIR" \
  --provider-address "$PROVIDER" --sso-url "$SSO_URL" \
  --oidc-origin http://localhost >/tmp/dsm.auth.json
assert "deep_link returned" \
  bash -c 'jq -e ".deepLink | type == \"string\"" /tmp/dsm.auth.json >/dev/null'

DEEP=$(jq -r .deepLink /tmp/dsm.auth.json)
SHORT_ID=${DEEP##*/}

blue "▸ Step 3: resolve shortener → callback URL"
RESOLVED=$(curl -fsS "$SHORTENER/api/resolve/$SHORT_ID")
ORIGINAL_URL=$(echo "$RESOLVED" | jq -r .original_url)
CALLBACK_URL=$(python3 -c "
from urllib.parse import urlparse, parse_qs, unquote
u = urlparse('$ORIGINAL_URL')
print(unquote(parse_qs(u.query)['callback_url'][0]))
")
assert "callback_url extracted from deep_link" \
  bash -c "[[ '$CALLBACK_URL' =~ ^https?:// ]]"

blue "▸ Step 4: POST mock signature → SSO callback (substitutes Alien App)"
HTTP_CODE=$(curl -s -o /tmp/dsm.cb.json -w '%{http_code}' \
  -X POST "$CALLBACK_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"session_signature_seed\":\"$MOCK_SESSION_SEED\",\"session_signature\":\"$MOCK_SESSION_SIG\",\"session_address\":\"$MOCK_SESSION_ADDRESS\"}")
assert "SSO accepted mock signature (200)" bash -c "[[ '$HTTP_CODE' = '200' ]]"

blue "▸ Step 5: bind (poll → DPoP token exchange → cnf.jkt verify)"
node plugins/agent-id-core/bin/cli.mjs bind --state-dir "$STATE_DIR" \
  --timeout-sec "$BIND_TIMEOUT_SEC" --poll-interval-ms 500 >/tmp/dsm.bind.json
assert "owner sub returned" \
  bash -c 'jq -e ".ownerSub | type == \"string\"" /tmp/dsm.bind.json >/dev/null'
assert "issuer matches develop SSO" \
  bash -c "[[ \"\$(jq -r .issuer /tmp/dsm.bind.json)\" = '$SSO_URL' ]]"

blue "▸ Step 6: id_token actually carries cnf.jkt (RFC 7800 binding from real SSO)"
JKT=$(jq -r '.idToken' "$STATE_DIR/owner-session.json" \
  | cut -d. -f2 \
  | python3 -c "
import sys, base64, json
t = sys.stdin.read().strip(); t += '=' * (-len(t) % 4)
print(json.loads(base64.urlsafe_b64decode(t)).get('cnf', {}).get('jkt', ''))
")
assert "cnf.jkt present in id_token" bash -c "[[ -n '$JKT' ]]"
yellow "    cnf.jkt = $JKT"

blue "▸ Step 7: status reports bound"
node plugins/agent-id-core/bin/cli.mjs status --state-dir "$STATE_DIR" >/tmp/dsm.status.json
assert "bound==true" \
  bash -c 'jq -e ".bound == true" /tmp/dsm.status.json >/dev/null'

blue "▸ Step 8: spawn demo-service, call /api/v1/whoami with RFC 9449 DPoP headers"
node examples/demo-service.mjs --port "$DEMO_PORT" --sso-url "$SSO_URL" \
  >/tmp/dsm.demo.log 2>&1 &
DEMO_PID=$!
for i in {1..30}; do
  curl -fsS "http://127.0.0.1:$DEMO_PORT/.well-known/alien-agent-id.json" >/dev/null 2>&1 && break
  sleep 0.1
done

WHOAMI_URL="http://127.0.0.1:$DEMO_PORT/api/v1/whoami"
node plugins/agent-id-auth/bin/cli.mjs header --state-dir "$STATE_DIR" \
  --url "$WHOAMI_URL" --method GET --raw >/tmp/dsm.headers.txt
AUTH_HDR=$(grep '^Authorization:' /tmp/dsm.headers.txt | sed 's/^Authorization: //')
DPOP_HDR=$(grep '^DPoP:'         /tmp/dsm.headers.txt | sed 's/^DPoP: //')
assert "auth-header emits DPoP scheme" \
  bash -c "[[ '$AUTH_HDR' == DPoP\ * ]]"
assert "auth-header emits a DPoP proof" \
  bash -c "[[ -n '$DPOP_HDR' ]]"

HTTP_CODE=$(curl -s -o /tmp/dsm.whoami.json -w '%{http_code}' \
  -H "Authorization: $AUTH_HDR" -H "DPoP: $DPOP_HDR" "$WHOAMI_URL")
assert "service returns 200 against develop-SSO-bound token" \
  bash -c "[[ '$HTTP_CODE' = '200' ]]"
assert "owner_sub returned by service" \
  bash -c 'jq -e ".owner_sub | type == \"string\"" /tmp/dsm.whoami.json >/dev/null'
assert "agent_jkt matches id_token cnf.jkt" \
  bash -c "test \"\$(jq -r .agent_jkt /tmp/dsm.whoami.json)\" = '$JKT'"

green ""
green "All 8 develop-SSO smoke steps passed against $SSO_URL."
green "  owner sub:  $(jq -r .ownerSub /tmp/dsm.bind.json)"
green "  fingerprint:$(jq -r .fingerprint /tmp/dsm.bind.json)"
green "  cnf.jkt:    $JKT"
