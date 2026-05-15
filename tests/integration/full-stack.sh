#!/usr/bin/env bash
# tests/integration/full-stack.sh — end-to-end against a real or local SSO.
#
# Two modes, controlled by SSO_URL:
#
#   Local mode (default):
#     Spawns examples/dev-sso.mjs on :SSO_PORT with auto-approval. Walks the
#     full bootstrap inline; finishes in seconds.
#
#   External mode (SSO_URL set):
#     Skips the local dev-sso. Points the agent at a real DPoP-deployed SSO
#     (develop / staging / prod). Step 3 (bind) blocks waiting for human
#     approval via the Alien App build that points at the same environment.
#     PROVIDER must be a valid client_id for that SSO env (production's
#     default-provider.txt won't work on develop and vice versa).
#
# Demo-service modes are independent: by default we spawn the local
# examples/demo-service.mjs, but if DEMO_URL is set we hit that instead.
#
# Asserts each step and exits non-zero on the first failure.
# Logs: /tmp/dev-sso.log, /tmp/demo.log (only populated in local mode).
#
# Usage:
#   bash tests/integration/full-stack.sh                                      # all-local
#   SSO_URL=https://sso.develop.alien-api.com PROVIDER=<dev-id> \             # external SSO
#     bash tests/integration/full-stack.sh
#   SSO_URL=… DEMO_URL=https://demo.develop.example \                         # external SSO + service
#     bash tests/integration/full-stack.sh

set -euo pipefail

cd "$(dirname "$0")/../.."

SSO_PORT=${SSO_PORT:-5050}
DEMO_PORT=${DEMO_PORT:-3141}
STATE_DIR=${STATE_DIR:-/tmp/agent-id-integration}
PROVIDER=${PROVIDER:-dev-fixture-provider}
SSO_URL=${SSO_URL:-}
DEMO_URL=${DEMO_URL:-}
BIND_TIMEOUT_SEC=${BIND_TIMEOUT_SEC:-10}

# Resolved endpoints used throughout the script.
RESOLVED_SSO_URL="${SSO_URL:-http://127.0.0.1:$SSO_PORT}"
RESOLVED_DEMO_URL="${DEMO_URL:-http://127.0.0.1:$DEMO_PORT}"

# In local mode we control the SSO and can shortcut the human-approval step.
# In external mode we must wait for a real Alien App, so step 3 needs more time.
if [[ -n "$SSO_URL" ]]; then
  BIND_TIMEOUT_SEC=${BIND_TIMEOUT_SEC:-300}
fi

cli() {
  # Usage: cli <command> [flags...]
  # `--state-dir` is forwarded to every command so all CLI invocations
  # share the same scratch state directory under STATE_DIR.
  #
  # Routes the legacy subcommand names to the per-plugin CLIs that own
  # them post-split. Old names (git-commit, vault-store, auth-header,
  # discover-service, …) are accepted on input and mapped to the
  # plugin's current subcommand name before forwarding.
  local cmd=$1 ; shift
  local plugin_path
  case "$cmd" in
    init|auth|bind|bootstrap|setup-owner-session|refresh|status|sign|verify|export-proof)
      plugin_path="plugins/agent-id-core/bin/cli.mjs" ;;
    git-setup)
      plugin_path="plugins/agent-id-git/bin/cli.mjs" ; cmd="setup" ;;
    git-commit)
      plugin_path="plugins/agent-id-git/bin/cli.mjs" ; cmd="commit" ;;
    git-verify)
      plugin_path="plugins/agent-id-git/bin/cli.mjs" ; cmd="verify" ;;
    vault-store)
      plugin_path="plugins/agent-id-vault/bin/cli.mjs" ; cmd="store" ;;
    vault-get)
      plugin_path="plugins/agent-id-vault/bin/cli.mjs" ; cmd="get" ;;
    vault-list)
      plugin_path="plugins/agent-id-vault/bin/cli.mjs" ; cmd="list" ;;
    vault-remove)
      plugin_path="plugins/agent-id-vault/bin/cli.mjs" ; cmd="remove" ;;
    auth-header)
      plugin_path="plugins/agent-id-auth/bin/cli.mjs" ; cmd="header" ;;
    discover-service)
      plugin_path="plugins/agent-id-auth/bin/cli.mjs" ; cmd="discover" ;;
    service-support)
      plugin_path="plugins/agent-id-auth/bin/cli.mjs" ; cmd="support" ;;
    call|capabilities)
      plugin_path="plugins/agent-id-auth/bin/cli.mjs" ;;
    *)
      echo "cli(): unknown subcommand: $cmd" >&2 ; return 1 ;;
  esac
  node "$plugin_path" "$cmd" --state-dir "$STATE_DIR" "$@"
}

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
blue()   { printf '\033[34m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

cleanup() {
  local code=$?
  [[ -n "${SSO_PID:-}"  ]] && kill "$SSO_PID"  2>/dev/null || true
  [[ -n "${DEMO_PID:-}" ]] && kill "$DEMO_PID" 2>/dev/null || true
  if (( code != 0 )); then
    red "FAILED."
    [[ -z "$SSO_URL"   ]] && { red "dev-sso log:"      ; tail -20 /tmp/dev-sso.log 2>/dev/null || true; }
    [[ -z "$DEMO_URL"  ]] && { red "demo-service log:" ; tail -20 /tmp/demo.log    2>/dev/null || true; }
  fi
  exit "$code"
}
trap cleanup EXIT INT TERM

# Reset agent state for a deterministic run.
rm -rf "$STATE_DIR" && mkdir -p "$STATE_DIR"

if [[ -z "$SSO_URL" ]]; then
  blue "▸ Starting dev-sso on :$SSO_PORT"
  node examples/dev-sso.mjs --port "$SSO_PORT" --verbose >/tmp/dev-sso.log 2>&1 &
  SSO_PID=$!
else
  blue "▸ Using external SSO: $SSO_URL"
fi

if [[ -z "$DEMO_URL" ]]; then
  blue "▸ Starting demo-service on :$DEMO_PORT (trusting SSO at $RESOLVED_SSO_URL)"
  node examples/demo-service.mjs --port "$DEMO_PORT" --sso-url "$RESOLVED_SSO_URL" \
    --verbose >/tmp/demo.log 2>&1 &
  DEMO_PID=$!
else
  blue "▸ Using external demo-service: $DEMO_URL"
fi

# Wait for both endpoints to be reachable.
for i in {1..30}; do
  sso_ok=$(curl -fsS "$RESOLVED_SSO_URL/.well-known/openid-configuration" >/dev/null 2>&1 && echo y || echo n)
  demo_ok=$(curl -fsS "$RESOLVED_DEMO_URL/.well-known/alien-agent-id.json" >/dev/null 2>&1 && echo y || echo n)
  [[ "$sso_ok" = y && "$demo_ok" = y ]] && break
  sleep 0.2
done
[[ "$sso_ok" = y ]] || { red "SSO discovery not reachable at $RESOLVED_SSO_URL"; exit 1; }
[[ "$demo_ok" = y ]] || { red "Demo manifest not reachable at $RESOLVED_DEMO_URL"; exit 1; }

# Sanity check: external SSO must advertise the cutover.
if [[ -n "$SSO_URL" ]]; then
  blue "▸ Verifying external SSO advertises DPoP cutover"
  curl -s "$SSO_URL/.well-known/openid-configuration" \
    | jq -e '(.claims_supported | index("cnf") != null)
             and ((.dpop_signing_alg_values_supported // []) | index("EdDSA") != null)' \
    >/dev/null \
    || { red "External SSO does not advertise cnf + EdDSA DPoP. Cutover not deployed there."; exit 1; }
  green "  ✓ external SSO advertises cnf + EdDSA"
fi

assert() {
  local label=$1 ; shift
  if "$@"; then green "  ✓ $label"; else red "  ✗ $label"; exit 1; fi
}

# Local demo-service runs over plain HTTP; external can be either. Pass
# --allow-insecure to discover-service / service-support only when the demo
# URL is http://. Real https endpoints obviously don't need it.
INSECURE_FLAG=()
if [[ "$RESOLVED_DEMO_URL" == http://* ]]; then
  INSECURE_FLAG=(--allow-insecure)
fi

blue "▸ Step 1: init"
cli init >/tmp/integ.init.json
assert "fingerprint produced" \
  bash -c 'jq -e ".fingerprint | type == \"string\"" /tmp/integ.init.json >/dev/null'

blue "▸ Step 2: auth (begin OIDC, dpop_jkt advertised)"
cli auth --provider-address "$PROVIDER" --sso-url "$RESOLVED_SSO_URL" >/tmp/integ.auth.json
assert "polling_code returned" \
  bash -c 'jq -e ".pollingCode | type == \"string\"" /tmp/integ.auth.json >/dev/null'

if [[ -n "$SSO_URL" ]]; then
  yellow ""
  yellow "  ┌─ Approve in the Alien App (build pointing at $SSO_URL)"
  yellow "  │  Deep link: $(jq -r .deepLink /tmp/integ.auth.json)"
  yellow "  └─ Bind will poll for up to ${BIND_TIMEOUT_SEC}s."
  yellow ""
fi

blue "▸ Step 3: bind (poll → exchange → verify cnf.jkt)"
cli bind --timeout-sec "$BIND_TIMEOUT_SEC" --poll-interval-ms 1000 >/tmp/integ.bind.json
assert "owner sub returned" \
  bash -c 'jq -e ".ownerSub | type == \"string\"" /tmp/integ.bind.json >/dev/null'
assert "agent jkt returned" \
  bash -c 'jq -e ".jkt | type == \"string\"" /tmp/integ.bind.json >/dev/null'

blue "▸ Step 4: status reports bound"
cli status >/tmp/integ.status.json
assert "bound==true" \
  bash -c 'jq -e ".bound == true" /tmp/integ.status.json >/dev/null'

blue "▸ Step 5: discover-service (well-known fetch)"
cli discover-service --url "$RESOLVED_DEMO_URL" "${INSECURE_FLAG[@]}" >/tmp/integ.discover.json
assert "manifest version 1" \
  bash -c 'jq -e ".manifest.version == 1" /tmp/integ.discover.json >/dev/null'
assert "manifest auth.scheme is DPoP" \
  bash -c '[[ "$(jq -r .manifest.auth.scheme /tmp/integ.discover.json)" = "DPoP" ]]'
assert "api.base under same authority" \
  bash -c "[[ \"\$(jq -r .manifest.api.base /tmp/integ.discover.json)\" =~ $RESOLVED_DEMO_URL ]]"

blue "▸ Step 6: service-support (meta-tag probe)"
cli service-support --url "$RESOLVED_DEMO_URL" "${INSECURE_FLAG[@]}" >/tmp/integ.support.json
assert "supported v1" \
  bash -c '[[ "$(jq -r .version /tmp/integ.support.json)" = "v1" ]]'

# Step 7+: RFC 9449 puts two headers on the wire — `Authorization: DPoP <at>`
# and `DPoP: <proof>`. The `cli call` one-shot wraps that for normal callers;
# the steps below use `cli auth-header --raw` so they can exercise tampered /
# bare-token failure paths via curl.

blue "▸ Step 7: auth-header --raw → call /api/v1/whoami"
HDR=$(cli auth-header --url "$RESOLVED_DEMO_URL/api/v1/whoami" --method GET --raw)
AUTH_LINE=$(printf '%s\n' "$HDR" | grep '^Authorization:')
DPOP_LINE=$(printf '%s\n' "$HDR" | grep '^DPoP:')
HTTP_CODE=$(curl -s -o /tmp/integ.whoami.json -w '%{http_code}' \
  -H "$AUTH_LINE" -H "$DPOP_LINE" "$RESOLVED_DEMO_URL/api/v1/whoami")
assert "service returns 200" bash -c "[[ '$HTTP_CODE' = '200' ]]"
assert "owner sub matches binding" \
  bash -c 'test "$(jq -r .owner_sub /tmp/integ.whoami.json)" = "$(jq -r .ownerSub /tmp/integ.bind.json)"'
assert "agent jkt matches binding" \
  bash -c 'test "$(jq -r .agent_jkt /tmp/integ.whoami.json)" = "$(jq -r .jkt /tmp/integ.bind.json)"'

blue "▸ Step 8: tampered DPoP proof → 401"
HDR_T=$(cli auth-header --url "$RESOLVED_DEMO_URL/api/v1/whoami" --method GET --raw)
AUTH_T=$(printf '%s\n' "$HDR_T" | grep '^Authorization:')
DPOP_T=$(printf '%s\n' "$HDR_T" | grep '^DPoP:')
# Flip a character mid-signature (after the second '.') so the proof JWS no longer verifies.
DPOP_TAMP=$(printf '%s' "$DPOP_T" | sed 's/\(.\{40\}\).\(.*\)/\1Z\2/')
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH_T" -H "$DPOP_TAMP" "$RESOLVED_DEMO_URL/api/v1/whoami")
assert "tampered DPoP → 401"  bash -c "[[ '$CODE' = '401' ]]"

blue "▸ Step 9: missing DPoP header → 401"
HDR_B=$(cli auth-header --url "$RESOLVED_DEMO_URL/api/v1/whoami" --method GET --raw)
AUTH_B=$(printf '%s\n' "$HDR_B" | grep '^Authorization:')
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH_B" "$RESOLVED_DEMO_URL/api/v1/whoami")
assert "no DPoP → 401"  bash -c "[[ '$CODE' = '401' ]]"

blue "▸ Step 10: refresh (DPoP-bound, sticky cnf.jkt)"
cli refresh >/tmp/integ.refresh.json
assert "refresh ok" \
  bash -c 'jq -e ".ok == true" /tmp/integ.refresh.json >/dev/null'

blue "▸ Step 11: post-refresh, service call still 200"
HDR2=$(cli auth-header --url "$RESOLVED_DEMO_URL/api/v1/whoami" --method GET --raw)
AUTH2=$(printf '%s\n' "$HDR2" | grep '^Authorization:')
DPOP2=$(printf '%s\n' "$HDR2" | grep '^DPoP:')
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH2" -H "$DPOP2" "$RESOLVED_DEMO_URL/api/v1/whoami")
assert "post-refresh → 200"  bash -c "[[ '$CODE' = '200' ]]"

green ""
green "All 11 integration steps passed."
