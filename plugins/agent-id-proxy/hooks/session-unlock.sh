#!/usr/bin/env bash
# Opt-in once-per-session vault unlock (1Password-style). Runs at SessionStart.
#
# Does NOTHING unless the user opted in by creating the marker file (the
# `agent-id-proxy autounlock` subcommand does this):
#     "${AGENT_ID_STATE_DIR:-$HOME/.agent-id}/autounlock"
# The marker's (optional) contents are extra `proxy start` args, e.g.:
#     --idle-timeout 8h
#
# When enabled, a vault exists, and no proxy is already running, it launches
# `proxy start --unlock-form` detached — so the unlock form pops once for the
# human and the proxy then serves the session. Needs a vault with a passphrase
# slot (dev mode) for the form unlock. Fail-soft: never blocks the session.
set -u

STATE="${AGENT_ID_STATE_DIR:-$HOME/.agent-id}"
MARK="$STATE/autounlock"
[ -f "$MARK" ] || exit 0                         # opt-in only
[ -f "$STATE/vault.enc" ] || exit 0              # need a vault
[ -n "${CLAUDE_PLUGIN_ROOT:-}" ] || exit 0
command -v node >/dev/null 2>&1 || exit 0
CLI="$CLAUDE_PLUGIN_ROOT/bin/cli.mjs"

# A proxy already running ⇒ nothing to unlock at session start.
if node "$CLI" status --state-dir "$STATE" 2>/dev/null | grep -q '"running": *true'; then
  exit 0
fi

# Extra `start` args from the marker (capped, single line).
EXTRA="$(head -c 400 "$MARK" 2>/dev/null | tr '\n' ' ')"

# Detached so the hook returns immediately; the proxy serves the session and the
# unlock form opens for the human. Output goes to a log, not the session.
# shellcheck disable=SC2086
nohup node "$CLI" start --unlock-form --state-dir "$STATE" $EXTRA \
  >>"$STATE/autounlock.log" 2>&1 &
disown 2>/dev/null || true
exit 0
