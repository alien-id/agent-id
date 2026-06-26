#!/usr/bin/env bash
# Materialize this plugin's npm dependencies (the shared @alien-id/agent-id-*
# libraries, plus any optional extras) at runtime, then expose them to the
# plugin's ESM code.
#
# Why this exists: the marketplace installs each plugin into its own isolated,
# versioned cache dir with NO sibling plugins and NO node_modules. The plugin's
# .mjs files import shared code as bare specifiers (`@alien-id/agent-id-core/...`),
# which Node resolves by walking up from the importing file looking for a
# node_modules directory. So we:
#   1. npm install the deps into CLAUDE_PLUGIN_DATA (persistent across sessions),
#   2. symlink CLAUDE_PLUGIN_ROOT/node_modules -> CLAUDE_PLUGIN_DATA/node_modules.
# CLAUDE_PLUGIN_ROOT is ephemeral (recreated each session), so only the symlink
# lives there and the hook recreates it every SessionStart; the real packages
# persist in CLAUDE_PLUGIN_DATA.
#
# Requires @alien-id/agent-id-core (+ -vault) to be published to npm first.
#
# Idempotent: skips the install when package.json is unchanged and node_modules
# is present. Fail-soft: never blocks or fails the session — on error it leaves a
# note and exits 0; the next session retries.
set -u

D="${CLAUDE_PLUGIN_DATA:-}"
R="${CLAUDE_PLUGIN_ROOT:-}"
[ -n "$D" ] && [ -n "$R" ] || exit 0   # dev / not run by the plugin harness
command -v npm >/dev/null 2>&1 || exit 0
mkdir -p "$D" || exit 0

link_node_modules() {
  # Point the ephemeral plugin root at the persistent node_modules. Skip when a
  # real node_modules already lives in the root (e.g. a dev checkout).
  if [ -e "$R/node_modules" ] && [ ! -L "$R/node_modules" ]; then return; fi
  [ -d "$D/node_modules" ] && ln -sfn "$D/node_modules" "$R/node_modules"
}

# Already installed and up to date? Refresh the (ephemeral) symlink and bail.
if [ -d "$D/node_modules" ] && diff -q "$R/package.json" "$D/package.json" >/dev/null 2>&1; then
  link_node_modules
  exit 0
fi

cp "$R/package.json" "$D/package.json"

if ( cd "$D" && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
      npm install --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error >/dev/null 2>&1 ); then
  link_node_modules
  exit 0
fi

# Install failed — drop the marker so the next session retries.
rm -f "$D/package.json"
echo "agent-id: dependency install deferred (offline?) — will retry next session" >&2
exit 0
