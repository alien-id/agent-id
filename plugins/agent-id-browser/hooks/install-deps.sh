#!/usr/bin/env bash
# Install this plugin's shared @alien-id/* deps at runtime so its imports resolve.
#
# Official "Persistent data directory" plugin pattern: a SessionStart hook
# `npm install`s into CLAUDE_PLUGIN_DATA (persistent). The docs pair that with
# NODE_PATH, but NODE_PATH is CJS-only and our code is ESM (+ one CJS qrcode.cjs
# createRequire) — so instead we symlink node_modules into the (ephemeral) plugin
# root, one mechanism for both. The symlink is a regenerated pointer, not state;
# real packages stay in CLAUDE_PLUGIN_DATA and a real dev node_modules is kept.
#
# Needs @alien-id/agent-id-core (+ -vault) published first. Idempotent; fail-soft.
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
