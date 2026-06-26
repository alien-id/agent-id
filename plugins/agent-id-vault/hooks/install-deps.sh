#!/usr/bin/env bash
# Materialize this plugin's npm dependencies (the shared @alien-id/agent-id-*
# libraries, plus any optional extras) at runtime, then expose them to the
# plugin's code.
#
# This is the official Claude Code "Persistent data directory" pattern (Plugins
# reference): a SessionStart hook runs `npm install` into CLAUDE_PLUGIN_DATA
# (persistent across plugin updates) — the docs' exact recommendation for
# installing language dependencies once and reusing them across sessions.
#
# One deliberate extension. The docs pair that install with NODE_PATH, but
# NODE_PATH is CJS-only — Node ignores it for ESM `import`. Our plugins are ESM
# (.mjs, bare specifiers like `@alien-id/agent-id-core/lib/crypto.mjs`) plus one
# CJS `createRequire` (proxy's qrcode.cjs). Both resolve by walking up from the
# importing file to a node_modules dir, and CLAUDE_PLUGIN_DATA is not on that
# path. So instead of NODE_PATH we place a node_modules SYMLINK in the plugin
# root — one mechanism that serves ESM and CJS uniformly.
#
# CLAUDE_PLUGIN_ROOT is documented as ephemeral ("do not write state here"); we
# honor that — the symlink is a pointer, not state. No real files are written to
# the root, it is recreated every SessionStart, and all real packages live in
# CLAUDE_PLUGIN_DATA, so it survives plugin updates (new root -> hook re-links).
# A pre-existing real node_modules in the root (dev checkout) is never clobbered.
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
