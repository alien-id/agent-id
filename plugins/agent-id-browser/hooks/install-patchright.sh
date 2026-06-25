#!/usr/bin/env bash
# Install patchright into the plugin's persistent data dir on first use.
#
# The marketplace ships NO node_modules (bundling 17 MB would bloat the pinned
# commit, and patchright is only needed for browser mode), so we materialize it
# at runtime here. The plugin's CLI then resolves patchright from this data dir
# (see lib/launch.mjs).
#
# Idempotent: only (re)installs when patchright is missing or package.json changed.
# Lean: patchright has no postinstall, and we drive the user's installed Chrome
# (channel="chrome"), so there is NO ~150 MB browser-binary download — just the
# stealth-patched driver JS (~17 MB). Stealth is a property of that driver, so it
# applies to the user's Chrome unchanged.
#
# Fail-soft: never blocks or fails the session — on error (e.g. offline) it leaves
# a note and exits 0; the next session retries and browser mode surfaces a clear
# PATCHRIGHT_MISSING error in the meantime.
set -u

D="${CLAUDE_PLUGIN_DATA:-}"
R="${CLAUDE_PLUGIN_ROOT:-}"
[ -n "$D" ] && [ -n "$R" ] || exit 0   # not run by the plugin harness; nothing to do
mkdir -p "$D" || exit 0

# Already installed and up to date?
if [ -d "$D/node_modules/patchright" ] && diff -q "$R/package.json" "$D/package.json" >/dev/null 2>&1; then
  exit 0
fi

cp "$R/package.json" "$D/package.json"
[ -f "$R/package-lock.json" ] && cp "$R/package-lock.json" "$D/package-lock.json"

if ( cd "$D" && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
      npm install --omit=dev --no-audit --no-fund --loglevel=error >/dev/null 2>&1 ); then
  exit 0
fi

# Install failed — drop the marker so the next session retries.
rm -f "$D/package.json"
echo "agent-id-browser: patchright install deferred (offline?) — browser mode will retry next session" >&2
exit 0
