#!/usr/bin/env bash
# Shared helpers for the in-container e2e scenario steps.
# Sourced by device-entry.sh / scenario.sh. Never run directly.

CORE="node /app/plugins/agent-id-core/bin/cli.mjs"
VAULT="node /app/plugins/agent-id-vault/bin/cli.mjs"

log()  { printf '  [%s] %s\n' "${DEVICE:-e2e}" "$*" >&2; }
die()  { printf '  [%s] FATAL: %s\n' "${DEVICE:-e2e}" "$*" >&2; exit 1; }

# Poll a URL until it answers 200, or fail after ~30s.
wait_http() {
  local url=$1 name=${2:-endpoint}
  for _ in $(seq 1 150); do
    curl -fsS "$url" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  die "timed out waiting for $name at $url"
}

# Poll a log file for a marker line, or fail after ~20s.
wait_log() {
  local file=$1 marker=$2 name=${3:-marker}
  for _ in $(seq 1 100); do
    [ -f "$file" ] && grep -q "$marker" "$file" && return 0
    sleep 0.2
  done
  die "timed out waiting for '$marker' in $name ($file)"
}

# Extract a field from a CLI JSON blob on stdin using node (no jq dependency).
# Usage:  echo "$json" | jget '.credentials.map(c=>c.name+":"+c.type).sort().join(",")'
jget() {
  node -e '
    let s=""; process.stdin.on("data",d=>s+=d).on("end",()=>{
      const j=JSON.parse(s);
      const f=new Function("j","return ("+process.argv[1]+");");
      const v=f(j);
      process.stdout.write(typeof v==="string"?v:JSON.stringify(v));
    });
  ' "$1"
}

# Sorted "name:type" set of the current vault credentials.
cred_set() { $VAULT list 2>/dev/null | jget 'j.credentials.map(c=>c.name+":"+c.type).sort().join(",")'; }
