#!/usr/bin/env bash
# Device container entrypoint — sets up the loopback SSO forward, then idles so
# the orchestrator can `docker compose exec` scenario steps into it.
#
#   socat 127.0.0.1:5050 -> sso:5050
#
# This is the mirror of the SSO container's forward: every CLI in this device
# talks to http://127.0.0.1:5050 (loopback → passes normalizeBaseUrl), and the
# bytes land on the shared dev-sso via compose DNS name `sso`.
set -euo pipefail

DEVICE=${DEVICE:-device}

# Force a genuinely headless environment. agent-id's hasTty() (core
# lib/trusted-input.mjs) decides "is a human here?" by whether /dev/tty is
# ACCESSIBLE (fs.accessSync, an existence check). In a containerized-root env
# /dev/tty is present + 0666, so hasTty() returns true even with no controlling
# terminal — and the vault sync approval prompt would block forever on a stdin
# that never gets a human "y/N". Replacing /dev/tty with a dangling symlink
# makes accessSync throw ENOENT → hasTty() is false → the CLI takes its proper
# headless path (sync prints approval-required and logs the peer jkt instead of
# prompting). AGENT_ID_SYNC_AUTOAPPROVE is checked BEFORE hasTty(), so the
# auto-approve scenarios are unaffected. This is a test-env shim only; no
# product code is touched.
rm -f /dev/tty && ln -s /nonexistent-agent-id-e2e /dev/tty

echo "[$DEVICE] forwarding 127.0.0.1:5050 -> sso:5050 (socat)" >&2
socat TCP-LISTEN:5050,fork,reuseaddr,bind=127.0.0.1 TCP:sso:5050 &
SOCAT_PID=$!

mkdir -p /state
trap 'kill "$SOCAT_PID" 2>/dev/null || true' INT TERM

echo "[$DEVICE] ready (SSO forward up). Idling for exec steps." >&2
# Idle forever; scenario steps arrive via `docker compose exec`.
tail -f /dev/null &
wait $!
