#!/usr/bin/env bash
# SSO container entrypoint.
#
# CONSTRAINT (agent-id-core lib/http.mjs normalizeBaseUrl): the SSO base URL
# must be https:// OR loopback http://. In a compose network `http://sso:5050`
# is NOT loopback, so it would be rejected. We make EVERY container talk to
# `http://127.0.0.1:5050` instead.
#
# dev-sso derives its issuer from --host: ISSUER = `http://${HOST}:${PORT}`.
# For the issuer baked into every id_token to be `http://127.0.0.1:5050`
# (reachable via loopback from all containers), dev-sso must bind 127.0.0.1.
# But then peers can't reach it. So:
#
#   dev-sso  --host 127.0.0.1 --port 5050        (issuer = http://127.0.0.1:5050)
#   socat    0.0.0.0:5050  ->  127.0.0.1:5050    (reachable as sso:5050 on the net)
#
# Device containers run the mirror-image forward (127.0.0.1:5050 -> sso:5050),
# so a device CLI hits http://127.0.0.1:5050 locally and it lands on this SSO.
set -euo pipefail

echo "[sso] starting dev-sso on 127.0.0.1:5050 (issuer http://127.0.0.1:5050)" >&2
node /app/examples/dev-sso.mjs --host 127.0.0.1 --port 5050 --verbose &
SSO_PID=$!

# Wait until dev-sso is answering on loopback, then expose it on the network.
for _ in $(seq 1 150); do
  curl -fsS http://127.0.0.1:5050/.well-known/openid-configuration >/dev/null 2>&1 && break
  sleep 0.2
done

# dev-sso already owns 127.0.0.1:5050, so socat CANNOT bind 0.0.0.0:5050
# (that range includes loopback). Bind socat to the container's own network
# IP (eth0) only, so `sso:5050` on the mesh reaches dev-sso on loopback.
ETH_IP=$(hostname -i | awk '{print $1}')
echo "[sso] forwarding ${ETH_IP}:5050 -> 127.0.0.1:5050 (socat)" >&2
socat TCP-LISTEN:5050,fork,reuseaddr,bind="${ETH_IP}" TCP:127.0.0.1:5050 &
SOCAT_PID=$!

trap 'kill "$SSO_PID" "$SOCAT_PID" 2>/dev/null || true' INT TERM
wait "$SSO_PID"
