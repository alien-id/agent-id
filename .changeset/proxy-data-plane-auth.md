---
"@alien-id/agent-id-proxy": minor
---

Opt-in data-plane authentication: `--auth-token-file <path>` makes the proxy
require `X-Agent-Id-Proxy-Token` (constant-time compared) on every data-plane
request and CONNECT, refused with 401 before any vault access. The header is
stripped before forwarding upstream in both data-plane modes. CORS preflights
are now always answered locally with 403 and never relayed upstream.
