---
"@alien-id/agent-id-proxy": minor
---

Opt-in data-plane authentication: `--auth-token-file <path>` makes the proxy
require `X-Agent-Id-Proxy-Token` (constant-time compared) on every data-plane
request and CONNECT, refused with 401 before any vault access. The token file
must be 0600 and hold printable ASCII, both checked before the vault is opened.
The header is stripped before forwarding upstream in both data-plane modes.
Repeated refusals are coalesced in the access log — one line per minute with a
suppressed count — so an unauthenticated caller cannot grow the log at will.
A CORS preflight is never relayed upstream: auth runs first, so an
unauthenticated preflight is refused with 401 like any other request, and an
authenticated one (or any preflight when auth is off) is answered locally with
403 `cross_origin_refused` and no `Access-Control-Allow-*`.

The CONNECT tunnel now also runs the SSRF guard the forwarded path has always
run — link-local (incl. cloud metadata), unspecified and multicast targets are
refused with 403 `upstream_blocked`, as are loopback/RFC1918/ULA targets under
`--block-private-hosts`, for literal addresses and for hostnames that resolve
into a blocked range — and it self-reopens an idle-locked vault on the
auto-unlock path instead of refusing.
