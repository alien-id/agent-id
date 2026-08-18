# @alien-id/agent-id-proxy

This package is `private` and listed in `.changeset/ignore`, so changesets never versions or
publishes it and cannot generate this file. Notable changes are recorded here by hand.

## Unreleased

### Minor Changes

- Opt-in data-plane authentication: `--auth-token-file <path>` makes the proxy
  require `X-Agent-Id-Proxy-Token` (constant-time compared) on every data-plane
  request and CONNECT, refused with 401 before any vault access. The token file
  must be 0600 and hold printable ASCII, both checked before the vault is opened.
  The header is stripped before forwarding upstream in both data-plane modes.
  Repeated refusals are coalesced in the access log — one line per minute with a
  suppressed count — so an unauthenticated caller cannot grow the log at will;
  the count a window ends on is written out by the next log entry, or by
  `close()`, as `auth_failed_suppressed`, so a flood that simply stops still
  leaves a record.
  A CORS preflight is never relayed upstream: auth runs first, so an
  unauthenticated preflight is refused with 401 like any other request, and an
  authenticated one (or any preflight when auth is off) is answered locally with
  403 `cross_origin_refused` and no `Access-Control-Allow-*`.
  
  The CONNECT tunnel now also runs the SSRF guard the forwarded path has always
  run — link-local (incl. cloud metadata), unspecified and multicast targets are
  refused with 403 `upstream_blocked`, as are loopback/RFC1918/ULA targets under
  `--block-private-hosts`, for literal addresses and for hostnames that resolve
  into a blocked range. Its target must be authority-form (`host:port`, numeric
  port in range): a malformed one is refused with 400 `bad_request` instead of
  throwing out of the handler. On an idle-locked vault the tunnel self-reopens
  only where a request would — the auto-unlock path with the control plane off;
  with the control plane on the unlock stays the owner's decision and the tunnel
  is refused with 401 `vault_locked`.

- Self-reopen for unattended deployments: when the vault was unlocked via the
  agent-key slot, the proxy can reopen it without a restart — a credential
  written after spawn is picked up on next use (one reopen + retry on a miss),
  and an idle lock without the control plane recovers on the next request.
  Consent/control-plane behavior is unchanged. Every write to `vault.enc` — a
  rotated OAuth refresh token, and phone pairing — now goes through a handle
  re-read from disk, and is refused when the vault cannot be re-read, so a write
  can no longer erase credentials another process added since the proxy started
  (a refused rotation stays in the in-memory cache and is logged; a refused
  pairing answers `409 vault_reread_unavailable`). The replaced handle is locked
  (no second decrypted copy in the heap) and its cached OAuth refresh tokens are
  dropped so a re-authorized credential's new refresh token wins, while still-valid
  access tokens are kept — a reopen costs no extra token-endpoint round trips.
