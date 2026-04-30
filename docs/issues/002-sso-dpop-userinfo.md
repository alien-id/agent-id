# SSO: DPoP-bound userinfo enforcement

**Type:** AFK
**Repo:** `alien-id/sso`
**Source PRD:** [docs/PRD-DPOP-POP.md](../PRD-DPOP-POP.md)

## Parent

PRD: RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

## What to build

Extend `/oauth/userinfo` to enforce a fresh DPoP proof when the presented access_token carries `cnf.jkt`. Plain Bearer access_tokens (issued in non-DPoP flows) keep current Bearer-only behavior. Enforcement is per-token, not per-endpoint — non-agent clients are untouched.

`OAuthUserInfoHandler` reads `claims.Cnf.Jkt` off the verified access_token. If non-empty, it requires a `DPoP` header on the request, calls `service.DPoPVerifier` (introduced in issue #1), and asserts the returned thumbprint equals the AT's `cnf.jkt`. Any failure is a 401 with `WWW-Authenticate: DPoP error="invalid_token"` per RFC 9449 §7.1.

## Acceptance criteria

- [ ] An access_token with `cnf.jkt` presented to `/oauth/userinfo` without a `DPoP` header is rejected with 401.
- [ ] An access_token with `cnf.jkt` presented with a valid DPoP proof whose thumbprint matches the AT's `cnf.jkt` succeeds.
- [ ] An access_token with `cnf.jkt` presented with a valid DPoP proof whose thumbprint differs from the AT's `cnf.jkt` is rejected with 401.
- [ ] An access_token with `cnf.jkt` presented with a DPoP proof whose `htm`/`htu` does not match the userinfo endpoint is rejected.
- [ ] An access_token with `cnf.jkt` presented with a replayed DPoP proof (same `jti` within freshness window) is rejected.
- [ ] A plain Bearer access_token (no `cnf.jkt`) presented to `/oauth/userinfo` continues to work with today's Bearer-only behavior, regardless of whether a `DPoP` header is present.
- [ ] `internal/handler/full_flow_oauth_test.go` grows scenarios covering all of the above.
- [ ] 401 responses on DPoP failure carry the RFC 9449 `WWW-Authenticate: DPoP` challenge header.

## Blocked by

- Blocked by #1 (SSO: DPoP-bound authorize+token mints cnf-bearing tokens) — needs `DPoPVerifier`, the `cnf` claim on access_tokens, and the schema in place.
