# SSO: DPoP on refresh-token grant

**Type:** AFK
**Repo:** `alien-id/sso`
**Source PRD:** [docs/PRD-DPOP-POP.md](../PRD-DPOP-POP.md)

## Parent

PRD: RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

## What to build

Extend the refresh-token grant path of `OAuthTokenHandler` to require a fresh DPoP proof when the original session was DPoP-bound, and to reissue refreshed tokens carrying the same `cnf.jkt` (RFC 9449 §5). Refresh of plain (non-DPoP) sessions is unchanged.

When the session row has `dpop_jkt`, the refresh request must include a `DPoP` header. The handler calls `service.DPoPVerifier`, asserts the returned thumbprint equals the session's `dpop_jkt`, then mints the new id_token and access_token with `cnf.jkt` set to that thumbprint — preserving binding across refresh.

## Acceptance criteria

- [ ] Refresh request against a DPoP-bound session without a `DPoP` header is rejected with 401.
- [ ] Refresh request with a valid DPoP proof whose thumbprint matches the session's `dpop_jkt` succeeds and reissues tokens carrying `cnf.jkt` equal to that thumbprint.
- [ ] Refresh request with a DPoP proof whose thumbprint differs from the session's `dpop_jkt` is rejected.
- [ ] Refresh request against a non-DPoP session works exactly as today, regardless of whether a `DPoP` header is present, and reissues plain Bearer tokens with no `cnf` claim.
- [ ] Replay of a DPoP `jti` across refresh attempts within the freshness window is rejected.
- [ ] `internal/handler/full_flow_oauth_test.go` covers refresh on DPoP-bound and plain sessions, including the rejection cases above.

## Blocked by

- Blocked by #1 (SSO: DPoP-bound authorize+token mints cnf-bearing tokens) — needs `DPoPVerifier`, schema, and JWTService cnf extension.
