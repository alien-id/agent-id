# SSO: DPoP-bound authorize+token mints cnf-bearing tokens

**Type:** AFK
**Repo:** `alien-id/sso`
**Source PRD:** [docs/PRD-DPOP-POP.md](../PRD-DPOP-POP.md)

## Parent

PRD: RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

## What to build

Make `/oauth/authorize` accept an optional `dpop_jkt` query parameter and `/oauth/token` honor it, so a DPoP-bound authorization-code exchange yields an `id_token` and `access_token` carrying `cnf: {jkt: <thumbprint>}`. This is the minimal end-to-end DPoP flow at the SSO; everything else in the PRD layers on top.

The slice covers, in one drop:

- **Schema:** new nullable column `oauth_sessions.dpop_jkt TEXT` (43-char base64url SHA-256 thumbprint) and new table `dpop_jti_seen (jti TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL)` with an index on `expires_at`.
- **`service.DPoPVerifier`** — new deep module with a single public method `VerifyProof(httpMethod, httpURI, dpopHeader) → (thumbprint, error)`. Internals: parse compact JWS, validate `typ=dpop+jwt` and `alg=EdDSA`, decode the embedded `jwk` (kty=OKP, crv=Ed25519), verify the Ed25519 signature, validate `htm` / `htu` / `iat (±60s)`, atomically insert `jti` (PK conflict ⇒ replay), compute and return the RFC 7638 thumbprint. Alg dispatch is a switch so ES256/RS256 can be added later.
- **`service.JWTService`** — extended so `CreateIDToken` and `CreateAccessToken` accept an optional `cnfJkt`. When set, the token carries `cnf: {jkt: ...}`. When unset, output is byte-identical to today.
- **`handler.OAuthAuthorizeHandler`** — accepts optional `dpop_jkt` query param (43-char base64url, decodes to 32 bytes); persists it on the `oauth_sessions` row.
- **`handler.OAuthTokenHandler`** (auth-code grant only in this slice; refresh path is issue #3): if the loaded session row has `dpop_jkt`, require the `DPoP` request header, call `DPoPVerifier`, assert returned thumbprint equals the session's `dpop_jkt`, then pass that thumbprint to both `CreateIDToken` and `CreateAccessToken`. If the session has no `dpop_jkt`, behavior is unchanged.
- **`service.SessionCleaner`** — extended to GC `dpop_jti_seen` rows past `expires_at`, alongside the existing expired-session sweep.

The non-DPoP path through authorize→token is preserved exactly: a request without `dpop_jkt` and without a `DPoP` header completes today's no-DPoP flow with byte-identical token output.

## Acceptance criteria

- [ ] Migration adds `oauth_sessions.dpop_jkt` (nullable) and `dpop_jti_seen (jti PK, expires_at, idx on expires_at)` and applies cleanly forward and back.
- [ ] `DPoPVerifier.VerifyProof` returns the correct RFC 7638 thumbprint for a valid Ed25519 DPoP proof and rejects each of: `typ != dpop+jwt`, `alg != EdDSA`, malformed JWK, tampered signature, `htm` mismatch, `htu` mismatch, `iat` outside `±60s`, reused `jti`. Each rejection has a distinct error.
- [ ] Concurrent token requests using the same `jti` resolve to exactly one success and one replay rejection (testcontainers Postgres race coverage).
- [ ] `JWTService.CreateIDToken` / `CreateAccessToken` produce JSON with no `cnf` claim when `cnfJkt` is unset (byte-identical to today's output) and produce `cnf: {jkt: <value>}` when set; both verify against the existing JWKS.
- [ ] `/oauth/authorize` validates `dpop_jkt` (43-char base64url decoding to 32 bytes); rejects malformed values; persists valid values on the session row.
- [ ] `/oauth/token` (auth-code grant): when the session row has `dpop_jkt`, a request without `DPoP` is rejected; a request with a `DPoP` header whose proof thumbprint differs from the session's `dpop_jkt` is rejected; a matching proof yields tokens with `cnf.jkt` equal to that thumbprint.
- [ ] `/oauth/token` non-DPoP path: when the session row has no `dpop_jkt`, presence/absence of a `DPoP` header is ignored and the issued tokens carry no `cnf` claim.
- [ ] `internal/handler/full_flow_oauth_test.go` keeps its existing no-DPoP scenario unchanged AND grows a new scenario covering `dpop_jkt` at authorize → DPoP at token → id_token has `cnf.jkt` matching the agent's pubkey thumbprint.
- [ ] `SessionCleaner` removes `dpop_jti_seen` rows whose `expires_at` is in the past on its next sweep; existing session GC behavior is unchanged.

## Out of scope (handled in follow-up issues)

- DPoP enforcement at `/oauth/userinfo` (issue #2).
- DPoP requirement on the refresh-token grant path (issue #3).
- OIDC discovery advertising DPoP capability (issue #4).

## Blocked by

None — can start immediately.
