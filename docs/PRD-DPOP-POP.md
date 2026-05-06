# Design — RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

**Status:** Implemented (3.0.0)
**Scope:** `alien-id/sso` (OIDC server) + `alien-id/agent-id` (CLI + verifier)
**Threat artifact:** [agent-id-forgery-poc](https://github.com/truehazker-eti/agent-id-forgery-poc)

---

## Problem

Pre-3.0, the SSO `id_token` did not commit to the agent's keypair. Anyone who could read a public repo's `refs/notes/agent-id` could extract a victim's `id_token`, generate their own Ed25519 keypair, hand-build an `owner-binding.json` claiming the victim's AlienID, and mint commits that pass `git-verify` end-to-end with `"ok": true`. Forgeries were indistinguishable from legitimate commits and survived `id_token` expiry, refresh-token revocation, and account changes — only rotating SSO's JWKS could invalidate them, which never happens.

Single root cause: **missing cryptographic binding** between the agent's keypair and the SSO-issued token.

## Solution

Bind the agent's public key into the OAuth flow via RFC 9449 DPoP and have SSO mint `id_tokens` carrying an RFC 7800 `cnf.jkt` confirmation claim (the agent's RFC 7638 JWK thumbprint). The Agent-ID verifier asserts `cnf.jkt == thumbprint(agent_jwk_in_proof_bundle)`. A mismatch terminates verification.

The `cnf.jkt` lives inside the SSO RS256 signature — it cannot be substituted offline. After the cutover, forgery requires private-key compromise (the assumed-out-of-scope baseline of all signature protocols), not extraction of a public artifact.

## Architectural decisions (as shipped)

- **Generic OAuth feature, not an agent feature.** SSO never learns the term "agent." DPoP is implemented as the standards-compliant capability of RFC 9449. PoP-bound id_tokens follow RFC 7800. Agent-ID happens to require both; future OIDC clients may opt in.
- **DPoP is opt-in at the SSO per-flow.** A flow becomes DPoP-bound when `dpop_jkt` is present at `/oauth/authorize`. If absent, behavior is exactly as before. **Humans signing in via standard OIDC RPs are unaffected.** Hard cutover applies to the agent-id CLI, not to the OIDC surface.
- **Both binding points enforced.** `dpop_jkt` query param at `/authorize` (locks the keypair into the auth session) AND `DPoP` proof header at `/token` (proves possession at exchange). Truncating to either alone weakens the chain.
- **Per-token enforcement at userinfo.** DPoP-bound ATs require `Authorization: DPoP` + per-request proof + `ath` claim matching `SHA-256(access_token)`. Bearer-only ATs require `Authorization: Bearer`. Cross-mismatch is rejected.
- **EdDSA-only DPoP.** Verifier is structured as an `alg`-switch; ES256/RS256 are a switch-case extension, not a redesign.
- **Hard cutover for the verifier.** `id_tokens` lacking `cnf.jkt` are rejected unconditionally. No flag, no grace period — every cnf-less `id_token` is a live forgery primitive.
- **Refresh tokens are not rotated.** Sticky `cnf.jkt` makes a stolen refresh token unusable to anyone without the matching private key. Rotation is not a load-bearing defense in this threat model.
- **Server does not issue DPoP nonces (RFC 9449 §8).** Replay defense is `iat` freshness + `jti` server-side dedup. The agent-id client tolerates and handles nonce challenges from third-party DPoP servers; per-URL nonce caching avoids the 400→retry roundtrip on subsequent calls.
- **No new scopes, no agent registry, no per-commit attestation API.** Out of scope for this release; warrants separate design once production usage informs requirements.

## Security invariants (enforced by tests)

1. `id_token` lacking `cnf.jkt` is rejected by the verifier. Always.
2. `id_token` with `cnf.jkt` mismatched against agent's JWK is rejected. Always.
3. DPoP proof signature must verify against the embedded JWK (RFC 9449 §4.3 step 2).
4. Proof's `jwk` header must not contain any RFC 7517 private-key member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`).
5. Proof's `htu`, after canonicalization (lowercase scheme/host, default-port stripped, query+fragment dropped), must equal the canonicalized request URI.
6. Proof's `htm` must equal the request method.
7. Proof's `iat` must be within `SIGNATURE_MAX_AGE_SEC + CLOCK_SKEW_TOLERANCE_SEC` of server time.
8. `(jkt, jti)` must not be in `dpop_jti_seen`. Idempotent insert via PK conflict.
9. `jti` must not exceed 256 chars (DB-write defense).
10. Multiple `DPoP` headers on a single request are rejected at every entry point.
11. At `/oauth/authorize`, `dpop_jkt` query duplication is rejected (RFC 9449 doesn't define a tiebreak).
12. At `/oauth/token`, the proof's JWK thumbprint must equal the session's persisted `dpop_jkt`.
13. At `/oauth/userinfo`, the proof's `ath = base64url(SHA-256(access_token))` is required and equality-checked against the AT bytes the server received.
14. At `/oauth/userinfo`, scheme is strictly typed by binding: bound AT requires `DPoP`, unbound AT requires `Bearer`, cross-mismatch → 401.
15. Userinfo 401s carry `WWW-Authenticate: DPoP error="invalid_token", algs="EdDSA"` for bound rejections, `Bearer` for unbound.
16. Userinfo successful responses set `Cache-Control: no-store, Pragma: no-cache`.

## Modules

### SSO (Go)

- `internal/service/dpop_verifier.go` — single deep module. Public surface: `VerifyProof(method, uri, header) (jkt, error)`, `VerifyResourceProof(method, uri, header, accessToken) (jkt, error)`. All claim, signature, freshness, replay, and binding checks live behind this interface.
- `internal/handler/oauth_token.go` — calls `VerifyProof` for code-exchange and refresh paths. Sets `token_type` based on `cnf.jkt` presence.
- `internal/handler/oauth_userinfo.go` — strict scheme-by-binding, calls `VerifyResourceProof` with the AT bytes for `ath` check.
- `internal/handler/oauth_authorize.go` — validates and persists `dpop_jkt`. Rejects duplicates and malformed values.
- `internal/handler/oidc_discovery.go` — advertises capabilities.

### agent-id (Node ESM)

- `skills/alien-agent-id/lib.mjs` — pure functions for thumbprint, DPoP proof construction, and `id_token` cnf verification. `getUserInfo` client uses `Authorization: DPoP` + `ath`. Module-level per-URL nonce cache for talking to third-party DPoP servers.
- Verifier — asserts `cnf.jkt == thumbprint(agent_jwk)` before reading any other claim.

## Out of scope

- ES256 / RS256 DPoP support (extension, not redesign).
- Server-side DPoP nonce issuance.
- Refresh-token rotation.
- Agent registry / per-commit attestation / revocation API.
- New OIDC scopes beyond `openid`.

## References

- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 7800 — Proof-of-Possession Key Semantics for JWTs
- RFC 7638 — JWK Thumbprint
- RFC 8037 — Ed25519 in JWK
- RFC 7517 — JSON Web Key (private-key members)
- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- RFC 3986 §6.2 — URI normalization
