# agent-id: CLI bootstrap + refresh emit DPoP, capture cnf-bearing id_token

**Type:** AFK
**Repo:** `alien-id/agent-id`
**Source PRD:** [docs/PRD-DPOP-POP.md](../PRD-DPOP-POP.md)

## Parent

PRD: RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

## What to build

Wire the agent CLI's OIDC bootstrap and refresh paths to participate in DPoP, so that `setup-owner-session` produces an `id_token` carrying `cnf.jkt` equal to the agent keypair's RFC 7638 thumbprint. The new `id_token` overwrites the old `owner-binding.json` proof bundle. The agent's existing keypair is preserved — no SSH rotation, no GitHub re-registration.

The slice covers, in one drop:

- **JWK helpers (new deep module of pure functions in `lib.mjs`).** `ed25519PublicKeyToJwk(publicKeyPem) → jwk` returns the canonical OKP/Ed25519 JWK. `jwkThumbprint(jwk) → string` returns the RFC 7638 SHA-256 thumbprint as base64url. Both are pure (no I/O, no state), publicly exported, unit-testable against RFC 7638 vectors.
- **DPoP proof signer (new deep module).** `createDPoPProof({privateKeyPem, htm, htu, jti?, iat?}) → string` returns the compact JWS DPoP proof (header: `typ=dpop+jwt`, `alg=EdDSA`, embedded `jwk`; payload: `htm`, `htu`, `iat`, unique `jti`). Pure, deterministic given fixed inputs.
- **`beginOidcAuthorization`** — computes the agent JWK thumbprint and appends `dpop_jkt=<thumbprint>` to the authorize URL. Returns the thumbprint to the caller for reuse at later steps.
- **`exchangeAuthorizationCode`** — constructs a DPoP proof for `POST {ssoBaseUrl}/oauth/token` and sends it as the `DPoP` header.
- **`refreshSession`** — constructs a DPoP proof for the refresh request (RFC 9449 §5 requires DPoP on refresh of DPoP-bound tokens).

The userinfo client is **not** in scope for this slice; if/when added later, it will reuse the same DPoP signer.

## Acceptance criteria

- [ ] `ed25519PublicKeyToJwk` round-trips a known Ed25519 public key against an independently-computed reference (Python `jwcrypto` fixture or RFC 7638 example).
- [ ] `jwkThumbprint` matches an independently-computed reference for at least one fixed key, and produces different thumbprints for different keys.
- [ ] `createDPoPProof` output round-trips: signing with the helper and verifying with `crypto.verify` succeeds for valid inputs.
- [ ] `createDPoPProof` output structure matches RFC 9449: header has `typ=dpop+jwt`, `alg=EdDSA`, and an embedded `jwk`; payload has `htm`, `htu`, `iat`, and a unique `jti`.
- [ ] `createDPoPProof` is deterministic given fixed `jti` and `iat` inputs.
- [ ] `beginOidcAuthorization` appends `dpop_jkt=<thumbprint>` to the authorize URL where the thumbprint matches the agent keypair's RFC 7638 thumbprint.
- [ ] `exchangeAuthorizationCode` sends a `DPoP` header on the token request whose proof's `htm`/`htu` match the request and whose JWK thumbprint matches the agent's `dpop_jkt`.
- [ ] `refreshSession` sends a `DPoP` header on the refresh request with the same properties.
- [ ] Running `setup-owner-session` end-to-end against an SSO that supports issue #1 yields an `id_token` with `cnf.jkt` equal to the agent's JWK thumbprint, and writes it into the proof bundle.
- [ ] JWK helpers and DPoP signer are added to the public exports of `lib.mjs` so downstream tools and tests can call them directly.

## Blocked by

- Blocked by #1 (SSO: DPoP-bound authorize+token mints cnf-bearing tokens) — required to integration-test the round trip. Helpers and unit tests can land before #1 is deployed; the integration assertion needs SSO with DPoP support reachable.
