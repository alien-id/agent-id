# Release Notes

## 3.0.0 — DPoP + cnf.jkt binding (BREAKING)

**Release type:** major, breaking.
**Migration guide:** [MIGRATION-DPOP.md](MIGRATION-DPOP.md).
**Deploy runbook:** [DEPLOY-DPOP.md](DEPLOY-DPOP.md).
**Design rationale:** [PRD-DPOP-POP.md](PRD-DPOP-POP.md).

This release closes the publish-and-replay forgery class documented in
[agent-id-forgery-poc](https://github.com/truehazker-eti/agent-id-forgery-poc)
by binding the agent's Ed25519 keypair into the SSO `id_token` itself via
[RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) `cnf.jkt`. Every operator
must re-bind once after upgrading. Pre-cutover commits become unverifiable.

### Verifier change (BREAKING)

`git-verify` now hard-rejects any `id_token` that lacks `cnf.jkt` or whose
`cnf.jkt` does not match the RFC 7638 thumbprint of the agent public key in
the proof bundle's owner binding. The check runs immediately after the SSO
RS256 signature passes and **before** the verifier reasons about any
`id_token` claim (including `sub` for the `Agent-ID-Owner` trailer).

Stable error strings (do not localize, do not paraphrase — these are part of
the contract for downstream consumers parsing verifier output):

- `id_token missing cnf.jkt`
- `id_token cnf.jkt mismatch: expected <a>, got <b>`

There is **no `--allow-legacy` flag, no environment variable, no policy
toggle** that disables this check. Per the PRD: every cnf-less `id_token` is
a live forgery primitive, not a historical artifact. A toggle that re-enabled
acceptance of cnf-less id_tokens would silently re-enable the entire forgery
class for any environment that flipped it on.

### Bootstrap change (BREAKING coordination)

`setup-owner-session` (and the underlying `auth` + `bind` commands) now use
[RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449) at both binding
points:

- `/oauth/authorize` receives a `dpop_jkt=<thumbprint>` query parameter
  computed from the agent's Ed25519 public key. This locks the keypair into
  the authorization session before user approval.
- `/oauth/token` receives a `DPoP: <compact-jws>` header on the
  authorization-code exchange. The proof's embedded JWK thumbprint must
  equal the session's `dpop_jkt`. The SSO returns id_token and access_token
  carrying `cnf: {jkt: <thumbprint>}`.

**The new SSO with DPoP support must be deployed first.** Running
`setup-owner-session` against an SSO that has not yet shipped DPoP will
either fail at token exchange or return a cnf-less id_token that this
verifier rejects. See [DEPLOY-DPOP.md](DEPLOY-DPOP.md) for ordering.

### Refresh change

Refresh of a DPoP-bound session now requires a fresh DPoP proof per
[RFC 9449 §5](https://www.rfc-editor.org/rfc/rfc9449#section-5). The agent
CLI does this automatically: `SignatureEngine.ensureValidSession` forwards
the agent's main key to `refreshSession`, which signs a DPoP proof for the
refresh token request. Refreshed `id_token` and `access_token` carry the
same sticky `cnf.jkt` as the originals.

Existing pre-deployment refresh tokens stay plain Bearer: their
`refresh_tokens.dpop_jkt` column on the SSO is `NULL`, so refresh continues
to work without DPoP. Only refresh tokens issued **after** the
`000011_dpop_refresh_tokens` SSO migration is live and after a DPoP-bound
authorize+token flow inherit the binding.

Refresh now always returns an `id_token` in the response (uniform code path
post the refresh-token migration). Clients that asserted absence of
`id_token` on refresh need updates; clients that ignored it are unaffected.

### Userinfo change (downstream consumers)

If the agent (or any downstream consumer using `lib.mjs`) calls
`/oauth/userinfo` with a DPoP-bound access_token, it must include a fresh
`DPoP` proof header per request. The proof's JWK thumbprint must equal the
access_token's `cnf.jkt`. Plain Bearer access_tokens issued in non-DPoP
flows continue to work at userinfo with the prior Bearer-only behavior — the
SSO enforces DPoP per-token, not per-endpoint.

### Unaffected behavior

- **Plain Bearer OAuth clients are unaffected.** Provider redirect flows and
  any future SPA that does not pass `dpop_jkt` at authorize produce
  byte-identical tokens to today. `/oauth/userinfo` for plain Bearer ATs is
  unchanged.
- **Legacy `/sso/*` miniapp endpoints are untouched.** Different handler
  tree, different token format, different keys. No coordinated migration is
  required for miniapps.
- **GitHub Verified badge is orthogonal.** GitHub pins SSH key → GitHub
  account, not SSH key → AlienID. The cnf mechanism does not affect the
  GitHub badge channel; out-of-band fingerprint pinning remains the only
  mitigation there.
- **SSH signing key is preserved.** The existing `~/.agent-id/ssh/` keypair
  and the matching key registered at GitHub stay valid. No SSH rotation, no
  GitHub re-registration.
- **Vault, audit log, signed operations** are unchanged.

### New library exports

`lib.mjs` exposes three new pure helpers (no I/O, no state) so downstream
front-ends and test harnesses can build alternate flows:

- `ed25519PublicKeyToJwk(publicKeyPem) → jwk` — canonical OKP/Ed25519 JWK.
- `jwkThumbprint(jwk) → string` — RFC 7638 SHA-256 thumbprint, base64url no
  padding. Verified against the RFC 8037 Appendix A.2 reference vector.
- `createDPoPProof({privateKeyPem, htm, htu, jti?, iat?}) → string` — RFC
  9449 compact JWS DPoP proof, deterministic given fixed `jti`/`iat`.

### Out of scope for this release

- Agent revocation registry.
- Per-commit attestations replacing the `id_token`-in-proof-bundle pattern.
- DPoP algorithms beyond EdDSA (the verifier on the SSO is structured as an
  alg-switch but only EdDSA is wired).
- Profile/email/address scopes and full UserInfo claims.
- `/sso/*` legacy miniapp endpoint migration.

See [PRD-DPOP-POP.md](PRD-DPOP-POP.md) "Out of Scope" for full rationale.

---

## 2.2.0

ALIEN-SKILL.md discovery, `@alien-id/sso-agent-id` SDK reference for
verification, demo service removed.

## 2.1.0 and earlier

See git history.
