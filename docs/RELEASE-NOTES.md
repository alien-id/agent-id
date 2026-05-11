# Release Notes — agent-id 3.0.0

**BREAKING.** Agent-driven authentication is cut over to DPoP-bound tokens (RFC 9449 + RFC 7800). The publish-and-replay forgery class documented in the [forgery PoC](https://github.com/truehazker-eti/agent-id-forgery-poc) is closed.

Human "Sign in with Alien" flows are unchanged. This release affects only the Agent-ID CLI and verifier; standard OIDC RPs continue to receive plain Bearer tokens via `/oauth/authorize` without modification.

## Why

The previous protocol bound nothing to the agent's keypair. An attacker who could read a published `refs/notes/agent-id` could mint forgeries indefinitely using any Ed25519 keypair they generated locally. The fix is a cryptographic binding between the agent's key and the SSO-issued `id_token`, expressed via RFC 7800 `cnf.jkt` (key thumbprint inside the SSO RS256 signature). Agent-ID verifiers now require this binding and refuse `id_tokens` that lack it.

## What changed (wire)

- **`/oauth/authorize`** — clients may pass `dpop_jkt` (RFC 9449 §10) to bind the resulting tokens to a keypair. Optional. If absent, behavior is unchanged.
- **`/oauth/token`** — a `DPoP` request header is required for sessions that bound `dpop_jkt`. Issued tokens carry `cnf.jkt`. Response `token_type` is `"DPoP"` for bound tokens, `"Bearer"` otherwise.
- **`/oauth/userinfo`** — strict scheme-by-binding:
  - DPoP-bound AT requires `Authorization: DPoP <token>` and a per-request DPoP proof with `ath = base64url(SHA-256(access_token))`.
  - Bearer-only AT requires `Authorization: Bearer <token>` (legacy human flow).
  - Cross-mismatch is rejected.
  - 401 errors carry `WWW-Authenticate: DPoP error="invalid_token", algs="EdDSA"`.
  - Successful responses set `Cache-Control: no-store, Pragma: no-cache`.
- **Refresh tokens** — DPoP-bound refresh tokens are not rotated. Sticky `cnf.jkt` makes a stolen refresh token unusable to anyone without the matching private key.
- **DPoP nonces (RFC 9449 §8)** — our SSO does not issue nonces. The agent-id client tolerates and handles nonce challenges from third-party DPoP servers, caching them per-URL to avoid the 400→retry roundtrip on subsequent calls.
- **`/.well-known/openid-configuration`** — advertises `dpop_signing_alg_values_supported: ["EdDSA"]` and `cnf` in `claims_supported`.

## What changed (CLI / library)

- `setup-owner-session` now generates a DPoP proof at token exchange and verifies the resulting `id_token` carries `cnf.jkt` matching the agent's JWK thumbprint. Bootstrap fails loudly if the SSO returns a token without `cnf`.
- Verifier rejects `id_tokens` without `cnf.jkt`. **Existing pre-3.0 commits no longer verify** — this is intentional; their `id_tokens` are forgery primitives.
- New public exports in `lib.mjs`:
  - `createDPoPProof({privateKeyPem, htm, htu, accessToken?, nonce?})`
  - `getUserInfo({ssoBaseUrl, accessToken, agentPrivateKeyPem})`
  - `ed25519PublicKeyToJwk` validates the SPKI Ed25519 OID prefix exactly before extracting the raw key.
  - htu canonicalization (lowercase scheme/host, strip default port, drop query+fragment) is applied consistently.

## Service discovery — `/.well-known/alien-agent-id.json`

This release also lands the well-known service-manifest discovery channel. Alien-aware services advertise their auth contract at a fixed path, parsed against a closed v1 schema before any agent attempts to call them.

- **Manifest schema (v1).** Required `version: 1`, `auth.header`, `api.base`. Optional `auth.scheme` (default `"DPoP"`; also `"Bearer"`, `"none"`), `api.specUrl`, `service.name`, `service.url`. All URLs must share the same authority as the user-supplied service URL (exact host or subdomain).
- **Hardened fetch.** 8 KiB body cap, 5s default timeout, redirects refused, `application/json` required, all derived URLs same-authority.
- **Trust boundary.** The manifest is third-party data, not instructions. The CLI parses, validates, and reduces it to a fixed field set before returning anything to the agent.
- **HTML support signal.** Closed-enum meta tag `<meta name="alien-agent-id" content="v1">` lets agents and crawlers detect support without probing every host's well-known path.
- **New CLI commands.** `discover-service --url <URL>` (fetch + validate manifest), `service-support --url <URL>` (probe meta tag).
- **New `lib.mjs` exports.** `parseServiceManifest`, `fetchServiceManifest`, `buildServiceAuthHeader`, `resolveServiceApiUrl`, `probeServiceSupportSignal`, plus constants `SERVICE_MANIFEST_PATH`, `SERVICE_MANIFEST_MAX_BYTES`, `SUPPORT_SIGNAL_MAX_BYTES`.
- **Wire scheme on the service edge.** Standard RFC 9449 DPoP: each authenticated request to a third-party service carries `Authorization: DPoP <access_token>` and a per-request `DPoP: <proof>` header. The agent's access_token is the SSO-issued `at+jwt` (RFC 9068) and carries the standard `sub` (owner), `aud`, `exp`, and `cnf.jkt` (RFC 7800 §3.1) — no custom envelope. The custom `Authorization: AgentID <self-contained-token>` envelope that earlier 3.0 drafts retained has been removed (cutover policy 401; no grace window).

## Security properties preserved / added

- **Replay resistance.** DPoP proofs include `iat` (freshness window) and `jti` (one-shot, server-side dedup). `jti` capped at 256 chars before DB insert.
- **Possession proof.** Verifier rejects DPoP proofs whose `jwk` header carries any RFC 7517 private-key member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`).
- **Header uniqueness.** Multiple `DPoP` headers on a single request are rejected at every entry point (token, userinfo) per RFC 9449 §4.3 step 1.
- **HTU robustness.** Server canonicalizes both proof and request URI before equality compare, so semantically-equal URIs (case differences, default-port presence) are accepted.
- **`dpop_jkt` query duplication** at `/authorize` is rejected with `400 invalid_request`.

## What is NOT in this release

- ES256 / RS256 DPoP support. EdDSA-only. Adding a new alg is a switch-case extension in the verifier; not done here.
- Server-side DPoP nonce issuance (RFC 9449 §8). Client handles challenges; server does not produce them.
- Refresh-token rotation. Sticky binding makes rotation unnecessary for the threat model addressed here.
- New OAuth scopes. `["openid"]` only. Userinfo plumbing is in place for future claims.

## Migration

See [MIGRATION-DPOP.md](MIGRATION-DPOP.md). Operator action is one CLI command (`alien-agent-id setup-owner-session`) per developer + verifier upgrade across CI fleets. Old commits are unverifiable post-upgrade — back-fill with the new CLI if continuity matters.
