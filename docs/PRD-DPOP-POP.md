# PRD — RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

**Status:** Proposed
**Author:** truehazker-eti
**Date:** 2026-04-30
**Scope:** `alien-id/agent-id` (CLI + verifier) + `alien-id/sso` (OIDC server)
**Related artifact:** `https://github.com/truehazker-eti/agent-id-forgery-poc` (live PoC of the vulnerability)

---

## Problem Statement

Anyone who can read a public repository that uses Agent-ID can forge commits attributed to any AlienID that has ever signed a commit in that repository.

Concretely, a maintainer of an Agent-ID-using repo today faces this: an attacker clones the repo, fetches `refs/notes/agent-id`, extracts a victim's `id_token` from any past commit's proof bundle, generates their own Ed25519 keypair, hand-builds an `owner-binding.json` claiming the victim's AlienID as owner, and produces a commit that passes the upstream `git-verify` chain end-to-end with `"ok": true`, six green provenance checks, and zero warnings. GitHub's "Verified" badge can be obtained in parallel by registering the attacker's keypair as a Signing Key on any GitHub account, including a typosquat. The forgery is visually and cryptographically indistinguishable from a legitimate commit. It survives `id_token` expiry, refresh-token revocation, and remains valid forever — the only thing that could invalidate it is rotating SSO's JWKS keys, which never happens.

The vulnerability has a single root cause: the SSO `id_token` does not commit to the agent's keypair. SSO is **agent-blind** — neither `/oauth/authorize` nor `/oauth/token` ever sees the agent's public key. The `id_token` only attests "human H approved provider P at time T." The agent-side `owner-binding.json` is a **self-attested** claim signed by the agent's own key. Because the published `id_token` does not reference any specific keypair, any keypair can pair with it. Publishing the `id_token` in `refs/notes/agent-id` is a necessary design property (it lets verifiers check the SSO RS256 signature offline) but in the current protocol it doubles as a forever-replayable forgery primitive.

This is not a bug in any single component. It is a missing cryptographic binding in the protocol itself. The only existing "defense" — GitHub's Verified badge — does not anchor agent fingerprints to AlienIDs (it anchors them to GitHub accounts) and is rendered only on github.com's web UI; no `git log`, CI, mirror, third-party verifier, or `format-patch` consumer ever sees it.

## Solution

Bind the agent's keypair into the OAuth flow using **RFC 9449 DPoP** at the SSO server, and have the SSO mint id_tokens (and access_tokens) that carry an **RFC 7800 `cnf.jkt`** confirmation claim committing to the keypair's RFC 7638 JWK thumbprint. The `cnf.jkt` claim lives inside the SSO RS256 signature — it cannot be substituted offline. The Agent-ID verifier then computes the JWK thumbprint of the agent public key embedded in the proof bundle and asserts equality with the id_token's `cnf.jkt`. A mismatch terminates verification.

After the change, the publish-and-replay attack class disappears. The `id_token` remains in the proof bundle (the verifier still needs it for offline signature checking), but it is now useless to anyone who does not hold the matching private key. Forgery is reduced from "extract a public artifact" to "compromise a private key" — which is the assumed-out-of-scope baseline of all signature-based protocols.

The work is delivered as one atomic protocol upgrade: a hard cutover. Verifiers reject id_tokens lacking `cnf.jkt`; existing agents must re-bind once with the new CLI to obtain a `cnf`-bearing id_token. Old commits with cnf-less id_tokens become unverifiable — this is the intended behavior, since those id_tokens *are* live forgery primitives until the keypair binding is established.

The changes preserve the SSO's existing OAuth2/OIDC standard surface for non-DPoP consumers (provider redirect flows, future SPAs, miniapp legacy endpoints). DPoP is opt-in per-flow at the SSO: if the client passes `dpop_jkt` at authorize and a `DPoP` proof header at token, the resulting tokens are PoP-bound. If not, behavior is unchanged. The `/sso/*` legacy miniapp endpoints are not touched at all. SSO never gains "agent" awareness — it gains a generic, standards-compliant DPoP capability.

## User Stories

1. As an Agent-ID maintainer, I want forged commits to fail `git-verify`, so that the publish-and-replay attack documented in the PoC cannot succeed against my repository.
2. As an Agent-ID maintainer, I want the fix to ship as a single auditable change so that compliance and security reviewers can evaluate the protocol upgrade in one diff.
3. As an Agent-ID maintainer, I want the new protocol to be standards-compliant (RFC 7800 + RFC 9449 + RFC 7638) so that external auditors recognize the construction without bespoke reasoning.
4. As an Agent-ID maintainer, I want the SSO server to remain a single-responsibility OAuth/OIDC token issuer so that human authentication and agent registration concerns do not cross-contaminate the codebase.
5. As an agent operator (developer), I want to re-bind my agent once and have all subsequent commits verify cleanly so that the migration cost is bounded and explicit.
6. As an agent operator, I want the agent CLI to fail loudly during bootstrap if the SSO does not return a `cnf`-bearing id_token, so that I never silently produce unverifiable commits.
7. As a verifier of Agent-ID commits (CI, third-party tool, audit script), I want id_tokens without `cnf.jkt` to be rejected, so that legacy forgeable artifacts cannot be smuggled through me.
8. As a verifier of Agent-ID commits, I want the cnf check to be fully offline so that verification works in air-gapped CI and on long-lived audit machines.
9. As a verifier of Agent-ID commits, I want a clear, specific error message when `cnf.jkt` is missing or mismatched so that operators understand exactly which guarantee failed.
10. As a miniapp operator using `/sso/*` legacy endpoints, I want my flow to be entirely unchanged after this upgrade, so that no coordinated migration is required.
11. As an OAuth client integrating against `/oauth/*` (e.g., a future provider SPA) that does not need PoP, I want to continue using plain Bearer flows with no DPoP, so that I am not forced into agent-style protocol overhead.
12. As a future OAuth client that *does* want PoP (e.g., a high-assurance browser app), I want the SSO's DPoP support to be the standard RFC 9449 surface so that I can adopt it with off-the-shelf libraries.
13. As an SSO operator, I want DPoP proof replay attempts to be rejected by `jti` uniqueness within the freshness window, so that captured proofs cannot be reused.
14. As an SSO operator, I want the `dpop_jti_seen` storage to be durable across server restarts and correct under horizontal scaling, so that the replay window is not reopened by ops events.
15. As an SSO operator, I want the existing background session cleaner to reclaim expired DPoP proof IDs, so that the table does not grow unbounded.
16. As an SSO operator, I want the `/oauth/userinfo` endpoint to enforce DPoP-bound access_tokens with a fresh proof per request, so that a leaked AT cannot be replayed against the userinfo endpoint.
17. As an SSO operator, I want OIDC discovery (`/.well-known/openid-configuration`) to honestly advertise the new capabilities (`dpop_signing_alg_values_supported`, `cnf` in `claims_supported`), so that automated OIDC clients can negotiate correctly.
18. As an SSO operator, I want the DPoP verifier to accept only `EdDSA` initially, so that the verifier surface area is minimal and matches the only consumer (Agent-ID).
19. As an SSO operator, I want adding more DPoP algorithms later (e.g., ES256 for browser clients) to require only adding a case to the alg switch, so that the verifier is extensible without rearchitecture.
20. As an agent author building on top of `lib.mjs`, I want a public RFC 7638 thumbprint helper and a public DPoP proof signer so that I can build alternate front-ends or test harnesses.
21. As a security engineer auditing the change, I want each layer of the trust chain to be enforced independently so that a regression in one check (e.g., binding signature) does not silently disable another check (e.g., cnf match).
22. As a security engineer auditing the change, I want the cnf check to be enforced before any decision based on `id_token` claims (e.g., `sub` is read out for the `Agent-ID-Owner` trailer), so that the verifier never reasons about claims from an un-bound token.
23. As an Agent-ID downstream consumer running existing repositories, I want my migration to be: upgrade the CLI → run `setup-owner-session` once → re-attach a fresh proof note to head, with a well-documented procedure for back-filling history if desired.
24. As the `agent-id-forgery-poc` operator, I want my forgery (commit `3a70d8f7…`) to fail verification under the new verifier so that the PoC becomes a regression test for the fix.
25. As an upstream-repo maintainer, I want the verifier's behavior on id_tokens without `cnf.jkt` to be a hard error, not a warning, so that no policy flag can silently disable the fix in CI.
26. As an SSO contributor, I want the DPoP verification logic encapsulated in a single deep module with a small interface (`VerifyProof(req) → (thumbprint, error)`) so that token and userinfo handlers consume it without duplicating crypto.
27. As an `lib.mjs` contributor, I want JWK thumbprint computation isolated in a single pure function (no I/O, no side effects) so that it is straightforwardly unit-testable against RFC 7638 vectors.
28. As an `lib.mjs` contributor, I want DPoP proof construction isolated in a single pure function returning the compact JWS string, so that it is callable from any of `beginOidcAuthorization`, `exchangeAuthorizationCode`, `refreshSession`, and the userinfo client without duplication.
29. As an SSO operator running CI, I want existing `full_flow_oauth_test.go` integration tests to continue passing for the no-DPoP path (provider flow without `dpop_jkt`) and to grow new cases for the DPoP path, so that the dual-mode behavior is explicitly covered.
30. As an SSO operator, I want the DPoP `jti` table to use a primary-key conflict to detect replay (idempotent insert), so that race conditions between concurrent token requests cannot bypass replay protection.
31. As a release manager, I want the discovery doc updated only after server support is live, so that clients negotiating DPoP capability never receive a 4xx from a not-yet-deployed code path.

## Implementation Decisions

### Architecture choices

- **Hard cutover** for Agent-ID verifier. No `--allow-legacy` flag, no time-window grace period. The verifier rejects id_tokens lacking `cnf.jkt`. Existing agents must re-bind to obtain a fresh id_token. This is non-negotiable: every cnf-less id_token is a live forgery primitive.
- **Generic OAuth feature in SSO, not an agent feature.** SSO never learns the term "agent." DPoP is exposed as the standards-compliant capability defined by RFC 9449. PoP-bound id_tokens follow RFC 7800. The Agent-ID consumer happens to require both; other future OIDC clients may opt in.
- **DPoP is opt-in at the SSO per-flow.** A flow becomes DPoP-bound when `dpop_jkt` is present at `/oauth/authorize`. If absent, all behavior is exactly as today. Provider flows, miniapp endpoints, and any future plain-Bearer client see no observable change.
- **Full RFC 9449.** Both binding points: `dpop_jkt` query param at `/oauth/authorize` (locks the keypair into the authorization session) AND `DPoP` proof header at `/oauth/token` (proves possession at exchange). Truncating to either alone is a regression on the cryptographic story we already accepted.
- **DPoP-bound access_tokens for the userinfo endpoint.** When the token request was DPoP-bound, the access_token receives `cnf.jkt` and the userinfo endpoint requires a fresh DPoP proof per request whose thumbprint matches the AT's `cnf.jkt`. Plain Bearer access_tokens (issued in non-DPoP flows) keep working at userinfo with current Bearer-only behavior. Per-token enforcement, not per-endpoint — non-agent clients are untouched.
- **EdDSA-only DPoP** to start, with the DPoP verifier structured as an `alg`-switch so that ES256/RS256 can be added later by extension.
- **No agent registry / no per-commit attestation / no revocation API** in this PRD. Those are different security properties (compromise response, not forgery prevention) and warrant their own design once production usage informs requirements. Listed in Out of Scope.
- **No new scopes** (`profile`, `email`, etc.) in this PRD. The discovery doc is updated to honestly reflect what is supported — `["openid"]` — and the userinfo endpoint remains plumbing-ready for future claims. Scope expansion is a separate PR once profile data sources exist.
- **Legacy `/sso/*` endpoints untouched.** Confirmed by reading the router: they use a different handler tree, do not share `oauth_sessions`, and mint Ed25519 (not RS256) tokens. Miniapps require zero migration.

### SSO server: modules to build / modify

- **`service.DPoPVerifier`** — new deep module. Single public method conceptually `VerifyProof(httpMethod, httpURI, dpopHeader) → (thumbprint, error)`. Internally: parse compact JWS, validate `typ=dpop+jwt` and `alg=EdDSA`, decode the embedded `jwk` (kty=OKP, crv=Ed25519), verify the Ed25519 signature, validate `htm`/`htu`/`iat (±60s)`, atomically insert `jti` into the replay table (PK conflict ⇒ replay), compute and return the RFC 7638 thumbprint. The interface is narrow; the cryptographic depth is hidden behind it. All other handlers consume this verifier, never DPoP internals.
- **`service.JWTService`** — extended to accept an optional `cnfJkt` parameter on `CreateIDToken` and `CreateAccessToken`. When set, the JWT carries `cnf: {jkt: ...}`. Existing call sites without the parameter produce identical output to today. Claims structs gain an optional `Cnf` field.
- **`handler.OAuthAuthorizeHandler`** — extended to accept an optional `dpop_jkt` query parameter. Validation: 43-character base64url string decoding to 32 bytes (SHA-256 output length). When present, persisted on `oauth_sessions`.
- **`handler.OAuthTokenHandler`** — extended at the authorization-code grant path: load the session row's `dpop_jkt`. If non-null, require `DPoP` header on the request, call `DPoPVerifier`, assert returned thumbprint equals the session's `dpop_jkt`. On success, pass the thumbprint to both `CreateIDToken` and `CreateAccessToken`. Refresh-token grant path: if the original session was DPoP-bound, require DPoP on refresh too and reissue tokens with the same `cnf.jkt` (RFC 9449 §5).
- **`handler.OAuthUserInfoHandler`** — extended to inspect `claims.Cnf.Jkt` on the verified access_token. If set, require a `DPoP` header on the request, call `DPoPVerifier`, assert returned thumbprint equals the AT's `cnf.jkt`. If absent, current Bearer-only behavior preserved.
- **`handler.OIDCDiscoveryHandler`** — extended to advertise `dpop_signing_alg_values_supported: ["EdDSA"]` and to add `cnf` to `claims_supported`.
- **`service.SessionCleaner`** — extended to GC `dpop_jti_seen` rows past `expires_at`.

### SSO server: schema changes

- New nullable column `oauth_sessions.dpop_jkt TEXT` (43-char base64url thumbprint).
- New table `dpop_jti_seen` with `jti TEXT PRIMARY KEY` and `expires_at TIMESTAMPTZ NOT NULL`, plus an index on `expires_at` for efficient cleanup. Replay protection relies on the primary-key conflict for atomic detection.

### agent-id (`lib.mjs` + `cli.mjs`): modules to build / modify

- **JWK helpers** — new deep module of pure functions. `ed25519PublicKeyToJwk(publicKeyPem) → jwk` returns the canonical OKP/Ed25519 JWK object. `jwkThumbprint(jwk) → string` returns the RFC 7638 SHA-256 thumbprint as base64url. Both are pure, no I/O, no state. Public exports so downstream tools and tests can call them directly.
- **DPoP proof signer** — new deep module: a single function `createDPoPProof({privateKeyPem, htm, htu, jti?, iat?}) → string` returns the compact JWS DPoP proof. Pure, deterministic given inputs. Used by all four call sites: authorize-time precomputation of `dpop_jkt`, token exchange, refresh, userinfo.
- **`beginOidcAuthorization`** — modified to compute the agent JWK thumbprint and append `dpop_jkt=<thumbprint>` to the authorize URL. Returns the thumbprint to the caller for use at later steps if needed.
- **`exchangeAuthorizationCode`** — modified to construct a DPoP proof for `POST {ssoBaseUrl}/oauth/token` and send it as the `DPoP` header.
- **`refreshSession`** — modified to construct a DPoP proof for the refresh request (RFC 9449 §5 requires DPoP on refresh of DPoP-bound tokens).
- **UserInfo client (new helper, optional in this PR)** — when the agent calls `/oauth/userinfo`, send a DPoP header. If we're not adding a userinfo client to `lib.mjs` in this PR, document the contract for downstream consumers.
- **`cmdGitVerify`** — modified verifier. After the existing chain (SSH sig → fingerprint match → binding payload hash → binding signature → SSO RS256 sig on id_token), add a new mandatory check: compute the JWK thumbprint of `binding.payload.agentInstance.publicKeyPem` and assert it equals `id_token.cnf.jkt`. Missing `cnf` ⇒ hard reject. Mismatch ⇒ hard reject. This check runs **before** any decision based on `id_token` claims (e.g., extracting `sub` for the `Agent-ID-Owner` trailer).

### Wire-level contract summary

`/oauth/authorize` accepts an optional `dpop_jkt` query parameter (43-char base64url string). When present, the authorization session is DPoP-bound. `/oauth/token` requires a `DPoP: <compact-jws>` header for DPoP-bound sessions; the proof's JWK thumbprint must equal the session's `dpop_jkt`. Issued id_token and access_token both carry `cnf: {jkt: <thumbprint>}`. `/oauth/userinfo` requires a fresh DPoP proof when the access_token has `cnf.jkt`; proof's thumbprint must equal AT's `cnf.jkt`. All flows without `dpop_jkt` at authorize behave exactly as before.

### Migration

A single CLI release ships the agent-side changes. SSO ships server-side changes first, then the agent CLI release. Existing agents re-run `setup-owner-session` once to obtain a `cnf`-bearing id_token; the existing agent keypair is preserved (no SSH key rotation, no GitHub re-registration). The new binding overwrites the old `owner-binding.json`. Old commits with cnf-less proof bundles fail verification — this is the intended outcome.

## Testing Decisions

A good test in this codebase exercises the *external behavior* of a module: "given input X at the public boundary, observe Y at the public boundary." We do not test private helpers, internal claim-assembly intermediates, or implementation details that may legitimately churn during refactor. We test what an attacker, a verifier, or a peer service would observe.

### Modules to test

- **SSO `service.DPoPVerifier`** — test target. Cases: (a) success returns the correct RFC 7638 thumbprint, (b) `typ != dpop+jwt` rejected, (c) `alg != EdDSA` rejected, (d) malformed JWK rejected, (e) tampered signature rejected, (f) `htm` mismatch rejected, (g) `htu` mismatch rejected, (h) `iat` outside `±60s` rejected, (i) reused `jti` rejected (replay), (j) concurrent requests with the same `jti` — only one succeeds (race coverage via testcontainers Postgres). Prior art: `internal/handler/full_flow_oauth_test.go` style for testcontainers integration.
- **SSO `service.JWTService` cnf extension** — test target. Cases: tokens minted without `cnfJkt` produce JSON identical to today (no `cnf` claim); tokens minted with `cnfJkt` carry `cnf: {jkt: <value>}` and verify against JWKS. Existing JWT tests are the prior art.
- **SSO full OIDC flow with DPoP** — extend `internal/handler/full_flow_oauth_test.go` with a new scenario covering `dpop_jkt` at authorize → DPoP at token → id_token has `cnf.jkt` → userinfo with DPoP succeeds → userinfo without DPoP on a DPoP-bound AT fails. The existing no-DPoP scenario is preserved unchanged to assert backwards compatibility.
- **agent-id JWK thumbprint helper** — test target. Cases: known-vector cross-check (RFC 7638 example or a generated fixture), thumbprint of a fixed Ed25519 public key matches an independently-computed reference (e.g., Python `jwcrypto` output captured as a fixture), thumbprint differs for different public keys. Prior art: existing `tests/` directory for `lib.mjs` helpers.
- **agent-id DPoP proof signer** — test target. Cases: round-trip (sign with the helper, verify with `crypto.verify`) for valid inputs; output structure matches RFC 9449 (header has `typ=dpop+jwt`, `alg=EdDSA`, `jwk`; payload has `htm`, `htu`, `iat`, unique `jti`); deterministic given fixed inputs.
- **agent-id verifier (`cmdGitVerify`)** — test target. Cases: id_token without `cnf` claim → hard reject with specific error code; id_token with `cnf.jkt` matching binding pubkey thumbprint → continues to pass; id_token with `cnf.jkt` mismatching binding pubkey thumbprint → hard reject; the existing PoC commit `3a70d8f7cb3d…` from `agent-id-forgery-poc` is added as a regression fixture and must fail verification under the new verifier.

### Tests we will not write

We do not test: that `JWTService` produces RS256 signatures (covered upstream by the `golang-jwt` library), that Postgres enforces primary keys (covered by Postgres), or that `crypto/ed25519` correctly verifies Ed25519 signatures (covered by Go stdlib). We do not test internal state shapes, intermediate variable names, or claim ordering inside JSON.

## Out of Scope

- **Agent revocation registry.** A separate microservice tracking active agents and exposing revocation is a real future need but a different security property — compromise response, not forgery prevention. Bundling it would harm review quality. Will be designed as a follow-up once production usage informs requirements.
- **Per-commit attestations.** Replacing the `id_token`-in-proof-bundle pattern with per-commit, commit-hash-scoped attestations from a registry service. Strictly stronger than `cnf` but a substantially larger surgery on the proof bundle, the verifier, and the SSO. Not required to close the publish-and-replay attack — `cnf` alone closes it.
- **Profile/email/address scopes and full UserInfo claims.** Discovery doc remains honest about supported scopes (`["openid"]`). Wiring `profile`, `email`, etc. requires SSO to obtain real profile data from devportal/chain — separate PR, separate data-source design.
- **DPoP algorithms beyond EdDSA.** The verifier is structured to be extensible (alg-switch), but only EdDSA is implemented. ES256/RS256 added when a non-Agent-ID consumer needs them.
- **Phishing UX hardening in the Alien App.** The `cnf` mechanism does not prevent an attacker from initiating a flow with their own thumbprint and tricking a victim into approving it. That is a UX problem (Alien App should display thumbprint context to the human), preexisting and orthogonal to this PRD.
- **Migrating `/sso/*` legacy miniapp endpoints to OIDC + DPoP.** Different handler tree, different token format, no shared code with `/oauth/*`. Untouched by this PRD.
- **GitHub "Verified" badge integration changes.** GitHub pins `(SSH key) → (GitHub account)`, not `(SSH key) → (AlienID)`; this is not something the protocol can fix. Out-of-band fingerprint pinning remains the only mitigation for that channel and is not designed here.
- **Soft-cutover or `--allow-legacy` verifier modes.** Already rejected upstream in design discussion: cnf-less id_tokens are live forgery primitives, not historical artifacts.

## Further Notes

- The PoC repository `https://github.com/truehazker-eti/agent-id-forgery-poc` (forged commit `3a70d8f7cb3d1d408b76ad15945a5898d6d877ce`) is the canonical demonstration of the vulnerability. After the fix ships, the same commit must fail verification — it becomes the regression test for the entire change.
- **Order of work, deploy-safe:** (1) SSO migrations, (2) SSO `DPoPVerifier` + JWT extension behind no observable feature, (3) SSO authorize/token/userinfo handlers updated, (4) discovery doc updated last, (5) agent-id CLI release with new lib + verifier. Discovery doc is updated only after the server actually supports DPoP, otherwise capability negotiation lies to clients.
- **Backwards compatibility for the SSO `/oauth/*` surface is preserved by construction.** Every new behavior is gated on the presence of `dpop_jkt` at authorize or `cnf` on the AT at userinfo. A consumer that does not opt in sees today's behavior verbatim.
- The cryptographic chain after the change reads: SSH signature on commit ↔ commit content; trailer fingerprint ↔ proof-bundle pubkey (sha256 of DER); binding payload pubkey ↔ proof-bundle pubkey; binding signature verified under that pubkey; **JWK thumbprint of that pubkey ↔ id_token's cnf.jkt**; id_token's RS256 signature against SSO JWKS. The new check is the bolded link. It is the one that closes the publish-and-replay class.
