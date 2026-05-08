# Wave 1 — agent-id Node PRs

**Source:** `backup/huge-refac-2026-05-08` (31 commits ahead of `main`), commit graph walked end-to-end on 2026-05-08.

**Goal:** deliver DPoP for agent-id end-to-end (`alien-agent-id` CLI can `auth → bind → git-verify` against a live SSO with full RFC 9449 + RFC 7800 enforcement) AND simultaneously decompose the spaghetti so `lib.mjs` does not regrow to 2,122 lines.

**Constraint applied throughout:** every PR cherry-picks `feat:` / `fix:` commits PAIRED with their `test:` (RED→GREEN), and within the same PR extracts the new exports out of `lib.mjs` into a single-responsibility module under `skills/alien-agent-id/lib/`. The exception is PR-A0/A1 (pure refactor warmup, moves only) and PR-A20 (docs bundle).

---

## 1. Commit graph table

Chronological order (oldest first). `M` = `lib.mjs`, `C` = `cli.mjs`, `Tx` = `tests/test-x.mjs`, `D` = `docs/`.

| # | SHA | Subject | Files (Δ lines) | RFC concern | Pair | Depends on | New module home |
|---:|---|---|---|---|:---:|---|---|
| 01 | `3114a23` | feat: JWK helpers + DPoP proof signer | `M` (+165), `T-dpop` (+486) | RFC 7638, RFC 8037 §A.2, RFC 9449 §4.2 | feat (vector tests inline) | — | `lib/jwk-thumbprint.mjs`, `lib/dpop-proof.mjs`, partly `lib/oauth-flow.mjs` |
| 02 | `e0140ba` | feat: wire CLI auth/bind dpop_jkt + DPoP header | `C` (+18) | RFC 9449 §10 | feat | 01 | `cli/commands/auth.mjs`, `cli/commands/bind.mjs` |
| 03 | `aa54707` | test: cnf.jkt binding RED | `T-cnf` (+374) | RFC 7800, RFC 9449 §6.1 | RED | 01 | `lib/cnf-verify.mjs` |
| 04 | `ace6eda` | feat: cnf.jkt enforcement GREEN | `C` (+35), `T-cnf` (+19) | RFC 7800, RFC 9449 §6.1 | GREEN of 03 | 01, 03 | `lib/cnf-verify.mjs` |
| 05 | `a135b1b` | docs: MIGRATION-DPOP | `D` (+107) | doc | doc | — | superseded by 21 |
| 06 | `6e67d87` | docs: RELEASE-NOTES | `D` (+132) | doc | doc | — | superseded by 21 |
| 07 | `a524c99` | docs: DEPLOY-DPOP | `D` (+121) | doc | doc | — | superseded by 21 |
| 08 | `0c558e5` | bump: 3.0.0 BREAKING | `package.json` (+1/-1) | release | release | 04 (semver-major) | bundles into PR-A20 |
| 09 | `2cd7ce9` | docs: PRD-DPOP-POP | `D` (+145) | doc | doc | — | superseded by 21 |
| 10 | `20d06e6` | docs: 7-issue tracer-bullet | `D` (+243, 7 files) | doc | doc | — | DELETED by 11, **never re-added** — drop from rebased history |
| 11 | `c87c52b` | docs: REMOVE stale DPoP docs | `D` (-748) | doc | doc | 05/06/07/09/10 | absorbed by squash in PR-A20 |
| 12 | `303cac3` | test: F-7 RED reject non-Ed25519 SPKI | `T-dpop` (+31) | RFC 8410 §4 | RED | 01 | `lib/keys.mjs` |
| 13 | `7518bab` | fix: F-7 GREEN validate SPKI OID | `M` (+9/-6) | RFC 8410 §4 | GREEN of 12 | 12 | `lib/keys.mjs` |
| 14 | `951fed8` | test: F-4 htu canonicalization regression guard | `T-dpop` (+23) | RFC 9449 §4.3 / RFC 3986 §6.2.2 | regression-only | 01 | `lib/dpop-proof.mjs` (test pins behavior) |
| 15 | `817559f` | test: F-1 RED ath/nonce/getUserInfo | `T-dpop` (+111) | RFC 9449 §4.2, §8 | RED | 01 | `lib/dpop-proof.mjs`, `lib/dpop-nonce-fetch.mjs`, `lib/userinfo.mjs` |
| 16 | `cef4453` | feat: F-1 GREEN ath/nonce/getUserInfo | `M` (+83) | RFC 9449 §4.2, §8/§9 | GREEN of 15 | 01, 15 | same as 15 |
| 17 | `0a03249` | test: F-5 RED nonce retry on token + refresh | `T-dpop` (+73) | RFC 9449 §8 | RED | 16 | `lib/dpop-nonce-fetch.mjs` |
| 18 | `d30baeb` | feat: F-5 GREEN nonce retry + tokenEndpointPost helper | `M` (+45/-26) | RFC 9449 §8 | GREEN of 17 | 16, 17 | `lib/dpop-nonce-fetch.mjs`, `lib/oauth-token.mjs` |
| 19 | `60dc3ed` | test: G-10 RED nonce cache per URL | `T-dpop` (+57) | RFC 9449 §8.2-1 | RED | 18 | `lib/dpop-nonce-fetch.mjs` |
| 20 | `02fd6f7` | feat: G-10 GREEN module-level nonce cache | `M` (+28/-8) | RFC 9449 §8.2-1 (MUST) | GREEN of 19 | 18, 19 | `lib/dpop-nonce-fetch.mjs` |
| 21 | `99563f9` | docs: regenerate DPoP docs (final state) | `D` (+272, 4 files) | doc | doc | 20 | bundles into PR-A20 |
| 22 | `5bf50b5` | fix: H2 dead synthetic-DER prefix test removal | `T-dpop` (+7/-14) | cleanup | cleanup | 13 | absorbed by PR-A4 |
| 23 | `3e14024` | feat: H1a verifyProofChain (universal) | `M` (+147) | RFC 7800, OIDC §3.1.3.7, RFC 9207 | feat | 04 (`cnf.jkt` semantics) | `lib/chain-verify.mjs` |
| 24 | `836a9f4` | test: H1b chain-verifier unit tests | `T-chain` (+388) | same | RED-shaped (post-impl) | 23 | `lib/chain-verify.mjs` |
| 25 | `9652606` | refactor: H1c migrate cmdGitVerify → verifyProofChain | `C` (-86), `T-cnf` (rebuilt) | same | refactor | 23, 24 | `cli/commands/git-verify.mjs` |
| 26 | `86a59e7` | docs: H1d INTEGRATION + README | `D` (+47, 2 files) | doc | doc | 23–25 | bundles into PR-A17 (chain) |
| 27 | `b10f8ce` | feat: setup-owner-session CLI | `C` (+69) | UX | feat | 04 | `cli/commands/setup-owner-session.mjs` |
| 28 | `cd807ea` | fix: token_type=DPoP discard rule | `M` (+12), `T-dpop` (+6), `T-refresh` (+9) | RFC 9449 §5 / RFC 6749 §5.1 | feat (mock-only) | 18 | `lib/oauth-token.mjs` |
| 29 | `fce7398` | test: isolate cnf-verifier git env | `T-cnf` (+11) | env-only | env-only | 25 | absorbed by PR-A17 |
| 30 | `9089768` | fix: RFC 9449 §9 RS nonce structured matching | `M` (+38), `T-dpop` (+79) | RFC 9449 §9, RFC 7235 §2.2 | feat (TDD pair inline) | 20 | `lib/dpop-nonce-fetch.mjs` |
| 31 | `52a84c5` | snapshot: pre-refactor capture (uncommitted bundle) | `M` (+328/-21), `C` (+27/-10), `T-refresh` (+243), `T-dpop` (+130), `T-chain` (+92), `T-id-token-verifier` (+861, NEW), `T-rfc9207-iss` (+234, NEW), `D-COMPLIANCE/REFACTOR-PLAN/REVIEW-PLAN` (+1173) | RFC 7515 §2/§4.1/§10.7, RFC 7518 §3.3, RFC 7519 §4.1.5/§7.2, RFC 8037 §2, RFC 8725 §3.5/§3.7/§3.11, RFC 9110 §5.6.2, RFC 9207 §2.4, OIDC §3.1.3.7 (full), RFC 6749 §10.4/§10.12 | **mixed bundle** — must be split | 30 | needs split into ~7 PRs (A11–A16, A20) |

**Total:** 31 commits → 11,362 net new lines. Of those, **23 are TDD-paired or independent feats** that cherry-pick cleanly. **6 are docs** (squashable into one release-doc PR). **2 are housekeeping** (`5bf50b5`, `fce7398`). **1 is the pre-refactor snapshot** which is a **bundle of ~7 distinct logical changes** that must be re-split for sane review.

---

## 2. Dependency analysis

### 2a. Intra-repo (agent-id Node) dependencies

```
01 (JWK + DPoP proof signer)
 ├── 02 (CLI wire-up)
 ├── 03/04 (cnf.jkt at git-verify) ────────────────┐
 ├── 12/13 (F-7 SPKI fix) ─── PR-A4               │
 ├── 14    (F-4 htu regression) ─── PR-A6         │
 ├── 15/16 (F-1 ath/nonce/getUserInfo) ───┐       │
 │     └── 17/18 (F-5 nonce retry) ───┐   │       │
 │           └── 19/20 (G-10 cache) ──┴───┴── 30 (§9 RS structured match)  │
 │                                          └── 28 (token_type=DPoP discard)
 │                                                                          │
 ├── 23 (chain verifier)  ◄────────────────────────┤                       │
 │    ├── 24 (chain unit tests)                    │                       │
 │    ├── 25 (cmdGitVerify migrate) ◄──────────────┤                       │
 │    │    └── 29 (test env isolation)             │                       │
 │    ├── 22 (dead test removal — cleanup)         │                       │
 │    └── 26 (INTEGRATION docs)                    │                       │
 │                                                  │                       │
 ├── 27 (setup-owner-session CLI) ◄────────────────┘                       │
 │                                                                          │
 └── 31 (snapshot bundle — depends on the entire chain above) ◄────────────┘
        ├── strict b64url alphabet                  } verifyJwtRs256Signature
        ├── RSA modulus floor                       } at lib.mjs:313
        ├── EdDSA JWS verify (verifyJwtEdDsaSignature)
        ├── RFC 9110 token regex on `htm`
        ├── assertSsoBaseUrlSafe (TLS guard)
        ├── assertIdTokenTyp (RFC 8725 §3.7)
        ├── verifyIdToken full hardening (OIDC §3.1.3.7 + RFC 9449 §6.1 + RFC 9207 + nbf + crit + alg allowlist)
        ├── RFC 9207 iss check on poll/authorize (test-rfc9207-iss.mjs new)
        ├── state/nonce CLI plumbing (OIDC §3.1.3.7 step 11 + RFC 6749 §10.12)
        ├── SubjectMismatchError + AuthRevokedError classes
        └── COMPLIANCE.md / REFACTOR-PLAN.md / REVIEW-PLAN.md
```

### 2b. Cross-repo (SSO server) dependencies

The agent-id Node lib talks to the SSO server's `/oauth/authorize`, `/oauth/token`, `/oauth/poll`, `/oauth/userinfo` and consumes id_token with cnf.jkt. End-to-end testing requires the server to honor the DPoP cutover. **However, every agent-id PR below is self-contained at the unit-test level** (mocked HTTP for the server, vector tests for crypto). The server-live requirement only matters for the **smoke-test gate** before tagging 3.0.0.

**Server-live needed for smoke test of:**

| agent-id PR | What it needs from SSO server |
|---|---|
| PR-A3 (CLI wire-up) | `/authorize?dpop_jkt=…` accepted; `/oauth/token` issues `token_type=DPoP` when proof present |
| PR-A4 (cnf.jkt at git-verify) | id_token `cnf.jkt` minted by `JWTService.CreateIDToken(cnfJkt)` |
| PR-A6 (F-1 ath/getUserInfo) | `/oauth/userinfo` requires DPoP scheme + ath claim |
| PR-A7 (F-5 nonce retry) | `/oauth/token` returns 400 + `use_dpop_nonce` (RFC 9449 §8) — **NOT enforced by SSO today**; mock-only validation |
| PR-A8 (G-10 nonce cache) | same — mock-only |
| PR-A9 (§9 RS structured match) | `/oauth/userinfo` returns 401 + `WWW-Authenticate: DPoP error="use_dpop_nonce"` — **NOT enforced by SSO today**; third-party RS interop |
| PR-A10 (token_type=DPoP discard) | `/oauth/token` emits `token_type=DPoP` (RFC 9449 §5) |

**Server-live NOT needed for any unit suite.** All 6 test files in `tests/` (chain, cnf, dpop, id-token-verifier, refresh, rfc9207-iss) run against in-process fixtures and an in-memory mock SSO using `node:http`.

**SSO server changes that must land FIRST (cross-repo blocker):** the `sso/sso` Wave 1 PRs covering DB migration + DPoPVerifier service + dpop_jkt at /authorize + DPoP at /token + DPoP at /userinfo + JWTService cnf.jkt extension + token_type=DPoP emission. Without those, agent-id PR-A3/A4/A6/A10 will **build and unit-test green but fail end-to-end**.

---

## 3. Proposed PRs

Numbering: `PR-A0`…`PR-A20` (21 PRs).

> **Rule applied to every PR:** when a feat introduces a NEW exported function, that function lands in a single-responsibility `lib/<name>.mjs` module — NEVER appended to `lib.mjs`. `lib.mjs` becomes a re-export shim PR-by-PR; by the end of Wave 1 it is < 200 lines (re-exports only). Pre-existing functions (`signEd25519Base64Url`, vault helpers, `SignatureEngine`, `verifyState`, etc.) are extracted by the final cleanup PR (A20-cleanup, listed separately at the end).

---

### PR-A0 — chore: add COMPLIANCE / REFACTOR-PLAN / REVIEW-PLAN docs

**Source:** part of snapshot `52a84c5` — the three new doc files only (`COMPLIANCE.md`, `REFACTOR-PLAN.md`, `REVIEW-PLAN.md`).

**Files at end of PR:**
- `docs/COMPLIANCE.md` (357 lines)
- `docs/REFACTOR-PLAN.md` (504 lines)
- `docs/REVIEW-PLAN.md` (312 lines)

**New `lib/*.mjs` modules:** none.
**Functions extracted:** none.
**Tests:** existing suite green (no behavior change).
**Self-containment:** docs only, zero behavior, zero risk. Warms up the review pipeline.
**Demo:** "the team can read the compliance snapshot and the refactor map."

---

### PR-A1 — refactor: extract storage + key utilities into focused modules

**Source:** pure refactor of EXISTING `lib.mjs` exports (no cherry-picks). Foundation for everything below — gives modules a home before new code lands.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/b64.mjs` | ~80 | `canonicalJSONString`, `sha256HexCanonical`, `b64url`, `fromB64url` (current strict version), `sha256B64url`, `sha256Hex`, `BASE64URL_REGEX` |
| `skills/alien-agent-id/lib/keys.mjs` | ~250 | `generateEd25519PemPair`, `fingerprintPublicKeyPem`, `ed25519PublicKeyToJwk` (with SPKI prefix check), `signEd25519Base64Url`, `verifyEd25519Base64Url`, `verifyEd25519HexMessage`, `ed25519PemToSshPublicKey`, `ed25519PemToOpenSSHPrivateKey`, `ED25519_SPKI_PREFIX` |
| `skills/alien-agent-id/lib/storage.mjs` | ~80 | `ensureDir`, `readJsonFile`, `writeJsonFile`, `appendJsonl`, `readJsonl`, `statePaths`, `setPrivateFilePermissions` |
| `skills/alien-agent-id/lib.mjs` | ~1,500 (was 2,122) | re-exports A1 modules; rest unchanged |

**Tests:** existing 6 suites green; no test changes.
**Self-containment:** ✅ pure structural refactor against current main state. No SSO server dependency.
**Demo:** "git-grep `from "./lib/keys.mjs"` and you can see the key surface in isolation."

---

### PR-A2 — refactor: extract JWS verifiers + JWT parser + discovery

**Source:** pure refactor (continues PR-A1 foundation).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/jwt-parse.mjs` | ~60 | strict 3-segment parse (currently inline in many call sites) |
| `skills/alien-agent-id/lib/jwt-verify.mjs` | ~120 | `verifyJwtRs256Signature` (with RFC 7518 §3.3 modulus floor), `verifyJwtEdDsaSignature` (RFC 8037 §2), `MIN_RSA_MODULUS_BYTES` |
| `skills/alien-agent-id/lib/discovery.mjs` | ~60 | `fetchOidcDiscovery`, `fetchJwks` |
| `skills/alien-agent-id/lib.mjs` | ~1,300 | re-exports |

**Tests:** existing suites green.
**Self-containment:** ✅ pure refactor.
**Demo:** "all JWS verification lives in `lib/jwt-verify.mjs` and is unit-testable in isolation."

---

### PR-A3 — feat(dpop): JWK thumbprint helper (RFC 7638) — **first new functionality**

**Source commits:** `3114a23` (partial — the thumbprint half: `ed25519PublicKeyToJwk` is already in `lib/keys.mjs` from PR-A1, only `jwkThumbprint` is new) + `52a84c5` partial (snapshot's RFC 8037 §A.2 vector reference).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/jwk-thumbprint.mjs` | ~30 | `jwkThumbprint(jwk)` — RFC 7638 SHA-256 thumbprint, base64url no padding |
| `tests/test-dpop.mjs` | (cherry-pick subset) | RFC 8037 §A.2 vector + canonicalization edge cases (~80 of the 486 lines from `3114a23`) |
| `skills/alien-agent-id/lib.mjs` | re-exports `jwkThumbprint` from new module |

**New module:** `lib/jwk-thumbprint.mjs`.
**Functions extracted from lib.mjs:** N/A (jwkThumbprint is born here).
**Tests must pass:** `node tests/test-dpop.mjs` — the thumbprint vector test specifically asserts `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`.
**Self-containment:** ✅ vector test, no SSO dependency.
**Demo:** "you can compute and verify any RFC 7638 thumbprint without spinning up a server."

---

### PR-A4 — feat(dpop): proof signer (RFC 9449 §4) + F-7 SPKI hardening

**Source commits:** `3114a23` (partial — `createDPoPProof` + `stripUrlQueryAndFragment`) + `303cac3`/`7518bab` (F-7 SPKI OID prefix RED+GREEN, must update `lib/keys.mjs`'s `ed25519PublicKeyToJwk`) + `5bf50b5` (drop synthetic-DER tautology) + `951fed8` (F-4 htu canonicalization regression guard) + snapshot `52a84c5` partial (RFC 9110 §5.6.2 token regex on `htm` + `HTTP_TOKEN_REGEX`).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/dpop-proof.mjs` | ~90 | `createDPoPProof`, `stripUrlQueryAndFragment`, `HTTP_TOKEN_REGEX`. NOTE: still single-shot (no nonce cache, no ath, no getUserInfo — those land in A6/A7) |
| `skills/alien-agent-id/lib/keys.mjs` | (updated) | `ed25519PublicKeyToJwk` validates `ED25519_SPKI_PREFIX` strictly (rejects X25519 / Ed448 / synthetic DER) |
| `tests/test-dpop.mjs` | (~390 of 486 from `3114a23`) | RED→GREEN for proof structure, htm/htu/iat/jti, F-7 OID prefix rejection, F-4 htu canonicalization regression |
| `skills/alien-agent-id/lib.mjs` | re-exports |

**RFC concerns:** RFC 9449 §4.1/§4.2/§4.3, RFC 8410 §4 (SPKI), RFC 9110 §5.6.2 (token), RFC 3986 §6.2.2 (htu canon).
**Self-containment:** ✅ pure crypto unit test. No server.
**Demo:** "`createDPoPProof({privateKeyPem, htm: 'POST', htu: '…/token'})` returns a verifiable JWS that the server can validate."

---

### PR-A5 — feat(cli): wire dpop_jkt + DPoP token-request header

**Source commits:** `3114a23` (partial — the OIDC entry-point wiring inside `beginOidcAuthorization`, `exchangeAuthorizationCode`, `refreshSession`, `SignatureEngine.ensureValidSession`) + `e0140ba` (CLI cmdAuth/cmdBind/cmdRefresh forwarding).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/oauth-flow.mjs` | ~100 | `generatePkcePair`, `beginOidcAuthorization` (now appends `dpop_jkt`), `pollForAuthorizationCode` |
| `skills/alien-agent-id/lib/oauth-token.mjs` | ~120 | `exchangeAuthorizationCode` (now sends `DPoP` header), `refreshSession` (now sends `DPoP` header) |
| `skills/alien-agent-id/cli.mjs` | (updated) | `cmdAuth` forwards `agentPublicKeyPem`; `cmdBind` forwards `agentPrivateKeyPem` + `agentPublicKeyPem` |
| `tests/test-dpop.mjs` | (existing assertions for the wire path remain green) |
| `skills/alien-agent-id/lib.mjs` | re-exports |

**RFC concerns:** RFC 9449 §10 (binding to OAuth flows), RFC 9449 §5 (DPoP at token endpoint).
**Self-containment:** ✅ unit-tested with mocked SSO HTTP.
**Server-live needed:** YES for end-to-end smoke test (server must accept `dpop_jkt`, must accept `DPoP` header on `/token`).
**Demo:** "`alien-agent-id auth && alien-agent-id bind` against a DPoP-enabled SSO returns a `cnf.jkt`-bound id_token."

---

### PR-A6 — feat(dpop): ath claim + getUserInfo + nonce-aware fetch

**Source commits:** `817559f`/`cef4453` (F-1 RED+GREEN — ath, nonce, getUserInfo, fetchWithDPoPNonce).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/dpop-proof.mjs` | (updated) | `createDPoPProof` accepts optional `accessToken` (emits `ath`) and `nonce` |
| `skills/alien-agent-id/lib/dpop-nonce-fetch.mjs` | ~60 | `fetchWithDPoPNonce(fetchFn, ...)` — single-retry on §8 challenge (no cache yet, comes in A7) |
| `skills/alien-agent-id/lib/userinfo.mjs` | ~40 | `getUserInfo({ssoBaseUrl, accessToken, agentPrivateKeyPem, agentPublicKeyPem})` |
| `tests/test-dpop.mjs` | (cherry-pick the 111 lines from `817559f`) | F-1 ath/nonce/getUserInfo RED→GREEN, all 6 wire assertions |
| `skills/alien-agent-id/lib.mjs` | re-exports |

**RFC concerns:** RFC 9449 §4.2 (ath), §8 (nonce response shape), §7.1 (RS scheme).
**Self-containment:** ✅ unit test with `http.createServer` mock RS.
**Server-live needed:** YES for `/oauth/userinfo` smoke test.
**Demo:** "`getUserInfo()` against a DPoP-protected `/oauth/userinfo` returns the authenticated subject."

---

### PR-A7 — feat(dpop): nonce retry on token + refresh, nonce cache (RFC 9449 §8/§8.2-1)

**Source commits:** `0a03249`/`d30baeb` (F-5 nonce retry on `/token`+`/refresh`) + `60dc3ed`/`02fd6f7` (G-10 nonce cache per URL).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/dpop-nonce-fetch.mjs` | ~110 (was 60) | adds `tokenEndpointPost` helper, module-level `dpopNonceCache: Map<string, string>`, pre-attaches cached nonce on subsequent requests |
| `skills/alien-agent-id/lib/oauth-token.mjs` | (updated) | `exchangeAuthorizationCode` and `refreshSession` route through `tokenEndpointPost` |
| `tests/test-dpop.mjs` | (~130 lines from F-5 + G-10) | RED→GREEN |

**RFC concerns:** RFC 9449 §8 (single retry), §8.2-1 (MUST: keep using nonce until server rotates).
**Self-containment:** ✅ mock-only — SSO does not emit nonces today, so the new path is exercised purely against fixture servers.
**Server-live needed:** NO (SSO opt-out is RFC-compliant per §8).
**Demo:** "third-party DPoP servers that DO emit nonces interop without retry storms."

---

### PR-A8 — feat(dpop): cnf.jkt enforcement at git-verify (RFC 7800)

**Source commits:** `aa54707`/`ace6eda` (cnf.jkt RED+GREEN at git-verify).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/cnf-verify.mjs` | ~50 | `enforceCnfJkt(idTokenPayload, agentPublicKeyPem)` — throws on missing or mismatch |
| `skills/alien-agent-id/cli.mjs` | (updated) | `cmdGitVerify` calls `enforceCnfJkt` after RS256 sig passes, before any claim reasoning |
| `tests/test-cnf-verifier.mjs` | (cherry-pick 374+19 lines) | full RED+GREEN coverage |

**RFC concerns:** RFC 7800 (`cnf` claim), RFC 9449 §6.1 (jkt confirmation method), RFC 7638 (thumbprint canonicalization).
**Self-containment:** ✅ uses ephemeral keypair fixtures.
**Server-live needed:** YES for the realistic flow (server must mint id_token with `cnf.jkt` claim) — but unit test covers semantics.
**Demo:** "`alien-agent-id git verify` rejects an id_token whose `cnf.jkt` does not match the agent's key — closes the substitution-forgery vector."

---

### PR-A9 — feat(dpop): token_type=DPoP discard rule (RFC 9449 §5)

**Source commits:** `cd807ea`.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/oauth-token.mjs` | (updated) | discard rule guard: when `useDPoP` and `tokenResponse.token_type !== 'DPoP'` → throw with stable error string |
| `tests/test-dpop.mjs` | +6 | mock returns `token_type: "Bearer"` → reject; mock returns `"DPoP"` → accept |
| `tests/test-refresh.mjs` | +9 | refresh path same |

**RFC concerns:** RFC 9449 §5 (MUST discard), RFC 6749 §5.1 (case-insensitive comparison).
**Self-containment:** ✅ mock-only.
**Server-live needed:** YES for smoke test (server must emit `token_type=DPoP` after F-2 fix). For unit test, mocks return both.
**Demo:** "downgrade attack closed — a misbehaving AS that returns Bearer for a DPoP-bound request is rejected, not silently accepted."

---

### PR-A10 — feat(dpop): RFC 9449 §9 RS nonce challenge structured matching

**Source commits:** `9089768`.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/dpop-nonce-fetch.mjs` | (updated, +50) | `fetchWithDPoPNonce` now also handles 401 + `WWW-Authenticate: DPoP error="use_dpop_nonce"` (RFC 9449 §9). Parses RFC 7235 §2.2 token-or-quoted-string structurally — won't be fooled by `realm="use_dpop_nonce_blocklist"`. |
| `tests/test-dpop.mjs` | +79 | both retry-on-401 and no-retry-on-error="invalid_token" cases |

**RFC concerns:** RFC 9449 §9 (RS nonce shape), RFC 7235 §2.2 (challenge ABNF).
**Self-containment:** ✅ mock-only.
**Server-live needed:** NO (SSO does not emit nonce today; this is third-party RS interop).
**Demo:** "agent-id is a fully-conformant DPoP client against any third-party server that emits nonces — token endpoint OR userinfo endpoint."

---

### PR-A11 — feat(verify): full id_token verifier (RFC 7515/7518/7519/8725 + OIDC §3.1.3.7)

**Source:** snapshot `52a84c5` partial — extract just the `verifyIdToken` rewrite + `assertIdTokenTyp` + `verifyIdTokenSignatureOnly` + `assertSsoBaseUrlSafe` (NOT the cnf.jkt path which already lands in PR-A8 as a separate module — A11 imports `enforceCnfJkt` from A8).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/id-token-verify.mjs` | ~160 | `verifyIdToken` (full OIDC §3.1.3.7 walk: alg allowlist, crit reject, typ check, exp/nbf/iat NumericDate, aud + azp + multi-aud, nonce match, signature via `verifyJwtRs256Signature` from PR-A2), `verifyIdTokenSignatureOnly` (provenance-only path) |
| `skills/alien-agent-id/lib/security-guards.mjs` | ~30 | `assertSsoBaseUrlSafe` (RFC 6749 §10.4 / RFC 8252) |
| `tests/test-id-token-verifier.mjs` | NEW (+861 from snapshot) | 11 describe blocks, each pinned to its RFC § |

**RFC concerns:** RFC 7515 §10.7 (alg allowlist), §4.1.11 (crit), §4.1 (header validation); RFC 7519 §4.1.5 (nbf), §4.1.6 (iat), §7.2 (strict structural); RFC 8725 §3.11 (typ confusion); OIDC §3.1.3.7 steps 1..15 (full walk including azp/multi-aud/nonce).
**Self-containment:** ✅ pure unit test against ephemeral RS256 fixtures.
**Server-live needed:** NO.
**Demo:** "11 RFC sections enforced and pinned to the regression suite. Any future drift breaks a named `describe` block."

---

### PR-A12 — feat(verify): RFC 9207 issuer identification on poll/authorize

**Source:** snapshot `52a84c5` partial — `iss` check additions inside `pollForAuthorizationCode` and `beginOidcAuthorization`, plus the new `tests/test-rfc9207-iss.mjs`.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/iss-verify.mjs` | ~40 | `assertExpectedIssuer(observed, expected)` — strict equality, throws on mismatch (RFC 9207 §2.4) |
| `skills/alien-agent-id/lib/oauth-flow.mjs` | (updated) | `pollForAuthorizationCode` accepts `expectedIssuer`, calls `assertExpectedIssuer` when AS returned `iss` |
| `tests/test-rfc9207-iss.mjs` | NEW (+234) | poll-side and authorize-side iss enforcement |

**RFC concerns:** RFC 9207 §2.4 (mix-up attack mitigation).
**Self-containment:** ✅ mock SSO returns `iss` field.
**Server-live needed:** NO.
**Demo:** "an AS that returns the wrong `iss` on the poll response is rejected — closes the iss mix-up vector."

---

### PR-A13 — feat(cli): plumb state + nonce + issuer through pending-auth state

**Source:** snapshot `52a84c5` partial — `cli.mjs` `cmdAuth` adds `state`/`nonce`/`issuer` to pending-auth JSON; `cmdBind` reads them and forwards `expectedState`/`expectedIssuer` to `pollForAuthorizationCode` and `expectedNonce` to `verifyIdToken`.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/cli.mjs` | (updated, +27/-10) | `cmdAuth` writes `state` + `nonce` + `issuer`; `cmdBind` reads + forwards |

**RFC concerns:** RFC 6749 §10.12 (state round-trip), OIDC §3.1.3.7 step 11 (nonce replay protection).
**Self-containment:** ✅ end-to-end via mock SSO.
**Server-live needed:** NO (uses mocked SSO).
**Demo:** "if the AS replays a stale `state`, bind fails with a stable error string — replay attack closed."

---

### PR-A14 — fix(jws): strict base64url alphabet on JWS parse

**Source:** snapshot `52a84c5` partial — the `fromB64url` strict-alphabet rewrite + `BASE64URL_REGEX` constant.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/b64.mjs` | (updated, +18 lines, -3 lines) | `fromB64url` rejects whitespace, `+`, `/`, `=`; rejects 4-residue=1 length; throws typed errors |
| `tests/test-id-token-verifier.mjs` | (cherry-pick subset already in A11) | already covers this — A14 is just the impl-side change without re-introducing the test file (already shipped in A11) |

**RFC concerns:** RFC 7515 §2 / RFC 7519 §7.2 (canonical base64url).
**Self-containment:** ✅.
**Server-live needed:** NO.
**Demo:** "JWS segments containing whitespace or padding are rejected — Buffer's permissive base64 no longer leaks into JWS validation."

> **Note:** A11 ships before A14 in the cherry-pick order, but A14's strict-alphabet test cases are a `describe` block inside `test-id-token-verifier.mjs`. Resolve by including the impl change in A11 directly (one PR, two RFC concerns since the strict alphabet IS the prerequisite for many id_token-verifier assertions). **Recommendation:** **merge A14 INTO A11** (single PR labeled "feat(verify): id_token verifier with strict base64url"). Keeps A11's `describe` blocks aligned with their impl.

---

### PR-A15 — fix(verify): RSA modulus floor + EdDSA JWS verifier

**Source:** snapshot `52a84c5` partial — `MIN_RSA_MODULUS_BYTES`, modulus check inside `verifyJwtRs256Signature`, new `verifyJwtEdDsaSignature`.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/jwt-verify.mjs` | (updated, +25) | modulus floor, EdDSA verifier |
| `tests/test-id-token-verifier.mjs` | (cherry-pick subset of A11 — alg allowlist + RS256 floor cases) | already shipped in A11 |

**RFC concerns:** RFC 7518 §3.3 / RFC 8725 §3.5 (RSA ≥ 2048), RFC 8037 §2 (Ed25519 in JOSE).
**Self-containment:** ✅.
**Server-live needed:** NO.
**Demo:** "an SSO that rotates to a 1024-bit RSA key is rejected — bad-key downgrade closed. EdDSA-signed id_tokens verify correctly (forward-compat)."

> **Recommendation:** **merge A15 INTO A11** for the same reason as A14. The result is A11 = "feat(verify): id_token verifier with strict alphabet, RSA floor, EdDSA, full OIDC §3.1.3.7 walk." That collapses three PRs into one cohesive landing.

---

### PR-A16 — feat(verify): chain verifier (universal provenance walker)

**Source commits:** `3e14024`/`836a9f4` (H1a feat + H1b unit tests, RED→GREEN-shaped) + `9652606` (H1c cmdGitVerify migration) + `5bf50b5` (H2 cleanup) + `86a59e7` (H1d INTEGRATION + README docs) + `fce7398` (cnf-verifier git env isolation).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/lib/chain-verify.mjs` | ~180 | `verifyProofChain(proof)` (9 steps, all fatal), `ChainError`, `SubjectMismatchError`, `AuthRevokedError`. Imports from `lib/jwt-verify.mjs` (PR-A2/A11), `lib/cnf-verify.mjs` (PR-A8), `lib/keys.mjs` (PR-A1) |
| `skills/alien-agent-id/cli.mjs` | (updated, -86 dup, +clean call) | `cmdGitVerify` becomes a thin consumer of `verifyProofChain` |
| `tests/test-chain-verifier.mjs` | NEW (+388 + 92 from snapshot = 480) | 13 unit cases + substitution-forgery integration |
| `tests/test-cnf-verifier.mjs` | (rebuilt fixtures from `9652606`) | end-to-end SSH-signed positive case |
| `docs/INTEGRATION.md` | (updated, +42) | step 9 added, anchoring rule, reference impl pointer |
| `README.md` | (updated, +8) | links to chain section |

**RFC concerns:** RFC 7800 (cnf), RFC 9449 §6.1 (jkt), RFC 7638, RFC 9207, OIDC §3.1.3.7 (consumed via PR-A11 `verifyIdToken`).
**Self-containment:** ✅ pure unit + integration with ephemeral SSH-signed commits.
**Server-live needed:** NO.
**Demo:** "every consumer of the Agent-ID chain (git-verify, the @alien-id/sso-agent-id SDK, capability-proof flows) walks the same 9-step verifier. Substitution-forgery test passes."

---

### PR-A17 — feat(cli): setup-owner-session command (DPoP/cnf migration UX)

**Source commits:** `b10f8ce`.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/cli/commands/setup-owner-session.mjs` | ~80 | the new command (extracted from `cli.mjs:69` into its own file as part of the cli decomposition) |
| `skills/alien-agent-id/cli.mjs` | (updated, +10 dispatch) | dispatches `setup-owner-session` |
| `docs/MIGRATION-DPOP.md` | (no change — A20 supersedes) |

**RFC concerns:** UX only (no normative RFC content).
**Self-containment:** ✅.
**Server-live needed:** YES for end-to-end (rebind triggers fresh /authorize+/token+/git-setup), but this is a CLI command users run interactively.
**Demo:** "`alien-agent-id setup-owner-session` rebinds a pre-3.0 agent under DPoP without losing the keypair or signed-commit history."

---

### PR-A18 — chore(version): bump alien-agent-id 3.0.0

**Source commits:** `0c558e5`.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `package.json` | (1 line) | version bump `2.2.0 → 3.0.0` |

**RFC concerns:** semver only.
**Self-containment:** ✅ trivial.
**Server-live needed:** NO.
**Demo:** "`npm view alien-agent-id versions` shows 3.0.0 once published."

> **Recommendation:** **merge A18 INTO A20** — version bump and release notes ship together.

---

### PR-A19 — refactor(cli): decompose cli.mjs into per-command files

**Source:** pure refactor — splits `cli.mjs` (1,390 lines) into one module per command.

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `skills/alien-agent-id/cli.mjs` | ~200 | main + arg parser + command dispatch table |
| `skills/alien-agent-id/cli/commands/init.mjs` | ~150 | `cmdInit` |
| `skills/alien-agent-id/cli/commands/auth.mjs` | ~180 | `cmdAuth` |
| `skills/alien-agent-id/cli/commands/bind.mjs` | ~180 | `cmdBind` |
| `skills/alien-agent-id/cli/commands/refresh.mjs` | ~120 | `cmdRefresh` |
| `skills/alien-agent-id/cli/commands/git-setup.mjs` | ~120 | `cmdGitSetup` |
| `skills/alien-agent-id/cli/commands/git-sign.mjs` | ~150 | sign-commit logic |
| `skills/alien-agent-id/cli/commands/git-verify.mjs` | ~140 | thin consumer of `verifyProofChain` |
| `skills/alien-agent-id/cli/commands/whoami.mjs` | ~80 | `cmdWhoami` |
| `skills/alien-agent-id/cli/commands/bootstrap.mjs` | ~120 | composite |
| `skills/alien-agent-id/cli/commands/setup-owner-session.mjs` | (already from A17) |

**Tests:** existing CLI integration tests must continue green.
**Self-containment:** ✅ pure file moves.
**Server-live needed:** NO.
**Demo:** "the CLI surface is one-file-per-command; future commands land without growing `cli.mjs`."

---

### PR-A20 — docs + version: 3.0.0 release bundle

**Source commits:** `2cd7ce9` + `99563f9` + `6e67d87` + `a524c99` + `a135b1b` + `0c558e5` (squashed; `c87c52b`'s deletions absorbed).

**Files at end of PR:**

| File | Size | Contents |
|---|---:|---|
| `docs/PRD-DPOP-POP.md` | 83 lines (final state from `99563f9`) |
| `docs/MIGRATION-DPOP.md` | 62 lines (final state) |
| `docs/DEPLOY-DPOP.md` | 75 lines (final state) |
| `docs/RELEASE-NOTES.md` | 52 lines (final state) |
| `package.json` | version 3.0.0 |

**RFC concerns:** none (release artifacts).
**Self-containment:** ✅ docs.
**Server-live needed:** NO for landing; YES for the publish gate (smoke test against staging SSO).
**Demo:** "`npm publish` ships 3.0.0 with a coherent release-notes/migration-guide/runbook trio."

---

### PR-A21 (optional, after Wave 1) — refactor: lib.mjs final cleanup

**Source:** pure refactor — extract pre-existing functions that have no DPoP concern but still live in `lib.mjs`. Listed only because the user asked to ensure `lib.mjs` does not regrow.

**Functions remaining in `lib.mjs` after PR-A1..A19 land:** verifyOwnerSessionProof, SignatureEngine class, verifyState, deriveVaultKey/vaultEncrypt/vaultDecrypt, createAgentToken, resolveAgentId, ChainError/SubjectMismatchError/AuthRevokedError (already in A16's chain-verify.mjs).

**Target homes:**

| File | Contents |
|---|---|
| `lib/owner-session.mjs` | `verifyOwnerSessionProof` |
| `lib/signature-engine.mjs` | `SignatureEngine` |
| `lib/state.mjs` | `verifyState` |
| `lib/vault.mjs` | `deriveVaultKey`, `vaultEncrypt`, `vaultDecrypt` |
| `lib/agent-token.mjs` | `createAgentToken`, `resolveAgentId` |

**Final `lib.mjs`:** ~100 lines, re-export shim only.

**Self-containment:** ✅.
**Server-live needed:** NO.
**Demo:** "`wc -l lib.mjs` ≈ 100 lines, all re-exports. The kitchen-sink era is over."

---

## 4. Critical milestone — agent-id signs a commit with DPoP-bound id_token against live SSO

**Minimum PR sequence to demo end-to-end:**

| Step | PR | Why required |
|---:|---|---|
| 1 | PR-A0 | docs warmup (optional but advised) |
| 2 | PR-A1 | foundation modules — lib/keys + lib/storage + lib/b64 |
| 3 | PR-A2 | foundation — lib/jwt-verify + lib/discovery |
| 4 | PR-A3 | RFC 7638 thumbprint module (used by /authorize wire-up) |
| 5 | PR-A4 | RFC 9449 §4 DPoP proof signer |
| 6 | PR-A5 | CLI emits `dpop_jkt` on /authorize; sends `DPoP` header on /token |
| 7 | PR-A8 | id_token cnf.jkt enforced at git-verify (Workstream-D closure) |
| 8 | PR-A9 | RFC 9449 §5 token_type=DPoP discard rule (downgrade closure) |
| 9 | PR-A11 (= A11+A14+A15) | full id_token verifier (alg, crit, typ, nbf, aud, nonce, RSA floor, EdDSA) |
| 10 | PR-A16 | chain verifier — `cmdGitVerify` consumes the universal walker |

**Once the SSO server has its Wave 1 PRs landed (DB migration + DPoPVerifier + dpop_jkt at /authorize + DPoP at /token + cnf.jkt minted in id_token + token_type=DPoP emitted), the above 10 agent-id PRs deliver the demo:**

```
$ alien-agent-id init
$ alien-agent-id auth         # opens deeplink, pending-auth.json includes dpop_jkt
$ alien-agent-id bind         # /token call carries DPoP proof; receives token_type=DPoP
                              # id_token has cnf.jkt = thumbprint(agent.publicKey)
$ alien-agent-id git setup    # registers SSH key for sign-commit
$ git commit -S -m "test"     # SSH-signs with agent key; agent-id auto-attaches Agent-ID-* trailers
$ alien-agent-id git verify <commit>
  ok=true
  agentFingerprint=...
  ownerSessionSub=...
  jkt=...
  bindingId=...
```

**The remaining 11 PRs (A6, A7, A10, A12, A13, A17, A18, A19, A20, A21) ship hardening, third-party RS interop, UX, version bump, decomposition cleanup. None blocks the demo, but A20 + A18 are required for the npm publish.**

---

## 5. Sequencing summary

```
┌─ PR-A0  docs (warmup, no risk) ─┐
│                                 │
└─ PR-A1  refactor: b64 + keys + storage modules
   │
   └─ PR-A2  refactor: jwt-verify + jwt-parse + discovery
      │
      └─ PR-A3  feat: jwk-thumbprint module (RFC 7638)
         │
         └─ PR-A4  feat: dpop-proof module (RFC 9449 §4) + F-7 SPKI fix
            │
            ├─ PR-A5  feat(cli): wire dpop_jkt + DPoP token header
            │  │
            │  ├─ PR-A6  feat: ath claim + getUserInfo + nonce-aware fetch
            │  │  │
            │  │  └─ PR-A7  feat: nonce retry + nonce cache (RFC 9449 §8/§8.2-1)
            │  │     │
            │  │     └─ PR-A10 feat: §9 RS structured WWW-Authenticate parse
            │  │
            │  └─ PR-A9  feat: token_type=DPoP discard (RFC 9449 §5)
            │
            ├─ PR-A8  feat: cnf.jkt at git-verify (Workstream-D close)
            │  │
            │  └─ PR-A16 feat: chain verifier (universal walker)
            │     │
            │     └─ PR-A17 feat(cli): setup-owner-session
            │
            └─ PR-A11 feat(verify): id_token verifier (merges A14 + A15)
               │
               └─ PR-A12 feat(verify): RFC 9207 iss check
                  │
                  └─ PR-A13 feat(cli): plumb state + nonce + issuer
                     │
                     └─ PR-A19 refactor: decompose cli.mjs into per-command
                        │
                        └─ PR-A20 docs + version: 3.0.0 release
                           │
                           └─ PR-A21 (optional) lib.mjs final cleanup
```

**Critical-path sequence (minimum 10 PRs to demo):** A0 → A1 → A2 → A3 → A4 → A5 → A8 → A9 → A11 → A16.
**Full Wave 1 (15 PRs):** add A6, A7, A10, A12, A13.
**Release Wave 1 (17 PRs):** add A19, A20.
**Polish Wave 1 (19 PRs):** add A17, A21.

---

## 6. Open questions surfaced during research

1. **PR-A11/A14/A15 collapse.** I recommend collapsing into one PR (titled "feat(verify): id_token verifier with strict alphabet, RSA floor, EdDSA, full OIDC §3.1.3.7 walk"). The three RFC concerns are tightly coupled in the same `verifyIdToken` body and the test file `test-id-token-verifier.mjs` cross-references them. Splitting forces a partial verifier in A11 that can't be tested without A14's strict-b64url reject cases. **Default in the plan: collapse.**

2. **PR-A18 collapse with A20.** Version bumps belong with their release notes. **Default: collapse.**

3. **`5bf50b5` H2 dead test removal.** Functionally irrelevant — folds into PR-A4's test-dpop.mjs cherry-pick set without ceremony. Already noted.

4. **`fce7398` cnf-verifier env isolation.** Env-only fix to `tests/test-cnf-verifier.mjs`. Folds into PR-A8 OR PR-A16 (both touch that file). Recommend PR-A16 since A16 rebuilds the fixtures.

5. **Snapshot `52a84c5` includes `docs/REVIEW-PLAN.md`.** That's a planning artifact from earlier in the session — assess whether to keep or drop. Default in plan: keep alongside REFACTOR-PLAN.md in PR-A0.

6. **Cross-repo blocker.** PR-A5/A6/A8/A9 will land green at unit level but the CRITICAL milestone smoke test only succeeds once SSO Wave 1 has shipped: dpop_jkt at /authorize, DPoP at /token, cnf.jkt minted, token_type=DPoP emitted, /userinfo DPoP-protected.

End of research report.
