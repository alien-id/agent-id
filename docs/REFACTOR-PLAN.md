# Pre-Release Refactor Plan

**Snapshot:** 2026-05-08
**Premise:** the ecosystem is RFC-compliant (see `COMPLIANCE.md`: 405 PASS / 0 FAIL / 9 PARTIAL). Code that landed across the DPoP cutover is correct but spread across ~85 files and ~11k net new lines. Several files now mix 5+ RFC concerns. This document is the map for breaking that surface back into focused, single-concern modules **without changing behavior**.

**Constraint:** every scope below is a behavior-preserving move/split. No new features, no RFC re-interpretation. The only place this plan adds code is where it explicitly closes a known caveat from `COMPLIANCE.md` §5 (called out per scope).

---

## 1. Inventory — the diff we are fixing

| Repo | Files changed | Insertions | Deletions | Net |
|---|---:|---:|---:|---:|
| `agent-id/` | 15 | 3,487 | 274 | +3,213 |
| `sso/sso/` (Go) | 33 | 4,539 | 187 | +4,352 |
| `sso/sso-sdk-js/` | 19 | 1,940 | 232 | +1,708 |
| `sso/sso-sdk-py/` | 17 | 1,409 | 428 | +981 |
| `miniapps/miniapp-sdk/` | 3 | 1,122 | 14 | +1,108 |
| **Total** | **87** | **12,497** | **1,135** | **+11,362** |

### Hot files (post-DPoP) — ranked by decomposition pressure

| Rank | File | Lines | Mixed concerns |
|---:|---|---:|---|
| 1 | `agent-id/skills/alien-agent-id/lib.mjs` | **2,122** | b64 utils, JSON canon, JWK thumbprint, key gen, PEM↔JWK, SSH conv, PKCE, OAuth flow, DPoP proof, DPoP nonce retry, RFC 9207 iss verify, ID token verify (basic + owner + chain + sig-only), refresh, file IO |
| 2 | `agent-id/skills/alien-agent-id/cli.mjs` | 1,390 | every subcommand (setup, login, refresh, sign-commit, verify-commit, whoami, …) in one switch |
| 3 | `sso/sso/internal/handler/oauth_token.go` | 596 | code-grant, refresh-grant, RT family cascade, DPoP `dpop_jkt` binding, scope subset, error emission |
| 4 | `sso-sdk-js/packages/core/src/client.ts` | 790 | startAuth, pollAuth, exchangeToken (Bearer + DPoP), refresh (Bearer + DPoP), verifyAuth, persistence, b64 helpers |
| 5 | `sso-sdk-py/packages/core/src/alien_sso/client.py` | 530 | same shape as #4 |
| 6 | `sso-sdk-js/packages/agent-id/src/index.ts` | 511 | basic verify, owner verify (cnf.jkt), chain verify, request-shape adapters |
| 7 | `sso/sso/internal/service/dpop_verifier.go` | 451 | proof verify, JWK extract, EdDSA prep, htu canon, %-encoding helpers |
| 8 | `miniapps/miniapp-sdk/packages/auth-client/src/index.ts` | 461 | JWKS resolver + RSA modulus floor, RS256 verify, EdDSA legacy verify, Bearer challenge, DPoP challenge, DPoP RS verifier |
| 9 | `sso-sdk-py/packages/agent-id/src/alien_sso_agent_id/verify.py` | 440 | basic + owner + request adapters |
| 10 | `sso/sso/internal/service/jwt.go` | 418 | mint AT, mint ID, verify AT, verify ID, header validators, JWKS export |
| 11 | `sso/sso/internal/config/config.go` | 367 | env loading + DPoP + OIDC keys + S3 + oracle + Solana + …  |

`docs/REVIEW-PLAN.md` (31K) and `docs/COMPLIANCE.md` (20K) are correct snapshots, not refactor targets.

---

## 2. Refactor strategy — three principles

1. **Behavior-preserving, file-level moves.** Each scope = one PR = `git mv` plus import-fix plus targeted decomposition. Tests stay green at every step.
2. **One RFC per file, where the RFC and the file are at the same granularity.** "DPoP proof construction" gets its own module; "RFC 7519 §4.1.x claim type guards" do not (too small — keep grouped under `_jwt.ts`).
3. **Bottom-up: primitives → verifiers → endpoints.** Phase-1 modules (b64, thumbprint, htu canon) ship first because every other scope imports from them. The big files get split last.

**Anti-goals.** No abstraction layer added "for symmetry". No cross-language contract changes. No public API rename. No new types invented just because the same shape exists in three SDKs. Each scope below has a hard diff cap; if a scope wants to grow past that, split it.

---

## 3. Scope index

| # | Phase | Scope | Repos touched | Diff cap (lines) | Closes caveat |
|---:|---|---|---|---:|:---:|
| 1 | P1 primitives | base64url + canonical JSON helpers | js / py / agent-id | 120 | — |
| 2 | P1 primitives | JWK thumbprint module (RFC 7638 + 8037) | go / js / py / agent-id | 200 | — |
| 3 | P1 primitives | htu canonicalization (RFC 3986 §6.2.2) | go / js / agent-id / miniapp | 250 | — |
| 4 | P1 primitives | Strict b64url alphabet pre-screen — outer envelope | agent-id | 30 | §5.5 |
| 5 | P2 verifiers | DPoP proof construction module (RFC 9449 §4) | js / py / agent-id | 500 | §5.3 |
| 6 | P2 verifiers | DPoP `use_dpop_nonce` retry (RFC 9449 §8/§9) | js / agent-id | 100 | §5.2 |
| 7 | P2 verifiers | DPoP server-side verifier split (RFC 9449 §4–§7) | go | 300 | — |
| 8 | P2 verifiers | WWW-Authenticate challenge builders (RFC 6750 §3, RFC 9449 §7.1) | go / miniapp | 180 | — |
| 9 | P3 decomp | Go token endpoint split (`oauth_token.go` 596 → 4 files) | go | 400 | — |
| 10 | P3 decomp | Go userinfo + challenge writers (`oauth_userinfo.go` 191 → 2) | go | 120 | — |
| 11 | P3 decomp | Go `service/jwt.go` split (418 → 3) | go | 200 | — |
| 12 | P3 decomp | Go `config.go` split (367 → 4) | go | 200 | — |
| 13 | P3 decomp | JS core `client.ts` split (790 → 5) | js | 700 | §5.1 |
| 14 | P3 decomp | JS agent-id `index.ts` split (511 → 4) | js | 300 | — |
| 15 | P3 decomp | Py core `client.py` split (530 → 5) | py | 500 | — |
| 16 | P3 decomp | Py agent-id `verify.py` split (440 → 3) | py | 300 | — |
| 17 | P3 decomp | **agent-id `lib.mjs` split (2,122 → ~14)** | agent-id | 2,300 | — |
| 18 | P3 decomp | agent-id `cli.mjs` split (1,390 → ~7) | agent-id | 1,500 | — |
| 19 | P3 decomp | miniapp-sdk `auth-client` split (461 → 4) | miniapp | 500 | — |
| 20 | P4 closeout | Cross-track parity sweep + `SOURCE-MAP.md` | all | 200 | — |

**Total diff cap:** ≤8,900 lines across 20 PRs, of which ≥80% are pure moves (net delta near zero per PR). The 5 caveats from `COMPLIANCE.md` §5.1, §5.2, §5.3, §5.5 close as side-effects of scopes 4, 6, 5, 13.

---

## 4. Phase 1 — primitives

### Scope 1 — base64url + canonical JSON helpers

**Standards:** RFC 7515 §2 (base64url alphabet + length residue), RFC 7638 + RFC 8259 (JCS-like canonical key sort).

**Currently inlined in:**
| Repo | Location |
|---|---|
| JS core | `packages/core/src/client.ts:26-45` (3 inline funcs); `packages/core/src/dpop.ts:42-49` (sha256 + b64url) |
| Py core | `packages/core/src/alien_sso/client.py:511-517` (`_b64url_decode`); `packages/core/src/alien_sso/_verify.py:32-41` (strict alphabet) |
| agent-id | `skills/alien-agent-id/lib.mjs:42-101` (`canonicalJSONString`, `b64url`, `fromB64url`, `sha256B64url`, `sha256Hex`) |
| miniapp | `packages/auth-client/src/index.ts:16-22` (`b64urlByteLength`) |

**Move:**
- JS core → new `packages/core/src/_b64.ts` (~30 lines). Import from `client.ts` and `dpop.ts`.
- Py core → new `packages/core/src/alien_sso/_b64.py` (matches the agent-id file already at `packages/agent-id/src/alien_sso_agent_id/_b64.py`). Delete duplicated logic in `_verify.py:32-41` and `client.py:511-517`.
- agent-id → new `skills/alien-agent-id/lib/b64.mjs` (~50 lines).
- miniapp → keep inline (single 5-line use site, not worth a module).

**Tests already in place:** RFC 7515 §2 vectors via `_verify.py` tests; agent-id covers via `test-id-token-verifier.mjs`. Add a parity test in JS that exercises the new module against `RFC 8037 §A.3` payload.

**Diff cap:** 120 lines.

---

### Scope 2 — JWK thumbprint module (RFC 7638 + RFC 8037)

**Standards:** RFC 7638 (canonical key set), RFC 8037 §A.3 (Ed25519 reference vector).

**Currently inlined in:**
| Repo | Location |
|---|---|
| Go | `internal/service/jwt.go` (Ed25519 thumbprint inline in mint + verify path) |
| JS core | `packages/core/src/dpop.ts:42-49` (`dpopJwkThumbprint`) |
| JS agent-id | `packages/agent-id/src/crypto.ts:77-89` (`ed25519JwkThumbprint`) — already isolated |
| Py core | absent (no DPoP send today) |
| Py agent-id | `packages/agent-id/src/alien_sso_agent_id/_crypto.py:53-76` — already isolated |
| agent-id | `skills/alien-agent-id/lib.mjs:138-196` (`ed25519PublicKeyToJwk` + `jwkThumbprint`) |

**Move:**
- Go → new `internal/service/jwk_thumbprint.go` with `Ed25519JwkThumbprint(pub ed25519.PublicKey) string`. Import from `jwt.go`.
- JS core → already small in `dpop.ts`. Promote to `_jwk.ts` so future RSA thumbprint can land alongside.
- agent-id → new `skills/alien-agent-id/lib/jwk-thumbprint.mjs`. ~80 lines.

**Test parity:** every track gets the RFC 8037 §A.3 vector (`x = 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo` → `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`). JS already has it (`tests/unit/dpop.test.ts:14-26`). Replicate in Go + agent-id.

**Diff cap:** 200 lines.

---

### Scope 3 — htu canonicalization (RFC 3986 §6.2.2 + RFC 9449 §4.3)

**Standards:** RFC 3986 §6.2.2 (scheme + host case, percent-encoding normalization, default-port stripping, dot-segment removal), RFC 9449 §4.3 (strip query + fragment).

**Currently in:**
| Repo | Location | Strength |
|---|---|---|
| Go | `dpop_verifier.go:298-447` (`canonicalizeHTU` + `normalizePercentEncoding` + `removeDotSegments` + `removeLastSegment` + helpers) | full §6.2.2 |
| JS core | `packages/core/src/dpop.ts:322-349` (`canonicalizeHtu`) | partial — strips `?` + `#`, lowercases scheme + host, strips default port |
| miniapp | `packages/auth-client/src/index.ts:322-349` (`canonicalizeHtu`) | parity with JS core |
| agent-id | `skills/alien-agent-id/lib.mjs:257-272` (`stripUrlQueryAndFragment`) | **weakest** — only strips `?` + `#`. **Upgrade target.** |

**Move:**
- Go → extract `canonicalizeHTU` + helpers to `internal/service/htu_canon.go`. Tests already exist in `htu_canon_test.go`.
- JS core → new `packages/core/src/_htu.ts`.
- agent-id → new `skills/alien-agent-id/lib/htu.mjs` **with §6.2.2 upgrade**: scheme + host lowercase + default port strip + dot-segment removal. Replace `stripUrlQueryAndFragment` call sites in `lib.mjs:198-256` (`createDPoPProof`).
- miniapp → import from `core` if cross-package boundary allows; otherwise duplicate intentionally.

**Tests:** port the Go `htu_canon_test.go` table to JS + agent-id.

**Diff cap:** 250 lines (includes the agent-id strength upgrade, which is the only behavior-changing move in P1).

---

### Scope 4 — strict b64url alphabet pre-screen on outer envelope

**Standard:** RFC 7515 §2 — closes `COMPLIANCE.md` §5.5.

**Currently:**
- agent-id `lib.mjs:1271` — outer token envelope decoded via Buffer's `'base64url'` (permissive on whitespace). Inner segments are strict via `parseJwt`. Sister findings (JS / Py agent-id) already strict-pre-screen the outer.

**Move:**
- agent-id → add `OUTER_BASE64URL = /^[A-Za-z0-9_-]+$/` regex pre-check at `lib.mjs:1271` before `Buffer.from(..., 'base64url')`. Re-use the constant from `lib/b64.mjs` shipped in Scope 1.

**Diff cap:** 30 lines.

---

## 5. Phase 2 — verification modules

### Scope 5 — DPoP proof construction (RFC 9449 §4)

**Standards:** RFC 9449 §4.1 (header), §4.2 (signing input), §4.3 (claims), RFC 8037 (alg), RFC 9110 §9.1 (htm case).

**Currently:**
| Repo | Location | Status |
|---|---|---|
| JS core | `packages/core/src/dpop.ts:1-145` | already isolated; reuse |
| agent-id | `skills/alien-agent-id/lib.mjs:198-256` (`createDPoPProof`) | inline in lib.mjs |
| Py core | absent | **NEW — closes §5.3** |

**Move:**
- agent-id → extract to `skills/alien-agent-id/lib/dpop-proof.mjs`. Re-use thumbprint (Scope 2) and htu canon (Scope 3).
- Py core → new `packages/core/src/alien_sso/_dpop.py` mirroring `dpop.ts`: `dpop_jwk_thumbprint`, `create_dpop_keypair`, `create_dpop_proof`. Closes `COMPLIANCE.md §5.3`.

**Tests:** RFC 8037 §A.3 vector parity across all 3 implementations + signature-verifies-with-embedded-jwk parity.

**Diff cap:** 500 lines (Py port is the largest piece).

---

### Scope 6 — DPoP `use_dpop_nonce` retry loop (RFC 9449 §8 / §9)

**Standards:** RFC 9449 §8 (token endpoint nonce), §9 (resource server nonce).

**Currently:**
- agent-id `lib.mjs:975-1017` (`fetchWithDPoPNonce`) — full implementation
- JS core — accepts `nonce` in `createDPoPProof` but no retry orchestration. **Closes `COMPLIANCE.md §5.2`.**
- Py core — N/A until Scope 5 ships.

**Move:**
- agent-id → extract to `skills/alien-agent-id/lib/dpop-nonce-fetch.mjs`.
- JS core → new `packages/core/src/_dpop_nonce.ts` wrapping `fetch` with single-retry on `400 use_dpop_nonce` carrying the `DPoP-Nonce` response header. Wire into `client.ts` `/oauth/token` paths (post-Scope 13 split, this lives in `token-exchange.ts` and `refresh.ts`). ~40 lines.

**Diff cap:** 100 lines.

---

### Scope 7 — Go DPoP server-side verifier split (RFC 9449 §4–§7)

**Standards:** RFC 9449 §4.3 (proof shape), §6.1 (cnf binding), §7.1 (RS challenge).

**Current:** `internal/service/dpop_verifier.go` 451 lines in one file:
- entry points (`VerifyProof`, `VerifyResourceProof`)
- proof verification (`verifyProofWithATH`)
- JWK extraction (`prepareEdDSAVerifier`)
- htu canon helpers (moves to Scope 3)
- jti replay (DB roundtrip)

**Move:**
- `dpop_verifier.go` — entry orchestration only (~150 lines)
- new `dpop_jwt_parse.go` — header decode, jwk extract, EdDSA prep (~120 lines)
- new `dpop_jti_replay.go` — DB-backed replay window (~80 lines)
- `htu_canon.go` already moved in Scope 3

**Tests:** existing `dpop_verifier_test.go` (532 lines) covers the surface; verify each test still applies after split.

**Diff cap:** 300 lines (mechanical move).

---

### Scope 8 — WWW-Authenticate challenge builders (RFC 6750 §3, RFC 9449 §7.1)

**Standards:** RFC 6750 §3 (Bearer challenge auth-param ABNF), RFC 9449 §7.1 (DPoP `algs=` advertisement), RFC 9110 §5.5 (header injection).

**Currently:**
| Repo | Location |
|---|---|
| Go | `internal/handler/oauth_userinfo.go:150-200` — 4 challenge writers inline in handler |
| miniapp | `packages/auth-client/src/index.ts:182-265` (`assertHeaderSafe`, `buildBearerChallenge`, `buildDPoPChallenge`) |

**Move:**
- Go → new `internal/handler/challenges.go` with `WriteBearerChallenge`, `WriteDPoPChallenge`, `WriteMissingAuthChallenge`. Re-export from `oauth_userinfo.go`.
- miniapp → new `packages/auth-client/src/challenges.ts`. Re-export from `index.ts`. Tests stay in `tests/challenge.test.ts`.

**Diff cap:** 180 lines.

---

## 6. Phase 3 — endpoint / client decomposition

### Scope 9 — Go `oauth_token.go` (596 → 4 files)

**Standards:** RFC 6749 §4.1 (code grant), §6 (refresh), RFC 9449 §5 (DPoP binding), RFC 9700 §2.2.2 (RT rotation + reuse cascade).

**Map:**
| New file | Source ranges (current `oauth_token.go`) | Approx |
|---|---|---:|
| `oauth_token.go` | `Token` router + `sendTokenResponse` + `sendError` (lines 45–63, 577–595) | 80 |
| `oauth_token_code.go` | `handleAuthorizationCodeGrant` (64–262) | 200 |
| `oauth_token_refresh.go` | `handleRefreshTokenGrant` + family cascade (300–503) | 250 |
| `oauth_token_helpers.go` | `dpopOrBearer`, `isScopeSubset`, `scopeContains`, `nullableString`, `createRefreshToken` (263–299, 504–576) | 80 |

**Test invariant:** `internal/handler/full_flow_oauth_test.go` and `oauth_token_rotation_test.go` stay green without changes.

**Diff cap:** 400 lines (moves only).

---

### Scope 10 — Go `oauth_userinfo.go` (191 → 2)

**Standards:** RFC 6750 §3, RFC 9068 §4, RFC 9449 §7.1.

**Map:**
| New file | Content | Approx |
|---|---|---:|
| `oauth_userinfo.go` | `UserInfo` handler + scheme selection (36–149) | 100 |
| `oauth_userinfo_challenges.go` | `sendInvalidRequest`, `sendBearerError`, `sendMissingAuthChallenge`, `sendDPoPError` (150–200) | 80 (folds into Scope 8 if `challenges.go` lands first) |

**Diff cap:** 120 lines.

---

### Scope 11 — Go `service/jwt.go` (418 → 3)

**Standards:** RFC 7519, RFC 9068, RFC 8725 §3.7, RFC 7800.

**Map:**
| New file | Content | Approx |
|---|---|---:|
| `jwt_mint.go` | `NewJWTService`, `CreateIDToken`, `CreateAccessToken`, `CreateLegacySSOAuthToken`, `GetJWKS` | 200 |
| `jwt_verify.go` | `VerifyAccessToken`, `VerifyIDToken` | 150 |
| `jwt_header_validators.go` | `requireKid`, `rejectCritHeader`, `isAccessTokenTyp`, `isIDTokenTyp` | 80 |

**Tests:** `jwt_aud_test.go`, `jwt_cnf_test.go`, `jwt_crit_test.go`, `jwt_id_token_typ_test.go`, `jwt_legacy_test.go`, `jwt_required_claims_test.go` already split by concern — no changes.

**Diff cap:** 200 lines.

---

### Scope 12 — Go `config/config.go` (367 → 4)

**Map:**
| New file | Content | Approx |
|---|---|---:|
| `config.go` | `Load` + `Config` struct skeleton + env helpers | 120 |
| `config_dpop.go` | DPoP-specific fields + load (jti window, algs, max-age, etc.) | 80 |
| `config_oidc.go` | OIDC issuer + RS256 signing key + JWKS | 80 |
| `config_external.go` | S3 + oracle + Solana + shortener client config | 80 |

**Diff cap:** 200 lines.

---

### Scope 13 — JS core `client.ts` (790 → 5 modules)  **— closes §5.1**

**Standards:** RFC 6749 §4.1+§6, RFC 9449 §5, RFC 9207, OIDC §3.1.3.7.

**Current concerns inside `client.ts`:**
- assertSsoBaseUrlSafe (TLS guard)
- AlienSsoClient class scaffolding + persistence
- `startAuth` / `pollAuth`
- `exchangeCode` (Bearer + DPoP path)
- `refreshAccessToken` (Bearer + DPoP path)
- `verifyAuth` (always-Bearer today — see `COMPLIANCE.md §5.1`)
- inline base64url helpers (move to Scope 1)

**Map:**
| New file | Content | Approx |
|---|---|---:|
| `client.ts` | class + ctor + persistence orchestration + TLS guard | 200 |
| `auth-flow.ts` | `startAuth` + `pollAuth` + RFC 9207 iss check | 180 |
| `token-exchange.ts` | `exchangeCode` (Bearer + DPoP) + Scope 6 nonce wrapper | 180 |
| `refresh.ts` | `refreshAccessToken` (Bearer + DPoP) + Scope 6 nonce wrapper | 180 |
| `userinfo.ts` | `verifyAuth` + DPoP wiring (closes §5.1: ~30 lines for `createDPoPProof({ htm: 'GET', htu, accessToken })` when `dpopKeypair` set) | 80 |

**Tests:** `tests/unit/client.test.ts` (512 lines), `refresh-token.test.ts`, `verify.test.ts`, `dpop.test.ts` stay green. Add 2-3 cases in `userinfo.test.ts` for the DPoP path.

**Diff cap:** 700 lines. The +30 for §5.1 closure is the only behavior-adding piece.

---

### Scope 14 — JS agent-id `index.ts` (511 → 4)

**Standards:** OIDC §3.1.3.7, RFC 7800, RFC 9449 §6.1.

**Map:**
| New file | Content | Approx |
|---|---|---:|
| `index.ts` | public exports (`verifyAgentToken`, `verifyAgentTokenWithOwner`, `verifyAgentRequest`, `verifyAgentRequestWithOwner`) | 80 |
| `verify-basic.ts` | `verifyAgentToken` body | 150 |
| `verify-owner.ts` | `verifyAgentTokenWithOwner` body + cnf.jkt enforcement (the post-fix-1 closure) | 120 |
| `verify-request.ts` | request-shape adapters | 100 |

**Diff cap:** 300 lines.

---

### Scope 15 — Py core `client.py` (530 → 5)

Same structure as Scope 13. Splits:

| New file | Content | Approx |
|---|---|---:|
| `client.py` | `AlienSsoClient` class + ctor + persistence + TLS guard | 200 |
| `_auth_flow.py` | `generate_deeplink` + `poll_auth` + `_verify_auth_once` | 180 |
| `_token_exchange.py` | `exchange_token` | 100 |
| `_refresh.py` | `refresh_access_token` + `_do_refresh*` + `with_auto_refresh` | 150 |
| `_nonce_store.py` | `NonceStore` Protocol + `_DefaultNonceStore` (already 30 lines) | 50 |

**Diff cap:** 500 lines.

---

### Scope 16 — Py agent-id `verify.py` (440 → 3)

| New file | Content | Approx |
|---|---|---:|
| `verify.py` | public exports + `verify_agent_token` | 150 |
| `_verify_owner.py` | `verify_agent_token_with_owner` + cnf.jkt + typ enforcement | 200 |
| `_verify_request.py` | `verify_agent_request*` + header extraction | 100 |

**Diff cap:** 300 lines.

---

### Scope 17 — agent-id `lib.mjs` (2,122 → ~14 modules) — **the headliner**

**Strategy:** one PR per module (≥14 PRs sub-stacked in this scope). Cap each sub-PR at ≤300 lines. **Do not bundle.** Sub-PRs land in dependency order.

**Module map:**
| New module | Source ranges | RFC concern | Approx |
|---|---|---|---:|
| `lib/b64.mjs` | 27–101 | RFC 7515 §2 + RFC 7638 canonical JSON | 80 |
| `lib/jwk-thumbprint.mjs` | 138–196 | RFC 7638 + RFC 8037 | 80 |
| `lib/keys.mjs` | 113–137, 274–402 | Ed25519 keygen + PEM↔JWK + SSH conv | 250 |
| `lib/jwt-parse.mjs` | (currently inline in many call sites) | RFC 7515 §2 strict 3-segment | 120 |
| `lib/jwt-verify.mjs` | 313–334 + parts of 1100–1220 | RS256 + EdDSA signature verify | 150 |
| `lib/htu.mjs` | 257–272 (upgraded — see Scope 3) | RFC 3986 §6.2.2 / RFC 9449 §4.3 | 100 |
| `lib/dpop-proof.mjs` | 198–256 | RFC 9449 §4 (Scope 5) | 100 |
| `lib/dpop-nonce-fetch.mjs` | 975–1017 | RFC 9449 §8/§9 (Scope 6) | 100 |
| `lib/iss-verify.mjs` | (RFC 9207 helper currently inline) | RFC 9207 | 80 |
| `lib/id-token-verify.mjs` | (steps 1..15 currently inline in basic + owner verify) | OIDC §3.1.3.7 | 200 |
| `lib/cnf-verify.mjs` | 1101–1112 | RFC 7800 / RFC 9449 §6.1 | 80 |
| `lib/chain-verify.mjs` | (chain branch currently inline) | OIDC §3.1.3.7 + RFC 7800 | 180 |
| `lib/refresh.mjs` | (RT flow currently inline) | RFC 6749 §6 + RFC 9700 §2.2.2 | 200 |
| `lib/oauth-flow.mjs` | (PKCE + dpop_jkt + redirect URI prep) | RFC 7636 + RFC 9449 §10 | 150 |
| `lib/storage.mjs` | (file IO scattered) | — | 100 |
| `lib.mjs` | re-export shim only | — | 80 |

**Test reorganization:** existing `test-chain-verifier.mjs`, `test-cnf-verifier.mjs`, `test-dpop.mjs`, `test-id-token-verifier.mjs`, `test-refresh.mjs`, `test-rfc9207-iss.mjs` are already split by concern. They stay where they are; only their `import` paths change.

**Sequencing within Scope 17:**
1. Land Phase-1 modules (`b64`, `jwk-thumbprint`, `htu`) first — these are the leaves.
2. Land verifiers (`jwt-parse`, `jwt-verify`, `cnf-verify`, `iss-verify`).
3. Land DPoP modules (`dpop-proof`, `dpop-nonce-fetch`).
4. Land flow modules (`id-token-verify`, `chain-verify`, `oauth-flow`, `refresh`).
5. Land entry-point modules (`keys`, `storage`).
6. Final PR: turn `lib.mjs` into a thin re-export shim and verify all 6 test files pass.

**Diff cap:** 2,300 lines net across ≥14 sub-PRs (~150 lines each, mostly moves).

---

### Scope 18 — agent-id `cli.mjs` (1,390 → ~7 commands)

**Map:**
| New file | Content | Approx |
|---|---|---:|
| `cli.mjs` | main + arg parsing + command dispatch | 200 |
| `cli/commands/setup.mjs` | `setup` subcommand | 200 |
| `cli/commands/login.mjs` | `login` subcommand | 200 |
| `cli/commands/refresh.mjs` | `refresh` subcommand | 150 |
| `cli/commands/sign-commit.mjs` | `sign-commit` subcommand | 200 |
| `cli/commands/verify-commit.mjs` | `verify-commit` subcommand | 250 |
| `cli/commands/whoami.mjs` | `whoami` subcommand | 100 |

**Diff cap:** 1,500 lines.

---

### Scope 19 — miniapp-sdk `auth-client/src/index.ts` (461 → 4)

| New file | Content | Approx |
|---|---|---:|
| `index.ts` | public exports | 50 |
| `jwks-resolver.ts` | `makeJwksResolver` + RFC 7518 §3.3 modulus floor (`b64urlByteLength`, `MIN_RSA_MODULUS_BYTES`) | 80 |
| `verify.ts` | `createAuthClient` + RS256 + EdDSA paths + JWE reject | 150 |
| `challenges.ts` | `assertHeaderSafe` + `buildBearerChallenge` + `buildDPoPChallenge` (Scope 8) | 90 |
| `dpop-verify.ts` | `verifyDPoPProof` + `canonicalizeHtu` (Scope 3) + DPoP defaults | 150 |

**Diff cap:** 500 lines.

---

## 7. Phase 4 — closeout

### Scope 20 — cross-track parity sweep + `SOURCE-MAP.md`

**Goal:** lock in the new structure so future drift is visible.

**Deliverables:**
1. `agent-id/docs/SOURCE-MAP.md` — a one-page index "RFC § X.Y → file:line in each track". Mirrors the `COMPLIANCE.md §7` parity matrix but with concrete file paths after the splits land.
2. CI lint that fails if any of the hot files in §1 grow back past their post-split cap (e.g., `oauth_token.go` ≤ 250 lines, `client.ts` ≤ 220 lines, `lib.mjs` ≤ 100 lines as a re-export shim).
3. Verify `COMPLIANCE.md` re-runs clean — every track still 0 FAIL.

**Diff cap:** 200 lines.

---

## 8. Sequencing rules

1. **Phase 1 → Phase 2 → Phase 3 → Phase 4**, in order. Phase boundaries are hard.
2. Within Phase 3, **no two scopes touching the same file run in parallel**. Each repo gets serialized: e.g., Go scopes 9 → 10 → 11 → 12; JS scopes 13 → 14; Py scopes 15 → 16; agent-id 17 → 18; miniapp 19. Different repos can run in parallel.
3. **Each PR ships green** — no "WIP, follow-up coming" comments. If a split forces a behavior change, it goes into its own PR, not bundled with the move.
4. **No PR merges if `bun test` / `pytest` / `go test ./...` regresses.** Use the existing test suites as the contract: `agent-id` 6 test files (~3.4k lines), `sso/sso` integration `full_flow_oauth_test.go` (1.2k lines) + service unit tests, `sso-sdk-js` Jest, `sso-sdk-py` pytest, `miniapp-sdk` bun:test.

---

## 9. Caveats this plan closes (free riders)

| Caveat (`COMPLIANCE.md` §) | Closed by | Lines added |
|---|---|---:|
| §5.1 JS core `verifyAuth()` always-Bearer | Scope 13 (in `userinfo.ts`) | ~30 |
| §5.2 JS core `use_dpop_nonce` retry | Scope 6 | ~40 |
| §5.3 Py core DPoP send | Scope 5 (Py port) | ~150 |
| §5.5 agent-id outer envelope b64url permissive | Scope 4 | ~5 |

Aggregate ~225 lines of new logic on top of the move-only work. None of these are blocking; they ride along for free with the relevant decomposition.

**Caveats explicitly NOT closed by this plan:** §5.4 (Py agent-id azp policy — single-line change, defer), §5.6 (`iat` freshness — RP policy), §5.7 (`verifyIdTokenSignatureOnly` permissive — intentional), §5.8 (forward-compat allowlist), §5.9, §5.10, §5.11.

---

## 10. Acceptance for the whole plan

After all 20 scopes land:

- [ ] Every file in §1 hot-files table is below its split cap.
- [ ] Every test suite green: `bun test` (4 of 5 tracks), `pytest`, `go test ./...`.
- [ ] `COMPLIANCE.md` re-audit yields **0 FAIL / ≤5 PARTIAL** (down from 9 — the four §5.x caveats above close).
- [ ] No public API renames in any SDK. Grep should show consumer code unchanged.
- [ ] `docs/SOURCE-MAP.md` exists and is accurate.
- [ ] Total net delta across the 20 PRs is **strictly negative or near-zero** (we are moving code, not adding it, except for the 4 caveat closures).
