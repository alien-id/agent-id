# Wave 1 — SSO server PRs

**Source branch:** `backup/huge-refac-2026-05-08` in `/Users/truehazker/Workspace/alien/sso/sso`, 47 commits ahead of `main`.
**Goal:** ship agent-id DPoP end-to-end as fast as possible while baking decomposition into each cherry-pick — no "monolith now, clean later".

---

## 1. Commit graph

Read top-to-bottom = oldest-first land order (the order the human intended).

| # | SHA | Subject | Touches | RFC | Depends on | Pair |
|---:|---|---|---|---|---|---|
|  1 | 6a22512 | chore: chain url + session-address log | `cmd/server/main.go` `handler/oauth_callback.go` | — | — | — |
|  2 | ac7db55 | chore: log node errors in authorize-miniapp | `handler/authorize_miniapp.go` | — | — | — |
|  3 | d9f0326 | feat: dpop_jkt + dpop_jti_seen migration | `migrations/000010_dpop.{up,down}.sql` | RFC 9449 §4 / §11.1 | — | — |
|  4 | d941f23 | feat: service.DPoPVerifier deep module | `service/dpop_verifier.go` `service/dpop_verifier_test.go` | RFC 9449 §4 §5 §11 | #3 | — |
|  5 | fff626f | feat: JWTService.cnfJkt for cnf claim | `service/jwt.go` `service/jwt_cnf_test.go` | RFC 7800 / RFC 9449 §6.1 | — | — |
|  6 | d98d049 | feat: enforce DPoP at authorize+token (auth-code) | `handler/oauth_authorize.go` `handler/oauth_helpers.go` `handler/oauth_token.go` `router/router.go` | RFC 9449 §4 §5 | #3 #4 #5 | — |
|  7 | d5f928d | feat: SessionCleaner GC dpop_jti_seen | `service/cleaner.go` `service/cleaner_test.go` | RFC 9449 §11.1 | #3 | — |
|  8 | a3e6d4f | test: 5 DPoP auth-code integration scenarios | `handler/full_flow_oauth_test.go` (+362) | RFC 9449 §4–§6 | #6 | RED partial pre-#6, becomes regression after |
|  9 | b7e2c89 | feat: enforce DPoP on userinfo when AT cnf-bound | `handler/full_flow_oauth_test.go` `handler/oauth_userinfo.go` `router/router.go` | RFC 9449 §7.1 | #4 | — |
| 10 | b8ad984 | feat: dpop_jkt column on refresh_tokens migration | `migrations/000011_dpop_refresh_tokens.{up,down}.sql` | RFC 9449 §5 sticky | — | — |
| 11 | 1137a52 | feat: enforce DPoP on refresh-token grant | `handler/oauth_token.go` (+76) | RFC 9449 §5 | #4 #5 #10 | — |
| 12 | eecc5b2 | test: DPoP refresh-token grant scenarios | `handler/full_flow_oauth_test.go` (+262) | RFC 9449 §5 | #11 | regression |
| 13 | 9f5fccb | feat: advertise DPoP + cnf in OIDC discovery | `handler/oidc_discovery.go` `handler/oidc_discovery_test.go` | RFC 9449 §5.1 / RFC 7800 | — (informational) | — |
| 14 | bbf8ec6 | test: F-6 reject duplicate dpop_jkt | `handler/full_flow_oauth_test.go` (+28) | RFC 9449 §10 | #6 | RED |
| 15 | c675c5e | fix: F-6 reject duplicate dpop_jkt | `handler/oauth_authorize.go` (+13) | RFC 9449 §10 | #14 | GREEN |
| 16 | 0a43436 | test: F-4 accept canonically-equal htu | `service/dpop_verifier_test.go` (+51) | RFC 9449 §4.3 | #4 | RED |
| 17 | a786dfc | fix: F-4 canonicalize htu | `service/dpop_verifier.go` (+31) `service/htu_canon_test.go` (+32) | RFC 9449 §4.3 / RFC 3986 | #16 | GREEN |
| 18 | 434161c | test: F-2 token_type=DPoP | `handler/full_flow_oauth_test.go` (+8) | RFC 9449 §5 | #6 | RED |
| 19 | 33fed23 | fix: F-2 emit token_type=DPoP | `handler/oauth_token.go` (+13) | RFC 9449 §5 | #18 | GREEN |
| 20 | edfd255 | test: F-3 strict scheme-by-binding userinfo | `handler/full_flow_oauth_test.go` (+101) | RFC 9449 §7.1 | #9 | RED |
| 21 | 7b01b4e | fix: F-3 strict scheme-by-binding | `handler/oauth_userinfo.go` (+26 -15) | RFC 9449 §7.1 | #20 | GREEN |
| 22 | e7b1b2f | test: F-1 ath required on userinfo proof | `handler/full_flow_oauth_test.go` (+67) | RFC 9449 §4.2 §7.1 | #9 | RED |
| 23 | d45e01c | fix: F-1 enforce ath on protected-resource proof | `handler/oauth_userinfo.go` (+1) `service/dpop_verifier.go` (+33) | RFC 9449 §4.2 §7.1 | #22 | GREEN — adds `VerifyResourceProof` |
| 24 | 54d5b62 | test: G-1 (final) reject duplicate DPoP header | `handler/full_flow_oauth_test.go` (+101) | RFC 9449 §4.3-1 | #6 #9 | RED |
| 25 | 5608a7e | fix: G-1 (final) reject duplicate DPoP at all entry points | `handler/oauth_helpers.go` (+22) `handler/oauth_token.go` (+10) `handler/oauth_userinfo.go` (+5) | RFC 9449 §4.3-1 | #24 | GREEN |
| 26 | a8b78a9 | test: G-1 (early — superseded by #25) | mostly noise rename | — | — | obsoleted by #24/#25 — **SKIP** |
| 27 | 5931123 | fix: G-1 (early — superseded by #25) | partial readSingleDPoPHeader | — | — | obsoleted by #24/#25 — **SKIP** |
| 28 | b475ec1 | test: G-9 reject JWK with private key | `service/dpop_verifier_test.go` (+31) | RFC 9449 §4.2-4 §4.3-7 | #4 | RED |
| 29 | 2dcf54a | fix: G-9 reject JWK with private fields | `service/dpop_verifier.go` (+9) | RFC 7517 / 9449 | #28 | GREEN |
| 30 | 6519b5d | test: G-5+G-6 algs + Cache-Control no-store userinfo | `handler/full_flow_oauth_test.go` (+28) | RFC 9449 §7.1 / OIDC §5.3.2 | #9 | RED |
| 31 | 26d5a02 | fix: G-5+G-6 advertise algs + no-store on success | `handler/oauth_userinfo.go` (+12) | RFC 9449 §7.1 / OIDC §5.3.2 | #30 | GREEN |
| 32 | 3c8b073 | test: G-8 reject oversized jti | `service/dpop_verifier_test.go` (+21) `service/dpop_verifier.go` (+7 placeholder) | RFC 9449 §11.1 | #4 | RED |
| 33 | 15ac6d4 | fix: G-8 cap jti at 256 chars | `service/dpop_verifier.go` (+3) | RFC 9449 §11.1 | #32 | GREEN |
| 34 | e027689 | fix: M1 canonicalizeHTU IPv6-safe port stripping | `service/dpop_verifier.go` (+14) `service/htu_canon_test.go` (+7) | RFC 9449 §4.3 | #17 | follow-up |
| 35 | 0e5605c | fix: L1 document strict-scheme deviation | `handler/oauth_userinfo.go` (+10 -2) doc-only | RFC 9449 §7.1 SHOULD | #21 | doc — superseded by snapshot's §7.2 rewrite |
| 36 | 83fd96a | fix: L2 Cache-Control on every userinfo response | `handler/oauth_userinfo.go` (+9 -4) | OIDC §5.3.2 | #9 | follow-up |
| 37 | 9b1a87e | fix: bind AT/RT on token-endpoint proof when no jkt | `handler/full_flow_oauth_test.go` `handler/oauth_token.go` (+27 -27) | RFC 9449 §5 | #6 | follow-up — replaces a test |
| 38 | 356b2b1 | fix: accept long-form `application/dpop+jwt` typ | `service/dpop_verifier.go` (+9 -7) `_test.go` (+16) | RFC 7515 §4.1.9 / 9449 §11.5 | #4 | follow-up |
| 39 | b7e4163 | test: bootstrap test env via generative helper | `internal/test/server.go` `internal/test/testenv.go` (NEW +87) `.gitignore` | — | — | **prerequisite for ALL tests** |
| 40 | 666bf94 | docs: cite RFC 7515 §4.1.9 for typ equivalence | `service/dpop_verifier.go` (doc) `_test.go` (doc) | doc-only | #38 | — |
| 41 | 7436a77 | fix: case-sensitive htm comparison | `service/dpop_verifier.go` (+3 -1) | RFC 9110 §9.1 | #4 | follow-up |
| 42 | 1e6bc77 | fix: enforce aud + iss + typ per RFC 9068 §4 | `service/jwt.go` (+59 -10) `service/jwt_aud_test.go` (+133) | RFC 9068 §4 / 7519 §4.1.3 / 7515 §4.1.9 | #5 (cnf) | — |
| 43 | 05f1601 | fix: validate aud at /oauth/userinfo | `handler/oauth_userinfo.go` (+5 -1) `service/jwt_cnf_test.go` (+4 -2) | RFC 9068 §4 | #42 | — |
| 44 | a55cb63 | fix(legacy): bind aud to providerAddress | `handler/access_token.go` (+11 -1) | RFC 7519 §4.1.3 | — | — |
| 45 | 475fa1c | fix(oidc): emit jti + client_id on AT | `service/jwt.go` (+10 -2) `service/jwt_aud_test.go` (+19) | RFC 9068 §2.2 | #5 | — |
| 46 | d7af03d | fix(legacy): aud check at /sso/access_token/verify | `handler/access_token.go` (+21) `handler/legacy_aud_test.go` (NEW +96) `internal/test/server.go` (+9 -7) | RFC 7519 §4.1.3 | #44 | — |
| 47 | e7c21a9 | snapshot: pre-refactor capture | huge — see §3 | many | many | **uncommitted-when-walked, not a real commit** |

`#26` and `#27` are explicitly **obsoleted** by the later G-1 (final) pair `#24`/`#25` — the early form returned a single string, the rest of the snapshot relies on the `(value, present, duplicate)` shape. Skip cherry-picking the early pair.

---

## 2. Snapshot delta (e7c21a9 = #47)

The snapshot is **40 files / 2,989 +97/197 −38** of work that was never broken into TDD'd commits. It contains nine logically-distinct features, listed here with their downstream PR home:

| Feature | Files | RFC | PR home |
|---|---|---|---|
| Full RFC 3986 §6.2.2 htu canonicalization (percent-encoding + dot-segment removal) — supersedes #17 (F-4) | `service/dpop_verifier.go` (+148) `service/htu_canon_test.go` (+13) | RFC 9449 §4.3 / RFC 3986 §6.2.2 | **PR-1** |
| `crit` reject in DPoP proof header | `service/dpop_verifier.go` (+8) | RFC 7515 §4.1.11 | **PR-1** |
| `typ` case-insensitive comparison via EqualFold | `service/dpop_verifier.go` (+2 -2) | RFC 6838 §4.2 | **PR-1** |
| JWTService crit/kid/typ helpers + LegacySSOClaims separation + AccessToken Scope claim + typ=JWT stamp on id_token | `service/jwt.go` (+138) `service/jwt_crit_test.go` `service/jwt_id_token_typ_test.go` `service/jwt_legacy_test.go` `service/jwt_required_claims_test.go` (NEW) | RFC 9068 §2.2 §2.2.3 / RFC 8725 §3.7 / RFC 7515 §4.1.11 | **PR-2** |
| oauth_token RT family rotation + reuse-detection cascade + auth_time persistence + scope subset enforcement + PKCE ABNF check | `handler/oauth_token.go` (+202 -41) `handler/oauth_helpers.go` (+30) `handler/oauth_token_rotation_test.go` `handler/oauth_token_scope_test.go` `handler/pkce_verifier_test.go` (NEW) `migrations/000012*` `000013*` `000014*` (NEW) | RFC 9700 §2.2.2 / RFC 6749 §6 / RFC 7636 §4.1 | **WAVE-2 PR-15** |
| oauth_authorize redirect_uri strict matching + RFC 8252 §7.3 loopback + fragment reject + scope-token containment + iss echo | `handler/oauth_authorize.go` (+69 -24) `handler/oauth_authorize_redirect_uri_test.go` (NEW) `handler/oauth_session.go` (+6) | RFC 6749 §3.1.2 §10.6 / RFC 8252 §7.3 / RFC 9207 / OIDC §3.1.2.1 | **WAVE-2 PR-13** |
| oauth_userinfo §7.2 no-info-leak scheme challenge (replaces L1 deviation) + aud from claims.ClientID + sendInvalidRequest 400 path | `handler/oauth_userinfo.go` (+64 -24) `handler/userinfo_aud_test.go` `handler/dpop_htu_test.go` (NEW) | RFC 9449 §7.2 / RFC 9068 §4 / RFC 6750 §3.1 | **PR-6 (overrides #35)** + **PR-9** |
| /oauth/poll echoes state + iss on terminal status + /.well-known/oauth-authorization-server alias | `handler/oauth_poll.go` (+24 -3) `router/router.go` (+5) | RFC 6749 §10.12 / RFC 9207 / RFC 8414 §3 | **WAVE-2 PR-14** |
| Trusted-proxy CIDR gate on `dpopHTU` X-Forwarded-* + dpopHTU(r, cidrs) signature change | `handler/oauth_helpers.go` (+44 -2) `handler/oauth_token.go` (+1) `handler/oauth_userinfo.go` (+1) | RFC 9449 §4.3 hardening | **WAVE-2 PR-10** |
| Config-load validators (RSA ≥2048, AT ≤900s, auth-code ≤10min, OIDC issuer scheme) + ParseTrustedProxyCIDRs + RSA strength on key load | `config/config.go` (+167) `config/config_dpop_test.go` (NEW +186) | RFC 7518 §3.3 / RFC 8725 §3.5 / RFC 9449 §11.2 / RFC 6749 §4.1.2 / RFC 8414 §2 | **WAVE-2 PR-11** |
| Legacy access_token: LegacySSOClaims usage + nbf check + iss check + iat optional + isLegacyAccessTokenTyp case-insensitive | `handler/access_token.go` (+46 -4) `handler/legacy_aud_test.go` (+204) | RFC 7515 §4.1.9 / RFC 7519 §4.1.{1,5,6} | **PR-9 (with the §2.2/§4 fixes)** |
| CORS DPoP header + slowloris timeouts | `cmd/server/main.go` (+17 -3) | operational | **WAVE-2 PR-10** |

The snapshot also brings 11 NEW test files; each one slots under its feature PR.

---

## 3. Dependency analysis

### Hard ordering
- `#3` migration → all DPoPVerifier code (`#4`, `#7`, `#34`, `#41`, …)
- `#10` migration 000011 → `#11` (RT sticky binding)
- `#5` JWTService cnfJkt → `#6` token-endpoint binds → `#11` refresh stickiness → `#42` aud enforcement (only because `#42` rebases on `#5`'s `Cnf` field; not strictly required, but safer)
- `#39` (test env bootstrap) → ANY `go test ./...` works. **Must be in PR-1 or earlier.**

### Migration count
- `000010` (`#3`) — `oauth_sessions.dpop_jkt` + `dpop_jti_seen` (Wave 1)
- `000011` (`#10`) — `refresh_tokens.dpop_jkt` (Wave 1)
- `000012` (snapshot) — `refresh_tokens.scope` (Wave 2 — RT family work)
- `000013` (snapshot) — `refresh_tokens.token_family_id` + `is_used` (Wave 2)
- `000014` (snapshot) — `refresh_tokens.auth_time` (Wave 2)

Wave 1 migrations are 000010 + 000011. The other three only land with the RT-family PR.

### Independent (parallel-branch-safe)
- `#13` discovery, `#7` cleaner, `#42`–`#46` aud enforcement, `#39` test env, `#1`/`#2` chore logs are all independent of each other once `#3`/`#5` exist.

### Files with multiple-feature contention (decomposition mandatory)

| File | Final size | Touched by | Decomposition target |
|---|---:|---|---|
| `service/dpop_verifier.go` | 451 | #4 #17 #23 #29 #33 #34 #38 #41 + snapshot | split 4-way (PR-1) |
| `service/jwt.go` | 418 | #5 #42 #45 + snapshot | split 5-way (PR-2) |
| `handler/oauth_token.go` | 596 | #6 #11 #19 #25 #37 + snapshot | split 4-way (PR-4 Wave 1; PR-5 layers refresh) |
| `handler/oauth_userinfo.go` | 191 | #9 #21 #23 #25 #31 #35 #36 #43 + snapshot | split 2-way (PR-6) |
| `handler/oauth_authorize.go` | 394 | #6 #15 + snapshot | split 3-way (Wave 2 PR-13; Wave 1 just adds a thin parser) |
| `handler/oauth_helpers.go` | 182 | #6 #25 + snapshot | extract `dpop_helpers.go` + `pkce_helpers.go` |
| `config/config.go` | 367 | snapshot only | split 4-way (Wave 2 PR-11) |
| `handler/access_token.go` | 394 | #44 #46 + snapshot | split 3-way (PR-9) |
| `handler/full_flow_oauth_test.go` | huge | #6 #8 #9 #12 #14 #18 #20 #22 #24 #30 #37 + snapshot | leave as one mega-file in Wave 1; split by scenario in Wave 2 |

---

## 4. Minimum-agent-id-DPoP-works milestone

Agent-id end-to-end DPoP needs the AS to:

1. **Accept** `dpop_jkt` on `/oauth/authorize`.
2. **Verify** a DPoP proof on `/oauth/token` (auth-code grant), bind cnf.jkt onto AT + ID, mint `token_type=DPoP`.
3. **Rotate** the binding through refresh (sticky on RT).
4. **Verify** DPoP proof + ath on `/oauth/userinfo` for cnf-bound ATs (so agent-id's verifyAuth lands).
5. **Advertise** DPoP in OIDC discovery (so clients discover support).
6. Survive routine adversarial inputs: duplicate header, duplicate `dpop_jkt`, oversized jti, JWK private fields, htu canonicalization variance, lowercase htm.

That is **PR-1 through PR-7**. Eight PRs, all sized for one-person review, decomposition baked in. PR-8 (cleaner GC) is not strictly required for demo but must ship before production (otherwise `dpop_jti_seen` grows without bound).

Wave 1B (PR-9 RFC 9068 §2.2/§4) is required for a passing audit but agent-id's flow technically works without it. Wave 1C (PR-10–PR-15) is hardening and follow-up features.

---

## 5. Proposed PRs — Wave 1 (agent-id DPoP critical path)

For each PR: cherry-pick list **in apply order**, decomposition done within the PR (not deferred), end-state file sizes, tests required, self-containment justification, what is explicitly NOT included.

---

### PR-0 — Test-env scaffolding + chore logging

**Why first.** `make tests` is `go test -v ./...`. Without `#39`'s `internal/test/testenv.go`, the snapshot suite can't run from a clean checkout. Every other PR's CI gate depends on this landing. The two chore log additions ride along — they're noise-level and unblock nothing but reduce later cherry-pick conflicts.

| Source | Commits |
|---|---|
| `b7e4163` | test env bootstrap |
| `6a22512` | chain url + session-address log |
| `ac7db55` | log node errors in authorize-miniapp |

**Files at end of PR**

| File | Status | Lines |
|---|---|---:|
| `internal/test/testenv.go` | NEW | 87 |
| `internal/test/server.go` | edited | +1 line |
| `cmd/server/main.go` | edited | +1 line |
| `internal/handler/oauth_callback.go` | edited | +1 line |
| `internal/handler/authorize_miniapp.go` | edited | +1 line |
| `.gitignore` | edited | -7 lines |

**Decomposition.** None — this PR is too small to warrant any.

**Tests.** `go test ./...` passes. Zero new assertions; this is infrastructure.

**Self-contained because.** No production handlers change behavior. Test scaffolding is additive.

**Does NOT include.** Any RFC fixes. Any decomposition.

---

### PR-1 — DPoP verifier service + decomposition

**Why this shape.** The DPoPVerifier is the foundation every later PR depends on. Cherry-picking the original `#4` (213 lines in one file) and then layering 8 follow-up commits would land 451+ lines into a single file. We split as we land.

The full RFC 3986 §6.2.2 canonicalizeHTU from the snapshot is folded in here — F-4 (`#17`) is its weaker draft, and the only sensible thing is to land the final version from day one. Same for `crit` reject and EqualFold typ.

| Source | In order |
|---|---|
| `d9f0326` | migration 000010 |
| `d941f23` | DPoPVerifier deep module + tests |
| `666bf94` | RFC 7515 §4.1.9 doc cite (re-folded as comments in split files) |
| `356b2b1` | accept long-form `application/dpop+jwt` typ |
| `7436a77` | case-sensitive htm |
| `2dcf54a` (RED `b475ec1` first) | G-9 reject JWK with private fields |
| `15ac6d4` (RED `3c8b073` first) | G-8 cap jti at 256 chars |
| `e027689` | M1 IPv6-safe port stripping (folded into htu_canon.go) |
| `a786dfc` (RED `0a43436` first) | F-4 basic htu canon (immediately superseded by snapshot delta in same PR) |
| **snapshot delta** | full RFC 3986 §6.2.2 percent-encoding + dot-segment + EqualFold typ + `crit` reject |

**Decomposition INSIDE this PR.** Split `service/dpop_verifier.go` (would-be 451 lines) into:

| File | Lines | Concern |
|---|---:|---|
| `service/dpop_verifier.go` | 130 | `DPoPVerifier` struct, `VerifyProof`, `VerifyResourceProof`, sentinel errors |
| `service/dpop_proof_jwt.go` | 130 | compact JWS parse, `dpopHeader`/`dpopPayload`, `prepareEdDSAVerifier`, JWK private-field reject, signature verify |
| `service/htu_canon.go` | 150 | `canonicalizeHTU`, `normalizePercentEncoding`, `removeDotSegments`, `removeLastSegment`, `fromHex`, `toHexUpper`, `isUnreserved`, `abs64` |
| `service/dpop_jti_replay.go` | 60 | jti length cap + DB-side `INSERT … ON CONFLICT` for replay |

Same partition for the test file (532 lines):

| File | Lines |
|---|---:|
| `service/dpop_verifier_test.go` | 220 — top-level VerifyProof + VerifyResourceProof |
| `service/dpop_proof_jwt_test.go` | 110 — JWK private-field rejection, alg, typ variants, crit |
| `service/htu_canon_test.go` | 110 — full-table canonicalization including IPv6 + percent-encoding |
| `service/dpop_jti_replay_test.go` | 90 — concurrent jti race, jti cap, expired GC |

**Tests.** `go test ./internal/service/...`: 30+ assertions; concurrent-jti race uses testcontainers Postgres.

**Self-contained because.** A new service module + DB table + migrations. No handler imports it yet (PR-3 is the first caller).

**Does NOT include.** Any handler integration. Cleaner GC (PR-8). The token endpoint binding wiring (PR-4).

---

### PR-2 — JWTService cnf.jkt + RFC 9068 §2.2/§4 minting + decomposition

**Why this shape.** `service/jwt.go` becomes 418 lines after `#5`, `#42`, `#45`, and the snapshot's helpers. We land the final shape now.

| Source | In order |
|---|---|
| `fff626f` | optional `cnfJkt` parameter, `Cnf` field, `omitempty` |
| `1e6bc77` | enforce aud + iss + typ on Verify\* |
| `475fa1c` | emit jti + client_id on AT |
| **snapshot delta** | `requireKid`, `rejectCritHeader`, `isIDTokenTyp`, `LegacySSOClaims` separation, `Scope` field on AT, `typ=JWT` stamp on id_token, EqualFold typ |

**Decomposition.** Split `service/jwt.go` into:

| File | Lines | Concern |
|---|---:|---|
| `service/jwt.go` | 80 | `JWTService` struct, `NewJWTService`, `GetJWKS`, `JWTHeader`, `JWKS` |
| `service/jwt_claims.go` | 60 | `IDTokenClaims`, `AccessTokenClaims`, `LegacySSOClaims`, `CnfClaim` |
| `service/jwt_mint.go` | 130 | `CreateIDToken`, `CreateAccessToken`, `CreateLegacySSOAuthToken` |
| `service/jwt_verify.go` | 130 | `VerifyAccessToken`, `VerifyIDToken` |
| `service/jwt_header_validators.go` | 70 | `requireKid`, `rejectCritHeader`, `isAccessTokenTyp`, `isIDTokenTyp` |

Test files already split by concern in the snapshot — bring them in as-is:

| File | Lines | Source |
|---|---:|---|
| `service/jwt_aud_test.go` | 237 | #42 + #45 + snapshot |
| `service/jwt_cnf_test.go` | 93 | #5 + #43 doc tweak |
| `service/jwt_crit_test.go` | 88 | snapshot |
| `service/jwt_id_token_typ_test.go` | 38 | snapshot |
| `service/jwt_legacy_test.go` | 25 | snapshot |
| `service/jwt_required_claims_test.go` | 116 | snapshot |

**Tests.** `go test ./internal/service/...` against the new layout. No assertions changed; only file split.

**Self-contained because.** Pure service-level change. Production handlers still call `CreateAccessToken(subject, audience, scope, expiresIn, cnfJkt)` etc.; the signature change ripples into PR-4 (which expects this).

**Does NOT include.** PR-4's call-site update (call-site change is in PR-4's diff). The aud-enforcement at userinfo (PR-6 picks up `#43`).

---

### PR-3 — `/oauth/authorize` accepts `dpop_jkt` (minimum scope)

**Why a separate PR.** `#6`'s authorize-side hunks are small and orthogonal to its token-side hunks. Splitting by file lets PR-3 ship without touching the 596-line `oauth_token.go`. PR-3 only requires schema migration `000010` and the `dpopHTU` reconstructor — both already in earlier PRs.

| Source | In order |
|---|---|
| Authorize-side hunks of `d98d049` | `oauth_authorize.go` (+19): parse + persist `dpop_jkt`; `oauth_helpers.go` (+18): `parseDPoPJkt` validator |
| `c675c5e` (RED `bbf8ec6` first) | F-6 reject duplicate dpop_jkt query parameter |

**Decomposition.** `oauth_helpers.go` keeps `parseDPoPJkt` plus existing helpers (still ≤200 lines, no split needed yet). `oauth_authorize.go` is 280 lines after this PR — under the 300-line decomposition threshold; defer the split to Wave 2 PR-13.

**Tests.** Existing integration tests already cover the no-DPoP path. Add a one-scenario assertion: authorize with valid dpop_jkt → session row carries the value.

**Self-contained because.** A request that doesn't include `dpop_jkt` is byte-identical to today. A request that includes it gets persisted but isn't yet enforced at /token (that's PR-4) — no client breakage.

**Does NOT include.** Any /token-side enforcement. Decomposition of `oauth_authorize.go` (defer to Wave 2). The redirect_uri rework.

---

### PR-4 — `/oauth/token` auth-code grant DPoP binding + decomposition

**Why this shape.** `oauth_token.go` is the single biggest spaghetti file (596 lines after Wave 1, 798 after Wave 2). We land the auth-code DPoP binding into a *split* layout from day one. Refresh-grant DPoP is in PR-5; this PR's `handleRefreshTokenGrant` is the unmodified pre-DPoP version.

| Source | In order |
|---|---|
| Token-side hunks of `d98d049` | DPoP verify + cnf.jkt binding on auth-code grant |
| `33fed23` (RED `434161c` first) | F-2 emit `token_type=DPoP` |
| `5608a7e` (RED `54d5b62` first) | G-1 reject duplicate DPoP header at token (and userinfo — that part fits PR-6) |
| `9b1a87e` | bind AT/RT when DPoP proof is presented even without authorize-time `dpop_jkt` |
| `a3e6d4f` | five integration scenarios |

**Decomposition.** Split `oauth_token.go` into:

| File | Lines | Concern |
|---|---:|---|
| `handler/oauth_token.go` | 80 | `OAuthTokenHandler.Token` router, `sendTokenResponse`, `sendError` |
| `handler/oauth_token_code.go` | 250 | `handleAuthorizationCodeGrant` |
| `handler/oauth_token_refresh.go` | 150 | `handleRefreshTokenGrant` (still pre-DPoP) |
| `handler/oauth_token_helpers.go` | 60 | `dpopOrBearer`, `createRefreshToken` (unbound version), `nullableString` |
| `handler/oauth_helpers.go` | grows by ~22 | `readSingleDPoPHeader` from G-1 lands here |

**Tests.** Five new DPoP-bound auth-code scenarios from `a3e6d4f`, plus regression coverage for unbound flows. `handler/full_flow_oauth_test.go` grows by ~370 lines; **NOT split yet** — it stays as the giant integration test until Wave 2 (the per-scenario split is mechanical and would conflict with PR-5's additions).

**Self-contained because.** After this PR, agent-id can do auth-code DPoP end-to-end up to "received AT and RT, AT carries cnf.jkt, RT is unbound" — which is fine for AT-only flows. Refresh works (pre-DPoP behaviour) but does NOT propagate DPoP binding. PR-5 closes that.

**Does NOT include.** Refresh-grant DPoP. Userinfo. Scope subset. PKCE ABNF check. RT family rotation. The CAS-based reuse cascade.

---

### PR-5 — `/oauth/token` refresh-grant DPoP sticky binding

| Source | In order |
|---|---|
| `b8ad984` | migration 000011 (`refresh_tokens.dpop_jkt`) |
| `1137a52` | sticky-binding refresh path |
| `eecc5b2` | refresh-grant integration scenarios (262 lines) |

**Decomposition.** `handler/oauth_token_refresh.go` grows from 150 → 250 lines. Still under threshold. The DPoP-on-refresh logic uses the helpers already in `oauth_token_helpers.go` from PR-4, so no new helper file.

**Tests.** Five new refresh DPoP scenarios. `full_flow_oauth_test.go` grows by ~262 lines.

**Self-contained because.** A refresh request without a presented DPoP header against an unbound RT is byte-identical to today (Bearer flow). DPoP-bound RTs require a DPoP proof matching the original key — same contract agent-id is built against.

**Does NOT include.** RT family rotation / reuse cascade (Wave 2). Scope subset enforcement. auth_time persistence on the new RT row.

---

### PR-6 — `/oauth/userinfo` DPoP + ath + scheme-by-binding + decomposition

**Why this shape.** Userinfo is the critical path for agent-id's `verifyAuth`. The handler is small (final 191 lines) but every ${RFC 9449 §7.1, §7.2, §4.2}, ${RFC 9068 §4}, ${OIDC §5.3.2}, ${RFC 6750 §3} concern is in it. Land everything.

| Source | In order |
|---|---|
| `b7e2c89` | enforce DPoP on userinfo when AT carries cnf.jkt |
| `7b01b4e` (RED `edfd255` first) | F-3 strict scheme-by-binding |
| `d45e01c` (RED `e7b1b2f` first) | F-1 ath enforcement (uses PR-1's `VerifyResourceProof`) |
| `26d5a02` (RED `6519b5d` first) | G-5+G-6 algs param + Cache-Control on success |
| `83fd96a` | L2 Cache-Control on every response |
| `5608a7e` (userinfo hunks already in PR-4 — the userinfo hunks land here as part of the same commit spread across two PRs; or fold the entire commit into PR-4 and let PR-6 import the helper) |
| `05f1601` | aud enforcement at userinfo |
| **snapshot delta** | RFC 9449 §7.2 no-info-leak rewrite (overrides `0e5605c`'s documented L1 deviation), `sendInvalidRequest` 400 path, `sendMissingAuthChallenge` for missing-creds, aud from `claims.ClientID` |

**Note on `0e5605c`.** Skip this commit — its only effect is updating a comment, and that comment is then completely rewritten by the snapshot's §7.2 path. Net diff against `main` is the snapshot's version.

**Decomposition.** Split `handler/oauth_userinfo.go` into:

| File | Lines | Concern |
|---|---:|---|
| `handler/oauth_userinfo.go` | 100 | `UserInfo` handler entry, scheme select, dispatch |
| `handler/oauth_userinfo_challenges.go` | 80 | `sendMissingAuthChallenge`, `sendBearerError`, `sendInvalidRequest`, `sendDPoPError`, `dpopSupportedAlgs` |

**Tests.** ~270 lines added to `full_flow_oauth_test.go` covering: bound + DPoP scheme + ath, mismatched ath, missing ath, scheme cross-mismatch (both directions), no-info-leak verification of WWW-Authenticate, Cache-Control on every path, aud rejection when claim mismatches issuer.

**Self-contained because.** `OAuthUserInfoHandler` now requires `Config` for the `TrustedProxyCIDRs` future hook — but in this PR `dpopHTU` doesn't yet take CIDRs (Wave 2). We pass `nil` until Wave 2 PR-10 wires it.

> Wait — the snapshot's `dpopHTU(r, h.Config.TrustedProxyCIDRs)` is a signature change from `dpopHTU(r)`. PR-6 either keeps the old signature (no Config field on handler) or adopts the new signature now and passes `nil` until PR-10 ships. **Decision: keep old signature in this PR; `Config` field added in PR-10.** Avoids a router constructor change here.

**Does NOT include.** Trusted-proxy gate. PR-9's RFC 9068 §4 broader audit (legacy access_token verifier).

---

### PR-7 — OIDC discovery advertise DPoP + cnf

| Source | In order |
|---|---|
| `9f5fccb` | discovery advertise + tests |

**Decomposition.** None needed — `oidc_discovery.go` is 76 lines.

**Tests.** Snapshot test asserting all advertised values. ~70 lines.

**Self-contained because.** Discovery is informational; clients that don't know DPoP ignore the new fields. Clients that do know DPoP can now negotiate.

**Does NOT include.** RFC 9207 `authorization_response_iss_parameter_supported: true` (snapshot delta — Wave 2 PR-14).

---

### PR-8 — SessionCleaner GCs `dpop_jti_seen`

| Source | In order |
|---|---|
| `d5f928d` | extend SessionCleaner + Sweep extraction |

**Decomposition.** None — `service/cleaner.go` is 70 lines.

**Tests.** `service/cleaner_test.go` (52 lines) asserts the contract via the new `Sweep` exported method.

**Self-contained because.** No handler call sites change. Required for production but not for demo (a demo run won't grow `dpop_jti_seen` past anything notable).

**Does NOT include.** Anything else.

---

## 6. Wave 1B — agent-id-DPoP-not-blocking but ship-blocking

These don't gate the agent-id demo but the COMPLIANCE.md audit requires them.

### PR-9 — RFC 9068 §2.2 / §4 / RFC 7519 §4.1.3 enforcement everywhere

| Source | In order |
|---|---|
| `a55cb63` | bind aud to providerAddress in legacy `/sso/access_token/exchange` |
| `d7af03d` | aud check at legacy `/sso/access_token/verify` |
| **snapshot delta** | LegacySSOClaims usage in `handler/access_token.go`, nbf check, iss check, iat-optional, `isLegacyAccessTokenTyp`, userinfo aud from `claims.ClientID` |

(Note: `1e6bc77`, `475fa1c`, `05f1601` already in PR-2 / PR-6.)

**Decomposition.** Split `handler/access_token.go` (394 lines) into:

| File | Lines | Concern |
|---|---:|---|
| `handler/access_token.go` | 130 | `AccessTokenHandler` struct, `ExchangeCode`, response types |
| `handler/access_token_verify.go` | 180 | `VerifyToken` (legacy EdDSA path) |
| `handler/access_token_helpers.go` | 80 | `isLegacyAccessTokenTyp`, signature reconstruction helpers |

**Tests.** `handler/legacy_aud_test.go` (~400 lines, mostly already in snapshot) + a few new unit tests for `isLegacyAccessTokenTyp`. New `handler/userinfo_aud_test.go` from snapshot.

**Self-contained because.** Independent of DPoP. Closes the §4 audience MUST across both legacy and OIDC userinfo paths.

---

## 7. Wave 1C — operational hardening (post-demo)

Numbered for stability across this document. Each PR is independent of the others within Wave 1C — none of them depends on Wave 1A/1B beyond what already shipped.

### PR-10 — Trusted-proxy CIDRs + dpopHTU honor proxy headers conditionally + slowloris timeouts

Source: snapshot only — `cmd/server/main.go`, `internal/handler/oauth_helpers.go` (`dpopHTU(r, cidrs)` signature change + `remoteAddrIsTrusted`), `internal/handler/oauth_token_code.go`, `oauth_token_refresh.go`, `oauth_userinfo.go` (call-site updates), `internal/router/router.go` (Config plumbing).

`OAuthUserInfoHandler` gets `Config *config.Config` field here, completing the ripple from PR-6.

### PR-11 — Config-load validators

Source: snapshot only — `config/config.go` validators + `config/config_dpop_test.go`.

Decomposition split `config/config.go` (367 lines) into:

| File | Lines | Concern |
|---|---:|---|
| `config/config.go` | 130 | `Config`, `LoadConfig` |
| `config/config_validators.go` | 130 | `ValidateAccessTokenLifetime`, `ValidateAuthCodeLifetimeMinutes`, `ValidateOIDCIssuerScheme`, `validateRSAKeyStrength` |
| `config/config_keys.go` | 70 | `loadRSAKey`, `deriveEd25519Key` |
| `config/config_proxy.go` | 50 | `ParseTrustedProxyCIDRs` |

### PR-12 — PKCE ABNF + scope subset on refresh + scope-token containment

Source: snapshot only — `oauth_helpers.go` (`isValidPKCEVerifier`), `oauth_token.go` (scope subset on refresh + PKCE check), `oauth_authorize.go` (`scopeContains` for `openid`).

### PR-13 — `/oauth/authorize` redirect_uri strict matching + RFC 8252 §7.3 loopback + fragment reject + iss echo + decomposition

Source: snapshot only.

Split `handler/oauth_authorize.go` (394 lines) into:

| File | Lines | Concern |
|---|---:|---|
| `handler/oauth_authorize.go` | 200 | entry handler |
| `handler/oauth_authorize_redirect_uri.go` | 100 | `isRedirectURIAllowed`, `loopbackPortFlexMatch`, `isLoopbackHost` |
| `handler/oauth_authorize_response.go` | 80 | `sendError`, `sendSuccess` (both echo `iss`) |

### PR-14 — `/oauth/poll` echoes state + iss + `/.well-known/oauth-authorization-server` alias

Source: snapshot only — `oauth_poll.go`, `router/router.go`, `oauth_session.go`. Trivial.

### PR-15 — RT family rotation + reuse-detection cascade + auth_time persistence + AccessToken Scope claim + scope subset enforcement

Source: snapshot only — migrations `000012`, `000013`, `000014`, `oauth_token.go` reuse cascade + CAS, `oauth_token_rotation_test.go`, `oauth_token_scope_test.go`, `pkce_verifier_test.go`, AT `Scope` field (already in PR-2), `oauth_authorize.go` `Scope` write into session.

This is the largest follow-up. After this PR, `oauth_token_refresh.go` is ~250 → 280 lines and `oauth_token_helpers.go` gains `createRefreshToken` with the family-id signature change. Migrations are additive and safe.

---

## 8. PR sequencing summary

```
Critical path for agent-id DPoP demo (≤8 PRs)
─────────────────────────────────────────────
  PR-0  test env scaffolding + chore                       [trivial]
  PR-1  DPoPVerifier service + decomposition (4-way split) [foundation]
  PR-2  JWTService cnf + §2.2/§4 mint + decomposition      [foundation]
  PR-3  /authorize accepts dpop_jkt                        [tiny]
  PR-4  /token auth-code DPoP + decomposition (4-way)      [headline]
  PR-5  /token refresh DPoP sticky                         [headline]
  PR-6  /userinfo DPoP + ath + scheme + decomposition      [headline]
  PR-7  discovery advertise                                [trivial]

  ─── DEMO READY ───

  PR-8  cleaner GC                                         [pre-prod]

Compliance close-out
────────────────────
  PR-9  RFC 9068 §2.2/§4 broad sweep                       [compliance]

Operational hardening (post-demo)
─────────────────────────────────
  PR-10 trusted-proxy CIDRs + slowloris
  PR-11 config-load validators (split config.go)
  PR-12 PKCE ABNF + scope subset
  PR-13 redirect_uri strict matching (+split authorize.go)
  PR-14 /poll state+iss + /.well-known alias
  PR-15 RT family rotation + reuse cascade
```

**Critical-path total diff (PR-0 → PR-7):** ≈ 4,000 lines net (cherry-pick churn ~3,200; decomposition is mostly file-renames ~700; the F-4 → snapshot-delta htu canon upgrade is the only behavior-additive piece beyond the cherry-pick set, ~140 lines).

**File-size guarantees at end of PR-8 (post-decomposition):**

| File | Lines | Was | Was post-everything |
|---|---:|---:|---:|
| `service/dpop_verifier.go` | 130 | n/a | 451 |
| `service/dpop_proof_jwt.go` | 130 | NEW | n/a |
| `service/htu_canon.go` | 150 | NEW | embedded in 451 |
| `service/dpop_jti_replay.go` | 60 | NEW | embedded |
| `service/jwt.go` | 80 | n/a | 418 |
| `service/jwt_claims.go` | 60 | NEW | embedded |
| `service/jwt_mint.go` | 130 | NEW | embedded |
| `service/jwt_verify.go` | 130 | NEW | embedded |
| `service/jwt_header_validators.go` | 70 | NEW | embedded |
| `handler/oauth_token.go` | 80 | n/a | 596 |
| `handler/oauth_token_code.go` | 250 | NEW | embedded |
| `handler/oauth_token_refresh.go` | 250 | NEW | embedded |
| `handler/oauth_token_helpers.go` | 60 | NEW | embedded |
| `handler/oauth_userinfo.go` | 100 | n/a | 191 |
| `handler/oauth_userinfo_challenges.go` | 80 | NEW | embedded |

Every file is ≤ 250 lines. Single-concern. Searchable.

---

## 9. Risks + open questions

1. **`dpopHTU` signature ripple.** Decided in §6: PR-6 keeps the old `dpopHTU(r)` signature. PR-10 introduces `dpopHTU(r, cidrs)` and updates all three call sites. Means PR-6's userinfo handler doesn't need a `Config` field yet. Trade-off: PR-10 has a 3-file ripple.

2. **`#26`/`#27` skip.** Verified — `5931123` introduced a 1-return-value `readSingleDPoPHeader` that `5608a7e` reshapes to 3-return-value. The rest of the snapshot relies on the 3-return shape. Cherry-picking only `5608a7e`/`54d5b62` is correct.

3. **`a786dfc` (F-4 basic htu canon) vs snapshot full §6.2.2.** F-4 lands ~30 lines of canon; the snapshot replaces those same ~30 lines with a 150-line full RFC 3986 §6.2.2 implementation. Cherry-picking F-4 then applying the snapshot delta means F-4's content is literally rewritten. Cleaner: skip F-4 cherry-pick, fold its INTENT (test cases + behavior) into PR-1's final `htu_canon.go` directly. The PR description should note both `a786dfc` and the snapshot as origins.

4. **`0e5605c` (L1 doc) vs snapshot's §7.2 rewrite.** `0e5605c` documents the prior deviation; the snapshot reverses it and rewrites the comment. Skip `0e5605c`. Take the snapshot's version directly in PR-6.

5. **Integration test split.** `handler/full_flow_oauth_test.go` ends Wave 1 around 1,800–2,000 lines. The current TDD-style accumulation makes splitting it premature; doing it during Wave 1 fights PR-4 and PR-5's adjacent test additions. Defer test-file split to Wave 2.

6. **`#39` (`b7e4163`) prereq for tests.** Without it, `go test ./...` is broken. Must land in PR-0. The snapshot makes ~26 lines of additional changes on `internal/test/testenv.go` — fold those into PR-0 since they're part of the same scaffolding.

7. **Snapshot has new test files orthogonal to commits.** 11 new test files (`config_dpop_test.go`, `dpop_htu_test.go`, `oauth_authorize_redirect_uri_test.go`, `oauth_token_rotation_test.go`, `oauth_token_scope_test.go`, `pkce_verifier_test.go`, `userinfo_aud_test.go`, `jwt_crit_test.go`, `jwt_id_token_typ_test.go`, `jwt_legacy_test.go`, `jwt_required_claims_test.go`). Each one slots under its feature PR per §3 above. None block Wave 1 critical path except `jwt_crit_test.go`, `jwt_id_token_typ_test.go`, `jwt_legacy_test.go`, `jwt_required_claims_test.go` (PR-2) and `userinfo_aud_test.go` (PR-6).

8. **`#37` (`9b1a87e`) modifies a test introduced in `#8` (`a3e6d4f`).** Specifically `NoDPoP_HeaderIgnored` becomes `NoJkt_DPoPProofBindsTokens`. PR-4 cherry-picks `a3e6d4f` then `9b1a87e` in that order — the second commit's test rename applies cleanly.

9. **Migration sequencing.** Wave 1: 000010 (PR-1), 000011 (PR-5). Wave 2: 000012/000013/000014 (PR-15). All are safe additive `up.sql` with corresponding `down.sql`. Each PR's migration applies before the code in that PR runs in CI.

10. **Test expansion in `#8`/`#9`/`#12` overlaps with `#24`/`#30`.** All happen in `full_flow_oauth_test.go`. PR-4/PR-5/PR-6 each add ~270/+262/+170 lines. Apply order is mechanical-cherry-pick — conflicts will be on tablerows in test data slices, resolvable per-line. No semantic conflict.

---

## 10. End-state file inventory (after PR-0 → PR-8)

```
internal/
├── config/
│   └── config.go (367)             [unchanged in Wave 1; Wave 2 PR-11 splits]
├── handler/
│   ├── access_token.go (398)       [unchanged; PR-9 splits]
│   ├── authorize_miniapp.go (+1)
│   ├── full_flow_oauth_test.go (~1850)  [unchanged shape; Wave 2 splits]
│   ├── legacy_aud_test.go (NEW 96)
│   ├── oauth_authorize.go (~140 after PR-3)
│   ├── oauth_callback.go (+1)
│   ├── oauth_helpers.go (~115 after PR-1+PR-3+PR-4)
│   ├── oauth_poll.go (unchanged)
│   ├── oauth_session.go (unchanged)
│   ├── oauth_token.go (80)
│   ├── oauth_token_code.go (NEW 250)
│   ├── oauth_token_refresh.go (NEW 250 after PR-5)
│   ├── oauth_token_helpers.go (NEW 60)
│   ├── oauth_userinfo.go (100)
│   ├── oauth_userinfo_challenges.go (NEW 80)
│   ├── oidc_discovery.go (~76 after PR-7)
│   ├── oidc_discovery_test.go (NEW 70)
│   └── ...
├── service/
│   ├── cleaner.go (~70 after PR-8)
│   ├── cleaner_test.go (NEW 52)
│   ├── dpop_verifier.go (130)
│   ├── dpop_verifier_test.go (220)
│   ├── dpop_proof_jwt.go (NEW 130)
│   ├── dpop_proof_jwt_test.go (NEW 110)
│   ├── htu_canon.go (NEW 150)
│   ├── htu_canon_test.go (~110)
│   ├── dpop_jti_replay.go (NEW 60)
│   ├── dpop_jti_replay_test.go (NEW 90)
│   ├── jwt.go (80)
│   ├── jwt_claims.go (NEW 60)
│   ├── jwt_mint.go (NEW 130)
│   ├── jwt_verify.go (NEW 130)
│   ├── jwt_header_validators.go (NEW 70)
│   ├── jwt_aud_test.go (~237)
│   ├── jwt_cnf_test.go (~93)
│   ├── jwt_crit_test.go (NEW 88)
│   ├── jwt_id_token_typ_test.go (NEW 38)
│   ├── jwt_legacy_test.go (NEW 25)
│   └── jwt_required_claims_test.go (NEW 116)
├── test/
│   ├── server.go (~17)
│   └── testenv.go (NEW 87)
└── ...

migrations/
├── 000010_dpop.up.sql (PR-1)
├── 000010_dpop.down.sql
├── 000011_dpop_refresh_tokens.up.sql (PR-5)
└── 000011_dpop_refresh_tokens.down.sql
```

Critical-path totals: 9 source files split into 22 single-concern files; ≤ 250 lines each; mean 116 lines.
