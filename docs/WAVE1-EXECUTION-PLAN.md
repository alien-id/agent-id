# Wave 1 — execution plan (cross-repo)

**Source:** synthesizes `WAVE1-SSO-RESEARCH.md` and `WAVE1-AGENTID-RESEARCH.md` plus the late-stage discovery (2026-05-08) that **most of the SSO Wave 1 work is already merged to `sso/sso` `develop`**.

**Goal of Wave 1:** `alien-agent-id` CLI can run `init → auth → bind → git setup → git commit -S → git verify` against a live SSO server with full RFC 9449 + RFC 7800 enforcement.

**Constraint applied throughout:** every code-level PR cherry-picks the relevant `feat:`/`fix:` work AND decomposes the affected file in the same PR. No "land monolith now, clean later" — the `lib.mjs`, `oauth_token.go`, `dpop_verifier.go`, `jwt.go` decomposition happens inline with the cherry-pick.

---

## 0. Headline finding — SSO is mostly done on `develop`

| Repo | Branches | Wave 1 critical path |
|---|---|---|
| `agent-id/` | `main` only (no `develop`) — all PRs target `main` | ~10 PRs, A0✅ pushed |
| `sso/sso/` | `main` (lagging) AND `develop` (48 commits ahead) — all PRs target `develop` | **~1 small PR** (5 RFC 9068 fixes) — see §5 |

The original `WAVE1-SSO-RESEARCH.md` (PRs S0–S7) was written assuming `main` as the base. Once we re-checked, `develop` already contains:

| Capability | Already on develop via |
|---|---|
| DPoPVerifier service module + DB migration | `d941f23` + `d9f0326` |
| JWTService `cnf.jkt` minting | `fff626f` |
| `/oauth/authorize` accepts `dpop_jkt` | `d98d049` |
| `/oauth/token` auth-code DPoP binding | `d98d049` |
| `/oauth/token` refresh DPoP sticky | `b8ad984` + `1137a52` |
| `/oauth/userinfo` DPoP + ath + scheme-by-binding | `b7e2c89` + `7b01b4e` + `d45e01c` + `26d5a02` + `83fd96a` |
| `token_type=DPoP` emission | `33fed23` |
| OIDC discovery advertises DPoP + cnf | `9f5fccb` |
| SessionCleaner GCs `dpop_jti_seen` | `d5f928d` |
| Adversarial-input hardening (G-1, G-5, G-6, G-8, G-9, F-1, F-2, F-3, F-4, F-6) | full set merged via PRs #49/#50/#51/#52 |
| `htm` case-sensitive comparison | `7436a77` |
| Long-form `application/dpop+jwt` `typ` | `356b2b1` |
| IPv6-safe `canonicalizeHTU` port stripping | `e027689` |

**Implication:** an `alien-agent-id` build that completes its Wave 1 (PRs A0–A16) can demo end-to-end **against `sso/sso/develop` as it stands today**. No SSO PRs are gating the demo.

The 6 SSO commits NOT yet on `develop`:

| SHA | Subject | Disposition |
|---|---|---|
| `1e6bc77` | enforce aud + iss + typ per RFC 9068 §4 / RFC 7519 §4.1.3 (JWTService.Verify*) | PR-S1 |
| `475fa1c` | emit jti + client_id on access tokens (RFC 9068 §2.2) | PR-S1 |
| `a55cb63` | bind aud to providerAddress in legacy `/sso/access_token/exchange` | PR-S1 |
| `05f1601` | validate aud at `/oauth/userinfo` (RFC 9068 §4) | PR-S1 |
| `d7af03d` | aud check at legacy `/sso/access_token/verify` (RFC 7519 §4.1.3) | PR-S1 |
| `e7c21a9` (snapshot) | ~9 distinct features + decomposition opportunities | PRs S2…S10 |

---

## 1. Cross-repo dependency map (revised)

```
sso/sso (Lane S — targets develop)        agent-id (Lane A — targets main)
─────────────────────────────────         ─────────────────────────────────
                                          A0   docs bundle (warmup)         ✅ pushed
                                          A1   refactor → lib/{b64,keys,storage}
                                          A2   refactor → lib/{jwt-verify,jwt-parse,discovery}
                                          A3   feat lib/jwk-thumbprint
                                          A4   feat lib/dpop-proof + F-7
                                          A11  feat lib/id-token-verify (collapses A11+A14+A15)
                                          A5   wire CLI dpop_jkt + DPoP /token
                                          A8   cnf.jkt at git-verify
                                          A9   token_type=DPoP discard
                                          A16  chain verifier
S1   RFC 9068 §2.2/§4 audit close-out    ───── DEMO READY ─────
       (5-commit PR targeting develop)

S2…  snapshot decomposition (≤9 PRs,     A6   ath + getUserInfo + nonce-fetch
       targeting develop)                A7   nonce retry + cache (mock)
                                         A10  §9 RS structured WWW-Auth
                                         A12  RFC 9207 iss check
                                         A13  state/nonce/issuer plumbing
                                         A17  setup-owner-session CLI
                                         A19  cli.mjs decomposition
                                         A20  3.0.0 release docs + version
```

**SSO PR-S1 and beyond are NOT on the demo critical path.** They're compliance close-out and operational hardening; the agent-id demo flow already passes against current `develop`.

---

## 2. Critical-path execution order (agent-id only)

Demo-blocking sequence. All target `agent-id/main`.

| # | PR | Cherry-picks | Decomposition done in PR | Cross-repo gate |
|---:|---|---|---|---|
| 1 | A0 ✅ docs bundle | snapshot doc files (COMPLIANCE, REFACTOR-PLAN, REVIEW-PLAN, WAVE1-*) | none | — |
| 2 | A1 refactor → lib/{b64,keys,storage} | none (pure move) | extracts ~410 lines from `lib.mjs` | — |
| 3 | A2 refactor → lib/{jwt-verify,jwt-parse,discovery} | none (pure move) | extracts ~240 lines from `lib.mjs` | — |
| 4 | A3 feat lib/jwk-thumbprint | partial `3114a23` + RFC 8037 §A.2 vector | new module | — |
| 5 | A4 feat lib/dpop-proof + F-7 SPKI | partial `3114a23`, `303cac3`, `7518bab`, `5bf50b5`, `951fed8` | new module | — |
| 6 | A11 feat full id_token verifier | snapshot partial + new `tests/test-id-token-verifier.mjs` | new modules `lib/{id-token-verify,security-guards}` | — |
| 7 | A5 wire CLI dpop_jkt + DPoP /token | partial `3114a23` (OIDC entry-points) + `e0140ba` | new modules `lib/{oauth-flow,oauth-token}` | smoke test against current `develop` |
| 8 | A8 cnf.jkt at git-verify (Workstream-D close) | `aa54707` + `ace6eda` | new module `lib/cnf-verify` | smoke test against current `develop` |
| 9 | A9 token_type=DPoP discard rule | `cd807ea` | adds to `lib/oauth-token` | smoke test against current `develop` |
| 10 | A16 chain verifier (universal walker) | `3e14024`, `836a9f4`, `9652606`, `5bf50b5`, `86a59e7`, `fce7398` | new module `lib/chain-verify` | — |

**10 PRs to demo.** All target `agent-id/main`. None blocks on SSO server work.

---

## 3. Parallel-safe lanes

**Can run in parallel** (no cross-PR dependency):

- **agent-id pure-foundation lane**: A0✅, A1, A2, A3, A4, A11. None require server. None require each other beyond A1 → A2 → A3/A4 ordering. Open as 5 parallel branches off main.
- **agent-id wire-up lane** (after foundation): A5, A8, A9 in parallel — none depends on the others, all unit-tested with mocks, all smoke-test against current `develop`.

**Strictly serialized** (hard dependency):

- A1 → A2 → A4 (modules layered)
- A11 + A8 → A16 (chain verifier consumes both)

**SSO Lane S (targeting develop)** can run in parallel with agent-id at any time — but it's no longer on the demo path. PR-S1 (5 RFC 9068 commits) is the only candidate to ship soon for compliance audit; the snapshot-derived PRs S2…S10 are decomposition + new features beyond the agent-id demo and can land on any cadence.

---

## 4. What "demo ready" looks like

After agent-id PRs A0✅ → A16 land:

```bash
$ alien-agent-id init
# generates Ed25519 agent keypair

$ alien-agent-id auth
# builds /oauth/authorize URL with response_mode=json + dpop_jkt=<thumbprint>
# pending-auth.json captures dpop_jkt + state + nonce + expectedIssuer

$ alien-agent-id bind
# user approves in browser → pollForAuthorizationCode()
# → exchangeAuthorizationCode() with DPoP header → token_type=DPoP
# → id_token has cnf.jkt = thumbprint(agent.publicKey)
# → enforceCnfJkt() passes; tokens persisted

$ alien-agent-id git setup
# registers SSH-format public key with git config; signs Agent-ID-* trailers

$ git commit -S -m "test"
# SSH-signs with agent key; commits with Agent-ID-Auth + Agent-ID-Owner-Session trailers

$ alien-agent-id git verify <commit>
# ok=true, agentFingerprint=…, ownerSessionSub=…, jkt=…, bindingId=…
# verifyProofChain() walks all 9 steps including cnf.jkt match
```

**Server prerequisite: `sso/sso/develop` already provides everything needed.** A staging deployment of develop is sufficient for the demo.

---

## 5. SSO Wave 1 — develop close-out (parallel to agent-id, not gating)

These PRs target `sso/sso/develop`. Wave 1 critical path was already merged to develop; what remains is compliance polish and snapshot-driven decomposition.

### PR-S1 — RFC 9068 §2.2 / §4 / RFC 7519 §4.1.3 audit close-out

**Cherry-picks** (in order, RED before GREEN where paired): `1e6bc77` → `475fa1c` → `a55cb63` → `05f1601` → `d7af03d`.

**Files touched:** `internal/service/jwt.go` (+59), `internal/service/jwt_aud_test.go` (+133, NEW), `internal/handler/oauth_userinfo.go` (+5), `internal/service/jwt_cnf_test.go` (+4), `internal/handler/access_token.go` (+32), `internal/handler/legacy_aud_test.go` (NEW +96).

**Decomposition done in PR.** None — files stay under threshold (`jwt.go` 360 → 418 still acceptable, `access_token.go` 363 → 394 still acceptable). Decomposition deferred to PR-S3 (jwt.go) and PR-S10 (access_token.go).

**Self-contained because:** all 5 fixes share the same theme (RFC 9068 §4 audience MUST + RFC 7519 §4.1.3 + RFC 9068 §2.2 jti/client_id requirements). Tests are TDD-paired with the fix in each commit.

**Demo:** legacy + OIDC userinfo paths now reject mismatched-aud tokens at the entry point, not after. Closes the §4 audit FAIL.

### PR-S2…S10 — snapshot decomposition (≤9 PRs)

The snapshot `e7c21a9` is a 40-file / +2,989 / −197 bundle of nine logically-distinct features that were never broken into TDD'd commits. Per `WAVE1-SSO-RESEARCH.md §2`, each maps to its own PR:

| # | Feature | RFC | Files | Decomposition |
|---:|---|---|---|---|
| S2 | Full RFC 3986 §6.2.2 htu canonicalization (supersedes `a786dfc`) + `crit` reject + EqualFold typ | RFC 9449 §4.3 / RFC 3986 §6.2.2 / RFC 7515 §4.1.11 / RFC 6838 §4.2 | `service/dpop_verifier.go`, `service/htu_canon_test.go` | split `dpop_verifier.go` 451 → `dpop_verifier.go (130) + dpop_proof_jwt.go (130) + htu_canon.go (150) + dpop_jti_replay.go (60)` |
| S3 | JWTService crit/kid/typ helpers + LegacySSOClaims separation + AccessToken Scope claim + typ=JWT stamp on id_token | RFC 9068 §2.2 §2.2.3 / RFC 8725 §3.7 / RFC 7515 §4.1.11 | `service/jwt.go`, `jwt_crit_test.go`, `jwt_id_token_typ_test.go`, `jwt_legacy_test.go`, `jwt_required_claims_test.go` | split `jwt.go` 418 → `jwt.go (80) + jwt_claims.go + jwt_mint.go + jwt_verify.go + jwt_header_validators.go` |
| S4 | RT family rotation + reuse-detection cascade + auth_time persistence + scope subset + PKCE ABNF | RFC 9700 §2.2.2 / RFC 6749 §6 / RFC 7636 §4.1 | `oauth_token.go`, `oauth_token_rotation_test.go`, `oauth_token_scope_test.go`, `pkce_verifier_test.go`, migrations 000012/13/14 | split `oauth_token.go` 596 → `oauth_token.go (80) + oauth_token_code.go (250) + oauth_token_refresh.go (250) + oauth_token_helpers.go (60)` |
| S5 | redirect_uri strict matching + RFC 8252 §7.3 loopback + fragment reject + scope-token containment + iss echo | RFC 6749 §3.1.2 §10.6 / RFC 8252 §7.3 / RFC 9207 / OIDC §3.1.2.1 | `oauth_authorize.go`, `oauth_authorize_redirect_uri_test.go`, `oauth_session.go` | split `oauth_authorize.go` 394 → `oauth_authorize.go (200) + oauth_authorize_redirect_uri.go (100) + oauth_authorize_response.go (80)` |
| S6 | userinfo §7.2 no-info-leak scheme challenge (replaces L1 deviation) + aud from claims.ClientID + sendInvalidRequest 400 path | RFC 9449 §7.2 / RFC 9068 §4 / RFC 6750 §3.1 | `oauth_userinfo.go`, `userinfo_aud_test.go`, `dpop_htu_test.go` | split `oauth_userinfo.go` 191 → `oauth_userinfo.go (100) + oauth_userinfo_challenges.go (80)` |
| S7 | /oauth/poll echoes state + iss + /.well-known/oauth-authorization-server alias | RFC 6749 §10.12 / RFC 9207 / RFC 8414 §3 | `oauth_poll.go`, `router/router.go` | none |
| S8 | Trusted-proxy CIDR gate on dpopHTU X-Forwarded-* + dpopHTU(r, cidrs) signature change + slowloris timeouts | RFC 9449 §4.3 hardening / operational | `cmd/server/main.go`, `oauth_helpers.go`, `oauth_token.go` (call-site update), `oauth_userinfo.go` (call-site), `router.go` | none |
| S9 | Config-load validators (RSA ≥2048, AT ≤900s, auth-code ≤10min, OIDC issuer scheme) + ParseTrustedProxyCIDRs | RFC 7518 §3.3 / RFC 8725 §3.5 / RFC 9449 §11.2 / RFC 6749 §4.1.2 / RFC 8414 §2 | `config/config.go`, `config/config_dpop_test.go` | split `config/config.go` 367 → `config.go (130) + config_validators.go (130) + config_keys.go (70) + config_proxy.go (50)` |
| S10 | Legacy access_token: LegacySSOClaims usage + nbf check + iss check + iat optional + isLegacyAccessTokenTyp + CORS DPoP header | RFC 7515 §4.1.9 / RFC 7519 §4.1.{1,5,6} | `handler/access_token.go`, `legacy_aud_test.go` | split `handler/access_token.go` 394 → `access_token.go (130) + access_token_verify.go (180) + access_token_helpers.go (80)` |

**Sequencing among S2…S10:** S2 and S3 are independent foundations (no inter-dep). S6 uses S3's claims types. S4, S5, S8, S9, S10 are independent of each other once S2/S3 land. Five parallel branches once S2/S3 are merged.

**None of S2…S10 gates the agent-id demo.** They are compliance polish + decomposition. Land them at any cadence after the agent-id Wave 1 ships.

---

## 6. Wave 1B — agent-id polish (post-demo, pre-publish)

These don't gate the demo but DO gate `npm publish` (3.0.0).

| # | PR | Source | Why |
|---:|---|---|---|
| 11 | A6 ath + getUserInfo + nonce-fetch | `817559f`, `cef4453` | full RS-side conformance |
| 12 | A7 nonce retry + cache | `0a03249`, `d30baeb`, `60dc3ed`, `02fd6f7` | third-party RS interop |
| 13 | A10 §9 RS structured matching | `9089768` | third-party RS interop |
| 14 | A12 RFC 9207 iss check | snapshot iss-verify + `tests/test-rfc9207-iss.mjs` | mix-up attack closure |
| 15 | A13 state/nonce plumbing | snapshot CLI delta | replay attack closure |
| 16 | A17 setup-owner-session CLI | `b10f8ce` | DPoP migration UX |
| 17 | A19 cli.mjs decomposition | pure refactor | file-size guarantees |
| 18 | A20 3.0.0 release bundle | `2cd7ce9`, `99563f9`, `a135b1b`, `6e67d87`, `a524c99`, `0c558e5` | npm publish gate |

A6/A7/A10/A12/A13 are independent — open all 5 in parallel.

---

## 7. Open questions surfaced by research

These need a yes/no before execution starts.

1. **A11+A14+A15 collapse.** Research recommends collapse into a single PR (full id_token verifier with strict alphabet + RSA floor + EdDSA all in one). Default in this plan: **collapsed**.

2. **A18+A20 collapse.** Version bump rides with release notes. Default: **collapsed**.

3. **Skip `5931123` + `a8b78a9`** (already on develop). Not in scope.

4. **Skip `a786dfc`** (F-4 basic htu canon — already on develop; snapshot replaces it in S2). Default: take snapshot version directly in S2.

5. **Skip `0e5605c`** (already on develop; snapshot's §7.2 path supersedes in S6). Default: take snapshot version directly in S6.

6. **`fce7398` (cnf-verifier env isolation).** Folds into A8 OR A16. Recommend A16 since A16 rebuilds the fixtures.

7. **REVIEW-PLAN.md fate.** Already shipped in PR-A0. No further action.

8. **`dpopHTU` signature ripple.** S8 introduces `dpopHTU(r, cidrs)` and updates 3 call sites in same PR. No ripple needed elsewhere since S2/S3/S6 all use the existing signature.

9. **`handler/full_flow_oauth_test.go` split.** Stays as one mega-file in Wave 1; splits in Wave 2 once additions stop. Default: defer split.

10. **Migrations.** Already on develop: 000010, 000011. Wave 1B (S4): 000012/13/14.

---

## 8. First-action recommendation (revised)

**Lightest possible first PR = A0 ✅ DONE** (`refactor/wave1-a0-planning-docs` pushed to origin).

**First "real code" parallel batch** (target `agent-id/main`):

- A1 refactor → lib/{b64,keys,storage}
- A2 refactor → lib/{jwt-verify,jwt-parse,discovery}
- A3 feat lib/jwk-thumbprint
- A4 feat lib/dpop-proof + F-7
- A11 feat full id_token verifier

5 PRs, each independent, each reviewable without server-side state.

**Second batch** (after foundation lands):

- A5 wire CLI dpop_jkt + DPoP /token
- A8 cnf.jkt at git-verify
- A9 token_type=DPoP discard

3 PRs, parallel-safe.

**Demo gate:** A16 (chain verifier).

**SSO PR-S1** (5 RFC 9068 fixes targeting `develop`) can ride in parallel with the agent-id batches but is **not** demo-gating.

---

## 9. Status of repos

| Repo | Backup branch | Pushed to origin | Base branch for Wave 1 PRs | Wave 1 PRs |
|---|---|:---:|---|---:|
| `agent-id/` | `backup/huge-refac-2026-05-08` | ✅ | `main` (no develop exists) | 18 (A0✅ pushed; A1–A20 minus collapses) |
| `sso/sso/` | `backup/huge-refac-2026-05-08` | ✅ | `develop` (most Wave 1 already merged) | ~10 (S1 + S2…S10 from snapshot) |
| `sso/sso-sdk-js/` | `backup/huge-refac-2026-05-08` | ✅ | TBD | deferred to Wave 2 |
| `sso/sso-sdk-py/` | `backup/huge-refac-2026-05-08` | ✅ | TBD | deferred to Wave 2 |
| `miniapps/miniapp-sdk/` | `backup/huge-refac-2026-05-08` | ✅ | TBD | deferred to Wave 2 |

All 5 backup branches are durably saved on origin. agent-id is on `refactor/wave1-a0-planning-docs` (PR-A0 ready). sso/sso still on backup branch — switching to `develop` is the next step before any S* PR.
