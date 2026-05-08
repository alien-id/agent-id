# Wave 1 — execution plan (cross-repo)

**Source:** synthesizes `WAVE1-SSO-RESEARCH.md` (47 commits → 8 critical-path PRs) and `WAVE1-AGENTID-RESEARCH.md` (31 commits → 10 critical-path PRs) into a single ordered playbook for delivering DPoP for agent-id end-to-end.

**Goal of Wave 1:** `alien-agent-id` CLI can run `init → auth → bind → git setup → git commit -S → git verify` against a live SSO server with full RFC 9449 + RFC 7800 enforcement.

**Constraint applied throughout:** every PR cherry-picks the relevant `feat:`/`fix:` work AND decomposes the affected file in the same PR. No "land monolith now, clean later" — `lib.mjs`, `oauth_token.go`, `dpop_verifier.go`, `jwt.go` get split as we re-land their content.

---

## 1. Cross-repo dependency map

```
sso/sso (Lane S)                       agent-id (Lane A)
─────────────────────────────────      ─────────────────────────────────
                                       A0   docs bundle (warmup, no risk)
S0   test env scaffolding              A1   refactor → lib/{b64,keys,storage}
S1   DPoPVerifier + 4-way split        A2   refactor → lib/{jwt-verify,
S2   JWTService + 5-way split                 jwt-parse,discovery}
                                       A3   feat lib/jwk-thumbprint
                                       A4   feat lib/dpop-proof + F-7
                                       A11* feat lib/id-token-verify
                                              (collapses A14+A15)
S3   /authorize accepts dpop_jkt
S4   /token auth-code DPoP             A5   wire CLI dpop_jkt + DPoP /token
        + 4-way split                  A8   cnf.jkt at git-verify
                                       A9   token_type=DPoP discard
S5   /token refresh sticky cnf.jkt     A16  chain verifier
S6   /userinfo DPoP + ath              A6   ath + getUserInfo + nonce-fetch
        + 2-way split                  A12  RFC 9207 iss check
S7   discovery advertise               A13  state/nonce/issuer plumbing
S8   cleaner GC dpop_jti_seen          A7   nonce retry + cache (mock-only)
                                       A10  §9 RS structured WWW-Auth
                                       A17  setup-owner-session CLI
                                       A19  cli.mjs decomposition
                                       A20  3.0.0 release docs + version

      ───── DEMO READY at end of S7 + A16 ─────
```

`*` PR-A11 in this plan = the agent-id research's recommended collapse of A11+A14+A15 (full id_token verifier + strict b64url + RSA modulus floor + EdDSA, all coupled in `verifyIdToken`'s body).

---

## 2. Critical-path execution order (≈18 PRs)

Interleaved by hard dependency. Parallel-safe lanes noted.

| # | Lane | PR | Cherry-picks | Decomposition done in PR | Cross-repo gate |
|---:|---|---|---|---|---|
| 1 | A | A0 docs bundle | snapshot doc files (COMPLIANCE, REFACTOR-PLAN, REVIEW-PLAN, WAVE1-*) | none | — |
| 2 | A | A1 refactor: lib/{b64,keys,storage} | none (pure move) | extracts ~410 lines from `lib.mjs` | — |
| 3 | A | A2 refactor: lib/{jwt-verify,jwt-parse,discovery} | none (pure move) | extracts ~240 lines from `lib.mjs` | — |
| 4 | A | A3 feat: lib/jwk-thumbprint (RFC 7638) | partial of `3114a23` + RFC 8037 §A.2 vector | new module | — |
| 5 | A | A4 feat: lib/dpop-proof + F-7 SPKI | partial `3114a23`, `303cac3`, `7518bab`, `5bf50b5`, `951fed8` | new module | — |
| 6 | A | A11 feat: id_token verifier (alg/crit/typ/nbf/aud/nonce + RSA floor + EdDSA) | snapshot partial + new `tests/test-id-token-verifier.mjs` | new modules `lib/{id-token-verify,security-guards}` | — |
| 7 | S | S0 test env scaffolding | `b7e4163` + `6a22512` + `ac7db55` | none | — |
| 8 | S | S1 DPoPVerifier + 4-way split | `d9f0326`, `d941f23`, `666bf94`, `356b2b1`, `7436a77`, `2dcf54a`, `b475ec1`, `15ac6d4`, `3c8b073`, `e027689`, `0a43436`, snapshot delta (skip `a786dfc`) | `service/dpop_verifier.go` 451 → `dpop_verifier.go (130) + dpop_proof_jwt.go (130) + htu_canon.go (150) + dpop_jti_replay.go (60)` | needs S0 |
| 9 | S | S2 JWTService cnf + RFC 9068 §2.2/§4 mint + 5-way split | `fff626f`, `1e6bc77`, `475fa1c` + snapshot helpers | `service/jwt.go` 418 → `jwt.go (80) + jwt_claims.go + jwt_mint.go + jwt_verify.go + jwt_header_validators.go` | needs S0 |
| 10 | S | S3 /authorize accepts dpop_jkt | authorize-side hunks of `d98d049` + `c675c5e` (RED `bbf8ec6`) | none (file under threshold) | needs S1 + S2 |
| 11 | S | S4 /token auth-code DPoP + 4-way split | token-side hunks of `d98d049`, `33fed23` (RED `434161c`), `5608a7e` (RED `54d5b62`), `9b1a87e`, `a3e6d4f` | `oauth_token.go` 596 → `oauth_token.go (80) + oauth_token_code.go (250) + oauth_token_refresh.go (150) + oauth_token_helpers.go (60)` | needs S1 + S2 + S3 |
| 12 | A | A5 wire CLI dpop_jkt + DPoP /token | partial `3114a23` (OIDC entry-points) + `e0140ba` | new modules `lib/{oauth-flow,oauth-token}` | needs A4 + smoke-test gate at S4 |
| 13 | A | A8 cnf.jkt at git-verify (Workstream-D close) | `aa54707` + `ace6eda` | new module `lib/cnf-verify` | needs A11 + smoke-test gate at S2 |
| 14 | A | A9 token_type=DPoP discard rule | `cd807ea` | adds to `lib/oauth-token` | needs A5 + smoke at S4 (mock for unit) |
| 15 | S | S5 /token refresh DPoP sticky | `b8ad984`, `1137a52`, `eecc5b2` | `oauth_token_refresh.go` grows 150→250 (under threshold) | needs S4 |
| 16 | S | S6 /userinfo DPoP + ath + scheme + 2-way split | `b7e2c89`, `7b01b4e` (RED `edfd255`), `d45e01c` (RED `e7b1b2f`), `26d5a02` (RED `6519b5d`), `83fd96a`, `05f1601`, snapshot §7.2 (skip `0e5605c`) | `oauth_userinfo.go` 191 → `oauth_userinfo.go (100) + oauth_userinfo_challenges.go (80)` | needs S1 + S2 |
| 17 | S | S7 discovery advertise DPoP + cnf | `9f5fccb` | none (file 76 lines) | needs S1 |
| 18 | A | A16 chain verifier (universal walker) | `3e14024`, `836a9f4`, `9652606`, `5bf50b5`, `86a59e7`, `fce7398` | new module `lib/chain-verify` | needs A2 + A8 + A11 |

**Demo gate:** the moment S7 (discovery) + A16 (chain verifier) both land, agent-id can do the full demo flow against live SSO. That's PRs 1–18 above; the SSO server is the gating dependency for the *smoke-test* of agent-id PRs A5/A8/A9 — those PRs build and unit-test green earlier but the end-to-end run requires the server-side path lit.

---

## 3. Parallel-safe lanes

**Can run in parallel** (no cross-PR dependency):

- A0, A1, A2, A3, A4, A11 — **agent-id pure-foundation lane**: doc bundle + refactor warmup + crypto primitives + verifier. None require SSO server. None require each other beyond A1 → A2 → A3/A4 ordering. All ship green before any server work lands.
- S0, S1, S2 — **server foundation lane**: test env + DPoPVerifier + JWTService. S1 and S2 are independent of each other once S0 lands. Can ship in parallel.

**Strictly serialized** (hard dependency):

- S3 → S4 → S5 (auth-code → refresh)
- S1 → S6 (userinfo needs verifier)
- A1 → A2 → A4 (modules layered)
- A11 + A8 → A16 (chain verifier consumes both)
- A5/A8/A9 require server side **for smoke test only**, not for unit tests

**Recommended cadence:** open A0–A4 + A11 + S0–S2 as 9 parallel PRs in the first batch — they're all reviewable independently and have no cross-dependencies. Once those merge, S3→S4 + A5+A8+A9 cluster as the second batch. Then S5+S6+S7 + A16 close out the demo.

---

## 4. What "demo ready" looks like

After PRs 1–18 above:

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

This requires server: dpop_jkt at /authorize, DPoP at /token, cnf.jkt minted on id_token, token_type=DPoP emitted, /userinfo DPoP-protected (when AT carries cnf), discovery advertising it.

This requires agent-id: jwk-thumbprint + dpop-proof modules, CLI wired, cnf.jkt enforced at git-verify, full id_token verifier, chain verifier consuming all of the above.

---

## 5. Wave 1B — compliance close-out (post-demo, pre-prod)

These don't gate the demo but DO gate `npm publish` / a clean COMPLIANCE.md re-audit.

| # | Lane | PR | Source | Why now |
|---:|---|---|---|---|
| 19 | S | S8 cleaner GC | `d5f928d` | dpop_jti_seen unbounded growth otherwise |
| 20 | S | S9 RFC 9068 §2.2/§4 broad sweep + access_token.go 3-way split | `a55cb63`, `d7af03d`, snapshot LegacySSOClaims usage | audit MUST |
| 21 | A | A6 ath + getUserInfo + nonce-fetch | `817559f`, `cef4453` | full RS-side conformance |
| 22 | A | A7 nonce retry + cache | `0a03249`, `d30baeb`, `60dc3ed`, `02fd6f7` | third-party RS interop |
| 23 | A | A10 §9 RS structured matching | `9089768` | third-party RS interop |
| 24 | A | A12 RFC 9207 iss check | snapshot iss-verify + tests/test-rfc9207-iss.mjs | mix-up attack closure |
| 25 | A | A13 state/nonce plumbing | snapshot CLI delta | replay attack closure |
| 26 | A | A17 setup-owner-session CLI | `b10f8ce` | DPoP migration UX |
| 27 | A | A19 cli.mjs decomposition | pure refactor | Wave 1 file-size guarantees |
| 28 | A | A20 3.0.0 release bundle | `2cd7ce9`, `99563f9`, `a135b1b`, `6e67d87`, `a524c99`, `0c558e5` | npm publish gate |

**Wave 1B is parallel-safe across A6, A7, A10, A12, A13** (they're independent client-side hardening). S8 and S9 are also independent.

---

## 6. Wave 1C — operational hardening (deferred)

Post-Wave-1B. Not blocking. Listed for sequencing only.

| # | Lane | PR | Source |
|---:|---|---|---|
| 29 | S | S10 trusted-proxy CIDRs + slowloris | snapshot |
| 30 | S | S11 config-load validators + 4-way split | snapshot |
| 31 | S | S12 PKCE ABNF + scope subset on refresh | snapshot |
| 32 | S | S13 redirect_uri strict matching + RFC 8252 §7.3 + 3-way split | snapshot |
| 33 | S | S14 /poll state + iss + /.well-known alias | snapshot |
| 34 | S | S15 RT family rotation + reuse cascade | snapshot, migrations 000012/13/14 |
| 35 | A | A21 lib.mjs final cleanup (≤100 lines, re-export shim) | pure refactor |

Wave 2 covers the SDK trio (sso-sdk-js, sso-sdk-py, miniapp-sdk) that we deferred — those are the monolithic-snapshot repos that need manual diff splits, not cherry-picks. Plan TBD when Wave 1 ships.

---

## 7. Open questions surfaced by research

These need a yes/no before execution starts.

1. **A11+A14+A15 collapse.** Research recommends collapse into a single PR (full id_token verifier with strict alphabet + RSA floor + EdDSA all in one). Default in this plan: **collapsed**.

2. **A18+A20 collapse.** Version bump rides with release notes. Default: **collapsed**.

3. **Skip `5931123` + `a8b78a9`.** Early G-1 (1-return-value) superseded by `5608a7e`/`54d5b62` (3-return-value). Skip from cherry-pick set. Default: **skip**.

4. **Skip `a786dfc`.** F-4 basic htu canon rewritten by snapshot's full RFC 3986 §6.2.2. Take the snapshot version directly in S1. Default: **skip the cherry-pick, fold the test cases into S1**.

5. **Skip `0e5605c`.** L1 doc rewritten by snapshot's §7.2 no-info-leak path. Default: **skip; take snapshot version in S6**.

6. **`fce7398` (cnf-verifier env isolation).** Folds into A8 OR A16. Recommend A16 since A16 rebuilds the fixtures.

7. **REVIEW-PLAN.md fate.** It's a planning artifact from earlier in the session. Default: **keep alongside REFACTOR-PLAN.md in A0**.

8. **`dpopHTU` signature ripple.** S6 keeps old `dpopHTU(r)`; S10 introduces `dpopHTU(r, cidrs)` and updates 3 call sites. Avoids a router constructor change in S6.

9. **`handler/full_flow_oauth_test.go` split.** Stays as one mega-file in Wave 1; splits in Wave 2 once additions stop. Default: **defer split**.

10. **Migrations.** Wave 1 = 000010 (S1) + 000011 (S5). Wave 1C migrations = 000012/13/14 (S15). All additive `up.sql`/`down.sql`.

---

## 8. First-action recommendation

**Lightest possible first PR = A0** (docs bundle, zero behavior change, no cherry-pick complexity — just `git checkout backup/huge-refac-2026-05-08 -- docs/*.md` onto a fresh branch from `agent-id/main`).

**First "real code" parallel batch:** A1, A2, A3, A4, A11, S0, S1, S2 — eight PRs, each independent, each reviewable in isolation, all unit-testable without server-side state. Ships the foundation. Reviewers can divide and conquer.

After that batch lands:

- S3 → S4 → S5 (one-week server sequence)
- A5, A8, A9 in parallel (one-week agent-id sequence, gated on S2 + S4 for smoke)
- S6 + S7 (close out server)
- A16 (chain verifier closes out demo path)

**The actionable sequence below is what unblocks everything else** — once `git checkout main && git checkout -b refactor/wave1-a0-docs` is done in agent-id, the cherry-pick playbook for every subsequent PR is mechanical and follows this document table-by-table.

---

## 9. Status of repos

| Repo | Backup branch | Pushed to origin | Wave 1 PRs |
|---|---|:---:|---:|
| `agent-id/` | `backup/huge-refac-2026-05-08` | ✅ | 18 (A0–A20 minus A6/A7/A10/A12/A13/A17/A18/A19/A21 = Wave 1B/C) |
| `sso/sso/` | `backup/huge-refac-2026-05-08` | ✅ | 8 critical-path (S0–S7), 7 follow-up (S8–S15) |
| `sso/sso-sdk-js/` | `backup/huge-refac-2026-05-08` | ✅ | deferred to Wave 2 |
| `sso/sso-sdk-py/` | `backup/huge-refac-2026-05-08` | ✅ | deferred to Wave 2 |
| `miniapps/miniapp-sdk/` | `backup/huge-refac-2026-05-08` | ✅ | deferred to Wave 2 |

All 5 backup branches are durably saved on origin. Working trees are still on backup branches; switching back to main per repo is the next step before any cherry-pick PR work begins.
