# Agent ID Roadmap

Forward sequencing for the agent-id stack post-3.0 cutover. Captures what each
phase actually consists of, what depends on what, and the design decisions
worth surfacing before we commit to one.

## Where we are (Phase A — landed)

| Component | State |
|---|---|
| **DPoP cutover** | Deployed on `sso.develop.alien-api.com` and `sso.staging.alien-api.com` (launch-template `lt-099a17b58fb7fd1e4` v11, 2026-05-06). Production pending. |
| **Verifier** | `@alien-id/sso-agent-id` v1.0.2 published; expected 2.0 with cnf-mandatory verification once prod SSO flips. |
| **CLI** | agent-id 3.0 sends `dpop_jkt`, signs DPoP proofs, enforces `cnf.jkt` match. |
| **Well-known manifest** | v1 schema landed (`/.well-known/alien-agent-id.json`). Closed-key-set + version-pinned. |
| **Alien App** | Zero changes required for cutover (verified by source-level diff: `authorize.go`, `app_callback.go`, `public_key.go` byte-identical pre/post-cutover). |

What this enables that earlier releases didn't: **sender-bound id_tokens**.
A leaked `refs/notes/agent-id` is no longer a forgery primitive. That's the
precondition for everything below — every Phase B+ feature ships verified
attributes that need cryptographic sender-binding to be trustworthy.

---

## Resolved decisions

Decisions made by the tech lead that bind the implementation. Update this log
as more land; refer to it from PR descriptions and ADRs.

| # | Decision | Resolution | Date |
|---|---|---|---|
| 5 | Selective-disclosure wire format (Phase D) | **SD-JWT-VC** ([draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)). Phase C MUST design claim names and structures that SD-JWT-VC can selectively disclose. Holder binding will reuse the Phase A `cnf.jkt` thumbprint — they compose without rework. | 2026-05-08 |

Decisions still open: 1 (scope policy), 2 (scope namespacing), 3 (trust chain),
4 (claim freshness), 6 (manifest versioning). See "Decisions for the tech
lead" at the bottom.

---

## Phase B — Scopes & consent surface

**Goal:** services declare what permissions they need; agents request them;
humans see and approve them in the App.

### Scope of change

| Layer | Change | Approx LOC |
|---|---|---|
| **SSO `oauth_authorize.go`** | Replace `strings.Contains(scope, "openid")` gate with `validateScopes(scope)` against `scopes_supported`. Persist requested scopes in the session row alongside `dpop_jkt`. | ~40 |
| **SSO `oidc_discovery.go`** | Extend `scopes_supported` from `["openid"]` to the configured set. | ~5 |
| **SSO `authorize.go`** (deep-link emitter) | Append `&scopes=<space-list>` to the signed deep-link payload. **First Alien App contract change since 2.x.** | ~15 |
| **Alien App** (iOS + Android) | Parse `scopes=` from deep link; render scope-aware consent UI ("Agent X wants: ✓ sign in, ✓ access age band, ✓ coarse geo"); pass through to backend approval call. | ~150 each platform |
| **Manifest v2** | `auth.requiredScopes: string[]` (optional). `parseServiceManifest` extended to parse v2 alongside v1. | ~30 |
| **CLI `cmdAuth`** | When the manifest declares scopes, pass `--scope` automatically. New `--scope` flag for ad-hoc use. | ~25 |
| **Verifier (`@alien-id/sso-agent-id`)** | Surface granted scopes from the inspected token. | ~15 |

### Open design decisions

1. **Per-provider scope policy vs. per-request.** Does each `provider_address`
   pin a fixed scope set in `developer-portal` (so the human consents once at
   provider onboarding, never per-request)? Or does each `/oauth/authorize`
   call carry its own scope list and require fresh consent? Cleaner UX is
   per-provider; cleaner security is per-request. Most likely a hybrid: a
   provider declares the *maximum* scope set; per-request can request any
   subset.
2. **Scope namespacing.** Stick with OIDC convention (`openid`, `profile`,
   `email`) and ad-hoc Alien names (`alien:age`, `alien:geo`)? Or invent a
   structured grammar (`age:band`, `geo:country`)? The latter is more
   evolvable but creates a parser surface. Industry trend (FAPI, GAIN) is
   structured.
3. **Backward compat.** Existing v1 manifests have no scope declarations. The
   agent should default to `openid` and log a discovery hint
   (`"manifest v1 — assuming scope=openid"`) when calling against a v2-aware
   service. Hard-fail only when the service's manifest is v2 with declared
   `requiredScopes` the agent can't satisfy.

### Dependency edges

- Phase B depends on **nothing** server-side that isn't already in place.
- Phase B is the **first phase that requires Alien App releases on both
  stores**. Plan accordingly — store review windows are weeks, not days.
- Phase C cannot ship without Phase B's consent surface (no point granting
  verified attributes without a way to display the request).

---

## Phase C — Verified attributes

**Goal:** SSO embeds attestations from the existing `enclaved-*` verifier
fleet into id_tokens, gated by Phase B scopes.

### Existing infrastructure to wire up

The org already runs verification microservices. Phase C is integration, not
greenfield:

| Service | Attests |
|---|---|
| `enclaved-passport-verifier` | Document-grade identity (passport MRZ + chip) |
| `enclaved-phone-number-verifier` | Carrier-grade phone possession |
| `facetec` | Liveness / face match |
| `enclaved-pnc` | (PNC = profile/credentials? — confirm with platform team) |
| `enclaved-{br, blc, bvg, lk, ms, sg, spk, pt}` | Other attestation types — TBD which map to which user-facing claims |

### Scope of change

| Layer | Change | Approx LOC |
|---|---|---|
| **SSO `oauth_userinfo.go`** | Replace hard-coded `OAuthUserInfoResponse{Sub, Aud}` with claim-pluggable struct. | ~80 |
| **SSO new `internal/service/claims_resolver.go`** | Map granted scopes → required claims → enclaved-service calls. Cache per-session. | ~250 |
| **SSO `oauth_token.go`** | When minting id_token, include resolved claims for granted scopes. | ~30 |
| **id_token claim conventions** | Define stable claim names (`alien.geo.country`, `alien.age.band`, `alien.identity.verified_at`) and document which scopes unlock them. | doc |
| **Manifest v2** | `api.requiredClaims: [{claim, freshness}]` — declarative requirement spec for services. | ~40 |
| **Verifier** | Helpers to extract verified claims with their freshness windows (`token.claim("alien.age.band").asOf`). | ~50 |
| **Agent CLI `auth-header`** | Surface granted claims to the calling agent for display. | ~15 |

### Open design decisions

1. **Claim namespacing.** `alien.*` prefix? Bare names? Aligning with
   established standards (eIDAS, OIDC4VC) buys interop later. Inventing
   bespoke names buys flexibility now. Recommend prefix-and-document
   (`alien.{geo,age,identity}.*`) and migrate to a standard registration
   later if the protocol takes off externally.
2. **Claim freshness model.** Three regimes worth picking from:
   - **Permanent**: `age.band` (changes only at 18/21/65 boundaries).
     Verify-once, embed in id_token at bind, refresh when band changes.
   - **Decaying**: `identity.verified_at` (auditors care that re-verification
     happened recently). Embed `verified_at` timestamp; consumer policy
     decides max age.
   - **Per-session**: `geo.country` (IP changes per request). Embed in the
     access token, not the id_token; refresh on every `/oauth/userinfo`
     call. Forces the agent to actually call userinfo when geo matters.

   Recommend all three regimes addressable, with the manifest's
   `requiredClaims[].freshness` field selecting per-claim.
3. **Trust chain for non-Alien attestations.** When SSO embeds e.g. a
   `enclaved-passport-verifier`-attested claim into an id_token, the
   verifier package needs to know **how to check that the SSO is allowed to
   make that claim**. Options:
   - **SSO-as-trust-anchor**: id_token is signed by SSO; SSO promises it
     vetted the verifier. Simplest. Agent and service just trust SSO.
   - **Chain-of-attestations**: id_token carries the verifier's own signed
     statement, embedded via JWT. Agent verifies SSO sig + verifier sig.
     More robust to SSO compromise; more bytes on the wire.

   Recommend chain-of-attestations for sensitive claims (identity,
   passport); SSO-as-trust-anchor for low-stakes (geo coarse).
4. **Re-verification UX.** When `passport_verified_at` decays past a service's
   policy threshold, who triggers re-verification — the agent (silent) or
   the App (consent UI)? Probably consent-required for identity-grade
   attributes; silent for low-stakes refresh.

### Dependency edges

- Phase C **requires Phase B** (no scope plumbing → no way to gate which
  claims appear in id_token).
- Phase C does **not** require Phase D (selective disclosure). Without D,
  the agent leaks all granted claims to every service it calls. That's
  acceptable for a v1 of the attribute story — Phase D is a privacy
  optimization, not a correctness fix.

---

## Phase D — Selective disclosure

**Goal:** the agent presents only the claims a specific service requires,
without leaking the rest, and without the SSO needing to re-mint per call.

### The problem Phase D solves

Without selective disclosure, the agent's `AgentID` token wraps an id_token
containing **every claim the agent has been granted**. Calling Service A
with `requiredClaims: [age.band]` leaks `geo.country` and `identity.*` too.
For sensitive attributes this is unacceptable.

### Format: SD-JWT-VC (resolved 2026-05-08)

| Approach | Status |
|---|---|
| **SD-JWT-VC** ([draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)) | ✓ **Chosen.** Standardized direction; composes cleanly with existing JWT/JWKS plumbing; verifier package gains a `presentation: [...]` API and the rest stays JSON. Holder binding via Phase A's `cnf.jkt` is the right primitive (RFC 7800 + SD-JWT-VC compose without rework). |
| Per-service token re-minting | Rejected — online dependency on SSO for every service call defeats the offline-verification property of the AgentID token. |
| BBS+ signatures | Rejected — bleeding-edge; libraries less mature; verifier complexity ↑ a lot. Reconsider only if a future regulatory regime mandates zero-knowledge claim proofs. |
| mdoc / ISO 18013-5 | Rejected — CBOR wire format would force dual codepaths in the verifier. Possible bridge later if mDL ecosystem interop is requested. |

### Scope of change

| Layer | Change | Approx LOC |
|---|---|---|
| **SSO `oauth_token.go`** | Mint SD-JWT-VC instead of plain JWT for sensitive claims. Embed disclosure digests; emit disclosures separately. | ~200 |
| **SSO new `internal/service/sd_jwt.go`** | Disclosure construction, salt generation, hash binding. | ~300 |
| **Agent CLI** | Per-call selection: read manifest's `requiredClaims`, present only matching disclosures alongside the AgentID token. | ~150 |
| **Verifier (`@alien-id/sso-agent-id` v3)** | Validate SD-JWT-VC presentations: hash chain, key binding (DPoP composes here), `vct` (verifiable-credential type) checks. | ~400 |
| **Manifest v3** | `api.requiredClaims[].disclose: "selective" \| "always"` — services that genuinely need a claim disclosed selectively vs. opt-out for low-stakes. | ~10 |

### Open design decisions

1. **Compatibility window.** Phase D introduces a new token format. Run
   classic-JWT and SD-JWT-VC tokens in parallel for some period? The
   verifier package can certainly accept both. SSO has to know which to
   mint — driven by the granted scopes (any sensitive scope → SD-JWT-VC).
2. **Holder binding.** SD-JWT-VC binds the holder via a JWT or proof-of-
   possession. Our DPoP key thumbprint (`cnf.jkt`) is exactly this binding.
   Phase A's choice to use RFC 7800 `cnf.jkt` is the **right binding shape
   for SD-JWT-VC** — they compose without rework.
3. **`vct` registry.** SD-JWT-VC requires a `vct` URI declaring the
   credential type. We'd need to publish stable URIs for our claim
   bundles (e.g. `https://alien.org/credential/age-band/v1`).
4. **Revocation / status lists.** SD-JWT-VC can carry status-list refs
   for revocation. Our pattern (sticky DPoP-bound RTs, short AT TTLs) means
   we can mostly avoid status lists by re-minting on refresh. Worth deferring
   unless a compliance regime forces it.

### Dependency edges

- Phase D **requires Phase C** (no claims to selectively disclose → nothing
  to do).
- Phase D is **independent of the App** — selective disclosure happens at
  the agent ↔ service layer. The App still consents on the full scope set;
  the agent decides per-call which claims to present.
- **Phase C MUST design SD-JWT-VC-compatible claim shapes from day one.**
  Specifically: claims must be JSON-serializable, addressable by JSON Pointer
  paths (so SD-JWT-VC's `_sd` digest list can target them), and grouped
  under `vct`-typed envelopes (e.g. one `vct` for identity claims, one for
  geo). Avoid claim shapes that depend on whole-token signature semantics
  (e.g. computed claims, claims that reference other claims by index) —
  those don't survive selective disclosure.

---

## Cross-cutting concerns

These don't fit cleanly in any phase but matter throughout.

### Manifest versioning

`SERVICE_MANIFEST_VERSION = 1` today. The closed-key-set design (rejecting
unknown keys) means clients **cannot** silently ignore unknown future
fields — this is intentional, defends against an attacker injecting a
new control field, but means each new field is a major version bump.

Two strategies:

1. **One-version-per-phase**: v1 (today) → v2 (Phase B + C) → v3 (Phase D).
   Predictable but coarse; agents need to support all live versions.
2. **Additive within a version**: extend the closed key set as we add
   fields, agents tolerate older sub-schemas, log when newer fields are
   missing. Faster iteration; harder to reason about.

Recommend (1) for the next two bumps (v2 covers Phase B + C, v3 for D),
then revisit. The cost of supporting 3 manifest versions in `lib.mjs` is
~50 LOC; cost of getting the schema wrong is 6+ months.

### Claim freshness convention

Bake the convention in once, in Phase C. Every claim carries:

```jsonc
{
  "alien.age.band": "18-24",
  "alien.age.band.iat": 1730000000,        // when computed
  "alien.age.band.policy": "permanent"     // freshness regime
}
```

Verifier package exposes `token.claim("alien.age.band").freshAsOf(maxAge)`.
Manifest's `api.requiredClaims[].freshness` declares per-claim policy a
service requires.

### Verifier package compatibility matrix

```
agent-id CLI   →  SSO server      →  verifier
   3.0 (DPoP)  →   v11 (DPoP)     →  v2.x (cnf-mandatory)    [Phase A]
   3.1+       →   v12+ (scopes)   →  v2.x                    [Phase B]
   3.2+       →   v13+ (claims)   →  v3.x (claims surface)   [Phase C]
   4.0       →    v14+ (SD-JWT-VC)→  v4.x (SD-JWT-VC)        [Phase D]
```

Each step is wire-compatible with the previous (older agent against newer
SSO/verifier still works for the subset it knows about). The verifier
package's published version cadence drives the team's ability to ship —
worth ensuring it's owned and on a release schedule.

### App release cadence

Three of four phases ship without App changes. **Phase B is the only
App-blocking phase.** Plan it to land in an App release that has other
work too — don't burn a release just to display new strings. App store
review windows + the gap between Android and iOS releases mean Phase B is
~2 months of calendar time even if all the code is ready.

---

## Suggested execution order

```
2026-Q2   Phase A  (cutover) — landed.  Production rollout: TBD by SSO ops.
2026-Q2   Phase A.5 — well-known manifest hardening, verifier package v2.x
2026-Q3   Phase B  (scopes) — depends on App release windows.
2026-Q4   Phase C  (verified attributes) — design SD-JWT-VC compat ahead.
2027-Q1   Phase D  (selective disclosure) — if compliance / privacy review
                    demands it sooner, can be brought forward.
```

Phases A.5 → B → C are sequential. Phase D's design choices should be
made in A.5 (specifically, claim naming and the decision to commit to
SD-JWT-VC) so Phase C doesn't bake in a structure that fights Phase D.

---

## Decisions for the tech lead

These don't have obvious right answers and shouldn't be punted to
implementation. Worth resolving before starting Phase B:

1. **Per-provider vs. per-request scope policy** (Phase B §"Open design
   decisions" #1). Affects Alien App consent UI shape.
2. **Scope namespacing convention** (Phase B #2). Affects every downstream
   consumer.
3. **Trust chain model for verified claims** (Phase C #3). Affects
   verifier complexity for years.
4. **Claim freshness regimes per claim type** (Phase C #2). Affects manifest
   schema and verifier API.
5. ~~**SD-JWT-VC commitment timing** (Phase D §dependency edges).~~
   ✓ Resolved 2026-05-08 — see Resolved decisions log.
6. **Manifest versioning strategy** (Cross-cutting §Manifest versioning).
   Affects every future schema change.

Pick a forum (eng meeting, ADR, RFC) to resolve each. Each one ships better
when the decision precedes the code. Move resolved items to the "Resolved
decisions" log near the top so future readers see committed direction at
first read.
