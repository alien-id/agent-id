# CONTINUE.md — Capability access control: named capabilities + ask-the-owner loop

_Last updated: 2026-07-02 · status: design agreed, implementation not started._
_Previous stream (browser plugin + vault modes) shipped; its still-open TODOs are
carried over at the bottom._

## Goal

Today the access model is **syntactic** (ro/rw + method/host/path globs) and
**binary** (allow or deny). This stream makes it **semantic** and **adaptive**:

1. Rules group into owner-legible **named capabilities** ("read-transactions",
   "make-transfers") — the unit the owner actually reasons about and the label
   the phone shows.
2. `evaluateAccess` gains a third verdict: **`ask`**. An unmatched or
   unclassifiable request parks and pushes an approval to the phone —
   **deny / allow once / allow always** — instead of dying. "Allow always"
   persists a scoped rule back into the vault through the existing relaxation
   ceremony (the phone approval IS the ceremony) and is signed into the audit
   trail.
3. First-seen opaque operations (GraphQL persisted-query IDs, unknown JSON-RPC
   methods) get classified once by the owner and **learned** — turning the
   known ro over-blocking limitation into a one-tap flow.
4. The enforcement point can **attest** (TEE track): prove to a verifier that a
   genuine, unmodified policy engine with policy hash X made each decision.

## Where we are (the substrate this builds on — all shipped)

- **Policy engine**: `plugins/agent-id-vault/lib/access.mjs` — `access: "ro"|"rw"`,
  `accessRules` (first-match-wins method/host/path globs),
  `evaluateAccess() → { allowed, reason, needsBody? }`, read-classifiers for
  POST-tunneled protocols (inline GraphQL / JMAP / JSON-RPC; unknown → blocked
  under ro). `isAccessRelaxation()` already distinguishes widening from
  tightening and gates the `set-access` owner ceremony.
- **Enforcement point #1 (HTTP)**: `plugins/agent-id-proxy/lib/proxy.mjs` —
  evaluates before materializing the credential; buffers POST bodies on
  `needsBody`.
- **Enforcement point #2 (sealed browser)**:
  `plugins/agent-id-browser/lib/access-guard.mjs` — network-layer route
  interception on the patchright context (`applyAccessGuard`), WebSockets +
  service workers blocked, ro-denied action vocabulary
  (`eval`/`fill-secret`/`fill-otp`/`upload`).
- **Phone channel**: `plugins/agent-id-proxy/lib/control.mjs` — the control
  plane ALREADY parks blocked requests in a pending registry awaiting the
  phone's `/approve` / `/deny` (sealed-box unlock + per-credential consent
  "agent wants `<cred>` → `<host>`"). `pairing.mjs` does the QR/deep-link
  pairing; `owner-approval.mjs` does the SSO-escrowed variant, DPoP-bound
  (RFC 9449). **The ask loop is a generalization of the consent prompt from
  (cred, host) granularity to (cred, capability) granularity.**
- **Audit**: hash-chained, agent-key-signed trail in
  `plugins/agent-id-core/lib/signature-engine.mjs`. Proxy decisions currently
  go to the proxy log only, NOT the trail.
- **TEE precedent**: the mobile slot already rests on the phone's Secure
  Enclave (P-256 ECDH KEK, `format.mjs` mobile slot type) — the pattern to
  extend, not invent.

## Design

### Verdict model

`evaluateAccess` returns `verdict: "allow" | "deny" | "ask"` (keep `allowed`
as a derived boolean for existing callers). Per-credential
`onUnmatched: "deny" | "ask"` (default `deny` — today's behavior — so nothing
changes for unattended vaults until the owner opts in; `ask` requires a paired
phone or owner-approval enrollment).

### Capabilities schema (vault)

```
capabilities: [
  { name: "read-transactions",         // ≤ 40 chars, shown on the phone
    rules: [ …same rule objects as accessRules… ],
    approval: "auto" | "ask" | "deny" } // ask = confirm EVERY use (dangerous ops)
]
```

- Compiled to a flat first-match rule list for evaluation; the matched
  capability name travels in `reason` → phone prompt + audit entry.
- Validation lives in `access.mjs` (same pattern as `validateAccessFields`),
  storage in `store.mjs`, `set-access` grows capability editing.
- `isAccessRelaxation` extends naturally: adding an allow rule to a capability
  is a relaxation; adding `approval:"ask"` or deny rules is tightening.
- Plain `accessRules` stay supported (a capability is sugar + a label).

### The ask loop

- **Proxy**: on `verdict:"ask"`, park the request in the pending registry
  (`control.mjs`) as a new action kind `access` carrying
  `{ cred, capability?, method, host, path, classified }` — metadata only,
  never bodies or credential material (same discipline the control plane has
  today). Phone responds deny / approve `{ scope: "once" | "always" }`.
  "Always" appends a rule scoped to exactly what was asked (method + host +
  path, or the learned operation hash — never a widening beyond the observed
  request), written through the vault relaxation path and audited.
- **Browser**: `access-guard.mjs` route handler parks instead of
  `route.abort()` when the verdict is `ask`, then `route.continue()` on
  approval. Park-and-continue (not deny-and-retry) matters: upstream POSTs are
  not idempotent; the request must proceed exactly once after approval.
- **Timeouts**: configurable hold (default 60s). Timeout / no paired phone /
  offline → deny with a distinct `reason: "approval_timeout" | "approval_unavailable"`
  so the agent can surface "awaiting owner approval" instead of a generic 403.
  Body buffering stays under the existing size cap while parked.

### Learned classification (fixes the persisted-query over-block)

- Per-credential learned map in the vault:
  `{ key: sha256(host + opaque-op-id), verdict: "read" | "write", approvedAt, approver }`.
  Keys: GraphQL `extensions.persistedQuery.sha256Hash`, unknown JSON-RPC
  method names, (later) other opaque op shapes.
- `classifyBodyRead` consults the map before returning `"unknown"`; misses go
  to the ask loop; entries are written ONLY via owner approval (poisoning
  resistance: the agent cannot self-teach the map).

### Audit

- Every decision (allow / deny / ask + outcome) appends to the hash-chained
  trail: capability name, rule id, decision, approver identity (device id or
  owner `sub`), request tuple. The trail already gives us tamper-evidence and
  agent-key signatures; approvals via SSO additionally carry the DPoP-bound
  token reference.
- Ride-along fix while we touch trail writes: persist `idTokenJti` as its own
  field (the known jti gap — trail entries must not depend on
  `owner-session.json` cache integrity).

### Attested enforcement (Frame track)

The `access.mjs` header already states the honest limit: the policy is only as
strong as the enforcement point + unlock boundary. We have the **Frame
platform** in deployment (AMD SEV-SNP confidential VMs, `enclave-sdk`) with
4-layer attestation — AMD hardware → auditor approval → **on-chain instance
registration** → client verification — and an on-chain enclave key registry +
JWKS. The plan is Frame-first, local hardware keys second:

1. **Enclave vault slot** — new slot type in `format.mjs`, symmetric with the
   existing `mobile` slot: KEK via ECDH against a Frame instance's *attested*
   key. The client verifies the attestation report against the on-chain
   auditor-approved measurement (client verification code exists:
   `enclave-sdk/api/verify.go` `VerifyKeysAndAttestation`) **before** sealing.
   The single-file vault is its own provisioning mechanism — sealing a slot
   to an enclave key is all a remote proxy needs.
2. **Frame-hosted proxy** — run proxy + policy engine as a Frame service.
   `enclave-sdk` is Go-only (mkosi Ubuntu disk images, no Node runtime), so:
   *near term*, add Node.js to the image package list and run the existing
   `.mjs` code unchanged behind the SDK's service server; *long term*, port
   the enforcement hot path (rewrite + `access.mjs` + audit signing) to Go as
   a first-class service type (pattern: `enclaved-sg`). Vault unlock inside
   the Frame via the enclave slot + owner approval; idle-lock semantics
   unchanged.
3. **Attestation in the audit trail** — each decision entry carries the Frame
   measurement + policy hash; a verifier walks entry → enclave signing key →
   attestation report → on-chain auditor-approved measurement. Upgrades the
   trail from "signed by the agent key" to "signed inside a runtime anyone
   can verify". Attestation stays a transport-level artifact beside the v3
   bundle (no bundle format change).
4. **Local hardware keys** — Secure Enclave/TPM for the agent key on dev
   machines. Still wanted, no longer the primary track.

Pre-M6 fixes in the SDK (blockers for honest attestation claims): launch
measurement verification is commented out (`enclave-sdk/api/verify.go` ~89
"not implemented"); sealed-artifact validation TODO in
`alien-host/internal/service/managers/download/manager.go`.

## Milestones / TODO

- [ ] **M1 — ask verdict + proxy loop**: `access.mjs` verdict model,
      `onUnmatched`, proxy parking via the existing pending registry,
      approve-once path end to end. (Highest leverage; no schema changes.)
- [ ] **M2 — capabilities schema**: vault schema + validation + `set-access`
      editing + phone prompts show capability names; allow-always persists
      scoped rules through the relaxation ceremony.
- [ ] **M3 — learned classification**: persisted-query / unknown-RPC map,
      owner-taught via the ask loop. (Closes the documented ro over-block.)
- [ ] **M4 — browser ask path**: park-and-continue in `access-guard.mjs`,
      distinct awaiting-approval surface on the session socket.
- [ ] **M5 — audit append**: decisions into the hash-chained trail + the
      `idTokenJti` persistence fix.
- [ ] **M6 — attested enforcement**: enclave vault slot (`format.mjs`) +
      Frame-hosted proxy (Node-in-image first, Go port later) +
      attestation-bearing audit entries. Prereq: the two enclave-sdk
      verification fixes noted above.
- [ ] **M7 — playbooks**: named task recipes = capability bundle + one-tap
      phone consent (builds on M2; the unit owners actually think in).
- [ ] Docs: new section in `docs/VAULT-PROXY.md`; vault + proxy + browser
      SKILL.md updates.
- [ ] Changesets: M1–M3 touch `agent-id-core`/`agent-id-vault` → each PR needs
      a `.changeset/*.md` (minor).

## Verification plan

- **Unit** (`tests/`): verdict matrix incl. `ask`; `onUnmatched` defaults;
  capability compilation + relaxation detection per capability; learned-map
  writes refused without approval provenance; scoped-rule generation from an
  approved request (no over-widening).
- **E2E against `examples/dev-sso.mjs` + a control-plane phone simulator**:
  park → approve-once → request proceeds exactly once; park → always → rule
  persisted → second identical request auto-allows; deny → 403 with reason;
  timeout → `approval_timeout`; audit chain verifies across all of the above.
- **Browser e2e**: ro session, click "Send" → parked at the wire → simulated
  approval → `route.continue()` fires once (guard against double-resolve);
  WebSocket/service-worker blocking unchanged under the new handler.

## Risks / open questions

- **Hold vs fail-fast**: parking blocks the agent's request for up to the
  timeout. Acceptable for interactive sessions; unattended runs should ship
  with `onUnmatched:"deny"` (the default) until we have a queued-approval
  retry story.
- **Rule explosion** from allow-always: needs a capability-grouped
  `vault show` view and a prune/expire pass (e.g. `approvedAt` + last-used).
- **Capability taxonomy**: free-form names now; per-site shared templates are
  a later concern (M7 playbooks pull in that direction).
- **Multi-device**: two paired phones racing an approval — first response
  wins, the registry already resolves a promise once; verify, don't assume.
- **Metadata to the phone**: prompts carry method/host/path/capability only —
  never bodies, headers, or credential material. Same rule as today's consent
  prompts; keep it that way when adding the classified-operation context.

## Alien infrastructure leverage (context for this stream and the next)

What exists across the org's repos that this work should plug into rather than
rebuild (see `~/devel/alien/repos/{documentation,enclave-sdk,enclaved-sg,sso,backend-app,alien-fleet,vault-approver-ios}`):

- **On-chain Agent ID (AAID)** — whitepaper §3 specifies agent accounts with
  capability masks, reputation tiers, revoked/suspended status, creator
  links, and ≤4-tier delegation with cascading revocation. Registering the
  bundle's JKT into an AAID account gives us **revocation** (our known gap:
  today a compromised key is permanent until re-bootstrap) and multi-hop
  delegation, verifiable from the chain without trusting the SSO.
  Implementation status on chain needs scoping with the network team
  (Session Generator exposes provider/session creation today; agent accounts
  don't appear implemented).
- **Assurance rides Phase B/C scopes** — `alien_assurance` / L1 should NOT be
  a bespoke claim: the SSO roadmap's scope machinery
  (`alien:identity:basic`, enclave-JWT-embedded claims for high-sensitivity
  scopes) is the vehicle. Sessions are cryptographically unlinkable across
  providers by construction — that IS the pairwise property L1 was waiting
  for; only the assurance claim is missing.
- **Push channel for the ask loop** — backend-app has APNs registration
  (`/v1/apns/register`, `/v2/apns/register`) and vault-approver-ios's
  components (DeviceKey, VaultCrypto sealed-box — byte-compatible with our
  format, BiometricAuth) are ready pending a transport swap from the
  localhost ControlClient to the push channel. M1 ships against the local
  control plane (works today); the push transport is the production path
  once the approver merges into the main app.
- **Per-human nullifiers** — alien-fleet already derives
  `SHA256(domain, iss, sub)` nullifiers from our DPoP tokens (one faucet
  trial per verified owner). The same primitive lets any RP rate-limit **per
  verified human** without linkability — the technical core of the
  delegated-presence story for the open web, and a natural companion claim
  to present alongside capability approvals.
- **External dependency to track**: DPoP is live on SSO staging/develop but
  the **production cutover is pending** (status doc 2026-05-08; detectable
  via `/.well-known/openid-configuration` → `dpop_algs`). Most of the above
  assumes it.

## Carried over from the previous stream

- [ ] Tighten user mode: reject agent-key + passphrase (app-unlock only);
      `init` enrolls owner-approval/mobile — awaits production Alien SSO
      escrow. **This stream reuses the same rails; M1's phone loop makes the
      tightening strictly more usable when SSO ships.**
- [ ] Full browser-plugin owner-approval unlock e2e against `examples/dev-sso.mjs`.
- [ ] Verify the Atom feed + "Security alert" anomaly behavior on a real
      **Workspace** account (consumer is proven).
- [ ] Optional: prune patchright's trace-viewer UI (~3.6 MB) to shrink the bundle.
