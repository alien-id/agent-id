# Capability broker

The capability broker is the authorization layer between an agent and a
credential-backed side effect. It answers one question before the proxy or
sealed browser commits an operation:

> May this authenticated principal use this credential to perform this exact
> action now?

The answer is `allow`, `deny`, or `ask`. An `ask` decision parks the request
until an approver authorizes that exact request or the request expires. The
development build simulates the phone through the proxy control plane and a
synchronous browser callback; the production path will put the broker and
credential material in an attested Alien Frame and use the Alien app as the
approver.

This document describes the version 1 policy and the enforcement invariants.
It is both a design reference and an operator guide. Capability labels are not
security boundaries by themselves: the broker is useful only when every path
to the credential and every relevant side effect passes through an enforcement
point that can classify the action.

The proposed human-facing policy editor, shared browser/mobile Render Manifest,
exact-action approval cards, agent feedback, and TEE advisor experience are
specified in
[`CAPABILITY-POLICY-UX-REQUIREMENTS.md`](CAPABILITY-POLICY-UX-REQUIREMENTS.md).

## Security invariants

1. **Bind authority to a principal.** A grant is made to a canonical Agent ID
   JWK thumbprint, not to a process name or a caller-supplied label. The local
   CLI binds one broker instance to its configured Agent ID key; it does not
   authenticate separate callers of that broker. Per-caller authentication is
   a Frame deployment requirement.
2. **Keep resource and authority separate.** A vault record owns the credential;
   its `capabilityPolicy` grants narrowly scoped uses of that credential to
   principals. Sharing a credential does not imply sharing every permission.
3. **Decide before materialization.** The proxy decides before injecting a
   bearer token, refreshing OAuth, or signing a wallet operation. A browser
   decides before continuing the intercepted network request.
4. **Bind approval to bytes.** Approving `mail.send` or `POST /send` is
   insufficient. Approval is bound to the authenticated principal, credential,
   normalized target, agent-controlled headers/body, policy epoch, and a fresh
   nonce. The enforcement point recomputes the digest immediately before the
   request is released.
5. **Fail closed.** Invalid policy, missing principal authentication, unknown
   action, unavailable approval, expiry, digest mismatch, and policy-epoch
   mismatch deny the action. Compatibility with the older `access` and
   `accessRules` evaluator must be requested explicitly with
   `onUnmatched: "legacy"`.
6. **Consume once.** An approve-once response releases one parked request. It
   is not a bearer grant and cannot release a second identical request.

## Trust boundaries and request flow

```text
agent key / authenticated session
             |
             v
   principal derivation       agent:jkt:<RFC 7638 thumbprint>
             |
             v
      capability broker  ---- policy + action envelope
        /      |      \
    allow     deny     ask ----> dev approver / Alien app
      |                 |                |
      |                 +<-- exact approval digest
      v
 credential materialization / browser route.continue()
             |
             v
          upstream
```

The canonical local principal is:

```text
agent:jkt:<base64url RFC 7638 thumbprint of the Agent ID Ed25519 public JWK>
```

The helper in `@alien-id/agent-id-core/lib/principal.mjs` derives it from the
Agent ID public key. Policy accepts the literal `"*"` only as an explicit
wildcard. Do not use the wildcard for write, purchase, security, signing, or
fund-transfer capabilities.

In the local development build, this principal identifies the broker's main
Agent ID key, not the OS process connecting to its loopback port. Every process
that can reach that broker acts as the same principal. This is suitable for a
single-agent development environment only; production isolation requires an
attested DPoP, mTLS, or equivalent channel that authenticates each caller to the
Frame before policy evaluation.

The credential record is the resource boundary. A policy on `gmail-work`
cannot grant use of `stripe-production`; that record needs its own policy.
The record's domain allowlist and SSRF checks remain mandatory outer bounds and
cannot be widened by a capability grant.

## `capabilityPolicy` version 1

`capabilityPolicy` is an optional field on a vault credential record:

```json
{
  "version": 1,
  "epoch": 3,
  "onUnmatched": "deny",
  "grants": [
    {
      "id": "mail-send-owner-confirmed",
      "principal": "agent:jkt:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "capability": "mail.send",
      "label": "Send email",
      "decision": "ask",
      "priority": 200,
      "match": {
        "methods": ["POST"],
        "hosts": ["mail.example.com"],
        "path": "/v1/messages/send",
        "json": [
          {
            "path": "/operation",
            "op": "eq",
            "value": "send"
          }
        ]
      },
      "constraints": [
        {
          "path": "/to",
          "op": "domainIn",
          "values": ["example.com"]
        }
      ],
      "previewFields": ["/to", "/subject"],
      "notBeforeMs": 1783555200000,
      "expiresAtMs": 1815091200000
    }
  ]
}
```

Records written by `set-capabilities` also carry a sibling monotonic marker:

```json
{
  "capabilityPolicyEpoch": 3,
  "capabilityPolicy": {
    "version": 1,
    "epoch": 3,
    "onUnmatched": "deny",
    "grants": [
      {
        "id": "read",
        "principal": "agent:jkt:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "capability": "mail.read",
        "decision": "allow",
        "match": { "methods": ["GET"] }
      }
    ]
  }
}
```

`capabilityPolicyEpoch` is not part of the policy hash; it is vault metadata
that prevents generation reuse during normal, authenticated vault updates.
When an active policy and marker are both present, their epochs must match.
Clearing a policy increments and retains the marker as a tombstone. Re-adding
then uses the tombstone rather than restarting at epoch 1, so an approval
created before clear cannot become valid against a later policy with a recycled
generation. Because the marker lives inside the same rollbackable encrypted
file, it is not durable anti-rollback state: restoring a complete older vault
backup across a broker restart can restore the old marker too. The Frame needs
external monotonic state.

The authoritative validator and deterministic evaluator are in
`@alien-id/agent-id-vault/lib/capability.mjs`:
`validateCapabilityPolicy`, `evaluateCapabilityPolicy`,
`evaluateCapabilityAccess`, and `capabilityPolicyHash`.

The complete example is in
[`examples/capability-policy.example.json`](../examples/capability-policy.example.json).
Its all-`A` JKT is a valid-shape placeholder; replace every occurrence with the
principal derived from the intended agent key before installing the policy.
The example assumes one credential for the fictional multi-function
`api.example.com`; real credentials should keep their existing narrow domain
scope and include only relevant grants.

### Policy fields

| Field | Required | Meaning |
|---|---:|---|
| `version` | yes | Schema version. Version 1 accepts only `1`. |
| `epoch` | yes | Positive-integer policy generation. It mirrors the record's `capabilityPolicyEpoch` when that marker is present; an approval for an older epoch is invalid. |
| `onUnmatched` | yes | `deny`, `ask`, or `legacy`. `legacy` delegates unmatched requests to the record's `access` / `accessRules` policy. |
| `grants` | yes | Non-empty array of at most 200 principal-scoped grants. |

### Grant fields

| Field | Required | Meaning |
|---|---:|---|
| `id` | yes | Stable, unique 1–96 character identifier (`A-Z`, `a-z`, digits, `.`, `_`, `:`, `-`) used in decisions and audit records. |
| `principal` | yes | Canonical printable principal string up to 256 characters, or the explicit `*` wildcard. Current Agent ID grants use exact `agent:jkt:<JKT>`. |
| `capability` | yes | Stable machine name such as `mail.send`, `form.submit`, or `commerce.purchase`. |
| `label` | no | Owner-facing label up to 120 characters. It must not replace the structured action preview. |
| `decision` | yes | `allow`, `deny`, or `ask`. |
| `priority` | no | Integer precedence from -1000 through 1000. Higher values win within one capability. The default is zero. |
| `match` | no | HTTP request classifier: methods, hosts, ports, pathname glob, query glob, and/or JSON-body predicates. If absent, it matches requests on the scheme's default port only. |
| `constraints` | no | JSON-body predicates that must all match after principal matching. |
| `previewFields` | no | Up to 24 RFC 6901 pointers selecting JSON-body values for the bounded owner preview. |
| `notBeforeMs` | no | Earliest epoch-millisecond time at which the grant is active. |
| `expiresAtMs` | no | Epoch-millisecond expiry. Expired grants do not match. |

The schema is closed: unknown keys at the policy, grant, matcher, or field-rule
level are rejected. Grant IDs must be unique. Capability names are lowercase
and dot-separated. Every segment starts with a lowercase letter; the first
segment then accepts lowercase letters and digits, while later segments may
also contain `_` or `-`. If both time bounds are present,
`notBeforeMs < expiresAtMs` is required.

Although the validator reserves printable principal strings for future
principal types, the local proxy must derive `agent:jkt:<JKT>` from its trusted
Agent ID key. Accepting an arbitrary caller-provided string would make
principal-scoped grants cosmetic.

`match.methods` contains uppercase HTTP methods. `match.hosts` uses the same
literal and leading-`*.` host matching as credential domain allowlists.
`match.ports` contains `"default"` and/or explicit decimal ports from 1 through
65535. A matcher that omits `ports` is default-port-only; this prevents a grant
for `api.example.com` from silently authorizing a different service at
`api.example.com:4443`. Name every intended non-default port explicitly.
`match.path` is an anchored pathname glob where `*` spans any characters. Query
parameters can be matched separately with `match.query`, which applies the same
anchored glob to the enforcement-supplied query string. The URL-rewrite proxy
supplies the `URLSearchParams`-normalized query, including its leading `?` when
non-empty. `match.json` and `constraints` contain the same field-rule objects
and are both evaluated against a parsed JSON body. A missing, empty, or
malformed JSON body does not satisfy a field rule.

Field rules address the body with RFC 6901 pointers. They use
`{ "path", "op", "value" }`, except `in`, `domainIn`, and `subsetOf`, which
use a non-empty string array named `values`. Version 1 operations are:

| Operation | Intended use |
|---|---|
| `exists` | Pointer presence or absence (`value` defaults to `true`). |
| `eq` / `neq` | Canonical structured-value equality or inequality. |
| `in` | The body value equals one member of `values`. |
| `contains` | A string contains `value`, or an array contains the canonical value. |
| `lte` / `gte` | Numeric upper or lower bound, such as a purchase amount in minor currency units. |
| `lengthLte` | Maximum string or array length. |
| `domainIn` | Every email address/domain in the scalar or array body value has a domain in `values`. |
| `subsetOf` | Every array member is canonically equal to a member of `values`. |

Use stable, typed JSON fields. For example, a commerce endpoint should expose
`totalMinor` and `currency`, not a formatted string such as `"CHF 19.95"`.
If a pointer is missing or its value has the wrong type for an operation, the
rule does not match. There may be at most 32 rules in either `match.json` or
`constraints`.

Policy files and JSON request bodies are parsed strictly. Duplicate object
keys, invalid UTF-8, non-finite or overflowing numbers, and integers outside
JavaScript's safe range are rejected rather than normalized into a potentially
different action. A non-empty body labelled as JSON that cannot be parsed
unambiguously is denied even if a transport-only grant would otherwise match.

### Resolution rules

Only active grants whose request matcher, principal (or `*`), and constraints
all match participate. The grant supplies the semantic capability name for the
matched request. Resolution is deterministic:

1. group matching grants by capability;
2. within each capability, highest `priority` wins;
3. within an equal-priority capability tie, `deny` wins over `ask`, which wins
   over `allow`;
4. if several different capabilities match, the strongest selected decision
   wins using the same `deny > ask > allow` order; and
5. if nothing matches, apply `onUnmatched`.

This makes an emergency deny reliable without depending on JSON array order.
Use higher priority for narrower exceptions and critical denies, and keep a
visible gap between tiers (for example 100, 200, 1000) so policy generation can
insert rules later.

`onUnmatched: "deny"` is the production default. Use `"ask"` for attended
exploration when every unknown action should be surfaced to an owner. Use
`"legacy"` only during migration; it preserves the older evaluator's semantics,
including its assumption that GET/HEAD/OPTIONS are read-shaped.

An explicit legacy `accessRules` deny remains a hard outer guard even when a
capability grant would allow the request. Other unmatched legacy behavior is
used only when `onUnmatched` is `legacy`.

## Semantic adapters

The version 1 kernel recognizes method, host, path, query, and JSON-body fields.
Those fields can distinguish many API operations, but they do not prove that a
request is a particular human-level action. A label such as
`commerce.purchase` is trustworthy only when the endpoint contract is stable or
a versioned adapter parses the protocol and produces the body/attributes the
policy and phone preview rely on.

A production adapter should:

- accept bytes plus normalized transport metadata, never credential material;
- reject ambiguous, malformed, batched, or unsupported payloads;
- return stable, typed fields that policy pointers can inspect and preview;
- identify itself and its version in the action envelope;
- commit all unredacted agent-controlled bytes in the request digest; and
- have adversarial fixtures for duplicate JSON keys, alternate encodings,
  redirects, amount/currency changes, hidden form fields, and multi-operation
  requests.

The evaluator commits an enforcement-supplied adapter ID and version to the
action envelope (`http`, version 1 by default). Version 1 policy does not select
or authenticate that adapter, so the enforcement point—not the agent—must
supply it. Future service adapters might include `gmail.send.v1`,
`web.form-submit.v1`, and `shopify.purchase.v1`. These names are contracts, not
aliases: changing parsing semantics requires a new adapter version and a policy
update.

Until a service adapter exists, an endpoint-matched capability remains useful
for coarse allow/deny/ask control, but the approver must treat its label as an
operator-authored description rather than a verified interpretation.

## Exact action approvals

Every decision creates an immutable action envelope; an `ask` decision sends
its digest through the approval flow. The phone may show the bounded preview,
but authorization is for the complete canonical envelope. The kernel emits
this version 1 shape:

```json
{
  "version": 1,
  "principal": "agent:jkt:...",
  "credential": "gmail-work",
  "credentialBindingHash": "sha256:64-lowercase-hex-characters",
  "capabilities": ["mail.send"],
  "grants": [
    { "id": "mail-send-owner-confirmed", "capability": "mail.send" }
  ],
  "policy": {
    "version": 1,
    "epoch": 3,
    "hash": "sha256:64-lowercase-hex-characters"
  },
  "adapter": { "id": "http", "version": 1 },
  "request": {
    "method": "POST",
    "scheme": "https",
    "host": "mail.example.com",
    "port": "",
    "path": "/v1/messages/send",
    "queryHash": "64-lowercase-hex-characters",
    "headersHash": "64-lowercase-hex-characters",
    "bodyHash": "64-lowercase-hex-characters",
    "bodyLength": 128
  },
  "preview": {
    "method": "POST",
    "scheme": "https",
    "host": "mail.example.com",
    "port": "",
    "origin": "https://mail.example.com",
    "path": "/v1/messages/send",
    "parameters": {
      "/to": ["alice@example.com"],
      "/subject": "Quarterly update"
    }
  },
  "nonce": "fresh-random-uuid",
  "expiresAtMs": 1783610060000
}
```

The kernel canonicalizes the envelope with deterministic key ordering and UTF-8
encoding, hashes it with SHA-256, and returns `actionDigest` as
`sha256:<64 lowercase hex characters>`.
Header names, capability names, and grant IDs used to construct envelope arrays
are ordered by raw UTF-8 bytes, never locale collation, so another Frame
implementation can reproduce the digest exactly.
It hashes the original body bytes rather than parsed and re-serialized JSON.
`port` is the normalized URL port string and is empty for the scheme's default
port. The proxy normalizes the query with `URLSearchParams` before both hashing
and forwarding it, and hides it behind `queryHash`. Header names are lowercased,
entries sorted, and values normalized before `headersHash`; hop-by-hop and local
origin headers are removed and `Host` is set to the upstream value before this
commitment. Because evaluation precedes credential injection, injected
authorization material is not present. `credentialBindingHash` commits the
credential's non-secret materialization configuration and monotonic
`credentialRevision` without exposing a hash oracle for raw low-entropy
secrets. Official replacement/rotation paths advance that revision. The
credential name, selected grant IDs/capabilities, policy hash/epoch, adapter
identity, and parsed preview are committed directly, so an approval cannot be
replayed through another credential configuration, grant selection, or policy.
Grant labels are returned in the decision and pending owner view; the policy
hash commits them even though the envelope's compact `grants` list carries only
ID and capability.

The generic preview always shows method, scheme, full origin (including a
non-default port), host, port, and path. `previewFields` values are size- and
depth-bounded, but they can still contain sensitive action data. Query and
header contents are committed by hash, not automatically rendered. Policies
and trusted semantic adapters for irreversible actions must explicitly expose
every human-relevant final value. Pending APIs and production push transports
must expose only what the owner needs and must never substitute the preview for
the raw-byte commitment. The pending-registry request ID is outside the
envelope and is checked alongside `actionDigest` by the control plane.

The enforcement point must:

1. buffer and bound the request before asking;
2. construct the envelope and park that specific request;
3. accept an approval only for its pending request ID **and** digest;
4. re-evaluate using the same nonce and expiry, then verify principal, current
   policy hash/epoch, and digest;
5. atomically consume the approval; and
6. release the parked bytes exactly once without an agent retry.

Redirects are new actions when they can change origin, method, or body. Do not
carry approval across them automatically. Wallet signing should bind the
unsigned transaction semantics and the signing adapter/version; normal
credential injection happens after approval and is not exposed to the phone.

An “allow always” UX must create a new owner-authorized policy grant; it must
never turn one action approval into a reusable token. Version 1 should favor
approve-once while policy-authoring and audit ceremonies mature.

## Development phone simulator

### Proxy simulator

The development simulator uses the proxy's pending-request registry and control
API. It exists to test park/approve/deny/timeout behavior without APNs or the
Alien app. It is **not** an independent security boundary: a process running as
the same OS user can generally read the proxy state file and obtain its control
token.

The current simulator is a deterministic auto-approver or auto-denier, not an
approval UI. The proxy CLI requires an explicit decision:

```bash
agent-id-proxy start --dev-phone-simulator approve
# or exercise the denial path:
agent-id-proxy start --dev-phone-simulator deny
```

The flag is accepted only for a dev-mode vault on the default loopback HTTP
control plane. It cannot be combined with `--no-control`, `--await-mobile`, a
non-loopback `--control-host`, or `--control-tls`. The simulator cannot unlock a
vault.

Tests and development harnesses may also start it after the proxy has bound its
control listener:

```js
import { startDevPhoneSimulator } from "@alien-id/agent-id-proxy/lib/dev-phone.mjs";

const phone = startDevPhoneSimulator({
  controlHost: "127.0.0.1",
  controlPort: proxy.controlPort,
  controlToken: proxy.controlToken,
  decision: "approve", // or "deny"
});

// Later:
await phone.stop();
```

It refuses a non-loopback host and deliberately ignores vault `unlock` and
legacy `authorize` entries. It handles only pending entries with
`action: "capability"` and a non-empty `actionDigest`. In `approve` mode it
approves every such entry, including an unmatched `ask` with no capability
label; it tests mechanics and must not be mistaken for owner judgment.

The simulator flow is:

1. start the proxy with the control plane enabled and a finite approval timeout;
2. issue an operation that resolves to `ask`; the data-plane request remains
   parked;
3. the simulator authenticates to `GET /pending` with the per-run control token;
4. copy the pending entry's ID and digest without inspecting or rewriting the
   action;
5. POST `/approve` or `/deny` with `{ id, actionDigest, scope: "once" }`;
6. verify that approve releases exactly one request, deny returns a distinct
   authorization error, and timeout fails closed.

The proxy's state file is mode `0600` and contains the development control URL
and token. Never print the token, request body, credential, or unredacted
sensitive action attributes to a transcript. Tests may call the control API
programmatically, but must assert the digest and never approve “the first
pending request” by position. A future interactive development UI should show
the principal, credential, selected grant labels/capabilities, structured
redacted preview, expiry, and action digest before it asks for a decision.

Before production, replace the local token-bearing simulator with an Alien app
approval signed by a registered device or bound through the owner SSO channel.
The response must still carry the action digest, expiry, nonce, approver
identity, and policy epoch. Transport security does not replace exact-action
binding.

### Browser simulator

The sealed browser has a separate synchronous simulator because it deliberately
does not park a live page request while DOM state, CSRF tokens, or checkout
totals can continue changing:

```bash
agent-id-browser open --name work --dev-phone-simulator approve
# or exercise fail-closed denial:
agent-id-browser open --name work --dev-phone-simulator deny
```

It is accepted only for a dev-mode vault and prints an explicit warning. For
each browser `ask`, it immediately returns `{ approved, scope: "once",
actionDigest }` to the route guard. The guard accepts only a synchronous
response with `approved: true`, the exact digest, `scope: "once"`, and an
unexpired envelope. Missing callbacks, promises, exceptions, wrong digests,
wrong scopes, expiry, and `deny` all abort the network request.

This callback is an in-process test adapter, not the proxy control-plane
simulator and not owner authentication. In approve mode it approves every
browser ask without judgment. A production browser flow needs either a
pre-authorized exact action or a design that freezes/revalidates the whole page
transaction around remote approval; it must not blindly park and resume a
request after mutable browser state has advanced.

## Operator guidance

### Authoring a policy

1. Inventory the credential and its mandatory domain allowlist.
2. Derive the exact agent principal from its Agent ID public key.
3. Start with `onUnmatched: "deny"` and explicit denies for security settings,
   account recovery, credential export, and funds transfer.
4. Add observational capabilities as `allow` only where the service contract is
   known. Treat mutating GET endpoints as writes despite the legacy read model.
5. Add irreversible or externally visible actions as `ask`: sending messages,
   submitting forms, purchasing, publishing, deleting, transferring, and
   changing account state.
6. Add typed JSON constraints and bounded preview fields for recipients, totals,
   currency, merchant, attachment count, destinations, and recurring terms.
   Use a versioned adapter where the wire format is not directly inspectable
   JSON.
7. Install the policy with `set-capabilities`. The vault assigns version 1 and
   increments the active epoch or retained epoch tombstone; caller-supplied
   version/epoch values are ignored.
8. Exercise allow, deny, ask/approve, ask/deny, timeout, stale epoch, wrong
   principal, digest mismatch, and concurrent identical actions before rollout.

The vault validator rejects malformed policy. Do not edit `vault.enc` directly.
Prefer a reviewed file over inline agent-generated JSON:

```bash
agent-id-vault set-capabilities \
  --name work-api \
  --policy-file examples/capability-policy.example.json

# Inline JSON is supported for controlled fixtures:
agent-id-vault set-capabilities --name work-api --policy '{...}'

# Removing policy is explicit:
agent-id-vault set-capabilities --name work-api --clear-policy
```

Exactly one of `--policy-file`, `--policy`, or `--clear-policy` is required.
Every actual replacement or removal—including an apparent tightening—opens the
secure owner form, shows the canonical hash and complete validated,
epoch-assigned policy JSON (including
every grant, matcher, constraint, value, priority, and validity bound), and
requires the owner to type the credential name. The form never truncates
permissive grants. Invalid closed-schema input fails before that ceremony. The
displayed JSON uses ordinary object key order; it is complete but is not the
canonical byte serialization used to calculate the hash. The proposed
permission-plan UI replaces JSON as the primary consent surface while retaining
it under Advanced and audit views.
vault overwrites the input's `version` with 1 and sets the
next epoch to one greater than the active policy epoch or
`capabilityPolicyEpoch` tombstone, whichever is larger. This prevents epoch
reuse through supported mutation paths and prevents caller-chosen future
epochs. Clear also increments
`capabilityPolicyEpoch` and leaves it on the record as a tombstone; clearing a
missing policy is an error. Existing credential
overwrite paths preserve both an attached policy and its epoch marker instead
of silently dropping them. Removing a capability-managed credential is also
owner-confirmed and advances its tombstones. Overwriting the entire vault with
`import --overwrite` requires a separate `OVERWRITE VAULT` owner ceremony.

The local proxy authenticates and reloads `vault.enc` with its already-held
master key at request entry, after an approval, and immediately before
credential materialization. A changed, cleared, or newly attached policy makes
an in-flight action fail with a stale-policy conflict; the caller must retry
under the new generation. It does not expose the master key or require another
unlock ceremony for the reload. The vault uses compare-and-swap saves under an
owned filesystem lock so a supported stale writer cannot silently overwrite a
newer file. A running proxy also keeps process-lifetime high-water marks for
policy epochs and credential revisions. Neither mechanism detects restoration
of a complete, valid old vault before a new proxy starts. A persistent browser
session still holds the policy supplied when it opened, so close and reopen it
after a policy change. Push revocation, durable anti-rollback state, and an
atomic policy/commit transaction remain requirements for the Frame deployment.

### Recommended decision posture

| Action | Recommended decision |
|---|---|
| Read mail or list orders | `allow`, scoped to the intended principal and service |
| Create a local draft or cart | `allow` with destination/item constraints |
| Send email or submit a form | `ask` for every exact payload |
| Purchase | `ask`, binding merchant, line items, final total, currency, delivery address, and recurring terms |
| Change password, MFA, recovery, or sessions | `deny` |
| Export credentials or private keys | `deny` |
| Transfer funds or sign arbitrary payloads | `deny` unless a specialized constrained adapter and approval flow exists |

## Threat model

### In scope

| Threat | Required defense |
|---|---|
| Prompt-injected or compromised agent attempts a forbidden action | Principal-scoped policy at the credential-holding enforcement point. |
| Another authenticated agent tries to reuse a grant | Canonical JKT principal binding at the Frame channel; the local single-agent broker does not provide per-caller authentication. |
| Request changes after the owner approves | Exact action digest recomputed immediately before release. |
| Approval replay | Fresh nonce, short expiry, atomic single-use consumption, request-specific ID. |
| Policy changes while a request waits | Epoch, policy hash/version, credential binding, reload, and re-evaluation; stale approval denied. |
| Two devices or requests race | Registry settlement and approval consumption are atomic; first valid settlement wins. |
| Opaque or malformed operation evades classification | Adapter rejects ambiguity; unmatched policy fails closed. |
| Agent redirects credential use to an attacker | Credential domain allowlist, capability host match, TLS verification, and SSRF guard all apply. |
| Approval UI could hide important parameters | Generic transport identity plus policy-selected JSON preview; a trusted adapter/policy must expose every final human-relevant value for irreversible actions, while the digest still commits all bytes. |
| Credential leaks into the agent transcript | Decision precedes injection; pending entries and logs contain metadata/digests, never credential values. |

### Out of scope or residual in the local development build

- A root attacker, compromised proxy/browser process, debugger, or arbitrary
  read of process memory can bypass policy or recover live credentials.
- The local simulator token is accessible to a malicious process running as the
  same OS user. It simulates interaction, not phone independence.
- Local data-plane callers are not individually authenticated. Every process
  that can reach one broker inherits the broker's configured Agent ID principal.
- Policy cannot control a credential copied outside the vault or an alternative
  unbrokered browser/CLI session. Deployment needs egress/tool isolation as well
  as credential isolation.
- The encrypted vault's epoch/revision tombstones can be rolled back together
  with the complete file across process restart. Compare-and-swap saves block
  supported stale writers and a live broker detects decreasing high-water
  marks, but durable rollback resistance requires non-rollbackable Frame state.
- The final local policy check and upstream commit are separate operations. A
  filesystem policy update in that small interval cannot be made atomic with a
  remote HTTP request; the Frame needs an atomic authorization/commit boundary.
- A process or host crash after an OAuth provider accepts a single-use refresh
  token but before its returned successor is durably merged can still strand
  that credential. Successful local writes fsync the file and parent directory,
  and live brokers serialize the chain, but only a provider-idempotent protocol
  or Frame-coordinated transaction can close the response-to-commit crash gap.
- Reloaded decrypted payloads are left for JavaScript garbage collection so an
  in-flight request's objects are not mutated underneath it. Idle lock wipes the
  active payload and master key, but the local runtime cannot guarantee prompt
  zeroization of those superseded heap objects.
- A wrong or malicious semantic adapter can mislabel an action. Adapter code and
  version are part of the trusted computing base and eventually the Frame
  measurement.
- The broker cannot prevent a service from violating its documented HTTP
  semantics, mutating on GET, changing a purchase after authorization, or
  applying server-side state not represented in the request. Use prepare/
  preview/commit APIs and signed receipts where available.
- Response confidentiality and data-exfiltration control are separate policy
  problems. Allowing a read can expose data that the agent later sends through
  another allowed channel.
- Availability is not guaranteed. Offline approval, timeout, vault lock, or
  Frame unavailability intentionally denies or leaves the action uncommitted.

## Proxy enforcement and limitations

The URL-rewrite proxy is the primary v1 enforcement point. It buffers a bounded
body for capability-controlled mutating requests, evaluates the policy, parks
the original request on `ask`, re-evaluates after approval, and injects the
credential only after authorization.

The CLI derives the principal from its Agent ID main public key and appends
capability decisions to the existing signed, hash-chained audit trail. It never
accepts a principal from a request header. Embedders calling `createProxy`
directly are responsible for supplying a trusted `principal` or
`resolvePrincipal` and a fail-closed `capabilityAudit` sink.

Important limits:

- HTTPS `CONNECT` is transparently tunneled without interception. Capability
  enforcement and credential injection cannot see actions inside that tunnel.
- Legacy `HTTP_PROXY` stub mode rejects any credential carrying a
  `capabilityPolicy`; capability-controlled integrations must use URL rewrite.
- Method/host/path/query matching is transport-level. JSON predicates can bind
  recipients, form fields, totals, and recurring terms only when the actual
  wire body is suitable JSON; encoded, multipart, opaque, or multi-step
  protocols need a trusted adapter.
- Requests larger than the broker's buffering limit cannot safely enter an
  exact approval flow and must fail closed or use a prepare/upload protocol.
  The current bound is 1 MiB.
- Capability-controlled wallet writes are refused with
  `capability_adapter_required`; generic HTTP approval cannot safely cover the
  transaction bytes that the signing path transforms. A versioned transaction
  adapter is required before enabling them.
- OAuth refresh and credential injection happen after authorization. A refresh
  request is broker infrastructure, not the agent's approved action, but must
  remain pinned to the credential's configured token endpoint. Local brokers
  serialize refresh-token chains per credential across processes, reload after
  acquiring that lease, and merge provider rotation into the newest vault
  revision. A vault lock immediately revokes data-plane use but permits an
  already-sent, time-bounded exchange to persist a returned next refresh token;
  it never caches or injects that access result after lock.
- An upstream redirect is not implicitly covered by the original approval.
- The current local data plane never trusts an agent-provided principal header,
  but it also does not authenticate individual callers: the CLI supplies one
  fixed main-key JKT for the broker. Production transport needs DPoP/mTLS or an
  equivalent authenticated channel bound to each Agent ID key.
- The proxy has no push watcher, but it performs an authenticated vault reload
  at request entry, after approval, and immediately before materialization.
  A generation change invalidates the in-flight action. The local file-backed
  check is not a substitute for the Frame's atomic policy/commit transaction.

## Sealed-browser enforcement and limitations

The sealed browser now evaluates `capabilityPolicy` alongside `ro`/`rw` and
`accessRules` at intercepted network requests, not at the visual widget. It
derives the principal from the Agent ID main key and commits the actual URL,
headers, and buffered post data. Missing principal, malformed policy, and
evaluation failure are converted to deny. Restricted sessions install the
guard while offline, block service workers and alternate realtime/worker
transports, destroy restored pre-guard page realms, create and verify a fresh
guarded realm, and only then enable network access. This is the correct boundary
for a submit button, but browser traffic is messier than a direct API:

- service workers are blocked for restricted profiles because they can answer
  or replay requests outside route inspection;
- WebSockets, WebTransport, WebRTC peer connections, workers, and shared workers
  are blocked because their writes cannot be classified by the HTTP route
  guard;
- `eval`, secret filling, OTP filling, and upload are refused for every
  access-restricted profile, including one restricted only by
  `capabilityPolicy`, where they would bypass or undermine the network policy;
- secret/OTP materializers also refuse a capability-restricted *target*
  credential even when the currently open profile itself is unrestricted;
- a single click can emit several requests, each of which needs its own decision;
- an interactive action reports a sanitized `BROWSER_POLICY_DENIED` or
  `BROWSER_APPROVAL_REQUIRED` result when a relevant same-page request is
  aborted. Feedback includes the verdict, reason, owner-reviewed grant labels,
  method/origin/path, and policy version/epoch/hash, but never query values,
  headers, body, preview, envelope, nonce, digest, or evaluator error text;
- action feedback uses a short, serialized, same-page correlation window and
  filters other tabs, assets, observational commands, and unmatched background
  GETs. It does not prove that an untrusted visual widget caused a particular
  request; busy applications can still require a site adapter to distinguish a
  user mutation from telemetry or a POST-tunneled read;
- form submissions may use redirects, hidden fields, beacons, iframes, workers,
  or dynamically computed values; the generic form adapter must commit the
  actual outgoing bytes, not a prior DOM snapshot;
- an `ask` continues only after the synchronous exact-once development callback
  succeeds; without it, the request aborts rather than parking or retrying; and
- cross-origin GET/query exfiltration and response-data policy are not solved by
  write authorization alone.

The browser simulator does not use a second device, pending registry, or signed
approval. There is no production remote-phone ask path yet, and browser
capability decisions are not yet appended to the proxy's signed capability
audit stream. Direct `ctx.request` traffic bypasses route interception; the
browser CLI's supported `fetch` path performs an explicit policy check, but
disables redirects and embedders must do the same for any other direct request
API. Restricted login credentials are not auto-materialized during auto-login;
perform the login manually in a headed session and attach the policy to the
resulting profile. A single click can
also generate multiple asks, each independently authorized by the development
auto-approver. A persistent session holds the policy supplied when it opened and
must be reopened after a vault policy change. These are development limitations,
not production approval semantics.

## Later deployment as an Alien Frame

The broker is designed so its decision kernel can move from the local Node
process into `alien-host` without changing policy meaning. Keep the following
properties portable now:

- canonical JSON and digest algorithms are specified, deterministic, and
  covered by cross-language test vectors;
- principal strings, policy documents, semantic action attributes, and decision
  receipts are language-neutral values;
- the decision kernel has no dependency on the local filesystem, CLI state, or
  approval UI;
- adapters are versioned and their code identity is included in the attested
  measurement and decision receipt; and
- time, nonce generation, policy lookup, audit append, and approval transport
  are explicit injected services.

The Frame-hosted design should add:

1. an enclave vault slot sealed to an attested Frame key;
2. DPoP or mTLS authentication of every calling agent principal;
3. verified policy provisioning with monotonic epoch/revocation handling;
4. an approval channel where the Alien app verifies the Frame attestation,
   policy hash, adapter measurement, exact action digest, and freshness;
5. atomic budget reservation and one-use approval consumption inside the Frame;
6. signed decision/commit receipts carrying principal, credential identifier,
   capability, grant, policy hash/epoch, action digest, outcome, upstream
   receipt identifier, Frame measurement, and approver identity; and
7. key zeroization, idle lock, rollback protection, and fail-closed recovery.

Attestation proves which code and policy made a decision; it does not make a
bad policy or adapter safe. The phone must verify an auditor-approved
measurement and current policy hash before approving. The Frame must verify the
phone/owner response and recompute the action digest before committing.

## Verification checklist

- Policy validation rejects unknown versions, malformed principals, duplicate
  grant IDs, invalid time windows, invalid matchers, and ill-typed constraints.
- Resolution tests cover priority and `deny > ask > allow` ties.
- Wildcard and exact-principal behavior is explicit and tested.
- Unmatched behavior covers all three modes; production fixtures use `deny`.
- Approvals fail for changed body, query, relevant headers, credential,
  principal, grant, adapter version, epoch, nonce, expiry, and request ID.
- One approval releases exactly one upstream request under races and duplicate
  responses.
- Deny, timeout, shutdown, vault lock, and policy reload cancel parked requests.
- Logs, pending APIs, errors, and receipts never contain credential material or
  raw sensitive bodies.
- Proxy and browser tests prove no credential materialization or route continue
  occurs before `allow` or a verified exact approval.
- Frame test vectors reproduce the Node principal, canonical envelope, policy
  hash, and action digest byte-for-byte.
