# VCT URIs — Alien Verifiable Credential Type Registry

> **Status: DRAFT / strawman.** This is a starting point for the platform
> team to redline. Nothing here is committed until it lands as non-draft and
> a Phase C implementation references it.

## What this is

When [Phase D](./ROADMAP.md#phase-d--selective-disclosure) ships SD-JWT-VC,
every credential the SSO mints carries a [`vct` claim][vct] naming its type.
Verifiers dispatch on `vct` to decide which claims to expect, what they
mean, and how to validate them.

This document is the registry of `vct` URIs Alien issues. Each entry pins:

- The URI itself (stable identifier; humans can resolve it to docs).
- The claim schema (names, types, semantics, freshness regime).
- The attestation source (which `enclaved-*` service produced the underlying
  evidence).
- Versioning policy.

[vct]: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/

## Conventions

### URI scheme

```
https://alien.org/credential/<bundle>/<version>
```

- **Scheme**: `https://`. Human-resolvable. The URI MUST resolve to the
  credential's [type-metadata document](#type-metadata) once that's hosted.
- **Authority**: `alien.org`. Matches our public-facing domain; not coupled
  to any single service host (avoids the `sso.alien-api.com` trap where
  retiring an SSO instance would invalidate every issued credential).
- **Path `/credential/`**: literal. Reserves the URL prefix for credential
  type definitions. Avoids collision with `/skill/`, `/api/`, etc.
- **`<bundle>`**: short kebab-case noun grouping claims by *natural privacy
  boundary*. Claims that are always disclosed together belong in the same
  bundle. Bundles are NOT how SD-JWT-VC selective disclosure works
  internally (that's per-claim) — they're how *we* group claims so the
  consent surface (Phase B) shows humans coherent permission requests.
- **`<version>`**: `v1`, `v2`, ... Major-version-only. Adding optional
  claims is additive within a version; removing claims, changing claim
  types, or changing semantics requires a version bump.

### Granularity rule

One `vct` per natural privacy boundary, not per individual claim. Rule of
thumb: **if asking a human "may Service X see Y?" requires distinct yes/no
answers, Y belongs in its own `vct`**. Identity-level claims (passport,
name, document expiry) all rise or fall together in a consent decision —
one `vct`. Coarse geo is a separate decision — its own `vct`. Age band
likewise.

Aim for 3–5 active `vct`s in the steady state. More than that and the
consent UI becomes a checkbox forest no human reads.

### Selective disclosure within a `vct`

SD-JWT-VC selectively discloses *individual claims* within a credential
([SD-JWT-VC §4][sd-jwt-vc-disclosure]). So the agent calling Service A
holding an `identity/v1` credential can disclose just `passport_country`
without revealing `given_name` or `date_of_birth`. The bundling is for
human consent and verifier dispatch; SD-JWT-VC handles per-claim hiding
inside.

[sd-jwt-vc-disclosure]: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/

### Freshness regimes

Three regimes (from [ROADMAP Phase C](./ROADMAP.md#phase-c--verified-attributes)):

- **`permanent`** — verify once, never refresh unless the underlying fact
  changes. Examples: `passport_country` (changes only on naturalization);
  `date_of_birth` (immutable).
- **`decaying`** — embed `verified_at`; consumer policy decides max age.
  Auditor concern, not freshness concern. Examples: identity verifications
  (consumer may require ≤90 days old); contact-channel verifications.
- **`session`** — populated at request time; never embedded in the
  long-lived id_token. Lives in the access token or per-call userinfo.
  Examples: `geo.country` (IP changes per request).

Every claim in this registry MUST declare its regime in the schema below.

### Type metadata

Per [SD-JWT-VC §6.4][sd-jwt-vc-type-metadata], a `vct` URI SHOULD resolve
(via HTTPS GET, `Accept: application/vc+sd-jwt-tm+json`) to a type-metadata
document describing the credential's schema, display strings, and
display-locale variants. We don't have to host these Day 1, but the URIs
in this registry are designed to anticipate it. Once hosting is in place
the documents themselves are owned by the platform team and version-pinned
the same way as the URI.

[sd-jwt-vc-type-metadata]: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/

## Registry

### `https://alien.org/credential/identity/v1`

Document-grade human identity. The most sensitive bundle; consent gate
required.

**Attestation source**: `enclaved-passport-verifier` for document claims;
`facetec` for liveness binding the document to the person presenting the
session.

| Claim | Type | Freshness | Notes |
|---|---|---|---|
| `given_name` | string | `permanent` | Per ICAO 9303 — name as printed on the travel document. |
| `family_name` | string | `permanent` | Per ICAO 9303. |
| `date_of_birth` | string (ISO 8601 full-date) | `permanent` | `YYYY-MM-DD`. Selectively disclosable; in practice, derived bundles (`age-band`) are preferred. |
| `passport_country` | string (ISO 3166-1 alpha-2) | `permanent` | Issuing country of the document. |
| `document_type` | string (closed enum) | `permanent` | `passport`, `national_id`, `residence_permit`. |
| `document_expires_at` | string (ISO 8601 date) | `permanent` | Document expiry. Service consumer may reject if past. |
| `verified_at` | string (ISO 8601 date-time) | `decaying` | When `enclaved-passport-verifier` last attested this evidence. |
| `verified_by` | string (URI) | `permanent` | Stable identifier of the attesting service version. |
| `liveness_verified_at` | string (ISO 8601 date-time) | `decaying` | When liveness was last asserted by `facetec`. |

**Disclosure default**: when a service requests `vct=identity/v1` without
specifying claims, the agent SHOULD disclose `given_name`, `family_name`,
`passport_country`, `verified_at`, `verified_by`. Other claims require
explicit `requiredClaims` enumeration in the manifest.

### `https://alien.org/credential/age-band/v1`

Closed-enum age band. Avoids leaking date of birth when the service only
needs an over-/under-threshold check.

**Attestation source**: derived server-side from `identity/v1.date_of_birth`.
Issued only if an `identity/v1` credential is present in the owner's
session.

| Claim | Type | Freshness | Notes |
|---|---|---|---|
| `age_band` | string (closed enum) | `decaying` | One of `under_13`, `13-17`, `18-20`, `21-24`, `25-34`, `35-49`, `50-64`, `65_plus`. Bands chosen to align with regulatory thresholds (COPPA 13, US drinking 21, EU age-of-majority 18). Editable but a major-version bump if changed. |
| `verified_at` | string (ISO 8601 date-time) | `decaying` | When the underlying identity attestation was checked; the band itself is permanent for the human, but the attestation feeding it isn't. |
| `verified_by` | string (URI) | `permanent` | Same as identity. |

**Disclosure default**: full credential. The credential is already
minimum-disclosure by construction.

### `https://alien.org/credential/geo/v1`

Coarse geographic location. Per-session by design; never embedded in the
long-lived id_token.

**Attestation source**: SSO observation of the request's source IP, mapped
through a geo-IP database. Caveat: not a strong attestation — IP geo can
be VPN'd. Services requiring strong proof of presence need a dedicated
credential (out of scope for v1).

| Claim | Type | Freshness | Notes |
|---|---|---|---|
| `country` | string (ISO 3166-1 alpha-2) | `session` | Country of the request's source IP. |
| `region` | string (ISO 3166-2) | `session` | Sub-division (state/province) code. Optional. |
| `precision` | string (closed enum) | `session` | `country`, `region`, `city`. Indicates the precision the service is permitted to use for *this* disclosure — agent caps the precision per manifest's request. |
| `observed_at` | string (ISO 8601 date-time) | `session` | When the SSO observed the IP. |
| `attested_by` | string (URI) | `permanent` | Stable identifier of the geo-IP database version. Allows verifiers to weight or reject specific databases. |

**Per-call delivery**: `geo/v1` credentials are attached to userinfo
responses, not embedded in id_tokens. Agents call `/oauth/userinfo` on
each service call where the manifest declares `requiredClaims` covering
geo. The per-call cost is one DPoP-bound request to the SSO; the SSO
populates `observed_at` from the inbound request.

### `https://alien.org/credential/contact/v1`

Verified contact channels. Attests *that* a human controls a contact
channel without revealing the channel value.

**Attestation source**: `enclaved-phone-number-verifier` for phone;
TBD for email (the platform team picks: existing email-verifier service
or external SaaS).

| Claim | Type | Freshness | Notes |
|---|---|---|---|
| `phone_verified_at` | string (ISO 8601 date-time) \| null | `decaying` | When phone control was last asserted. `null` if never verified. |
| `phone_verified_by` | string (URI) \| null | `permanent` | Attesting service identifier; `null` if `phone_verified_at` is null. |
| `email_verified_at` | string (ISO 8601 date-time) \| null | `decaying` | Same pattern for email. |
| `email_verified_by` | string (URI) \| null | `permanent` | |

**Note on values.** The credential intentionally does NOT carry the
phone number or email address itself. Services that need the *value*
(e.g., to send a 2FA SMS) request it via a separate scope and a separate
credential type, gated by additional consent. This bundle answers
"is this person reachable on these channels" without leaking which
addresses they use.

## Adding a new `vct`

Lightweight process; no separate ADR per credential type:

1. **Open a PR** adding a section to this document mirroring the structure
   above. Include claim schemas with types, freshness regimes, and
   attestation sources.
2. **Platform-team review**: mostly a privacy review (does this bundle
   create a consent boundary that makes sense to a human?) and a
   schema-stability review (are these claims likely to remain stable for
   the lifetime of `v1`?).
3. **Land the PR before any implementation references the URI.** No code
   should ship a `vct` string that hasn't been approved here.

For breaking changes to an existing `vct`, bump the version (`v1` →
`v2`), keep the `v1` section in this document marked as legacy, and
provide a migration note. SSO mints both versions during the migration
window; verifiers accept both. Drop `v1` only after telemetry confirms
no live tokens reference it.

## Type-metadata hosting (deferred)

The URIs in this registry are designed to be live HTTPS resources, but
hosting the type-metadata documents is deferred until Phase D
implementation. Initial implementation can hard-code the schemas in the
verifier package; the URIs serve only as stable string identifiers
during the interim. Cut-over to live hosting is a documentation +
infrastructure task, not a protocol change.

## Open questions

These deserve platform-team attention before Phase C starts implementation:

1. **Does `identity/v1` carry the document number / MRZ data?** Including
   it allows downstream verifiers to cross-check against issuer revocation
   lists; excluding it is more privacy-preserving. Recommend: exclude
   from `v1`; if a regulatory requirement appears, ship `identity-strong/v1`
   as a separate credential.
2. **Does `age-band/v1` need a `country_specific_band` claim?** Drinking
   age, voting age, age of majority vary by jurisdiction. Recommend: no —
   bands are jurisdiction-neutral, services do their own threshold
   mapping. Adding country-specific bands creates a combinatorial
   maintenance burden.
3. **Is `geo/v1.region` opt-in for users?** Some users may be comfortable
   disclosing country but not region. Recommend: yes, treat `region` and
   `precision: city` as separate disclosure decisions in the consent UI.
4. **Should `contact/v1` carry channel values under a separate
   `requiredScope`?** I.e., is there an `alien:contact:read-values` scope
   that, when granted, lets the credential carry actual phone/email?
   Recommend: yes — a separate `vct` (`contact-values/v1`) keeps the
   privacy boundary cleaner than overloading `contact/v1` with
   conditionally-present claims.

Resolve these as part of the Phase C kick-off and update this document.
