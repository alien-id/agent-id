# Deploy Runbook: DPoP + cnf.jkt cutover

**Audience:** SSO operators and Agent-ID operators rolling out the
3.0.0 release.
**Companion docs:** [MIGRATION-DPOP.md](MIGRATION-DPOP.md),
[RELEASE-NOTES.md](RELEASE-NOTES.md), [PRD-DPOP-POP.md](PRD-DPOP-POP.md).

The cutover is a coordinated two-repo deploy. The order below is **load
bearing** — flipping any step out of order can either expose a clientele to
a server returning 4xx on capabilities it advertises, or produce
silently-unverifiable commits.

## Server-side deploy order (alien-id/sso)

Roll the SSO repo to your environment in this exact sequence. Each step is
safe to deploy independently and is a no-op for plain Bearer clients.

1. **Apply migrations.** Both are additive (a nullable column add and a new
   replay-tracking table). Safe online, no backfill required, no lock on the
   hot path.
   - `000010_dpop.up.sql` / `000010_dpop.down.sql` — adds nullable
     `oauth_sessions.dpop_jkt TEXT` and creates the `dpop_jti_seen`
     replay-protection table with `jti TEXT PRIMARY KEY` and an index on
     `expires_at`.
   - `000011_dpop_refresh_tokens.up.sql` /
     `000011_dpop_refresh_tokens.down.sql` — adds nullable
     `refresh_tokens.dpop_jkt TEXT` so that DPoP-bound sessions can carry
     their `cnf.jkt` across refresh per RFC 9449 §5. Pre-existing refresh
     tokens have `dpop_jkt = NULL` and continue to work as plain Bearer.

2. **Deploy `service.DPoPVerifier` and the `JWTService` cnf extension.**
   The verifier is a single deep module exposing `VerifyProof(httpMethod,
   httpURI, dpopHeader) → (thumbprint, error)`. The `JWTService` change
   adds an optional `cnfJkt` parameter to `CreateIDToken` /
   `CreateAccessToken`. Both are observable only when called by upstream
   handlers, so this step is a no-op for live traffic until step 3 lands.

3. **Deploy the authorize / token / userinfo handler updates.** This wires
   the verifier and the cnf-aware JWT service into the OAuth flows:
   `/oauth/authorize` accepts `dpop_jkt`, `/oauth/token` requires DPoP for
   DPoP-bound sessions, `/oauth/userinfo` requires fresh DPoP for
   DPoP-bound access_tokens. After this step, agent CLIs that send
   `dpop_jkt` will receive cnf-bearing id_tokens; agent CLIs that do not
   continue to receive cnf-less id_tokens (which the new verifier rejects,
   but that is the intended forcing function for re-bind).

4. **Update OIDC discovery last.** Only after steps 1–3 are fully live
   should `/.well-known/openid-configuration` be updated to advertise
   `dpop_signing_alg_values_supported: ["EdDSA"]` and add `cnf` to
   `claims_supported`. Updating discovery before the server can actually
   honor DPoP causes capability negotiation to lie to clients — automated
   OIDC clients will attempt DPoP and receive 4xx from a code path that
   does not yet exist.

The session cleaner extension (GC for `dpop_jti_seen` rows past
`expires_at`) ships with step 2 and runs on the existing background
schedule. No operator action required.

## Agent-side deploy order (alien-id/agent-id)

5. **Cut the alien-agent-id 3.0.0 release.** This release contains the
   `lib.mjs` JWK / DPoP helpers, the `cli.mjs` wiring through
   `cmdAuth` / `cmdBind` / `cmdRefresh`, and the `cmdGitVerify` cnf
   enforcement check. Ship it **after** the SSO is fully live (steps 1–4
   complete) in the target environment.

6. **Operators run `setup-owner-session`.** Each operator runs the rebind
   exactly once per environment (see
   [MIGRATION-DPOP.md](MIGRATION-DPOP.md) for the user-facing
   procedure). Existing Ed25519 keypair and SSH signing key are preserved;
   GitHub re-registration is not required. The new
   `owner-binding.json` and `owner-session.json` carry the cnf
   commitment.

Operators should not run `setup-owner-session` against an environment
where the SSO has not yet completed step 3 — the resulting
`owner-session.json` would carry a cnf-less id_token, and the agent's own
`git-verify` would reject every commit they produce.

## Compatibility properties this ordering preserves

- **Plain Bearer OAuth clients** see no observable change at any step.
  Provider redirect flows that do not pass `dpop_jkt` at authorize
  produce byte-identical tokens to today, and `/oauth/userinfo` for plain
  Bearer ATs is unchanged.
- **Legacy `/sso/*` miniapp endpoints** are untouched throughout. Different
  handler tree, different token format, different keys. No coordinated
  migration with miniapps is required.
- **Existing pre-deployment refresh tokens** stay plain Bearer: their
  `refresh_tokens.dpop_jkt` is NULL. Only refresh tokens issued after
  migration `000011` is live and after a DPoP-bound authorize+token flow
  inherit the binding.

## Rollback

If a problem surfaces during the SSO rollout, the safe rollback is the
inverse of the deploy order: revert handlers (step 3), revert the verifier
and JWT extension (step 2), then revert migrations (step 1) only if
absolutely necessary. The migrations are additive and can stay in place
indefinitely with no observable effect — leaving them applied makes
re-attempting the rollout cheaper.

The agent CLI 3.0.0 release cannot be partially rolled back per-operator
once an operator runs `setup-owner-session` against a DPoP-capable SSO,
because the new `owner-binding.json` carries the cnf commitment. To
downgrade an individual operator, restore their `~/.agent-id/` from
backup taken before the rebind. The 3.0.0 verifier will not accept the
restored cnf-less binding; you would also need to downgrade the CLI to
2.x for that machine.

## Verification after deploy

- `curl https://<sso>/.well-known/openid-configuration | jq .dpop_signing_alg_values_supported`
  should return `["EdDSA"]`.
- `node skills/alien-agent-id/cli.mjs git-verify --commit <fresh-commit>`
  should produce `id_token cnf.jkt binds agent key <prefix>...` in the
  provenance trail.
- `node skills/alien-agent-id/cli.mjs git-verify --commit 3a70d8f7cb3d1d408b76ad15945a5898d6d877ce`
  (against a clone of `agent-id-forgery-poc` with notes fetched) must
  fail with `id_token missing cnf.jkt`. This is the regression fixture
  for the entire change.
