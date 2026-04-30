# SSO: OIDC discovery advertises DPoP + cnf

**Type:** AFK
**Repo:** `alien-id/sso`
**Source PRD:** [docs/PRD-DPOP-POP.md](../PRD-DPOP-POP.md)

## Parent

PRD: RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

## What to build

Update `handler.OIDCDiscoveryHandler` (`/.well-known/openid-configuration`) to honestly advertise the new DPoP + cnf capability now that authorize, token, refresh, and userinfo support it. Add `dpop_signing_alg_values_supported: ["EdDSA"]` and add `cnf` to `claims_supported`.

Per the PRD's deploy-safe ordering, this slice must ship **after** the server actually supports DPoP end-to-end (issues #1, #2, #3). Otherwise capability negotiation lies to clients and they will receive 4xx from a not-yet-deployed code path.

## Acceptance criteria

- [ ] `GET /.well-known/openid-configuration` response includes `dpop_signing_alg_values_supported: ["EdDSA"]`.
- [ ] Response's `claims_supported` array includes `cnf`.
- [ ] No other discovery field changes shape or semantics; existing fields remain byte-identical (modulo JSON key ordering tolerance).
- [ ] Existing discovery handler tests pass; a new test asserts the two additions above.
- [ ] Deploy ordering is documented in the release notes / runbook: this change ships after #1, #2, #3 are live in the target environment.

## Blocked by

- Blocked by #1 (DPoP-bound authorize+token).
- Blocked by #2 (DPoP-bound userinfo).
- Blocked by #3 (DPoP on refresh-token grant).
