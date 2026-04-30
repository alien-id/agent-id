# agent-id: cmdGitVerify enforces cnf check (PoC commit as regression fixture)

**Type:** AFK
**Repo:** `alien-id/agent-id`
**Source PRD:** [docs/PRD-DPOP-POP.md](../PRD-DPOP-POP.md)

## Parent

PRD: RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

## What to build

Add the cnf-binding check to the `cmdGitVerify` chain. After the existing checks (SSH sig → trailer fingerprint match → binding payload hash → binding signature → SSO RS256 sig on id_token), compute the JWK thumbprint of `binding.payload.agentInstance.publicKeyPem` and assert it equals `id_token.cnf.jkt`. **This check runs before any decision based on `id_token` claims** — including extraction of `sub` for the `Agent-ID-Owner` trailer — so the verifier never reasons about claims from an unbound token.

This is the link in the cryptographic chain that closes the publish-and-replay attack class. The verifier becomes a **hard-cutover** gate:

- Missing `cnf` claim on the id_token → hard reject with a specific error code/message identifying the missing-binding condition.
- `cnf.jkt` present but not equal to `jwkThumbprint(binding.payload.agentInstance.publicKeyPem)` → hard reject with a specific error code/message identifying the mismatch.
- No `--allow-legacy` flag, no warning level, no policy bypass. Per the PRD: every cnf-less id_token is a live forgery primitive, not a historical artifact.

The forged commit `3a70d8f7cb3d1d408b76ad15945a5898d6d877ce` from `https://github.com/truehazker-eti/agent-id-forgery-poc` is added to the test suite as a regression fixture and must fail verification under the new verifier.

## Acceptance criteria

- [ ] An id_token without the `cnf` claim → `git-verify` returns a non-zero exit, fails before reading any id_token claim, and emits a distinct error message identifying the missing-binding condition.
- [ ] An id_token with `cnf.jkt` matching `jwkThumbprint(binding.payload.agentInstance.publicKeyPem)` → verification continues through to `"ok": true` (assuming all other links pass).
- [ ] An id_token with `cnf.jkt` not matching that thumbprint → `git-verify` returns a non-zero exit and emits a distinct error message identifying the mismatch.
- [ ] The cnf check runs before `sub` is extracted from the id_token for any purpose (e.g., the `Agent-ID-Owner` trailer or any logged claim).
- [ ] No CLI flag, env var, or config option can suppress, downgrade, or skip this check.
- [ ] The PoC commit `3a70d8f7cb3d1d408b76ad15945a5898d6d877ce` (or a captured proof bundle equivalent to it) is added as a regression fixture under `tests/`, and the fixture is asserted to fail verification with the missing-cnf error.
- [ ] A positive fixture — a freshly bound commit produced via the updated bootstrap (issue #5) — is added and asserted to pass verification.

## Blocked by

- Blocked by #5 (agent-id: CLI bootstrap + refresh emit DPoP, capture cnf-bearing id_token) — the positive fixture requires an agent that produces cnf-bearing id_tokens. The verifier code itself can be drafted in parallel against hand-constructed fixtures; the round-trip assertion needs #5.
