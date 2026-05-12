## [3.0.1] — 2026-05-12

Patch release. No runtime behavior change.

- Synced plugin / skill manifest versions with `package.json` and the git tag. `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, and `skills/alien-agent-id/SKILL.md` were still stamped `2.2.0` after the 3.0.0 cutover, which would have shown the wrong version in the Claude Code marketplace.
- Dropped internal-only pre-cutover docs from the repo: `docs/COMPLIANCE.md`, `docs/REFACTOR-PLAN.md`, `docs/REVIEW-PLAN.md`, `docs/PRD-DPOP-POP.md`, `docs/DEPLOY-DPOP.md`. None of these were linked from `README.md` or any user-facing surface; they were planning snapshots for the 3.0 cutover work.
- `docs/TESTING.md`: corrected L1 test count (115 → 158) and removed a dangling link to the deleted deploy doc.
- Added `.DS_Store` to `.gitignore`.
- Added this `CHANGELOG.md`.

## [3.0.0] — 2026-05-11

**Breaking.** Agent-driven authentication cut over to DPoP-bound tokens (RFC 9449 + RFC 7800). Pre-3.0 commits stop verifying because their `id_tokens` lack the `cnf.jkt` confirmation claim the new verifier requires — by design; pre-cutover `id_tokens` are forgery primitives.

- New: `cnf.jkt` binding between agent keypair and SSO id_token.
- New: `/.well-known/alien-agent-id.json` service-manifest discovery channel (v1 schema, hardened fetch, same-authority enforcement).
- New: v3 commit-attestation bundle in `refs/notes/agent-id` (drops the agent-self-signed `ownerBinding` envelope; the SSO id_token IS the chain).
- New trailers: `Agent-ID-JKT`, `Agent-ID-Owner` (replaces `Agent-ID-Fingerprint`, `Agent-ID-Binding`).
- Wire scheme: RFC 9449 `Authorization: DPoP <access_token>` + `DPoP: <proof>`. The custom `Authorization: AgentID` envelope is gone.
- Library surface deletions: `verifyProofChain`, `ChainError`, `verifyOwnerBindingRecord`, `paths.ownerBinding`, `SessionEngine.{ownerBinding,loadOwnerBinding,hasOwnerBinding,getOwnerBinding}`, `decodeProofIdToken`, `createAgentToken`.
- Library surface additions: `createDPoPProof`, `getUserInfo`, `ed25519PublicKeyToJwk`, service-manifest helpers, typed `AuthRevokedError` / `SubjectMismatchError`.
- Human "Sign in with Alien" flows are unchanged.

Full prose release notes: [`docs/RELEASE-NOTES.md`](docs/RELEASE-NOTES.md). Migration guide: [`docs/MIGRATION-DPOP.md`](docs/MIGRATION-DPOP.md).

## Earlier versions

See git tags `v2.3.0` and earlier. Pre-3.0 release notes were not maintained in-repo.
