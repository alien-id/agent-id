# Changelog

All notable changes are documented here.

## [3.0.2] — 2026-05-12

Patch release. No runtime behavior change. Documentation cleanup and version-stamp bump.

### Documentation

- Trimmed `docs/` to the two user-facing references: `AGENT-SSO.md` (system overview) and
  `INTEGRATION.md` (service-side integration guide). Removed `MIGRATION-DPOP.md`,
  `RELEASE-NOTES.md`, and `TESTING.md` — none were linked from the top-level navigation and the
  3.0.x release content lives in this file now.
- Rewrote `docs/AGENT-SSO.md` to drop residual v2 "owner binding" prose; the SSO-signed
  `id_token` (with `cnf.jkt`, RFC 7800 §3.1) is the chain attestation in v3.
- Converted ASCII diagrams in `docs/AGENT-SSO.md` and `docs/INTEGRATION.md` to Mermaid.
- Fixed Mermaid parse errors: sequence-diagram messages and flowchart edge labels no longer
  embed `<br/>` (GitHub's Mermaid lexer interprets it as a NEWLINE token mid-arrow). Flowchart
  node labels still use `<br/>` where appropriate.
- Restored the README's original centered-logo HTML header (`<p align="center">` / centered
  `<h1>` / centered tagline) that a prior pass had converted to plain markdown.
- Fact-checked claims against `skills/alien-agent-id/lib.mjs` and `cli.mjs`: corrected the
  `examples/demo-service.mjs` size reference, fixed a stale cross-repo path in `INTEGRATION.md`,
  and aligned the file-layout table in `AGENT-SSO.md` with the actual `skills/alien-agent-id/`
  tree.

### Why a 3.0.2 instead of re-stamping 3.0.1

The `v3.0.1` tag on origin points at an orphaned commit because a GitHub tag-protection rule
blocked the rewrite when the underlying commit was re-signed. `3.0.2` cleanly supersedes it
with the same intended content plus the doc cleanup above.

## [3.0.1] — 2026-05-12

Patch release. No runtime behavior change.

- Synced plugin and skill manifest versions with `package.json` and the git tag.
  `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, and
  `skills/alien-agent-id/SKILL.md` were still stamped `2.2.0` after the 3.0.0 cutover, which
  would have shown the wrong version in the Claude Code marketplace.
- Dropped internal-only pre-cutover docs from the repo: `COMPLIANCE.md`, `REFACTOR-PLAN.md`,
  `REVIEW-PLAN.md`, `PRD-DPOP-POP.md`, `DEPLOY-DPOP.md`. None of these were linked from
  `README.md` or any user-facing surface; they were planning snapshots for the 3.0 cutover work.
- Added `.DS_Store` to `.gitignore`.
- Added this `CHANGELOG.md`.

## [3.0.0] — 2026-05-11

Breaking. Agent-driven authentication cut over to DPoP-bound tokens (RFC 9449 + RFC 7800).
Pre-3.0 commits stop verifying because their `id_tokens` lack the `cnf.jkt` confirmation claim
the new verifier requires — by design; pre-cutover `id_tokens` are forgery primitives.

### Added

- `cnf.jkt` binding between agent keypair and SSO `id_token`.
- `/.well-known/alien-agent-id.json` service-manifest discovery (v1 schema, hardened fetch,
  same-authority enforcement).
- v3 commit-attestation bundle in `refs/notes/agent-id` — the SSO `id_token` is the chain;
  the agent-self-signed `ownerBinding` envelope is gone.
- Commit trailers `Agent-ID-JKT` and `Agent-ID-Owner` (replace `Agent-ID-Fingerprint` and
  `Agent-ID-Binding`).
- Library exports: `createDPoPProof`, `getUserInfo`, `ed25519PublicKeyToJwk`, service-manifest
  helpers, typed `AuthRevokedError` and `SubjectMismatchError`.

### Changed

- Wire scheme on the service edge is RFC 9449: `Authorization: DPoP <access_token>` plus
  `DPoP: <proof>`. The custom `Authorization: AgentID` envelope is gone.

### Removed

- Library surface: `verifyProofChain`, `ChainError`, `verifyOwnerBindingRecord`,
  `paths.ownerBinding`, `SessionEngine.ownerBinding` / `loadOwnerBinding` / `hasOwnerBinding` /
  `getOwnerBinding`, `decodeProofIdToken`, `createAgentToken`.
- Human "Sign in with Alien" flows are unchanged.

## Earlier versions

See git tags `v2.3.0` and earlier. Pre-3.0 release notes were not maintained in-repo.
