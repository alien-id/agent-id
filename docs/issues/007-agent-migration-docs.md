# agent-id: re-bind migration docs and release notes

**Type:** AFK
**Repo:** `alien-id/agent-id`
**Source PRD:** [docs/PRD-DPOP-POP.md](../PRD-DPOP-POP.md)

## Parent

PRD: RFC 9449 DPoP + RFC 7800 PoP for Agent-ID

## What to build

Operator-facing documentation for the hard cutover. Existing agents must re-run `setup-owner-session` once after upgrading to obtain a `cnf`-bearing id_token; the existing agent keypair is preserved (no SSH rotation, no GitHub re-registration). The new binding overwrites the old `owner-binding.json`. Old commits with cnf-less proof bundles fail verification — this is the intended outcome.

Deliverables:

- **Migration guide** under `docs/` (or extending `docs/INTEGRATION.md`) covering: upgrade the CLI → run `setup-owner-session` once → re-attach a fresh proof note to head. Include a documented procedure for back-filling history if a maintainer wants past commits to verify under the new chain.
- **Release notes** for the CLI release explicitly listing this as a **breaking** verifier change: id_tokens without `cnf.jkt` are hard-rejected; no opt-out flag exists.
- **Cross-link** to the PoC repository `https://github.com/truehazker-eti/agent-id-forgery-poc` and a one-line statement that the PoC commit `3a70d8f7cb3d1d408b76ad15945a5898d6d877ce` is now a regression fixture.
- **Server-deploy ordering note** for operators running both `alien-id/sso` and `alien-id/agent-id`: SSO ships first (issues #1–#4), then the agent CLI release (issues #5–#6). Re-binding is run only after the SSO side is live in the target environment.

## Acceptance criteria

- [ ] Migration guide states the rebind procedure in numbered steps and is linkable from the CLI release notes.
- [ ] Migration guide explicitly notes: SSH key preserved, GitHub re-registration not required, `owner-binding.json` overwritten in place.
- [ ] Migration guide documents the back-fill procedure for re-attaching proof notes to historical commits, and is honest about the alternative (those commits become unverifiable).
- [ ] Release notes call the verifier change BREAKING and state there is no `--allow-legacy` mode by design.
- [ ] Deploy ordering (SSO first, agent CLI second; discovery doc shipped after SSO handlers) is recorded in the runbook / release notes so coordinated rollouts do not invert the order.
- [ ] PoC repo and forged commit hash are referenced as the regression fixture.

## Blocked by

- Blocked by #4 (SSO: OIDC discovery advertises DPoP + cnf) — discovery doc is the last server-side step.
- Blocked by #5 (agent-id: CLI bootstrap + refresh emit DPoP) — migration steps cite CLI behavior.
- Blocked by #6 (agent-id: cmdGitVerify enforces cnf check) — release-notes BREAKING statement describes this verifier behavior.
