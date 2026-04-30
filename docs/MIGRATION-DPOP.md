# Migration Guide: DPoP + cnf.jkt Binding

**Applies to:** alien-agent-id 3.0.0 and later
**Audience:** existing operators upgrading from 2.x

## What changed and why

The Agent-ID protocol now binds the agent's Ed25519 keypair into the SSO
`id_token` itself via an [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800)
`cnf.jkt` confirmation claim. The claim carries the RFC 7638 JWK thumbprint of
the agent's public key, is signed by the SSO under RS256, and is enforced as a
mandatory check by the agent-side verifier. The bootstrap flow now uses
[RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449) at `/oauth/authorize`
and `/oauth/token` so the SSO learns and commits to the agent's keypair before
issuing an id_token. This closes the publish-and-replay attack class
demonstrated by the [agent-id-forgery-poc](https://github.com/truehazker-eti/agent-id-forgery-poc):
previously, anyone who could read a public repository could lift a victim's
`id_token` from a proof note and pair it with their own Ed25519 keypair to
produce a forged commit that passed `git-verify` end-to-end. After this change
an `id_token` is useless without the matching private key, and forgery is
reduced to private-key compromise — the assumed-out-of-scope baseline of every
signature-based protocol.

## Rebind procedure for existing operators

1. **Upgrade the CLI to the new version.**
   ```bash
   npm install -g alien-agent-id@^3.0.0
   ```
   Or, for skill-installed deployments, re-run `npx skills add alien-id/agent-id`.

2. **Run `setup-owner-session` once.**
   ```bash
   /alien-agent-id setup-owner-session
   ```
   This walks through `auth` and `bind` against the new SSO. The existing
   Ed25519 keypair under `~/.agent-id/keys/main.json` is preserved. The
   existing SSH signing key under `~/.agent-id/ssh/` is preserved. **GitHub
   re-registration is NOT required** — the SSH public key on your GitHub
   account is unchanged. The new binding overwrites
   `~/.agent-id/owner-binding.json` and `~/.agent-id/owner-session.json`
   with artifacts that carry the `cnf.jkt` commitment.

3. **Re-attach a fresh proof note to HEAD of working repositories.**
   ```bash
   node skills/alien-agent-id/cli.mjs git-commit --message "chore: refresh agent-id proof note" --allow-empty
   git push origin refs/notes/agent-id
   ```
   Every commit you make from this point forward carries a `cnf`-bearing
   id_token in its proof note and verifies cleanly against the new verifier.

## Back-filling history

Old commits whose proof notes carry pre-cutover (cnf-less) id_tokens **become
unverifiable under the new verifier**. This is the intended behavior — every
cnf-less id_token is a live forgery primitive, not a historical artifact, and
no `--allow-legacy` mode exists by design (see
[Release Notes](RELEASE-NOTES.md) and [PRD-DPOP-POP](PRD-DPOP-POP.md)).

You have two options:

**Option A — back-fill notes for selected commits.** For commits you authored
yourself and want to keep verifiable, you can re-attach a fresh proof note
that points the cnf-bearing id_token at the same commit hash:

```bash
# After running setup-owner-session above, for each commit you want to back-fill:
node skills/alien-agent-id/cli.mjs git-attach-proof --commit <hash>
git push origin refs/notes/agent-id
```

The replacement proof note proves provenance under the **new** keypair
binding. It does not retroactively prove that the historical commit was made
by that keypair — only that you, holding the private key today, vouch for it
now. Treat back-filled notes as a soft attestation, not a cryptographic
time-travel guarantee.

**Option B — accept that pre-cutover commits are unverifiable.** This is the
honest answer for most repositories. `git-verify` will fail on those commits
with `id_token missing cnf.jkt`. The signed history remains intact in git;
only the agent-id provenance overlay no longer verifies. New commits on top
of old history verify normally.

There is no third option. We do not ship a verifier mode that accepts
cnf-less id_tokens, because such a mode would silently re-enable the
publish-and-replay forgery class for any environment that toggled it on.

## Regression fixture

The PoC repository [github.com/truehazker-eti/agent-id-forgery-poc](https://github.com/truehazker-eti/agent-id-forgery-poc)
demonstrates the original vulnerability against an unfixed verifier. The
forged commit `3a70d8f7cb3d1d408b76ad15945a5898d6d877ce` is now a regression
fixture: it must fail `git-verify` under the new verifier with
`id_token missing cnf.jkt`. If you maintain a fork of this project, run
`git-verify` against that commit as part of your verifier acceptance suite.

## Operator deploy ordering

See [DEPLOY-DPOP.md](DEPLOY-DPOP.md) for the full server-side and agent-side
deploy ordering. In short: SSO must be fully live in your environment before
operators run `setup-owner-session`.

## Related documents

- [RELEASE-NOTES.md](RELEASE-NOTES.md) — full breaking-change list and stable error strings.
- [DEPLOY-DPOP.md](DEPLOY-DPOP.md) — operator runbook for the server + CLI rollout.
- [PRD-DPOP-POP.md](PRD-DPOP-POP.md) — design rationale and threat model.
