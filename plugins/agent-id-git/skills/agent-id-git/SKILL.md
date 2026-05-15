---
name: agent-id-git
description: SSH-signed git commits with Alien Agent ID provenance trailers and a v3 proof note. Sign every line of agent-written code so it is cryptographically attributable to the agent + a verified human owner via Alien Network SSO. Verify provenance on any commit — your own or third-party — without needing the signer's local state. Use when the user asks to make a signed commit, push agent-signed work, check the Agent-ID chain on a commit, audit who signed a commit, or configure git for SSH-format signing with the bound agent key.
license: MIT
metadata:
  author: Alien Wallet
  version: "0.0.0"
allowed-tools: Bash(node *agent-id-git/bin/cli.mjs:*) Bash(git:*) Read
---

# Alien Agent ID — Git

SSH-signed commits whose signing key is bound, via the SSO-issued id_token (`cnf.jkt`), to a verified human owner. Each commit carries:

- An SSH signature in the commit object (visible via `git log --show-signature`).
- Two trailers in the commit message: `Agent-ID-JKT: <thumbprint>` and `Agent-ID-Owner: <sub>`.
- A v3 proof bundle attached as a git note under `refs/notes/agent-id` containing the SSO-signed id_token and the agent's public JWK.

Verification is universal: it does not require the agent's local state, only the commit and its proof note. The verifier walks `SSH sig → agent_jwk → cnf.jkt → SSO RS256 signature → verified owner sub`.

## Resolve the CLI

`bin/cli.mjs` lives in this plugin's directory. Substitute `CLI` with the absolute path (e.g. `node /abs/path/to/plugins/agent-id-git/bin/cli.mjs`) in the examples below.

## Setup (one-time, after bootstrap)

After `agent-id-setup bootstrap` has produced a keypair and bound an owner, configure git signing:

```bash
node CLI setup
```

This writes `$stateDir/ssh/{agent-id, agent-id.pub, allowed_signers}` and prints the public key. Add it to GitHub (Settings → SSH and GPG keys → New SSH key → Key type: **Signing Key**) to earn the *Verified* badge on commits.

## Make a signed commit

```bash
node CLI commit --message "feat: implement auth flow"
node CLI commit --message "fix: handle empty body" --push        # push commit + proof note
node CLI commit --message "release: 1.2.0" --push --remote upstream
```

Output is JSON: `{ ok, commitHash, signed, jkt, proofAttached, pushed, notesPushed, ... }`.

A normal `git commit` still works but skips trailers, signing, and the proof note.

## Verify a commit's provenance

```bash
node CLI verify --commit HEAD          # current commit
node CLI verify --commit <hash>        # any commit with a v3 proof note
```

Verification runs three checks in order:

1. **Universal bundle verification** (handled by `agent-id-core`): id_token SSO signature, `cnf.jkt` ↔ `jwkThumbprint(agent_jwk)`, agent_jwk validity.
2. **Trailer binding**: `Agent-ID-JKT` and `Agent-ID-Owner` in the commit message must agree with the bundle.
3. **SSH commit signature**: `git verify-commit` against the agent_jwk derived from the bundle.

On success: `{ ok: true, commit, jkt, ownerSub, issuer, aud, iat, summary }`.

The verifier is **standalone** — it does not require a bound identity on the verifying machine. Auditors, CI runners, and code reviewers can run it on any repository with a v3 proof note attached.

## Common flag

`--state-dir <path>` — only needed for `setup` and `commit` (verify is stateless). Defaults to `$AGENT_ID_STATE_DIR` then `~/.agent-id`.
