---
name: agent-id-git
description: SSH-signed git commits with Alien Agent ID provenance trailers and a v3 proof note. Sign every line of agent-written code so it is cryptographically attributable to the agent + a verified human owner via Alien Network SSO. Verify provenance on any commit — your own or third-party — without needing the signer's local state. Use when the user asks to make a signed commit, push agent-signed work, check the Agent-ID chain on a commit, audit who signed a commit, or configure git for SSH-format signing with the bound agent key.
license: MIT
metadata:
  author: Alien Wallet
  version: "7.0.0"
allowed-tools: Bash(node *agent-id-git/bin/cli.mjs:*) Bash(git:*) Read
---

# Alien Agent ID — Git

SSH-signed commits whose signing key is — when the agent is bound — tied via the SSO-issued id_token (`cnf.jkt`) to a verified human owner. Each commit carries:

- An SSH signature in the commit object (visible via `git log --show-signature`).
- `Agent-ID-JKT: <thumbprint>` in the commit message — always; plus `Agent-ID-Owner: <sub>` when the agent is human-backed (L1/L2).
- A v3 proof bundle attached as a git note under `refs/notes/agent-id` containing the agent's public JWK, plus the SSO-signed id_token when bound.

**Binding is optional — commit works at any assurance level.** A fresh, unbound agent (L0) commits with its key alone: still SSH-signed, still independently verifiable as "this key", just with no human attestation. Bind later (`agent-id-core auth` + `bind`) and subsequent commits become human-backed (L1 anonymous / L2 linked) with no key change. Verification reports the level it proves.

Verification is universal: it does not require the agent's local state, only the commit and its proof note. For a bound commit the verifier walks `SSH sig → agent_jwk → cnf.jkt → SSO RS256 signature → verified owner sub`; for an L0 commit it confirms `SSH sig → agent_jwk → JKT trailer` and reports level 0.

## Resolve the CLI

`bin/cli.mjs` lives in this plugin's directory. Substitute `CLI` with the absolute path (e.g. `node /abs/path/to/plugins/agent-id-git/bin/cli.mjs`) in the examples below.

## Setup (one-time)

After `agent-id-core init` (or `bootstrap`) has produced a keypair — binding is **not** required for setup — configure git signing:

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

Output is JSON: `{ ok, commitHash, signed, level, assurance, jkt, ownerSub, proofAttached, pushed, notesPushed, ... }`. `level` is 0 (self-asserted), 1 (anonymous-human), or 2 (linked); an unbound agent commits at level 0 and emits a notice.

A normal `git commit` still works but skips trailers, signing, and the proof note.

## Verify a commit's provenance

```bash
node CLI verify --commit HEAD          # current commit
node CLI verify --commit <hash>        # any commit with a v3 proof note
```

Verification runs three checks in order:

1. **Universal bundle verification** (handled by `agent-id-core`): agent_jwk validity, and — when the bundle is bound — id_token SSO signature + `cnf.jkt` ↔ `jwkThumbprint(agent_jwk)`. An L0 bundle (no id_token) is accepted as self-asserted.
2. **Trailer binding**: `Agent-ID-JKT` must agree with the bundle; `Agent-ID-Owner`, if present, must equal the verified `sub` (a forged owner trailer on an L0 commit is rejected here).
3. **SSH commit signature**: `git verify-commit` against the agent_jwk derived from the bundle.

On success: `{ ok: true, commit, level, assurance, jkt, ownerSub, issuer, aud, iat, summary }`. `ownerSub` is null at level 0.

The verifier is **standalone** — it does not require a bound identity on the verifying machine. Auditors, CI runners, and code reviewers can run it on any repository with a v3 proof note attached.

## Common flag

`--state-dir <path>` — only needed for `setup` and `commit` (verify is stateless). Defaults to `$AGENT_ID_STATE_DIR` then `~/.agent-id`.
