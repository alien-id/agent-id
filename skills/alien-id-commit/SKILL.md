---
name: alien-id-commit
description: Make SSH-signed git commits with Alien Agent ID trailers, a v3 proof note, and an audit-trail entry — and verify the provenance chain of any commit. Use when the user asks to commit, sign, push, or attest code with provenance, when they want a GitHub *Verified* badge tied to the agent's owner binding, when they reference `Agent-ID-JKT` / `Agent-ID-Owner` trailers, or when they ask to verify who signed a commit. Also covers signing arbitrary non-git operations into the audit trail and exporting proof bundles.
license: MIT
metadata:
  author: Alien Wallet
  version: "3.1.1"
allowed-tools: Bash(node *alien-agent-id/cli.mjs:*) Bash(git:*) Read
---

# Alien Agent ID — Signed git commits

Every commit is SSH-signed with the agent's Ed25519 key, tagged with trailers linking to the agent and human owner, logged in the hash-chained audit trail, and proof-bundled as a git note that anyone can verify without access to the agent's machine.

## Resolve the CLI path

`cli.mjs` lives in the sibling skill directory `alien-agent-id/`. Substitute `CLI` with its absolute path (e.g. `node /abs/path/to/skills/alien-agent-id/cli.mjs`) in every example below.

## Precondition — identity must be bound

```bash
node CLI status
```

If `"bound": false`, run [[alien-id-setup]] first — there is no key to sign with otherwise.

## Make a signed commit

```bash
node CLI git-commit --message "feat: implement auth flow"
node CLI git-commit --message "feat: implement auth flow" --push   # commit + proof note in one push
```

`--push` pushes the commit and handles `refs/notes/agent-id` ref merging. Default remote is `origin`; override with `--remote <name>`. Allow empty commits with `--allow-empty`.

A plain `git commit` still works — but skips trailers, signing, and the proof note. Use `git-commit` whenever provenance matters.

## Verify a commit

```bash
node CLI git-verify --commit HEAD
node CLI git-verify --commit <hash>
```

Traces the chain: SSH signature → `agent_jwk` → id_token `cnf.jkt` → SSO RS256 signature. When the commit has a proof note, verification is fully self-contained — no access to the agent's state directory or any external service required.

Anyone who clones the repo and fetches notes can verify:

```bash
git fetch origin refs/notes/agent-id:refs/notes/agent-id
node CLI git-verify --commit <hash>
```

Pre-v3 commits (`Agent-ID-Fingerprint` / `Agent-ID-Binding` trailers) are intentionally rejected — their id_tokens predate the RFC 7800 `cnf.jkt` binding.

## What a signed commit looks like

```text
feat: implement auth flow

Agent-ID-JKT: wEf6o2ux8sBAUG4oQYhP284gfpZwUJMTxXDPH5XxthY
Agent-ID-Owner: 00000003010000000000539c741e0df8
```

Anyone can trace: **this commit** → **this agent key (JKT)** → **this human (id_token `sub`)** → **verified AlienID holder**.

## GitHub *Verified* badge

For the *Verified* badge, register the agent's SSH public key on GitHub as a **Signing Key** (not authentication). The key is printed by `git-setup` and lives at `~/.agent-id/ssh/agent-id.pub`.

GitHub → Settings → SSH and GPG keys → New SSH key → Key type: **Signing Key**.

## Sign other operations

Append signed entries to the audit trail for any significant non-git action:

```bash
node CLI sign --type TOOL_CALL --action "bash.exec"        --payload '{"command":"deploy"}'
node CLI sign --type API_CALL  --action "github.create-pr" --payload '{"repo":"foo/bar"}'
```

Verify the entire state chain:

```bash
node CLI verify
```

Export a portable proof bundle:

```bash
node CLI export-proof
```

## Command reference

| Command | Purpose |
|---|---|
| `git-commit --message <M> [--push] [--remote R] [--allow-empty]` | Signed commit + trailers + v3 proof note + audit log. |
| `git-verify [--commit <hash>]` | Verify the provenance chain of a commit. |
| `sign --type T --action A --payload <JSON>` | Sign an arbitrary operation into the audit trail. |
| `verify` | Verify the state chain integrity. |
| `export-proof` | Emit a proof bundle to stdout. |

Common flag: `--state-dir <path>` (defaults to `~/.agent-id`, or `AGENT_ID_STATE_DIR`).

## Reference docs

- [../alien-agent-id/reference/git-commits.md](../alien-agent-id/reference/git-commits.md) — signed commit anatomy, GitHub *Verified* badge.
- [../alien-agent-id/reference/state-and-errors.md](../alien-agent-id/reference/state-and-errors.md) — state-dir layout, error catalog.
