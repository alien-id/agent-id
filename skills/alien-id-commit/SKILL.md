---
name: alien-id-commit
description: Make SSH-signed git commits with Alien Agent ID trailers, a v3 proof note, and an audit-trail entry. Use when the user asks to commit, sign, push, or attest code with provenance, when they want a GitHub *Verified* badge tied to the agent's owner binding, or when they reference `Agent-ID-JKT` / `Agent-ID-Owner` trailers. Also covers signing arbitrary non-git operations into the audit trail and exporting proof bundles. To verify someone else's commit, use `alien-id-verify`.
license: MIT
metadata:
  author: Alien Wallet
  version: "4.0.0"
allowed-tools: mcp__alien-agent-id__* Bash(node *bin/cli.mjs:*) Bash(git:*) Read
---

# Alien Agent ID — Signed git commits

Every commit is SSH-signed with the agent's Ed25519 key, tagged with trailers linking to the agent and human owner, logged in the hash-chained audit trail, and proof-bundled as a git note that anyone can verify without access to the agent's machine.

This skill prefers MCP tools (`mcp__alien-agent-id__*`). If the MCP server is not registered, fall back to the CLI — see [CLI fallback](#cli-fallback) at the bottom.

## Precondition — identity must be bound

Call `mcp__alien-agent-id__status`. If `bound: false`, run `alien-id-setup` first — there is no key to sign with otherwise.

## Make a signed commit

Call `mcp__alien-agent-id__git_commit` with:

- `message: "<commit message>"` (required)
- `push: true` — pushes the commit and `refs/notes/agent-id` in one step.
- `remote: "<name>"` — defaults to `origin`.
- `allowEmpty: true` — allow empty commits.

A plain `git commit` still works — but skips trailers, signing, and the proof note. Use `git_commit` whenever provenance matters.

## What a signed commit looks like

```text
feat: implement auth flow

Agent-ID-JKT: wEf6o2ux8sBAUG4oQYhP284gfpZwUJMTxXDPH5XxthY
Agent-ID-Owner: 00000003010000000000539c741e0df8
```

Anyone can trace: **this commit** → **this agent key (JKT)** → **this human (id_token `sub`)** → **verified AlienID holder**.

## GitHub *Verified* badge

For the *Verified* badge, register the agent's SSH public key on GitHub as a **Signing Key** (not authentication). The key is printed by `git_setup` and lives at `~/.agent-id/ssh/agent-id.pub`.

GitHub → Settings → SSH and GPG keys → New SSH key → Key type: **Signing Key**.

## Sign other operations

Append signed entries to the audit trail for any significant non-git action via `mcp__alien-agent-id__sign`:

- `type: "TOOL_CALL"` / `"API_CALL"` / …
- `action: "bash.exec"` / `"github.create-pr"` / …
- `payload: '<JSON string>'`

Verify the entire state chain: `mcp__alien-agent-id__verify`.
Export a portable proof bundle: `mcp__alien-agent-id__export_proof`.

## Verifying commits

This skill only *makes* signed commits. To verify provenance on a commit the agent (or someone else) produced — use `alien-id-verify`. It is standalone and does not require a bound identity.

## Tool reference

| Tool | Purpose |
|---|---|
| `mcp__alien-agent-id__git_commit` | Signed commit + trailers + v3 proof note + audit log. Args: `message`, optional `push`/`remote`/`allowEmpty`. |
| `mcp__alien-agent-id__sign` | Sign an arbitrary operation into the audit trail. Args: `type`, `action`, `payload`. |
| `mcp__alien-agent-id__verify` | Verify the state chain integrity. |
| `mcp__alien-agent-id__export_proof` | Emit a proof bundle to stdout. |

Common arg: `stateDir` (defaults to `~/.agent-id`, or `AGENT_ID_STATE_DIR`).

## CLI fallback

When MCP is unavailable, the same operations are reachable via the CLI. `CLI` below is the absolute path to `cli.mjs` (e.g. `node /abs/path/to/bin/cli.mjs`).

```bash
node CLI git-commit --message "feat: implement auth flow"
node CLI git-commit --message "feat: implement auth flow" --push   # commit + proof note in one push
node CLI sign --type TOOL_CALL --action "bash.exec" --payload '{"command":"deploy"}'
node CLI verify
node CLI export-proof
```

## Reference docs

- [../../docs/reference/git-commits.md](../../docs/reference/git-commits.md) — signed commit anatomy, GitHub *Verified* badge.
- [../../docs/reference/state-and-errors.md](../../docs/reference/state-and-errors.md) — state-dir layout, error catalog.
