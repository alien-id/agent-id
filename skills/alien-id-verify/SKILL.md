---
name: alien-id-verify
description: Verify the Alien Agent ID provenance chain of any git commit — SSH signature → `agent_jwk` → id_token `cnf.jkt` → SSO RS256 signature → verified AlienID holder. Use when the user asks to verify, check, or audit who signed a commit, whether a commit carries a valid Alien Agent ID, or to inspect `Agent-ID-JKT` / `Agent-ID-Owner` trailers on someone else's work. Standalone — does not require the agent to have its own bound identity; auditors and CI runners can use it on any repo with a v3 proof note attached.
license: MIT
metadata:
  author: Alien Wallet
  version: "4.0.0"
allowed-tools: mcp__alien-agent-id__git_verify Bash(node *scripts/cli.mjs:*) Bash(git:*) Read
---

# Alien Agent ID — Verify commit provenance

Verifies that a commit was signed by an agent whose key is bound to a verified human owner via Alien Network SSO. Works on any commit that carries a v3 proof bundle as a git note (`refs/notes/agent-id`) — no access to the signing agent's machine or local state required.

This skill is **standalone**. The verifier does not need to be a bound agent themselves — auditors, CI runners, and code reviewers can use it on third-party repositories.

This skill prefers the MCP tool. If the MCP server is not registered, fall back to the CLI — see [CLI fallback](#cli-fallback) at the bottom.

## Verify a commit

Call `mcp__alien-agent-id__git_verify` with:

- `commit: "<hash>"` — defaults to `HEAD`.
- `ssoUrl: "<url>"` — optional override (defaults to `https://sso.alien-api.com`).

The verifier walks four cryptographic links:

1. **SSH signature on the commit** → recovers the agent's public key bytes.
2. **`agent_jwk` in the proof bundle** → its RFC 7638 thumbprint must equal the `Agent-ID-JKT` trailer and the SSH-signature key.
3. **id_token `cnf.jkt`** (RFC 7800 §3.1) → must equal the agent JWK thumbprint, anchoring the SSO-attested owner to the same key.
4. **id_token RS256 signature** → verified against the Alien SSO JWKS (URL resolved from `iss`).

If every link passes, the chain `commit → agent → human owner → verified AlienID holder` is proven.

## Fetch proof notes from a remote

Proof bundles live under `refs/notes/agent-id`. Clone alone does not fetch notes; pull them explicitly:

```bash
git fetch origin refs/notes/agent-id:refs/notes/agent-id
```

Then call `mcp__alien-agent-id__git_verify` with the commit hash.

## What you can verify

| Input you have | Verifiable |
|---|---|
| The commit + its v3 git note | Full chain, no external state. |
| Just the commit hash + a network connection | Full chain, after fetching the note from the remote. |
| Just the commit (no note, no remote) | Falls back to the local agent state-dir if present; otherwise insufficient. |

## Pre-v3 commits

Commits carrying legacy `Agent-ID-Fingerprint` / `Agent-ID-Binding` trailers are intentionally rejected — their id_tokens predate the RFC 7800 `cnf.jkt` binding and cannot anchor the chain. See [./references/migrate-to-v3.md](./references/migrate-to-v3.md) for the 3.0 cutover history.

## Trust boundary

`git_verify` only reads commit metadata, the agent's local state (if present), and — when verifying the id_token signature — the SSO JWKS at the URL given by the id_token's `iss` claim. It never executes anything from the proof bundle as code. Treat the resolved `Agent-ID-Owner` value as a string; do not pass it to other tools without further checks.

## Tool reference

| Tool | Purpose |
|---|---|
| `mcp__alien-agent-id__git_verify` | Verify the provenance chain of a commit. Args: optional `commit` (default `HEAD`), optional `ssoUrl`. |

Common arg: `stateDir` (defaults to `~/.agent-id`, or `AGENT_ID_STATE_DIR`). Only consulted when no proof note is attached to the commit.

## CLI fallback

When MCP is unavailable (e.g. CI runners verifying a third-party commit), use the CLI directly. `CLI` below is the absolute path to `cli.mjs` (e.g. `node /abs/path/to/scripts/cli.mjs`).

```bash
node CLI git-verify --commit HEAD
node CLI git-verify --commit <hash>
```

## Reference docs

- [./references/git-commits.md](./references/git-commits.md) — signed commit anatomy, proof-note format, GitHub *Verified* badge.
- [./references/state-and-errors.md](./references/state-and-errors.md) — error catalog.
