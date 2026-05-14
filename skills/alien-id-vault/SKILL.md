---
name: alien-id-vault
description: Store, retrieve, list, and remove external-service credentials (GitHub PAT, Slack token, AWS keys, OAuth tokens, etc.) in an AES-256-GCM-encrypted vault keyed off the agent's Ed25519 private key. Use when the user asks to store, save, retrieve, look up, or rotate a credential / API key / token / secret for an external service — or when an existing flow needs a credential and `vault_get` reports it is missing. Also covers the secure out-of-band intake protocol so secrets never get pasted into chat.
license: MIT
metadata:
  author: Alien Wallet
  version: "4.0.0"
allowed-tools: mcp__alien-agent-id__* Bash(node *bin/cli.mjs:*) Bash(curl:*) Bash(jq:*) Read
---

# Alien Agent ID — Credential vault

Encrypted storage for external-service credentials. Records live in `~/.agent-id/vault/<service>.json` (mode 0600); the AES-256-GCM key is derived from the agent's Ed25519 private key via HKDF — only this agent can decrypt.

Never hard-code credentials. Always use the vault.

This skill prefers MCP tools (`mcp__alien-agent-id__*`). If the MCP server is not registered, fall back to the CLI — see [CLI fallback](#cli-fallback) at the bottom.

## Precondition — identity must exist

Call `mcp__alien-agent-id__status`. If there is no keypair, run `alien-id-setup` first — the encryption key is derived from it.

## Retrieve

Call `mcp__alien-agent-id__vault_get` with `service: "<name>"`. Returns:

```json
{ "ok": true, "service": "github", "type": "api-key", "credential": "<secret>", "url": "...", "username": "..." }
```

List entries (metadata only, no secrets): `mcp__alien-agent-id__vault_list` (no args).

Remove: `mcp__alien-agent-id__vault_remove` with `service: "<name>"`.

## Use a stored credential

The credential lands inside the tool result as a JSON field. Pipe it directly into the consumer; do not echo it to the chat. For shell use, fall back to the CLI route below where stdout is straightforward to pipe through `jq`.

## Store — the secure flow

When a credential is missing, follow this protocol.

### Step 1 — confirm absence

Call `mcp__alien-agent-id__vault_get` with the service name. If it returns the credential, use it. Otherwise continue.

### Step 2 — ask the user out-of-band

**Never accept a secret pasted into chat — transcripts persist.** Give the user out-of-band options:

> "I need a GitHub personal access token. Do not paste it into this chat. Choose one:
>
> Option A (recommended) — load it into your shell as an env var, then restart this agent:
> ```bash
> read -rs GITHUB_TOKEN && export GITHUB_TOKEN
> ```
> Paste the token at the prompt (the terminal will not echo it, and `read` does not write to history). Then tell me 'done'.
>
> Option B (CI / non-interactive) — write it to a private file:
> ```bash
> umask 077 && touch /tmp/gh-token && chmod 600 /tmp/gh-token
> # then put the token into /tmp/gh-token
> ```
> Tell me the path."

### Step 3 — store

Call `mcp__alien-agent-id__vault_store` with:

- `service: "<name>"` (required)
- `type: "api-key" | "password" | "oauth" | "bearer" | "custom"` (default `api-key`)
- One source of secret:
  - `credentialEnv: "<VAR>"` — read from env var (preferred for env-loaded secrets).
  - `credentialFile: "<path>"` — read from a file (best for CI; delete after).
  - `credential: "<value>"` — inline; avoid — visible in MCP-server process args.
- Optional `username: "<name>"`, `url: "<service URL>"`.

After storing from a file, delete it (`rm -f /tmp/gh-token`). After storing from an env var, unset it (`unset GITHUB_TOKEN`).

## Store-tool args

| Arg | Required | Description |
|---|---|---|
| `service` | yes | Service identifier (also the lookup key). Sanitized to `[A-Za-z0-9._-]`. |
| `type` | no (default `api-key`) | One of `api-key`, `password`, `oauth`, `bearer`, `custom`. Use `password` with `username`. |
| `credentialEnv` | one of these required | Env var name to read the secret from — most agent-friendly. |
| `credentialFile` | | Path to file containing the secret (best for CI). |
| `credential` | | Inline secret. Avoid — visible in process args. |
| `username` | no | Account/login. Required by convention with `type: "password"`. |
| `url` | no | Service URL stored as metadata. Useful when one credential is tenant-specific. |

Re-calling `vault_store` with the same `service` updates the credential and metadata; the original `createdAt` is preserved.

## Tool reference

| Tool | Purpose |
|---|---|
| `mcp__alien-agent-id__vault_get` | Retrieve a decrypted credential. Args: `service`. |
| `mcp__alien-agent-id__vault_list` | List vault entries (metadata only). |
| `mcp__alien-agent-id__vault_store` | Store a credential securely. See table above. |
| `mcp__alien-agent-id__vault_remove` | Remove a credential. Args: `service`. |

Common arg: `stateDir` (defaults to `~/.agent-id`, or `AGENT_ID_STATE_DIR`).

## CLI fallback

When MCP is unavailable, the same operations are reachable via the CLI. `CLI` below is the absolute path to `cli.mjs` (e.g. `node /abs/path/to/bin/cli.mjs`).

```bash
node CLI vault-get --service github
node CLI vault-list
node CLI vault-remove --service github
node CLI vault-store --service github --type api-key --credential-env GITHUB_TOKEN
node CLI vault-store --service github --type api-key --credential-file /tmp/gh-token

# Use a stored credential without leaking it:
GH_TOKEN=$(node CLI vault-get --service github | jq -r .credential)
curl -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user
unset GH_TOKEN
```

## Reference docs

- [../../docs/reference/vault.md](../../docs/reference/vault.md) — secure credential storage and retrieval.
- [../../docs/reference/state-and-errors.md](../../docs/reference/state-and-errors.md) — error catalog.
