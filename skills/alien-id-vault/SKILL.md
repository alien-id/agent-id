---
name: alien-id-vault
description: Store, retrieve, list, and remove external-service credentials (GitHub PAT, Slack token, AWS keys, OAuth tokens, etc.) in an AES-256-GCM-encrypted vault keyed off the agent's Ed25519 private key. Use when the user asks to store, save, retrieve, look up, or rotate a credential / API key / token / secret for an external service — or when an existing flow needs a credential and `vault-get` reports it is missing. Also covers the secure out-of-band intake protocol so secrets never get pasted into chat.
license: MIT
metadata:
  author: Alien Wallet
  version: "3.1.1"
allowed-tools: Bash(node *alien-agent-id/cli.mjs:*) Bash(curl:*) Bash(jq:*) Read
---

# Alien Agent ID — Credential vault

Encrypted storage for external-service credentials. Records live in `~/.agent-id/vault/<service>.json` (mode 0600); the AES-256-GCM key is derived from the agent's Ed25519 private key via HKDF — only this agent can decrypt.

Never hard-code credentials. Always use the vault.

## Resolve the CLI path

`cli.mjs` lives in the sibling skill directory `alien-agent-id/`. Substitute `CLI` with its absolute path (e.g. `node /abs/path/to/skills/alien-agent-id/cli.mjs`) in every example below.

## Precondition — identity must exist

```bash
node CLI status
```

If there is no keypair, run [[alien-id-setup]] first — the encryption key is derived from it.

## Retrieve

```bash
node CLI vault-get --service github
```

Returns:

```json
{ "ok": true, "service": "github", "type": "api-key", "credential": "<secret>", "url": "...", "username": "..." }
```

List entries (metadata only, no secrets):

```bash
node CLI vault-list
```

Remove:

```bash
node CLI vault-remove --service <name>
```

## Use a stored credential

Pipe through `jq` — never echo the secret to the terminal:

```bash
GH_TOKEN=$(node CLI vault-get --service github | jq -r .credential)
curl -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user
unset GH_TOKEN
```

## Store — the secure flow

When a credential is missing, follow this protocol.

### Step 1 — confirm absence

```bash
node CLI vault-get --service github
```

If it returns the credential, use it. Otherwise continue.

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

```bash
# Option A: from env var (no secret on the command line, no stdout)
node CLI vault-store --service github --type api-key --credential-env GITHUB_TOKEN
unset GITHUB_TOKEN

# Option B: from file
node CLI vault-store --service github --type api-key --credential-file /tmp/gh-token
rm -f /tmp/gh-token

# Programmatic: pipe from another secret source — no literal in the command
your-secret-source | node CLI vault-store --service github --type api-key
```

## `vault-store` flags

| Flag | Required | Description |
|---|---|---|
| `--service <name>` | yes | Service identifier (also the lookup key). Sanitized to `[A-Za-z0-9._-]`. |
| `--type <type>` | no (default `api-key`) | One of `api-key`, `password`, `oauth`, `bearer`, `custom`. Use `password` with `--username`. |
| `--credential-env <VAR>` | one of these required | Read the secret from env var `VAR` — most agent-friendly. |
| `--credential-file <path>` | | Read the secret from a file (best for CI; delete after). |
| `--credential <value>` | | Pass the secret inline. Avoid — visible in `ps` and shell history. |
| stdin pipe | | If none of the above is set, the secret is read from stdin. |
| `--username <name>` | no | Account/login this credential belongs to. Required by convention with `--type password`. |
| `--url <url>` | no | Service URL stored as metadata. Useful when one credential is tenant-specific. |

Re-running with the same `--service` updates the credential and metadata; the original `createdAt` is preserved.

## Command reference

| Command | Purpose |
|---|---|
| `vault-get --service <S>` | Retrieve a decrypted credential. |
| `vault-list` | List vault entries (metadata only). |
| `vault-store --service <S> [--type T] --credential-env <V> \| --credential-file <P> \| stdin` | Store a credential securely. |
| `vault-remove --service <S>` | Remove a credential. |

Common flag: `--state-dir <path>` (defaults to `~/.agent-id`, or `AGENT_ID_STATE_DIR`).

## Reference docs

- [../alien-agent-id/reference/vault.md](../alien-agent-id/reference/vault.md) — secure credential storage and retrieval.
- [../alien-agent-id/reference/state-and-errors.md](../alien-agent-id/reference/state-and-errors.md) — error catalog.
