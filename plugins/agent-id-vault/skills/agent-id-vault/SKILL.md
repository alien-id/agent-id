---
name: agent-id-vault
description: Encrypted credential vault keyed off the agent's Alien Agent ID private key. Store, retrieve, list, and remove external-service credentials (GitHub PAT, Slack token, AWS keys, etc.) without ever hardcoding secrets. Use when the user asks to save, fetch, or remove a service credential, or whenever a downstream tool needs an external-service secret that should not appear in shell history, source files, or process arguments.
license: MIT
metadata:
  author: Alien Wallet
  version: "0.0.0"
allowed-tools: Bash(node *agent-id-vault/bin/cli.mjs:*) Bash(curl:*) Bash(jq:*) Read
---

# Alien Agent ID — Vault

Encrypted storage for external-service credentials. The encryption key is derived from the agent's main private key via HKDF-SHA256, so credentials are only readable on the same machine as the bound agent. Encryption is AES-256-GCM with a fresh IV per write.

Requires that `agent-id-setup bootstrap` has already produced a keypair under `${AGENT_ID_STATE_DIR:-$HOME/.agent-id}`.

## Resolve the CLI

`bin/cli.mjs` lives in this plugin's directory. Substitute `CLI` with the absolute path (e.g. `node /abs/path/to/plugins/agent-id-vault/bin/cli.mjs`) in the examples below.

## Store a credential

```bash
# Most secure — never appears in argv or shell history:
node CLI store --service github --credential-file /tmp/gh-token

# From an environment variable (typed/pasted into the calling shell):
GH_TOKEN=ghp_... node CLI store --service github --credential-env GH_TOKEN

# Piped via stdin:
echo "$GH_TOKEN" | node CLI store --service github

# Fallback — visible in process list and shell history, avoid:
node CLI store --service github --credential "ghp_..."
```

Optional flags: `--type api-key|oauth|...`, `--url <hint>`, `--username <hint>`.

Never accept a secret pasted into chat. Transcripts persist. Use a file or env var as the transport.

## Retrieve a credential

```bash
node CLI get --service github
```

Returns JSON `{ ok, service, type, credential, url, username }`. Pipe `.credential` into the calling tool:

```bash
GH_TOKEN=$(node CLI get --service github | jq -r .credential)
curl -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user
```

## List or remove

```bash
node CLI list             # metadata only — never returns plaintext credentials
node CLI remove --service github
```

## Common flag

`--state-dir <path>` — defaults to `$AGENT_ID_STATE_DIR` then `~/.agent-id`.
