# Credential vault

Stores external-service credentials (API keys, passwords, OAuth tokens, bearer tokens) encrypted with AES-256-GCM. The key is derived from the agent's Ed25519 private key via HKDF — only this agent instance can decrypt.

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

## Store — the secure flow

When a credential is missing, follow this protocol.

### Step 1 — confirm absence

```bash
node CLI vault-get --service github
```

If it returns the credential, use it. Otherwise continue.

### Step 2 — ask the user out-of-band

**Never accept a secret pasted into chat — transcripts persist.** Give the user out-of-band options:

> "I need a GitHub personal access token. **Do not paste it into this chat.** Choose one:
>
> **Option A (recommended)** — load it into your shell as an env var, then restart this agent:
> ```bash
> read -rs GITHUB_TOKEN && export GITHUB_TOKEN
> ```
> Paste the token at the prompt (the terminal will not echo it, and `read` does not write to history). Then tell me 'done'.
>
> **Option B (CI / non-interactive)** — write it to a private file:
> ```bash
> umask 077 && touch /tmp/gh-token && chmod 600 /tmp/gh-token
> # then put the token into /tmp/gh-token
> ```
> Tell me the path."

### Step 3 — store it

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
| `--credential <value>` | | Pass the secret inline. **Avoid** — visible in `ps` and shell history. |
| stdin pipe | | If none of the above is set, the secret is read from stdin. |
| `--username <name>` | no | Account/login this credential belongs to. Stored as metadata; required by convention with `--type password`. |
| `--url <url>` | no | Service URL stored as metadata. Useful when one credential is tenant-specific. |

The record is encrypted and written to `~/.agent-id/vault/<service>.json` (mode 0600). Re-running with the same `--service` updates the credential and metadata; the original `createdAt` is preserved.

## Example — call an external API with a stored credential

```bash
# Retrieve, then use
GH_TOKEN=$(node CLI vault-get --service github | jq -r .credential)
curl -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user
unset GH_TOKEN
```

Never hard-code credentials. Always use the vault.
