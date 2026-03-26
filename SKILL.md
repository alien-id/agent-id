---
name: agent-id
description: Obtain a verifiable Agent ID linked to a human owner via Alien Network SSO. Authenticate with Alien-aware services. Store and retrieve credentials for external services (GitHub, Slack, AWS, etc.). Sign git commits so every line of agent-written code is cryptographically attributable.
license: Proprietary (internal use only)
compatibility: Any AI agent with shell access and Node.js 18+ (Claude Code, OpenClaw, etc.)
metadata:
  author: Alien Wallet
  version: "2.0.0"
allowed-tools: Bash(node:*) Bash(git:*) Bash(curl:*) Read
---

# Agent ID — Identity, Authentication & Credentials for AI Agents

You are an AI agent. This skill gives you:

1. **A cryptographic identity** linked to a verified human owner (Alien Network)
2. **Service authentication** — signed tokens accepted by Alien-aware services
3. **A credential vault** — encrypted storage for API keys, passwords, OAuth tokens
4. **Signed git commits** — every commit traceable to you and your human owner

## Quick Start — Bootstrap

Run one command to go from zero to a working identity:

```bash
node CLI bootstrap
```

This generates your keypair, starts OIDC auth with Alien SSO, waits for the human owner to approve (via QR code / Alien App), and configures git signing — all in one step.

If `"alreadyBootstrapped": true` appears in the output, you're already set up.

### Prerequisites

- **Node.js 18+** and **git 2.34+** available in the shell
- **Provider address**: See below for how to resolve this.
- **Alien App**: The user must have it installed with a verified AlienID

### Resolve the CLI path first

The CLI tool is at `cli.mjs` in the same directory as this skill file. Before running any commands, resolve the absolute path. In all commands below, replace `CLI` with the resolved path: `node /absolute/path/to/cli.mjs`.

### Provider address

Bootstrap reads the provider address from (in order):
1. `--provider-address <addr>` flag
2. `ALIEN_PROVIDER_ADDRESS` environment variable
3. `provider.txt` file next to the CLI

If none are found, ask the user: **"Would you like to use the default Alien provider, or set up your own?"**

- **Default provider**: Ask the user for the provider address.
- **Set up your own**: Direct the user to create a SSO provider:
  > Create your SSO provider at: https://dev.alien.org/dashboard/sso

## 1) When to use

**Check for an existing Agent ID at the start of every session** if you expect to make commits, call authenticated services, or access stored credentials.

```bash
node CLI status
```

If `"bound": true` — you have an identity. If not, run `bootstrap`.

Use this skill when:
- You need to make git commits (always sign them)
- You need to call a service that requires agent authentication
- You need credentials for an external service (GitHub API, AWS, etc.)
- The user asks you to "sign in with Alien" or "get an Agent ID"

## 2) Authenticating with services

### Alien-aware services (Agent ID token)

Generate a signed authentication token:

```bash
node CLI auth-header
```

This returns JSON with a `token` field. Use it in HTTP requests:

```bash
# Get the auth header for curl
AUTH=$(node CLI auth-header --raw)
curl -H "$AUTH" https://service.example.com/api/whoami
```

The token is a self-contained Ed25519-signed assertion containing your fingerprint, public key, owner identity, and a timestamp. Tokens are valid for 5 minutes.

### External services (vault credentials)

For services that use API keys, passwords, or OAuth tokens, retrieve stored credentials from the vault:

```bash
# Retrieve a stored credential
node CLI vault-get --service github
```

Returns:
```json
{"ok": true, "service": "github", "type": "api-key", "credential": "ghp_xxx..."}
```

Use the `credential` value in the appropriate header or config for that service. For example:

```bash
# GitHub API
GITHUB_TOKEN=$(node CLI vault-get --service github | node -e "process.stdin.resume(); let d=''; process.stdin.on('data',c=>d+=c); process.stdin.on('end',()=>console.log(JSON.parse(d).credential))")
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user

# Or more simply using jq if available
GITHUB_TOKEN=$(node CLI vault-get --service github | jq -r .credential)
```

If the credential doesn't exist in the vault, **ask the user** to provide it (see Section 3 below for the secure flow), then store it and retrieve again.

**Never hardcode credentials. Always use the vault.**

## 3) Credential vault

The vault encrypts credentials with a key derived from your agent's Ed25519 private key (HKDF + AES-256-GCM). Only this agent instance can decrypt them.

### Storing credentials — the human-agent flow

When you need a credential for an external service, follow this protocol:

**Step 1: Check if it's already stored**
```bash
node CLI vault-get --service github
```

If it returns the credential, use it. If not, continue.

**Step 2: Ask the user**

Tell the user exactly what you need and give them secure options to provide it:

> "I need a GitHub personal access token to proceed. Please provide it using one of these methods (most secure first):
>
> **Option A** — Write it to a temporary file:
> ```
> echo 'ghp_your_token' > /tmp/gh-token && chmod 600 /tmp/gh-token
> ```
> Then tell me the file path.
>
> **Option B** — Set it as an environment variable and restart:
> ```
> export GITHUB_TOKEN=ghp_your_token
> ```
> Then tell me the variable name.
>
> **Option C** — Paste it here and I'll store it immediately."

**Step 3: Store it securely**

Depending on which option the user chose:

```bash
# Option A: from file (most secure — secret never on command line)
node CLI vault-store --service github --type api-key --credential-file /tmp/gh-token
# Then clean up the temp file:
rm /tmp/gh-token

# Option B: from environment variable
node CLI vault-store --service github --type api-key --credential-env GITHUB_TOKEN

# Option C: piped via stdin (secret not in process list)
echo 'ghp_xxx' | node CLI vault-store --service github --type api-key

# Last resort: direct argument (visible in process list)
node CLI vault-store --service github --type api-key --credential "ghp_xxx"
```

**Step 4: Confirm and use**
```bash
node CLI vault-get --service github
```

**IMPORTANT:** Prefer `--credential-file` or `--credential-env` over `--credential`. The `--credential` flag puts the secret in the process argument list, visible via `ps`. The other methods keep it off the command line entirely.

### Credential types

Use `--type` to tag what kind of credential it is:
- `api-key` — API key / personal access token (default)
- `password` — username + password pair (use with `--username`)
- `oauth` — OAuth access/refresh token
- `bearer` — Bearer token
- `custom` — Anything else

### Store examples

```bash
# GitHub personal access token (from file)
echo 'ghp_abc123' > /tmp/cred && chmod 600 /tmp/cred
node CLI vault-store --service github --type api-key --credential-file /tmp/cred
rm /tmp/cred

# AWS credentials (from env)
node CLI vault-store --service aws --type api-key --credential-env AWS_SECRET_ACCESS_KEY --username "$AWS_ACCESS_KEY_ID" --url "https://aws.amazon.com"

# Service with username + password (piped)
echo 'mypassword' | node CLI vault-store --service docker-hub --type password --username "myuser" --url "https://hub.docker.com"

# OAuth token
node CLI vault-store --service slack --type oauth --credential-env SLACK_BOT_TOKEN
```

### Retrieve a credential

```bash
node CLI vault-get --service <name>
```

Returns JSON with `service`, `type`, `credential`, `url`, `username`.

### List stored credentials

```bash
node CLI vault-list
```

Returns a list of services with metadata (without decrypting credential values).

### Remove a credential

```bash
node CLI vault-remove --service <name>
```

### Update a credential

Run `vault-store` again with the same `--service` name. The existing credential is replaced; the original creation timestamp is preserved.

## 4) Making signed git commits

### Option A: Use `git-commit` (recommended)

```bash
node CLI git-commit --message "feat: implement auth flow"
```

This creates a commit that is:
1. **SSH-signed** with your Ed25519 key
2. **Tagged with trailers** linking to your identity and human owner
3. **Logged in your audit trail** with a hash-chained signed record
4. **Proof-bundled** as a git note for external verification

### Push commits and proof notes

```bash
node CLI git-commit --message "feat: implement auth flow" --push
```

The `--push` flag pushes both the commit and proof notes (handling note ref merging automatically).

### Option B: Normal `git commit`

Since `bootstrap` / `git-setup` sets `commit.gpgsign = true`, any `git commit` is SSH-signed. But it won't have Agent ID trailers or proof notes.

### GitHub verified badge

After bootstrap, tell the user:
> "To get the 'Verified' badge on GitHub, add this SSH public key to your GitHub account:
> Go to GitHub → Settings → SSH and GPG keys → New SSH key → Key type: **Signing Key**"

The SSH public key is shown in the `git-setup` output.

## 5) Verifying commit provenance

```bash
node CLI git-verify --commit HEAD
```

Traces the full chain: SSH signature → agent key → owner binding → SSO attestation.

If the commit has a proof note (from `git-commit`), verification is **fully self-contained** — works without access to the agent's state directory.

## 6) Signing other operations

Sign any significant action for the audit trail:

```bash
node CLI sign --type TOOL_CALL --action "bash.exec" --payload '{"command":"deploy"}'
node CLI sign --type API_CALL --action "github.create-pr" --payload '{"repo":"foo/bar"}'
```

## 7) Step-by-step bootstrap (manual)

If `bootstrap` doesn't work for your setup, you can run each step individually:

### Step 1: Initialize keypair
```bash
node CLI init
```

### Step 2: Start OIDC authorization
```bash
node CLI auth --provider-address <PROVIDER_ADDRESS>
```

This returns JSON containing a `deepLink` and a `qrCode` (Unicode text). Output the `qrCode` value directly in a code block so the user can scan it with the Alien App. Also show the deep link as a fallback:

> Scan this QR code with your Alien App:
> ```
> <qrCode value from JSON>
> ```
> Or open this link: <deepLink>

### Step 3: Wait for approval
```bash
node CLI bind --no-require-owner-proof
```

Blocks for up to 5 minutes while the user scans the QR code with Alien App.

### Step 4: Configure git signing

Before running git-setup, ask the user for their **GitHub email** so commits are associated with their GitHub account:

> "What email should I use for commits? This should match your GitHub account email (you can find it at GitHub → Settings → Emails). A GitHub noreply email like `user@users.noreply.github.com` works too."

```bash
node CLI git-setup --email <USER_GITHUB_EMAIL>
```

## 8) Command reference

| Command | Purpose | Blocking? |
|---------|---------|-----------|
| `bootstrap` | One-command setup: init + auth + bind + git-setup | **Yes** (up to 5 min) |
| `status` | Check if Agent ID exists and is bound | No |
| `auth-header [--raw]` | Generate signed auth token for service calls | No |
| `vault-store --service S --credential C` | Store encrypted credential | No |
| `vault-get --service S` | Retrieve decrypted credential | No |
| `vault-list` | List stored credentials (no secrets shown) | No |
| `vault-remove --service S` | Remove a credential | No |
| `init` | Generate keypair | No |
| `auth --provider-address <addr>` | Start OIDC auth, get QR code | No |
| `bind` | Poll for approval, create owner binding | **Yes** (up to 5 min) |
| `git-setup [--global] [--email E]` | Configure git SSH signing | No |
| `git-commit --message "..." [--push]` | Signed commit + trailers + proof note | No |
| `git-verify [--commit <hash>]` | Verify provenance chain | No |
| `sign --type T --action A --payload JSON` | Sign operation for audit trail | No |
| `verify` | Verify state chain integrity | No |
| `export-proof` | Export proof bundle to stdout | No |

### Common flags

| Flag | Default | Description |
|------|---------|-------------|
| `--state-dir <path>` | `~/.agent-id` | State directory (or `AGENT_ID_STATE_DIR` env) |
| `--provider-address <addr>` | — | Alien provider address |
| `--sso-url <url>` | `https://sso.alien-api.com` | SSO base URL |
| `--raw` | — | Output raw text instead of JSON (auth-header) |
| `--timeout-sec <n>` | `300` | Poll timeout for `bind` |
| `--global` | — | Apply git config globally instead of per-repo |
| `--name <name>` | `Agent` | Git committer name |
| `--email <email>` | auto-generated | Git committer email |
| `--allow-empty` | — | Allow empty commits with `git-commit` |
| `--push` | — | Push commit and proof notes after `git-commit` |
| `--remote <name>` | `origin` | Remote to push to (with `--push`) |

## 9) State directory

```
~/.agent-id/
├── keys/main.json             # Ed25519 keypair (mode 0600)
├── ssh/
│   ├── agent-id               # SSH private key (mode 0600)
│   ├── agent-id.pub           # SSH public key
│   └── allowed_signers        # For git signature verification
├── vault/
│   ├── github.json            # Encrypted credential (mode 0600)
│   ├── slack.json
│   └── ...
├── audit/operations.jsonl     # Hash-chained signed operation log
├── owner-binding.json         # Owner binding (human ↔ agent link)
├── owner-session.json         # Session tokens (mode 0600) — NEVER commit
├── nonces.json                # Per-agent nonce tracking
├── sequence.json              # Sequence counter
```

## 10) Integration patterns

### Claude Code (CLAUDE.md)
```
Before making your first git commit, run: node /path/to/cli.mjs bootstrap
```

### Environment variables
```bash
export ALIEN_PROVIDER_ADDRESS="00000003..."
export AGENT_ID_STATE_DIR="~/.agent-id"
```

### CI/CD (GitHub Actions)
```yaml
- name: Bootstrap agent identity
  env:
    ALIEN_PROVIDER_ADDRESS: ${{ secrets.ALIEN_PROVIDER_ADDRESS }}
  run: node /path/to/cli.mjs bootstrap
```

## 11) Error handling

| Error | Action |
|-------|--------|
| `No provider address` | Set `--provider-address`, env var, or `provider.txt` |
| `No pending auth found` | Run `auth` or `bootstrap` |
| `Alien SSO authorization session expired` | Run `bootstrap` again |
| `User rejected Alien SSO authorization` | Ask user to try again |
| `Timed out waiting` | Run `bootstrap` again, remind user to scan promptly |
| `No agent keypair` | Run `bootstrap` or `init` |
| `No credential stored for "..."` | Ask user for the credential, then `vault-store` |

## 12) Security

- Private keys stored with **0600** permissions — never transmitted
- Vault credentials encrypted with **AES-256-GCM** (key derived via HKDF from agent's Ed25519 key)
- **PKCE** prevents authorization code interception
- Auth tokens are **short-lived** (5 minute validity)
- **Hash-chained audit log** — any tampering breaks the chain
- **Ed25519 SSH signatures** on commits provide non-repudiation
- Never expose `owner-session.json` or vault files
