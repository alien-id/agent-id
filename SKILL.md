---
name: agent-id
description: Obtain a verifiable Agent ID linked to a human owner via Alien Network SSO. Sign git commits so every line of agent-written code is cryptographically attributable to the agent and its human owner.
license: Proprietary (internal use only)
compatibility: Any AI agent with shell access and Node.js 18+ (Claude Code, OpenClaw, etc.)
metadata:
  author: Alien Wallet
  version: "1.1.0"
allowed-tools: Bash(node:*) Bash(git:*) Read
---

# Agent ID — Verifiable Identity for AI Agents

You are an AI agent. This skill gives you a **cryptographic identity** linked to a verified human owner. Once you have it, every git commit you make is signed and traceable — from code, to you, to the human who authorized you.

## 1) What you get

- An **Ed25519 keypair** unique to you (this agent instance)
- A verified **owner binding** — cryptographic proof that a real human authorized you via the Alien App
- **SSH-signed git commits** with a "Verified" badge on GitHub
- **Agent ID trailers** on every commit linking to your identity and your human owner
- A **hash-chained audit log** of all your signed operations

## 2) When to use

**ALWAYS check for an existing Agent ID at the start of a session** if you expect to make commits or perform signed operations. If you don't have one, obtain it before proceeding.

Use this skill when:
- You are about to write code and make git commits
- The user asks you to "sign in with Alien" or "get an Agent ID"
- You need a verifiable identity for any operation
- A system requires agent identity verification

## 3) Prerequisites

- **Node.js 18+** and **git 2.34+** available in the shell
- **Provider address**: Ask the user if you don't have it. This is the Alien provider address for your deployment.
- **Alien App**: The user must have it installed with a verified AlienID

## 4) Resolve tool path

The CLI tool is at `cli.mjs` in the same directory as this skill file. Before running any commands, resolve the absolute path. For example, if this skill file is at `/home/user/alien/agent-id/SKILL.md`, then the tool is at `/home/user/alien/agent-id/cli.mjs`.

In all commands below, replace `CLI` with the resolved path: `node /absolute/path/to/cli.mjs`.

## 5) Obtain Agent ID — Step by Step

### Step 1: Check status

```bash
node CLI status
```

If `"bound": true` — you already have an Agent ID. Skip to **Section 6**.

### Step 2: Start authentication

```bash
node CLI auth --provider-address <PROVIDER_ADDRESS>
```

This returns **immediately** with JSON containing:
- `deepLink` — URL for the Alien App
- `qrCode` — the QR code as Unicode text

### Step 3: Show the QR code to the user

**You MUST present this to the user before proceeding to Step 4.**

Output the `qrCode` value from the JSON directly as text in your response inside a code block so the user can see and scan it. Also show the deep link as a fallback.

Example output:
> Scan this QR code with your Alien App:
> ```
> <qrCode value from JSON>
> ```
> Or open this link: <deepLink>

### Step 4: Wait for approval

```bash
node CLI bind --no-require-owner-proof
```

**This blocks** for up to 5 minutes while the user scans the QR code. On success:
```json
{"ok": true, "ownerSessionSub": "0x...", "bindingId": "...", "fingerprint": "..."}
```

Note: `--no-require-owner-proof` is needed because some Alien App versions don't yet return the session proof in the OAuth callback. The binding is still valid — it just won't include the embedded session signature proof.

If it fails (timeout, rejection, expired session), run `auth` again from Step 2.

### Step 5: Set up git signing

```bash
node CLI git-setup
```

This configures git in the current repository to:
- Sign all commits with your Agent ID key (SSH signature)
- Use your agent identity as the committer

The command outputs an SSH public key. **Tell the user:**
> "To get the 'Verified' badge on GitHub, add this SSH public key to your GitHub account:
> Go to GitHub → Settings → SSH and GPG keys → New SSH key → Key type: **Signing Key**
>
> `ssh-ed25519 AAAAC3...`"

The user only needs to do this once per agent keypair.

**Done.** Your Agent ID is active and git signing is configured.

## 6) Making signed commits

### Option A: Use `git-commit` (recommended)

```bash
node CLI git-commit --message "feat: implement auth flow"
```

This creates a commit that is:
1. **SSH-signed** with your Ed25519 key (git verifies this)
2. **Tagged with trailers** linking to your identity and human owner:
   ```
   Agent-ID-Fingerprint: 945d41991dac1187...
   Agent-ID-Owner: 0xabc123...
   Agent-ID-Binding: uuid-here
   ```
3. **Logged in your audit trail** with a hash-chained signed record

Each `git-commit` also attaches a **proof bundle** as a git note (`refs/notes/agent-id`). This contains the agent's public key, owner binding, and SSO id_token — everything needed for anyone to verify the provenance chain without access to the agent's local state.

### Pushing commits and proof notes

Use `--push` to push the commit **and** proof notes in one step:
```bash
node CLI git-commit --message "feat: implement auth flow" --push
```

This handles the proof notes automatically — git notes share a single ref (`refs/notes/agent-id`) across all commits, so pushing them requires fetching and merging with the remote first. The `--push` flag takes care of this.

To push to a non-default remote:
```bash
node CLI git-commit --message "feat: something" --push --remote upstream
```

If you need to push notes separately (e.g., for commits already made):
```bash
git push origin refs/notes/agent-id
```
If that fails due to divergence, fetch and merge first:
```bash
git fetch origin refs/notes/agent-id:refs/notes/agent-id-remote
git notes --ref=agent-id merge refs/notes/agent-id-remote
git push origin refs/notes/agent-id
```

### Option B: Use normal `git commit`

Since `git-setup` sets `commit.gpgsign = true`, any `git commit` is automatically SSH-signed. This works but does not add the Agent ID trailers, audit log entry, or proof note.

### What the commit looks like on GitHub

```
✓ Verified  — This commit was signed with the committer's verified signature.

feat: implement auth flow

Agent-ID-Fingerprint: 945d41991dac118776409673019ed0fba36e13fc9d6b5534145f9e31128a3ec6
Agent-ID-Owner: 0x7a3f...session-address
Agent-ID-Binding: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Anyone can trace: **this code** → **this agent** (fingerprint) → **this human** (owner session) → **verified AlienID holder**.

## 7) Signing other operations

Beyond git commits, sign any significant action:

```bash
node CLI sign --type TOOL_CALL --action "bash.exec" --payload '{"command":"rm -rf /tmp/old"}'
node CLI sign --type API_CALL --action "deploy.trigger" --payload '{"env":"staging"}'
node CLI sign --type MESSAGE_SEND --action "slack.post" --payload '{"channel":"#ops"}'
```

Each signed operation is appended to the hash-chained audit log.

## 7b) Verifying commit provenance

To verify the full chain from a git commit back to its human owner:

```bash
node CLI git-verify --commit HEAD
```

This traces the provenance chain:
1. **SSH signature** — `git verify-commit` checks the commit signature
2. **Agent key match** — commit's `Agent-ID-Fingerprint` trailer matches the agent's stored key
3. **Owner binding** — agent's Ed25519-signed binding links the agent to a human owner
4. **SSO attestation** — the id_token's RS256 signature (verified against Alien SSO's JWKS) proves the SSO server attested the agent-to-human binding

Output includes a `summary` field like:
> "Commit a1b2c3d4e5f6 was signed by agent 945d41991dac... owned by 0x7a3f..."

If the commit has a proof note attached (via `git-commit`), verification is **fully self-contained** — no access to the agent's state directory needed. The proof is read from the git note. Falls back to local state if no note is found.

## 8) Command reference

| Command | Purpose | Blocking? |
|---------|---------|-----------|
| `status` | Check if Agent ID exists and is bound | No |
| `init` | Generate keypair (auto-called by `auth`) | No |
| `auth --provider-address <addr>` | Start OIDC auth, get QR page | No |
| `bind` | Poll for approval, create owner binding | **Yes** (up to 5 min) |
| `git-setup [--global] [--name N] [--email E]` | Configure git SSH signing | No |
| `git-commit --message "..." [--push]` | Signed commit with trailers + audit log; `--push` pushes commit and proof notes | No |
| `git-verify [--commit <hash>]` | Verify provenance: commit → agent → human | No |
| `sign --type T --action A --payload JSON` | Sign any operation | No |
| `verify` | Verify state chain integrity | No |
| `export-proof` | Export proof bundle to stdout | No |

### Common flags

| Flag | Default | Description |
|------|---------|-------------|
| `--state-dir <path>` | `~/.agent-id` | State directory (or set `AGENT_ID_STATE_DIR` env var) |
| `--provider-address <addr>` | — | Alien provider address (required for `auth`) |
| `--sso-url <url>` | `https://sso.alien-api.com` | SSO base URL |
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
├── audit/operations.jsonl     # Hash-chained signed operation log
├── owner-binding.json         # Owner binding (human ↔ agent link)
├── owner-session.json         # Session tokens (mode 0600)
├── nonces.json                # Per-agent nonce tracking
├── sequence.json              # Sequence counter
```

## 10) Error handling

| Error | Action |
|-------|--------|
| `No pending auth found` | Run `auth` before `bind` |
| `Alien SSO authorization session expired` | Run `auth` again |
| `User rejected Alien SSO authorization` | Ask user to try again |
| `Timed out waiting` | Run `auth` again, remind user to scan promptly |
| `Owner binding missing` | Complete auth + bind first |
| `git commit failed` | Check that `git-setup` was run and files are staged |
| `--provider-address is required` | Ask the user for the provider address |

## 11) Security

- Private keys stored with **0600** permissions
- **PKCE** prevents authorization code interception
- **Owner session proof** cryptographically binds the human's identity
- **Hash-chained audit log** — any tampering breaks the chain
- **Ed25519 SSH signatures** on commits provide non-repudiation
- Never expose `owner-session.json` (contains tokens)
