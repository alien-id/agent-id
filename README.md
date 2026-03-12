# Agent ID

Verifiable cryptographic identity for AI agents, linked to human owners via [Alien Network](https://alien.id) SSO.

When an AI agent has an Agent ID, every git commit it makes is SSH-signed and carries trailers that trace back to the specific agent and the human who authorized it. The provenance chain is fully verifiable: **commit → agent key → owner binding → SSO attestation → verified AlienID holder**.

## How it works

```
┌─────────┐      ┌───────────┐      ┌───────────┐      ┌───────────┐
│ AI Agent │──1──▶│ Alien SSO │──2──▶│ Alien App │──3──▶│ Alien SSO │
│          │◀─4──│           │      │  (human)  │      │           │
└─────────┘      └───────────┘      └───────────┘      └───────────┘
     │
     ▼
  Agent ID bound ──▶ SSH-signed git commits with provenance trailers
```

1. Agent starts OIDC auth, gets a QR code / deep link
2. Human scans QR with Alien App
3. Human approves, Alien App calls back to SSO
4. Agent exchanges tokens, creates cryptographic owner binding

The agent now has an Ed25519 keypair with a signed binding proving a verified human authorized it.

## What's in the box

| File | Purpose |
|------|---------|
| `SKILL.md` | Instructions for AI agents — point your agent here |
| `cli.mjs` | CLI tool the agent runs (`status`, `auth`, `bind`, `git-setup`, `git-commit`, `git-verify`, etc.) |
| `lib.mjs` | Portable library — crypto, OIDC, signing engine, verification (zero npm deps) |
| `package.json` | Minimal metadata |

## Quick start

### 1. Tell your agent to use the skill

**Claude Code** — add to your project's `.claude/settings.json` or `CLAUDE.md`:

```
Read /path/to/agent-id/SKILL.md and follow the instructions to obtain an Agent ID before making commits.
```

Or reference it in a prompt:

```
Before writing any code, read /path/to/agent-id/SKILL.md and obtain an Agent ID.
Use provider address: <YOUR_PROVIDER_ADDRESS>
```

**Any other agent with shell access** — the agent reads `SKILL.md`, which contains step-by-step instructions and exact shell commands. The agent needs:
- Shell access with Node.js 18+ and git 2.34+
- Permission to run `node cli.mjs ...` commands

### 2. The agent does the rest

The agent follows the skill file to:
1. Generate an Ed25519 keypair
2. Start OIDC auth and show you a QR code
3. You scan with Alien App and approve
4. Agent creates the owner binding
5. Agent configures git SSH signing
6. Every commit is now signed with provenance trailers

### 3. Add the signing key to GitHub

The agent will output an SSH public key after `git-setup`. Add it to your GitHub account:

**GitHub → Settings → SSH and GPG keys → New SSH key → Key type: Signing Key**

Commits will show a "Verified" badge.

## What a signed commit looks like

```
✓ Verified

feat: implement auth flow

Agent-ID-Fingerprint: 945d41991dac118776409673019ed0fba36e13fc9d6b5534145f9e31128a3ec6
Agent-ID-Owner: 00000003010000000000539c741e0df8
Agent-ID-Binding: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Anyone can trace: **this code** → **this agent** (fingerprint) → **this human** (owner address) → **verified AlienID holder**.

## Verifying provenance

```bash
node cli.mjs git-verify --commit HEAD
```

Verification is **self-contained** — `git-commit` attaches a proof bundle as a git note (`refs/notes/agent-id`) containing the agent's public key, owner binding, and SSO id_token. Anyone who clones the repo and fetches the notes can verify the full chain without access to the agent's machine.

```bash
# Fetch proof notes from remote
git fetch origin refs/notes/agent-id:refs/notes/agent-id

# Verify any commit
node cli.mjs git-verify --commit abc123
```

The verification chain:
1. **SSH signature** — commit is signed, verified against the agent's public key from the proof note
2. **Agent fingerprint** — public key hash matches the `Agent-ID-Fingerprint` trailer
3. **Owner binding** — Ed25519-signed by the agent, links agent to human owner
4. **id_token hash** — binding contains the hash of the SSO id_token, proving they're linked
5. **SSO attestation** — id_token RS256 signature verified against Alien SSO's JWKS

Falls back to the agent's local state (`~/.agent-id/`) if no git note is found.

## Prerequisites

- **Node.js 18+** (uses built-in `crypto`, `fetch`, `fs` — zero npm dependencies)
- **git 2.34+** (SSH commit signing support)
- **Alien App** with a verified AlienID
- **Provider address** — an Alien provider address registered in the [Developer Portal](https://developer.alien.id)

## Agent state

All state is stored in `~/.agent-id/` (configurable via `--state-dir` or `AGENT_ID_STATE_DIR`):

```
~/.agent-id/
├── keys/main.json           # Ed25519 keypair (mode 0600)
├── ssh/                     # SSH key files for git signing
├── owner-binding.json       # Cryptographic human ↔ agent link
├── owner-session.json       # SSO tokens (mode 0600)
└── audit/operations.jsonl   # Hash-chained signed operation log
```

## CLI commands

| Command | Purpose |
|---------|---------|
| `status` | Check if Agent ID exists and is bound |
| `auth --provider-address <addr>` | Start OIDC auth, get QR page |
| `bind` | Poll for user approval, create owner binding |
| `git-setup` | Configure git SSH signing with agent key |
| `git-commit --message "..."` | Signed commit with trailers + audit log |
| `git-verify [--commit <hash>]` | Verify provenance chain of a commit |
| `sign --type T --action A --payload JSON` | Sign any operation |
| `verify` | Verify state chain integrity |
| `export-proof` | Export proof bundle |

Run `node cli.mjs --help` for all flags.

## Security

- Private keys stored with `0600` permissions
- PKCE prevents authorization code interception
- Owner binding is Ed25519-signed by the agent's key
- SSO id_token (RS256) provides server attestation of the human-agent link
- Hash-chained audit log — any tampering breaks the chain
- `owner-session.json` contains tokens — never commit or share it
