# Alien Agent SSO

A system for giving AI agents verifiable identity, service authentication, and secure credential storage — all linked to a real human via the Alien Network.

## The problem

AI agents (Claude Code, OpenClaw, Cursor, Copilot, custom scripts) operate without identity. They can't prove who authorized them, can't authenticate to services on their own, and have no safe place to store credentials. Humans end up pasting API keys into chat, hardcoding secrets in configs, or giving agents unrestricted access.

## What Agent SSO provides

**1. Cryptographic identity** — Each agent gets an Ed25519 keypair linked to a verified human owner through Alien Network SSO. The human scans a QR code once; the agent has a permanent, verifiable identity.

**2. Service authentication** — Agents generate short-lived signed tokens (5-minute Ed25519 assertions) accepted by any service that imports the verification library. No API keys, no shared secrets.

**3. Credential vault** — Encrypted storage (AES-256-GCM) for external service credentials. The encryption key is derived from the agent's private key via HKDF. Only that specific agent instance can decrypt its own vault.

**4. Signed git commits** — Every commit is SSH-signed and tagged with trailers tracing back to the agent and its human owner. Proof bundles embedded as git notes make verification self-contained.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Human                                                          │
│  (AlienID holder)                                               │
│                                                                 │
│  1. Scans QR code with Alien App (one time)                     │
└────────────┬────────────────────────────────────────────────────┘
             │ OIDC approval
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Alien SSO (sso.alien-api.com)                                  │
│                                                                 │
│  • /oauth/authorize    Start OIDC flow, return deep link        │
│  • /oauth/poll         Agent polls for human approval           │
│  • /oauth/token        Exchange code for id_token + access_token│
│  • /oauth/userinfo     Query owner identity                     │
│  • /oauth/jwks         Public keys for signature verification   │
│                                                                 │
│  Refresh tokens allow agents to maintain sessions indefinitely  │
│  without further human interaction.                             │
└────────────┬────────────────────────────────────────────────────┘
             │ id_token + access_token
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Agent (Claude Code, OpenClaw, any AI with shell access)        │
│                                                                 │
│  ~/.agent-id/                                                   │
│  ├── keys/main.json          Ed25519 keypair (0600)             │
│  ├── owner-session.json      SSO tokens — id_token IS the       │
│  │                           chain attestation (0600)           │
│  ├── vault/                  Encrypted credentials (0600)       │
│  │   ├── github.json                                            │
│  │   ├── aws.json                                               │
│  │   └── ...                                                    │
│  ├── ssh/                    Git signing keys                   │
│  └── audit/operations.jsonl  Hash-chained operation log         │
│                                                                 │
│  Capabilities:                                                  │
│  • Sign git commits with provenance trailers                    │
│  • Generate auth tokens for Alien-aware services                │
│  • Store/retrieve encrypted credentials for external services   │
│  • Sign arbitrary operations for audit trail                    │
└────────────┬──────────────┬─────────────────────────────────────┘
             │              │
     Auth tokens       Vault credentials
             │              │
             ▼              ▼
┌────────────────┐  ┌───────────────────┐
│ Alien-aware    │  │ External services │
│ services       │  │ (GitHub, AWS,     │
│                │  │  Slack, etc.)     │
│ Verify agent   │  │                   │
│ Ed25519 token  │  │ Use stored API    │
│ inline — no    │  │ keys, OAuth       │
│ pre-            │  │ tokens, passwords │
│ registration   │  │                   │
└────────────────┘  └───────────────────┘
```

## How to give an agent these capabilities

### The skill file

The file `SKILL.md` in this repository contains everything an AI agent needs to bootstrap its identity, authenticate with services, and manage credentials. It is written as agent-facing instructions — the agent reads it and follows the steps autonomously.

To give any AI agent these capabilities, point it at the skill file.

### Claude Code

Add to your project's `CLAUDE.md`:

```markdown
## Agent Identity

Before making git commits or accessing authenticated services, read and follow
the skill file at /path/to/agent-id/SKILL.md to obtain your Agent ID.
```

Or reference it directly:

```markdown
Read /path/to/agent-id/SKILL.md and follow the bootstrap instructions.
```

Claude Code will:
1. Read `SKILL.md`
2. Run `node cli.mjs bootstrap`
3. Show you the QR code
4. Wait for you to scan with Alien App
5. Start signing commits and authenticating with services

### OpenClaw / other agents

Any agent that can run shell commands and read files can use this system. The agent needs:
- **Node.js 18+** available in the shell
- **Read access** to `SKILL.md` and the CLI files
- **Shell access** to run `node cli.mjs <command>`

Instruct the agent however that platform supports it — system prompt, instructions file, initial message — to read `SKILL.md` and follow the bootstrap steps.

### CI/CD

```yaml
# GitHub Actions example
- name: Bootstrap agent identity
  env:
    ALIEN_PROVIDER_ADDRESS: ${{ secrets.ALIEN_PROVIDER_ADDRESS }}
  run: node /path/to/agent-id/cli.mjs bootstrap
```

In CI, the bootstrap will block waiting for QR approval. For attended CI (developer watches the run), the QR link is printed to the log. For unattended CI, pre-bootstrap on the runner and persist `~/.agent-id/` across runs.

### Environment variables

| Variable | Purpose |
|---|---|
| `ALIEN_PROVIDER_ADDRESS` | Provider address (avoids `--provider-address` flag) |
| `AGENT_ID_STATE_DIR` | Custom state directory (default: `~/.agent-id`) |

The provider address can also be set in `default-provider.txt` next to the CLI.

## SSO flow in detail

### What happens during bootstrap

```
Agent                              Alien SSO                    Human
  │                                   │                           │
  │  1. Generate Ed25519 keypair      │                           │
  │     (stored in ~/.agent-id/)      │                           │
  │                                   │                           │
  │  2. GET /oauth/authorize ────────►│                           │
  │     client_id = provider_address  │                           │
  │     code_challenge = PKCE hash    │                           │
  │◄──── deep_link, polling_code ─────│                           │
  │                                   │                           │
  │  3. Open QR page in browser ──────┼──────────────────────────►│
  │     (or print deep link)          │                           │
  │                                   │    4. Scan QR with        │
  │                                   │       Alien App           │
  │                                   │◄─── approve ──────────────│
  │                                   │                           │
  │  5. POST /oauth/poll ────────────►│                           │
  │     (repeats every 3s, up to 5m)  │                           │
  │◄──── authorization_code ──────────│                           │
  │                                   │                           │
  │  6. POST /oauth/token ───────────►│                           │
  │     code + PKCE verifier          │                           │
  │◄──── id_token (RS256 JWT) ────────│                           │
  │      access_token, refresh_token  │                           │
  │                                   │                           │
  │  7. Verify id_token signature     │                           │
  │     against SSO JWKS (RFC 7519,   │                           │
  │     RFC 9449 §6.1 cnf.jkt)        │                           │
  │                                   │                           │
  │  8. Create owner binding:         │                           │
  │     Sign {agent_key, owner_sub,   │                           │
  │     id_token_hash, hostname}      │                           │
  │     with agent's Ed25519 key      │                           │
  │                                   │                           │
  │  9. Configure git SSH signing     │                           │
  │                                   │                           │
  │  ✓ Done. Agent has identity.      │                           │
```

### What the agent gets

After bootstrap, the agent holds:

- **Ed25519 keypair** — for signing operations, auth tokens, and git commits
- **Owner binding** — cryptographic proof that `agent_key X` is authorized by `human Y`, signed by the agent and attested by the SSO server
- **id_token** — RS256 JWT from Alien SSO, proving the SSO server witnessed the binding (valid for 30 days; signature remains verifiable after expiry)
- **access_token** — short-lived JWT for SSO API calls (refreshable)
- **refresh_token** — long-lived token to renew access without human interaction
- **SSH signing config** — git configured to sign all commits with the agent's key

### Trust chain

Anyone can verify an agent's identity by tracing the provenance chain:

```
Git commit (SSH signature)
  └─► Agent public key (fingerprint in commit trailer)
        └─► Owner binding (Ed25519 signature by agent)
              └─► id_token (RS256 signature by Alien SSO)
                    └─► Alien SSO JWKS (public keys)
                          └─► Verified AlienID holder (human)
```

Every link is cryptographically verifiable. Proof bundles embedded as git notes make verification self-contained — no access to the agent's local state needed.

## Credential storage flow

### Overview

The vault stores credentials for external services (GitHub, AWS, Slack, etc.) encrypted with a key derived from the agent's Ed25519 private key. This means:

- Credentials are encrypted at rest (AES-256-GCM)
- Only the agent that stored them can decrypt them
- The encryption key never leaves the agent's machine
- If the agent's keypair is deleted, the credentials are irrecoverable

### How credentials get into the vault

There are three parties involved: the **human** (who has the credential), the **agent** (who needs to use it), and the **vault** (encrypted storage on the agent's machine).

#### Flow: human provides credential to agent

```
Human                              Agent                         Vault
  │                                  │                             │
  │  "I need a GitHub token          │                             │
  │   to create pull requests"       │                             │
  │◄─────────────────────────────────│                             │
  │                                  │                             │
  │  Option A (most secure):         │                             │
  │  $ echo 'ghp_xxx' > /tmp/tok    │                             │
  │  $ chmod 600 /tmp/tok            │                             │
  │  "It's in /tmp/tok"             │                             │
  │─────────────────────────────────►│                             │
  │                                  │  vault-store                │
  │                                  │  --credential-file /tmp/tok │
  │                                  │────────────────────────────►│
  │                                  │  (encrypt + store)          │
  │                                  │◄────────────────────────────│
  │                                  │  rm /tmp/tok                │
  │                                  │                             │
  │  Option B (env var):             │                             │
  │  $ export GH=ghp_xxx            │                             │
  │  "Variable name is GH"          │                             │
  │─────────────────────────────────►│                             │
  │                                  │  vault-store                │
  │                                  │  --credential-env GH        │
  │                                  │────────────────────────────►│
  │                                  │◄────────────────────────────│
  │                                  │                             │
  │  Option C (paste in chat):       │                             │
  │  "Here: ghp_xxx"                │                             │
  │─────────────────────────────────►│                             │
  │                                  │  echo 'ghp_xxx' |           │
  │                                  │  vault-store --service gh   │
  │                                  │────────────────────────────►│
  │                                  │◄────────────────────────────│
  │                                  │                             │
  ▼                                  ▼                             ▼
  One-time action.                   All future sessions can       Encrypted
  Human doesn't need to              retrieve the credential       with agent's
  provide it again.                  from the vault.               Ed25519 key.
```

#### Security properties of each method

| Method | Secret in `ps`? | In shell history? | In chat log? |
|---|---|---|---|
| `--credential-file` | No | No | No |
| `--credential-env` | No | Depends on shell | No |
| stdin pipe | No | The `echo` line, yes | No |
| `--credential` | **Yes** | **Yes** | No |
| Paste in chat | No | No | **Yes** |

The agent is instructed (via SKILL.md) to prefer `--credential-file` and offer all options to the human in order of security.

#### Flow: agent uses stored credential

```bash
# Agent retrieves credential, uses it for API call
TOKEN=$(node cli.mjs vault-get --service github | jq -r .credential)
curl -H "Authorization: Bearer $TOKEN" https://api.github.com/user/repos
```

The credential is decrypted in memory, used for the API call, and never written to disk in plaintext.

### Vault encryption details

```
Agent's Ed25519 private key (PKCS8 DER)
  │
  ▼ HKDF-SHA256 (salt: "agent-id-vault-v1", info: "vault-encryption")
  │
  ▼ 256-bit symmetric key
  │
  ▼ AES-256-GCM (random 96-bit IV per credential)
  │
  ▼ Ciphertext + 128-bit authentication tag
  │
  ▼ Stored as JSON: { iv, data, tag } (hex-encoded, mode 0600)
```

## Service authentication

### For Alien-aware services

Services verify agents with RFC 9449 DPoP. Per request the agent sends two headers:

```
Authorization: DPoP <access_token>
DPoP: <proof JWT>
```

The access_token (RFC 9068 `at+jwt`) is issued by Alien SSO and carries the standard claims that
attest the owner ↔ agent chain:

| Claim | Meaning |
|---|---|
| `sub` | Owner's AlienID address |
| `aud` | Target service identifier |
| `iss` | `https://sso.alien-api.com` |
| `exp` | Access-token expiry |
| `cnf.jkt` | JWK SHA-256 thumbprint of the agent's Ed25519 public key (RFC 7800 §3.1) |

The agent generates the per-request proof for a specific method and URL:

```bash
node cli.mjs auth-header --url https://service.example.com/api/whoami --method GET
# → Authorization: DPoP <access_token>
# → DPoP: <proof JWT>
```

Service-side verification walks RFC 9449 §4.3:

1. Exactly one `Authorization: DPoP <at>` and one `DPoP: <proof>` header.
2. Proof is a JWS with `typ=dpop+jwt`, `alg=EdDSA`, and an OKP/Ed25519 `jwk` (no private `d`) in the header.
3. EdDSA signature over the proof verifies against the embedded JWK.
4. `htm` equals the request method byte-for-byte; `htu` equals the reconstructed `<origin><pathname>` (no query, no fragment).
5. `iat` is within ±`PROOF_MAX_AGE_SEC` (default 30s); `jti` not seen before.
6. Parse access_token; validate `typ`/`alg`, verify signature against SSO JWKS.
7. Claim checks: `iss == expectedIss`, optional `aud` allow-list, `exp > now`, non-empty `sub`.
8. RFC 9449 §6.1: `at.cnf.jkt === jwkThumbprint(proof.header.jwk)`.
9. RFC 9449 §4.3 step 10: `proof.ath === b64url(sha256(access_token))`.

Owner identity, agent identity, and proof-of-possession come from signed standard claims. No
custom envelope, no key pre-registration.

### For services to integrate

Use `verifyDPoPRequest` from
[`@alien-id/sso-agent-id`](https://www.npmjs.com/package/@alien-id/sso-agent-id):

```javascript
import { verifyDPoPRequest } from "@alien-id/sso-agent-id";

// In your HTTP handler:
const result = verifyDPoPRequest(
  { method: req.method, url: req.url, headers: req.headers },
  { jwks: await getSsoJwks(), expectedAudience: process.env.SERVICE_AUDIENCE },
);
if (!result.ok) {
  return res
    .status(401)
    .set("WWW-Authenticate", `DPoP error="invalid_token", error_description="${result.code}"`)
    .json(result);
}

// result.sub               — owner's AlienID address (from access_token.sub)
// result.jkt               — agent key thumbprint (from access_token.cnf.jkt)
// result.accessTokenClaims — full verified access_token payload
// result.proofClaims       — full verified DPoP proof payload
```

A working demo service is included in `examples/demo-service.mjs`.

### For external services

External services (GitHub, AWS, Slack) don't know about Agent ID tokens. The agent authenticates to them using credentials stored in the vault:

```bash
# Retrieve stored credential
node cli.mjs vault-get --service github
# → {"credential": "ghp_xxx", "type": "api-key", ...}

# Use it
curl -H "Authorization: Bearer ghp_xxx" https://api.github.com/...
```

## Files in this repository

| File | Purpose |
|---|---|
| `SKILL.md` | Agent-facing instructions — give this to any AI agent |
| `AGENT-SSO.md` | This file — system documentation for humans |
| `cli.mjs` | CLI tool — all agent operations |
| `lib.mjs` | Core library — crypto, OIDC, vault, token verification |
| `examples/demo-service.mjs` | Demo HTTP service with agent authentication |
| `default-provider.txt` | Default provider address |
| `package.json` | Package metadata (zero dependencies) |
| `README.md` | Project overview |

## Quick reference

```bash
# Bootstrap (one command, requires human QR scan once)
node cli.mjs bootstrap

# Check status
node cli.mjs status

# Store a credential securely
echo 'ghp_xxx' > /tmp/tok && chmod 600 /tmp/tok
node cli.mjs vault-store --service github --type api-key --credential-file /tmp/tok
rm /tmp/tok

# Retrieve a credential
node cli.mjs vault-get --service github

# Generate auth token for service calls
node cli.mjs auth-header --raw

# Sign a git commit with provenance
node cli.mjs git-commit --message "feat: something" --push

# Verify a commit's provenance chain
node cli.mjs git-verify --commit HEAD

# Start the demo service
node examples/demo-service.mjs
```
