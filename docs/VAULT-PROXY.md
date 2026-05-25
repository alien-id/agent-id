# Credential Vault + Proxy

How Alien Agent ID lets an AI agent authenticate to external services **without ever seeing the credential value**.

- The **vault** (`plugins/agent-id-vault/`) holds typed, domain-scoped credential records in a single encrypted file with a LUKS-style slot construction.
- The **proxy** (`plugins/agent-id-proxy/`) holds the unlocked vault in memory, accepts HTTP requests on localhost, and injects credentials into outbound requests by type. The agent calls a local URL that names the credential and the upstream host; the proxy forwards over real HTTPS.

Companion docs:
- [vault-proxy-mvp-proposal.md](../documentation/agent-id/vault-proxy-mvp-proposal.md) — design proposal (locked decisions + deferred items)
- [Vault skill](../plugins/agent-id-vault/skills/agent-id-vault/SKILL.md) — operator-facing CLI reference
- [Proxy skill](../plugins/agent-id-proxy/skills/agent-id-proxy/SKILL.md) — operator-facing CLI reference

---

## Why

An AI agent's transcript, prompt cache, tool-call envelopes, and stdout are all potentially logged or replayable. Anywhere a credential value enters that path, it's compromised. The agent must be able to **identify** the credential it wants to use without ever **reading** its value.

The trust boundary:

```
+---------+    cred name    +---------+   real auth   +-----------+
|  Agent  | --------------> |  Proxy  | ------------> | Upstream  |
| (Claude |    (in URL or   |  (sep.  |  (HTTPS, full |  service  |
|  Code,  |    AgentVault   |  proc)  |   credential) |           |
|  MCP,   |    stub)        |         |               |           |
|  curl)  | <-------------- +---------+ <------------ +-----------+
              response                    response
```

- Agent sees: credential **names**, request URLs, response bodies.
- Proxy sees: vault ciphertext on disk, decryption keys in process memory only, real credentials at injection time.
- Vault on disk: opaque ciphertext, copyable between machines.

---

## Vault: portable format

One file at `~/.agent-id/vault.enc`. LUKS-style: a random master key encrypts the credential payload (AES-256-GCM). The master key is wrapped into one or more **slots**, each holding a different way to derive a key-encryption key (KEK).

```
+---------------------------------------------------+
| header: magic, version, cipher                    |
+---------------------------------------------------+
| slot 0  type=passphrase                           |
|   KEK = scrypt(passphrase, salt, N=32768, r=8)    |
|   wrapped_mk = AES-256-GCM(KEK, master_key)       |
+---------------------------------------------------+
| slot 1  type=agent-key  (optional, fast unlock)   |
|   KEK = HKDF-SHA256(agent_ed25519_sk, salt)       |
|   wrapped_mk = AES-256-GCM(KEK, master_key)       |
+---------------------------------------------------+
| slot 2..N  reserved for future KDFs (Argon2id,    |
|            hardware-backed, recovery)             |
+---------------------------------------------------+
| payload: AES-256-GCM(master_key, credentials.json)|
+---------------------------------------------------+
```

### Two unlock paths

1. **Agent-key slot (fast, unattended).** The proxy on the agent's own machine loads the main key from `~/.agent-id/keys/main.json`, HKDF-derives the KEK, and unwraps the master key in microseconds. No human in the loop. This is the default startup path on the machine that owns the agent identity.

2. **Passphrase slot (portable, attended).** scrypt-derive the KEK from the passphrase + slot salt; ~300 ms. Used the first time on a new machine, on shared agents, or as the recovery path if the agent key is rotated. The passphrase is entered via the **trusted-input channel** (`/dev/tty` on POSIX) so it never enters the agent's stdin pipe or transcript.

### Portability

The file is already AEAD-encrypted at rest — copy it to a second machine and `agent-id-vault import` accepts it. Type the passphrase once. Optionally `rekey add-agent-key` to bind the new machine's agent key in for unattended unlock from then on. Cloud backup is safe to the strength of the passphrase (scrypt N=32768 ≈ 30 ms/guess on commodity hardware).

### Migration from v4

v4.0.0 vaults used a single HKDF-derived key from the agent's main key — non-portable, no passphrase, no slots. `agent-id-vault migrate` reads the old per-credential files, generates a new master key, builds the slot construction, and writes `vault.enc`. The legacy directory is renamed to `vault.bak/`. Migrated records get the placeholder allowlist `["UNCONFIGURED.invalid"]` — the proxy refuses to inject them until real domains are attached via `agent-id-vault add`.

---

## Credential records

Each record carries:

```json
{
  "name": "github-pat",
  "type": "bearer",
  "domains": ["*.github.com", "api.github.com"],
  "upstreamScheme": "https",
  "description": "GitHub PAT for repo operations",
  "createdAt": 1779723989946,
  "updatedAt": 1779723989946,
  "lastUsedAt": null,
  "value": "ghp_xxx..."
}
```

- `name`: stub identifier (`[a-zA-Z0-9._-]{1,64}`). What the agent puts in URLs / stubs.
- `type`: how to materialize the credential into a request (see table below).
- `domains`: required, non-empty. Default-deny — the proxy refuses to inject anywhere not on this list. Supports literal hostnames and `*.<suffix>` wildcards.
- `upstreamScheme`: `"https"` (default) or `"http"` for legacy/internal services reachable over plain HTTP.
- Type-specific fields: `value` (bearer/header/query/cookie), `username`+`password` (basic), `headerName` (header), `paramName` (query), `cookieName` (cookie), `secret`+`period`+`digits`+`algorithm` (totp), `cookies` (cookie-jar), `otpHeader` (totp).

### Materialization table

| Type | Where the credential ends up |
|---|---|
| `bearer` | `Authorization: Bearer <value>` |
| `basic` | `Authorization: Basic <b64(user:pass)>` |
| `header` | `<headerName>: <value>` |
| `query` | URL query param `<paramName>=<value>` |
| `cookie` | `Cookie: <cookieName>=<value>` (appended to existing Cookie) |
| `cookie-jar` | `Cookie: k1=v1; k2=v2; …` (appended) |
| `totp` | `<otpHeader \|\| X-OTP-Code>: <6-digit RFC 6238 code>` |

---

## Proxy: two request shapes

The proxy listens on `127.0.0.1:48771` by default. It supports two request shapes; **URL-rewrite is the recommended path for new code**.

### Mode 1 — URL-rewrite (recommended, universal)

The agent calls a local URL that names the credential and the upstream:

```
http://<proxy>/<credname>/<upstream-host>/<path...>
```

The proxy:

1. Parses `<credname>`, validates it.
2. Looks up the credential in the vault. Missing → `400 credential_not_found`.
3. Parses `<upstream-host>` (may include `:port`).
4. Validates the host against `cred.domains`. Mismatch → `403 host_not_allowed`.
5. Builds `https://<upstream-host>/<path>` (or `http://` if `cred.upstreamScheme == "http"`).
6. Materializes the credential into the request based on its type.
7. Rewrites `Host`; strips `Origin` and `Referer` (which leak the proxy's localhost URL).
8. Forwards over real HTTPS using `https.request`. The system CA bundle verifies the upstream cert — **no TLS interception on our side, no local CA, no trust-store install.**

The proxy is the HTTPS client. The agent stops doing TLS to upstream entirely.

```bash
# GitHub
curl http://localhost:48771/github-pat/api.github.com/user

# OpenAI
curl -X POST http://localhost:48771/openai-key/api.openai.com/v1/chat/completions \
  -H 'Content-Type: application/json' -d '{...}'

# Internal service over plain HTTP (set upstreamScheme=http on the credential)
curl http://localhost:48771/intra-tok/intranet.corp.example/api/v2/things
```

### Mode 2 — HTTP_PROXY stub injection (legacy, HTTP only)

For agents that want the transparent `HTTP_PROXY` env path. The agent writes `AgentVault <name>` markers in headers or query parameters; the proxy substitutes them. Only works for plain HTTP upstream — HTTPS would require TLS MITM, which is out of scope.

```bash
export HTTP_PROXY=http://127.0.0.1:48771
curl -H 'Authorization: AgentVault github-pat' http://api.example.com/foo
```

New code should prefer Mode 1. Mode 2 stays for backward compatibility.

### CONNECT handling

`CONNECT <host>:<port>` tunnels are forwarded transparently — no MITM, no injection. Stubs left inside an HTTPS CONNECT tunnel will be sent to upstream untouched.

---

## Idle auto-lock

After `--idle-timeout` (default **12 h**, 1Password parity) of no traffic, the proxy zeroes the master key + drops decrypted credential records from process memory. Subsequent requests return `401 {error: "vault_locked", reason: "idle_timeout"}`. The proxy must be restarted to re-unlock:

```bash
agent-id-proxy stop && agent-id-proxy start --passphrase-file ~/.agent-id-pass
```

Override:

```bash
agent-id-proxy start --idle-timeout 30m       # tighter
agent-id-proxy start --idle-timeout never     # disable, for unattended agents
```

`agent-id-proxy status` reports the configured `idleTimeout`.

In-process re-unlock (`agent-id-proxy unlock` via a control socket) is the natural follow-up.

---

## Threat model

| Adversary capability | Outcome |
|---|---|
| Has vault file only | Must scrypt-brute-force the passphrase. Memory-hard, ~30 ms/guess at default params. |
| Has vault file + agent private key | Unlocks instantly via slot 1. Same threat model as the v4 vault. |
| Has running proxy process memory | Extracts master key + decrypted records. Mitigation: idle auto-lock. |
| Has agent's transcript | Sees credential names, request URLs, response bodies. **No credential values.** |
| Has the upstream URL the agent typed | Sees the upstream hostname (also visible in DNS / TLS SNI / access logs anyway). |
| On-path network attacker between proxy and upstream | Bounded by upstream's TLS — the proxy verifies the upstream cert against the system CA bundle. |
| On-path attacker between agent and proxy | Plain HTTP on `127.0.0.1` loopback. Same-host non-root user processes are the realistic concern; mitigation is OS file/socket perms. |
| Steal proxy CA private key | Not applicable. **There is no CA**, because we use URL-rewrite instead of TLS interception. |

---

## Operational scope and explicit non-goals (v1)

- **Inbound TLS interception is out of scope.** The proposal sketched a local-CA + system-trust-store install for full HTTPS_PROXY transparency. Shipping URL-rewrite mode eliminates the need: HTTPS upstream coverage without the CA-management blast radius. If/when transparent HTTPS_PROXY semantics become a hard customer ask, the spike is documented in the proposal.
- **No consent prompts.** Host allowlist is the only authorization gate in v1. Per-credential "agent X wants to use Y for Z" prompts on first use are a planned follow-up.
- **No in-process re-unlock.** Restart the proxy after idle lock. A control-socket `unlock` subcommand is the natural follow-up.
- **No browser proxying / form login / cookie auto-refresh.** Cookie-jar credentials can be imported and used, but expired-session re-login is the user's job.
- **POSIX trusted-input only.** Windows `CONIN$` direct open is not implemented in v1.

---

## File layout

```text
~/.agent-id/
├── keys/main.json           # Ed25519 agent keypair (mode 0600)
├── vault.enc                # Portable encrypted vault (mode 0600)
├── vault.bak/               # Legacy v4 vault dir, if migrated (mode 0700)
├── proxy.json               # Running-proxy state (pid, port, idleTimeoutMs)
├── proxy.log                # Append-only JSONL access log (no values, no bodies)
├── owner-session.json       # SSO tokens
└── …
```

---

## Quick reference

```bash
# Initialize
agent-id-vault init --passphrase-file ~/.agent-id-pass

# Add credentials
agent-id-vault add --name github-pat --type bearer \
  --domains '*.github.com,api.github.com' --value-file /tmp/tok
agent-id-vault add --name openai --type header --header-name X-Api-Key \
  --domains api.openai.com --value-env OPENAI_KEY

# Start the proxy
agent-id-proxy start --passphrase-file ~/.agent-id-pass

# Use a credential
curl http://localhost:48771/github-pat/api.github.com/user

# Portability
agent-id-vault export --out vault.enc           # copy to another machine
agent-id-vault import --in vault.enc            # install
agent-id-vault rekey add-agent-key              # bind local agent for fast unlock

# Manual export (use sparingly; prefer the proxy at runtime)
agent-id-vault show --name github-pat

# Migration from v4
agent-id-vault migrate --passphrase-file ~/.agent-id-pass
```
