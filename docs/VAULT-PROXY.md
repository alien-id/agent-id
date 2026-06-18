# Credential Vault + Proxy

How Alien Agent ID lets an AI agent authenticate to external services **without ever seeing the credential value**.

- The **vault** (`plugins/agent-id-vault/`) holds typed, domain-scoped credential records in a single encrypted file with a LUKS-style slot construction.
- The **proxy** (`plugins/agent-id-proxy/`) holds the unlocked vault in memory, accepts HTTP requests on localhost, and injects credentials into outbound requests by type. The agent calls a local URL that names the credential and the upstream host; the proxy forwards over real HTTPS.

Companion docs:
- [vault-proxy-mvp-proposal.md](../documentation/agent-id/vault-proxy-mvp-proposal.md) — design proposal (locked decisions + deferred items)
- [Vault skill](../plugins/agent-id-vault/skills/agent-id-vault/SKILL.md) — operator-facing CLI reference
- [Proxy skill](../plugins/agent-id-proxy/skills/agent-id-proxy/SKILL.md) — operator-facing CLI reference
- [Clean-room demo](../examples/clean-room-demo/) — consumer-facing skill: how an agent *uses* vaulted credentials (starts the proxy, calls the service, phone-approved unlock) without ever seeing a secret

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

## For AI Agents: The Proxy Interface

AI agents should not handle credentials, API keys, or OAuth2 tokens. Instead, they interact with the proxy using a **credential-naming contract**.

### The URL Contract

To make an authenticated request, the agent replaces the upstream HTTPS URL with a local proxy URL:

```
http://localhost:48771/<credential-name>/<upstream-host>/<path>
```

- **credential-name**: the vault name of the credential to use (e.g. `github-pat`, `openai-key`).
- **upstream-host**: the real host (and optional port) of the target service (e.g. `api.github.com`, `api.openai.com`).
- **path**: the rest of the URL, including query parameters.

**Example: GitHub API**

| | URL |
|---|---|
| Upstream | `https://api.github.com/user` |
| Proxy call | `http://localhost:48771/github-pat/api.github.com/user` |

**Example: OpenAI**

| | URL |
|---|---|
| Upstream | `https://api.openai.com/v1/chat/completions` |
| Proxy call | `http://localhost:48771/openai-key/api.openai.com/v1/chat/completions` |

### Mental Model Shift

- **Old way**: *"I need my GitHub PAT to call this API. I will add `Authorization: Bearer ghp_xxx` to my request."*
- **New way**: *"I want to use the `github-pat` credential to talk to `api.github.com`. I will send the request to the proxy."*

The agent never sees the token value, never manages refresh cycles, never handles `401` responses due to expired tokens. The proxy handles the auth mechanism (Bearer, Basic, OAuth2 refresh) transparently.

### Rules for Agents

1. **No secrets in prompts.** Never ask the user for a key. Never print a key to stdout or a transcript.
2. **Use named credentials.** Only reference names present in the vault (e.g. `openai-key`, `github-pat`). If you need a new credential, ask the user to add it via `agent-id-vault add`.
3. **Trust the proxy.** If the proxy returns `403 host_not_allowed`, the credential is not scoped for that domain — don't try to work around it. If you get `401 vault_locked`, the proxy needs to be restarted or unlocked.

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
| slot 2  type=mobile     (phone-approved unlock)   |
|   KEK = HKDF(ECDH(ephemeral, device_enclave_pk))  |
|   wrapped_mk = AES-256-GCM(KEK, master_key)       |
+---------------------------------------------------+
| slot 3  type=owner-approval (SSO-escrowed unlock) |
|   KEK = random 32 bytes, escrowed with the SSO    |
|   (slot stores only an opaque keyRef, never KEK)  |
|   wrapped_mk = AES-256-GCM(KEK, master_key)       |
+---------------------------------------------------+
| payload: AES-256-GCM(master_key, credentials.json)|
+---------------------------------------------------+
```

Slots 0–1 are **startup** unlock (below); slots 2–3 are **re-unlock-while-running** approvals driven over the control plane ([Re-unlock without restart](#re-unlock-without-restart-the-control-plane)).

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
- Type-specific fields: `value` (bearer/header/query/cookie), `username`+`password` (basic), `headerName` (header), `paramName` (query), `cookieName` (cookie), `secret`+`period`+`digits`+`algorithm` (totp), `cookies` (cookie-jar), `otpHeader` (totp), `tokenEndpoint`+`clientId`+`refreshToken`+`clientSecret?`+`scope?` (oauth2).

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
| `oauth2` | `Authorization: Bearer <access token>` — refreshed on demand from the stored refresh token |
| `solana-keypair` | ed25519 signature filled into the `sendTransaction` JSON-RPC body |
| `evm-keypair` | `eth_sendTransaction` → signed EIP-1559 `eth_sendRawTransaction` |

#### oauth2: refresh-on-demand

An `oauth2` credential stores a long-lived refresh token plus the client
credentials and token endpoint needed to mint short-lived access tokens. On each
request the proxy serves a cached access token, or — when it is missing or within
60 s of expiry — POSTs `grant_type=refresh_token` to `tokenEndpoint` (RFC 6749
§6), caches the result, and injects it as a bearer. Concurrent requests for the
same credential share one in-flight refresh. A rotated refresh token is written
back to the vault. `invalid_grant` (refresh token revoked/expired) surfaces as
`401 oauth_refresh_token_invalid` — re-mint the token; any other token-endpoint
failure is `502 oauth_refresh_failed`. The agent sees none of this — only the
credential name in its URL. `tokenEndpoint` must be `https` (loopback allowed for
local dev). URL-rewrite mode only; the legacy stub path cannot do the async
refresh. Cached access tokens are zeroed on idle-lock.

### Wallet credentials: keys that are BORN in the vault

`solana-keypair` and `evm-keypair` records are not imported — they are
**generated inside the vault process** by `agent-id-vault generate` and sealed
(`exportable: false`):

- `generate` prints only the public address (`publicKey` base58 for Solana,
  EIP-55 `address` for EVM). `list` carries it too.
- `show` redacts the private key; `add` refuses the type outright. There is no
  code path that emits the key material.
- The only way to *use* the key is transaction signing inside the proxy, gated
  by the record's RPC-host allowlist.

```bash
agent-id-vault generate --name sol-hot --type solana-keypair \
  --domains api.mainnet-beta.solana.com
# → Address: A2Rc…Tpzk   (the seed never leaves the vault)

agent-id-vault generate --name polygon-hot --type evm-keypair \
  --domains polygon-bor-rpc.publicnode.com
# → Address: 0x1135…485f
```

At request time the credential materializes **inside the JSON-RPC body**, not
in a header:

- **Solana** — the agent submits a normal `sendTransaction` carrying an
  *unsigned* transaction (base58/base64 per the request's own `encoding`); the
  proxy fills every signature slot whose account key matches the vaulted key
  and forwards. Legacy and v0 messages are supported; existing co-signatures
  (e.g. an x402 facilitator fee-payer) are preserved — partial signing works.
  All other methods (`getBalance`, `getLatestBlockhash`, …) pass through.
- **EVM** — the agent submits `eth_sendTransaction` with an explicit tx object
  (`chainId`, `nonce`, `gas`, `maxFeePerGas`, `maxPriorityFeePerGas`,
  `to`/`value`/`data`); the proxy signs an EIP-1559 transaction (RFC 6979
  deterministic ECDSA, low-s) and forwards it as `eth_sendRawTransaction`. A
  `from` field, if present, must equal the credential address.

The agent-visible artifacts — request URLs, unsigned transactions, signatures,
tx hashes — are all public-by-design data (they land on chain anyway). The
access log records `solana_signed` / `evm_signed` events with signatures / tx
hashes, never key material.

See `examples/solana-transfer-via-proxy.mjs` for the full agent-side flow
(blockhash → build unsigned → submit via proxy → confirm), verified end-to-end
on Solana and Polygon mainnet.

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

After `--idle-timeout` (default **12 h**, 1Password parity) of no traffic, the proxy zeroes the master key **and the whole decrypted credential payload** (every bearer/cookie/password and wallet private key) from process memory. A subsequent request to a locked vault doesn't hard-fail: if the vault carries a re-unlock slot (mobile or owner-approval) and the control plane is on, the request **parks** and an approval re-unlocks it without restarting (see the next section). With no re-unlock slot it returns `401 {error: "vault_locked"}` and the proxy must be restarted:

```bash
agent-id-proxy stop && agent-id-proxy start --passphrase-file ~/.agent-id-pass
```

Override:

```bash
agent-id-proxy start --idle-timeout 30m       # tighter
agent-id-proxy start --idle-timeout never     # disable, for unattended agents
```

`agent-id-proxy status` reports the configured `idleTimeout`.

---

## Re-unlock without restart: the control plane

When the vault is locked — after idle-lock, or when started locked with `--await-mobile` — a request doesn't fail. The proxy **parks** it and asks for an approval over a second listener, the **control plane** (default `127.0.0.1:48772`). Two slot types can satisfy the approval: a **mobile** slot (a phone's Secure-Enclave key) or an **owner-approval** slot (a KEK escrowed with the Alien SSO). In both cases the approver POSTs the recovered master key to `/approve` and the parked request completes.

### Control-plane security

- **Loopback by default.** The control plane binds to `--control-host` (default `127.0.0.1`), independent of the data-plane `--host` — so `--host 0.0.0.0` does **not** expose it.
- **Token-gated.** `/pending`, `/approve`, `/deny`, `/register` require a bearer token (auto-generated at start, written to the `0600` proxy state file). `/status` stays open for liveness. A co-resident process or LAN host cannot drive an approval or pair a device without the token.
- **The master key is never sent in cleartext.** `/approve` accepts *only* a master key **sealed** (ECDH-P256 + HKDF + AES-256-GCM) to the proxy's per-run control-plane public key — there is no plaintext path. The approver pins that public key out-of-band (it's in the pairing QR), so an on-path attacker can't substitute their own and capture the key.
- **Network exposure runs over TLS.** When the control plane is bound beyond loopback it serves **HTTPS** with a per-run self-signed cert (loopback stays plain HTTP — there's no network to sniff). There's no CA and no trust-store install: the approver/phone **pins the cert's SHA-256 fingerprint**, which it gets from the pairing QR. So the bearer token (and everything else) is encrypted on the wire and the connection is authenticated to the right proxy by the pinned fingerprint. `--control-tls` forces TLS on loopback too; `--no-control-tls` opts out (only sane on loopback).

### Owner-approval slot — recommended for a separate approver

The master key is wrapped by a random 32-byte KEK that is **escrowed with the Alien SSO**; the vault file stores only an opaque `keyRef`, never the KEK. A stolen `vault.enc` is therefore inert — the only thing that can unwrap the slot lives behind an owner approval at the SSO. The KEK is released **once per approval**, bound to the owner and the enrolling agent key.

**Enroll once** (needs an owner session from `agent-id-core auth`):

```bash
agent-id-vault rekey add-owner-approval
# mint KEK → POST /vault/enroll (DPoP + owner-token bound) → SSO returns keyRef
# → wrap the master key with the KEK, store the slot → zero the KEK locally
```

**Unlock at runtime** — the proxy drives it itself; no phone app runs on the proxy host:

```
agent     → locked proxy             request parks
proxy     → control /pending         surfaces the owner-approval keyRef (no secret)
approver  → SSO /vault/unlock/start  (DPoP + access-token bound)
              SSO checks jkt+sub match the enrolled keyRef, PUSHES a prompt to the
              owner's Alien app, returns { polling_code, deep_link }
owner taps Approve in the Alien app
approver  → SSO /vault/unlock/poll   → status "authorized" → one-time KEK  (over TLS)
approver  unwraps the slot locally → master key → POST 127.0.0.1/approve
agent     ← 200                       parked request completes
```

Why this is the sound separate-device path:

- **No phone↔proxy link.** The phone talks to the SSO; the proxy talks to the SSO. They need not share a network — the phone can be on cellular.
- **No master key on the network.** The SSO releases a *KEK* over **TLS** (`assertTransportSafe` enforces https; loopback exempt for dev). The proxy unwraps the slot itself, so the master key crosses only **loopback inside the proxy process**.
- **Bound + replay-resistant.** Every SSO call carries a single-use DPoP proof (`jti` cache) plus the owner access token; the SSO binds the `keyRef` to the enrolling agent key — a foreign key gets `403`, an unknown `keyRef` `404`. The approver pins the SSO URL to the locally-trusted owner session, never the slot's cleartext field, so a tampered vault can't redirect the owner's access token.

**Status / caveat.** The escrow contract (`/vault/enroll`, `/vault/unlock/{start,poll}`) and the human push are implemented in this repo **only by `examples/dev-sso.mjs`, which auto-approves** (no human, no real app) for the tests. The client half — slot crypto, the DPoP-bound SSO client, and the proxy wiring — is real and tested; real-world use depends on the production Alien SSO shipping these endpoints plus the app-side approval.

### Mobile slot — phone Secure Enclave, over TLS

A `mobile` slot seals the master key to a phone's P-256 Secure-Enclave key (ephemeral ECDH + HKDF). To unlock, the phone recomputes the shared secret, unseals the master key, **re-seals it to the proxy's control-plane key** (from the pairing QR), and POSTs that sealed box to `/approve` over the **TLS** control plane. So both the master key (sealed) and the channel (TLS, cert pinned via the QR) are protected end-to-end — nothing sensitive crosses the LAN in cleartext.

`agent-id-proxy pair` shows a QR / `alien-vault://pair` deep-link carrying the control URL, token, the proxy's seal public key, **and the TLS cert fingerprint to pin**. It refuses to print a loopback URL (a separate device can't reach `127.0.0.1`). To use it:

```bash
agent-id-proxy start --control-host 0.0.0.0   # non-loopback → control plane on HTTPS
agent-id-proxy pair                            # QR: https URL + token + pk + cert fingerprint
```

Two practical notes:

- **The cert is per-run** (regenerated each restart), as are the token and seal key, so a paired phone re-pairs after a proxy restart.
- **Owner-approval is still the lighter-weight separate-device path** — it needs no phone↔proxy network link at all (the phone and proxy each talk to the SSO). Reach for mobile when you specifically want the phone's Secure Enclave to hold the unlock key.

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
| Reach the control plane (local process or LAN host) | Loopback-bound by default; mutating routes require the bearer token. The master key on `/approve` is always sealed to the proxy's pinned key. A network-exposed plane runs over TLS (self-signed, fingerprint pinned via the QR), so the token isn't sniffable either. Residual: the pin trusts the QR's out-of-band channel, and a stolen token is replayable until the proxy restarts (new token). |
| Drive the agent to hit an internal/metadata host | SSRF guard refuses link-local (incl. `169.254.169.254`), unspecified, and multicast upstreams; `--block-private-hosts` adds loopback/RFC1918. Independent of the per-credential allowlist. |
| Get the wallet key to sign an arbitrary tx | Bounded by the credential's RPC-host allowlist, plus optional `chainIdAllowlist` / `toAllowlist` (EVM) and `programAllowlist` (Solana) enforced before signing. |
| Steal proxy CA private key | Not applicable. **There is no CA**, because we use URL-rewrite instead of TLS interception. |

---

## Operational scope and explicit non-goals (v1)

- **Inbound TLS interception is out of scope.** The proposal sketched a local-CA + system-trust-store install for full HTTPS_PROXY transparency. Shipping URL-rewrite mode eliminates the need: HTTPS upstream coverage without the CA-management blast radius. If/when transparent HTTPS_PROXY semantics become a hard customer ask, the spike is documented in the proposal.
- **Self-signed control-plane TLS, pinned out-of-band.** A network-exposed control plane uses a per-run self-signed cert; there's no CA, so the approver/phone pins the SHA-256 fingerprint from the pairing QR. This is a deliberate pin-not-PKI model: it authenticates the exact proxy without a trust-store install, but it means a paired phone re-pairs after a restart (new cert), and the pin's integrity rests on the QR being shown/scanned over a trusted out-of-band channel.
- **Owner-approval depends on the SSO.** Only `examples/dev-sso.mjs` (auto-approving) implements the escrow + human-push contract today; production use waits on the Alien SSO.
- **No browser proxying / form login / cookie auto-refresh.** Cookie-jar credentials can be imported and used, but expired-session re-login is the user's job. (Wallet recipient/program allowlists and per-credential consent are now available; see the records and control-plane sections.)
- **POSIX trusted-input only.** Windows `CONIN$` direct open is not implemented in v1.

---

## File layout

```text
~/.agent-id/
├── keys/main.json           # Ed25519 agent keypair (mode 0600)
├── vault.enc                # Portable encrypted vault (mode 0600)
├── vault.bak/               # Legacy v4 vault dir, if migrated (mode 0700)
├── proxy.json               # Running-proxy state (pid, ports, idleTimeoutMs, control token) — 0600
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
