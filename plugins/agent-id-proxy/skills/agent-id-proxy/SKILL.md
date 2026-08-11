---
name: agent-id-proxy
description: Local credential-injecting HTTP proxy. The agent calls `http://localhost:PORT/<credname>/<upstream-host>/<path>`; the proxy looks up the credential in the vault, validates the host against that credential's allowlist (default-deny), materializes the credential into the appropriate request location, and forwards over real HTTPS. For vault-generated wallet credentials it signs blockchain transactions in-process — Solana `sendTransaction` bodies are ed25519-signed, EVM `eth_sendTransaction` becomes a signed EIP-1559 `eth_sendRawTransaction`. The agent never sees the credential value or private key. Use whenever the agent calls an external service with a vaulted credential, or needs to send a blockchain transaction from a vault-held wallet (payments, trading, x402, transfers).
license: MIT
metadata:
  author: Alien Wallet
  version: "7.1.0"
allowed-tools: Bash(node *agent-id-proxy/bin/cli.mjs:*) Bash(curl:*) Read
---

# Alien Agent ID — Proxy

The proxy holds the unlocked vault's master key in memory, accepts HTTP requests on localhost, and forwards them to real upstream services with the configured credential injected. Two request shapes are supported.

Requires `agent-id-vault init` to have produced a portable vault with at least one credential.

> **Security note:** this skill pre-approves `Bash(curl:*)` so calls to the local proxy don't prompt each time. That grant also authorizes arbitrary outbound HTTP — a potential exfiltration channel. For higher-stakes use, drop the blanket `curl` grant and approve proxy calls per-invocation.

## Resolve the CLI

`bin/cli.mjs` lives in this plugin's directory. In the examples below, `CLI` is `${CLAUDE_PLUGIN_ROOT}/bin/cli.mjs` — the `${CLAUDE_PLUGIN_ROOT}` path is filled in for you when the skill loads.

## Start the proxy

```bash
# Foreground (Ctrl-C to stop). Tries agent-key unlock first, falls back to /dev/tty prompt.
node CLI start --port 48771

# Once-per-session unlock via an out-of-band browser form (1Password-style): the
# human types the vault passphrase into a localhost form; the proxy holds the key
# for the session and re-locks when idle. Agent-key auto-unlock is bypassed, so the
# agent cannot unlock the vault itself. (Vault must have a passphrase slot — dev mode.)
node CLI start --unlock-form

# With an explicit passphrase source:
node CLI start --passphrase-file ~/.agent-id-pass

# Idle auto-lock window (default 12h; "never" disables for unattended agents):
node CLI start --idle-timeout 30m

# Authenticate the data plane (loopback alone is a weak boundary in a shared
# network namespace). The file must be 0600 and hold printable ASCII; the token
# never rides argv:
node CLI start --auth-token-file ~/.agent-id-proxy-token
```

With `--auth-token-file`, every proxy call — including `CONNECT` tunnels — must present the token, or the answer is `401 {error: "unauthorized"}`:

```bash
curl -H "X-Agent-Id-Proxy-Token: $(cat ~/.agent-id-proxy-token)" \
  http://localhost:48771/github-pat/api.github.com/user
```

The header is stripped before anything is forwarded upstream, and the check runs before the vault is touched at all. The control plane is unaffected — it has its own bearer token.

The CLI prints the suggested env exports. Set them in any shell that should route through the proxy:

```bash
export AGENT_ID_PROXY=http://127.0.0.1:48771
```

## Mode 1 — URL-rewrite (recommended, universal)

The agent calls a local URL that names the credential and the real upstream host:

```
http://<proxy>/<credname>/<upstream-host>/<path>
```

The credname picks the credential, the next path segment names the upstream host (validated against that credential's allowlist), and the rest is forwarded verbatim. The proxy is the HTTPS client — the system CA bundle verifies the upstream cert. No TLS interception on the agent side.

```bash
# GitHub PAT (bearer credential):
curl http://localhost:48771/github-pat/api.github.com/user

# OpenAI key (header credential, name configured at `vault add` time):
curl -X POST http://localhost:48771/openai-key/api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" -d '{"model":"...","messages":[...]}'

# Stripe secret (bearer):
curl http://localhost:48771/stripe-sk/api.stripe.com/v1/charges

# Geocoder API (query param credential):
curl 'http://localhost:48771/geo/api.example.com/lookup?address=1+Main+St'

# Cookie-based session for a private app:
curl http://localhost:48771/intranet-sess/intranet.corp.example/api/v2/things
```

The credential is materialized into the request based on its type:

| Type | Materialization |
|---|---|
| `bearer` | `Authorization: Bearer <value>` |
| `basic` | `Authorization: Basic <b64(user:pass)>` |
| `header` | `<headerName>: <value>` |
| `query` | URL query param `<paramName>=<value>` |
| `cookie` | `Cookie: <cookieName>=<value>` (appended if Cookie present) |
| `cookie-jar` | `Cookie: k1=v1; k2=v2; …` |
| `totp` | `<otpHeader || X-OTP-Code>: <6-digit code>` |
| `solana-keypair` | signature inside the JSON-RPC body (see below) |
| `evm-keypair` | signature inside the JSON-RPC body (see below) |

Upstream scheme defaults to **HTTPS**. Set `upstreamScheme: "http"` on the credential to opt into plain HTTP (legacy/internal services). The proxy rewrites the `Host` header and strips `Origin` / `Referer` before forwarding.

## Access levels (read-only credentials)

A credential added with `--access ro` (see the vault skill) is enforced here on
every request: `GET`/`HEAD`/`OPTIONS` pass; a `POST`/`PUT`/`PATCH`/`DELETE` is
allowed only if the credential's `accessRules` allow it or the body classifies
as a tunneled read (an inline GraphQL `query`, a JMAP `*/get`/`*/query`, or a
JSON-RPC method on the recognized-read allowlist such as `eth_call`/`getBalance`).
It is default-deny: a submitting method like `sendTransaction`, and any
unrecognized method, are blocked. Anything else:

```json
{ "ok": false, "error": "access_denied", "credential": "mail-ro", "access": "ro", "reason": "write_blocked" }
```

Don't retry a `403 access_denied` — the level is the owner's decision. Ask the
owner to widen it (`agent-id-vault set-access`, human-confirmed). Denials are
logged as `access_denied` events.

Classification needs the operation to be visible in the request. A POST whose
body doesn't reveal a read — a **persisted-query** GraphQL (hash only, no query
text), opaque binary RPC (gRPC-web/Connect), or an unknown JSON-RPC method —
fails safe: it's denied, not allowed. So `ro` works cleanly on REST-with-verbs,
inline GraphQL, JMAP, and known JSON-RPC, and over-blocks (reads too) on
hash-only endpoints. See the vault skill's "Where `ro` works" table.

## Wallet credentials — transaction signing in the proxy

`solana-keypair` / `evm-keypair` credentials (created with
`agent-id-vault generate`) don't inject headers — the proxy signs
**transactions inside the JSON-RPC request body**. The agent builds an
*unsigned* transaction from public material only and submits it through the
proxy; the private key never leaves the proxy process.

**Solana** — `sendTransaction` params are signed (base58 or base64 per the
request's own `encoding`); every other method (`getBalance`,
`getLatestBlockhash`, `simulateTransaction`, …) passes through:

```bash
# Balance check (passthrough):
curl http://localhost:48771/sol-hot/api.mainnet-beta.solana.com/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["<address>"]}'

# Submit an UNSIGNED tx — the proxy fills the signature slot(s) for its key:
curl http://localhost:48771/sol-hot/api.mainnet-beta.solana.com/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"sendTransaction",
       "params":["<unsigned tx, base64>", {"encoding":"base64"}]}'
```

Partial signing is preserved: existing co-signatures (e.g. an x402
facilitator fee-payer) stay in place; only slots matching the vault key are
filled.

**EVM** — `eth_sendTransaction` is rewritten to `eth_sendRawTransaction`
with an EIP-1559 tx signed by the vaulted key. The agent must supply
`chainId`, `nonce`, `gas`, `maxFeePerGas`, `maxPriorityFeePerGas` explicitly
(read them through the proxy first). A `from` field, if present, must match
the credential's address:

```bash
curl http://localhost:48771/polygon-hot/polygon-bor-rpc.publicnode.com/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_sendTransaction","params":[{
        "to":"0x…","value":"0x38d7ea4c68000","chainId":137,"nonce":"0x0",
        "gas":21000,"maxFeePerGas":120000000000,"maxPriorityFeePerGas":30000000000}]}'
```

Signing failures return `400 {error: "solana_sign_failed" | "evm_sign_failed"}`.
The access log records `solana_signed` / `evm_signed` events with signatures/
tx hashes (public on-chain data) — never key material.

## Mode 2 — HTTP_PROXY stub injection (legacy, HTTP only)

For agents that want to use the standard `HTTP_PROXY` env without rewriting URLs. Only works for plain HTTP upstream; HTTPS upstream needs TLS interception (out of scope).

```bash
export HTTP_PROXY=http://127.0.0.1:48771
curl -H "Authorization: AgentVault github-pat" http://api.example.com/foo
```

Prefer Mode 1 for new code.

## Idle auto-lock

After `--idle-timeout` of no traffic (default **12h**, 1Password parity), the proxy zeroes the master key + drops decrypted credential records. What the next request gets depends on how the vault was unlocked at start:

- **Agent-key auto-unlock** (the default — not `--unlock-form`, not `--no-agent-key`) **with `--no-control`:** the proxy re-opens the vault itself and the request proceeds. No human, no restart. A `CONNECT` tunnel is re-opened the same way.
- **Control plane on** (the default) with a phone or owner-approval slot: the request parks until the unlock is approved — unchanged, unlock stays an owner action there. A `CONNECT` tunnel has nowhere to park, so it is refused with `401 vault_locked` rather than re-unlocking itself.
- **Control plane on with nothing to ask** (no paired device, no owner-approval slot): `401 {error: "no_unlock_method"}` on every request, agent key or not — self-reopen is reached only with `--no-control`. Pair a device before the lock, or restart the proxy.
- **Anything else** (passphrase, passkey, `--unlock-form`): `401 {error: "vault_locked"}`; restart to re-unlock:

```bash
node CLI stop && node CLI start --passphrase-file ~/.agent-id-pass
```

Override:

```bash
node CLI start --idle-timeout 30m       # tighter
node CLI start --idle-timeout never     # disable (unattended agents)
```

`node CLI status` reports the configured `idleTimeout`.

## Credentials added while the proxy runs

With agent-key auto-unlock (any control-plane setting), a `credential_not_found` makes the proxy re-read `vault.enc` once and retry the lookup — so a credential another process wrote after the proxy started (an `agent-id-vault add` following an OAuth flow) is picked up on next use, no restart and no port change. Started any other way, a miss stays a miss until the proxy is restarted.

## Error responses

```json
{ "ok": false, "error": "credential_not_found", "credential": "github-pat" }
{ "ok": false, "error": "host_not_allowed", "credential": "github-pat", "host": "evil.example.com", "allowed": ["*.github.com"] }
{ "ok": false, "error": "vault_locked", "reason": "idle_timeout" }
{ "ok": false, "error": "access_denied", "credential": "mail-ro", "access": "ro", "reason": "write_blocked" }
{ "ok": false, "error": "bad_request", "message": "..." }
{ "ok": false, "error": "unauthorized", "message": "..." }
```

The `X-AgentVault-Proxy-Error` response header carries the same code. A `CONNECT` refusal has no JSON body — it is a status line plus that header (`unauthorized`, `vault_locked`, `bad_request` for a target that is not `host:port`, `upstream_blocked`, `upstream_error`).

## Status + stop

```bash
node CLI status
node CLI stop
```

## Limitations

- **HTTPS only at the upstream leg** in URL-rewrite mode. The agent-to-proxy leg is plain HTTP loopback by design; `--auth-token-file` gates who may use it, but does not encrypt it.
- Authorization gates: per-credential **host allowlist**, **access level**
  (`ro`/`rw` + rules), and — when started with `--require-consent` — a
  per-(credential, host) human consent grant.
- Stub-injection mode (legacy) enforces access levels by method/host/path only
  — POST-tunneled reads are not classified there; use URL-rewrite mode.
