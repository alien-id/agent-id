---
name: agent-id-proxy
description: Local credential-injecting HTTP proxy. The agent calls `http://localhost:PORT/<credname>/<upstream-host>/<path>`; the proxy looks up the credential in the vault, validates the host against that credential's allowlist (default-deny), materializes the credential into the appropriate request location, and forwards over real HTTPS. The agent never sees the credential value. Use whenever the agent calls an external service and the credential must not enter the transcript, argv, or environment.
license: MIT
metadata:
  author: Alien Wallet
  version: "0.2.0"
allowed-tools: Bash(node *agent-id-proxy/bin/cli.mjs:*) Bash(curl:*) Bash(jq:*) Read
---

# Alien Agent ID — Proxy

The proxy holds the unlocked vault's master key in memory, accepts HTTP requests on localhost, and forwards them to real upstream services with the configured credential injected. Two request shapes are supported.

Requires `agent-id-vault init` to have produced a portable vault with at least one credential.

## Resolve the CLI

`bin/cli.mjs` lives in this plugin's directory. Substitute `CLI` with the absolute path.

## Start the proxy

```bash
# Foreground (Ctrl-C to stop). Tries agent-key unlock first, falls back to /dev/tty prompt.
node CLI start --port 48771

# With an explicit passphrase source:
node CLI start --passphrase-file ~/.agent-id-pass

# Idle auto-lock window (default 12h; "never" disables for unattended agents):
node CLI start --idle-timeout 30m
```

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

After `--idle-timeout` of no traffic (default **12h**, 1Password parity), the proxy zeroes the master key + drops decrypted credential records. Subsequent requests get `401 {error: "vault_locked"}`. Restart the proxy to re-unlock:

```bash
node CLI stop && node CLI start --passphrase-file ~/.agent-id-pass
```

Override:

```bash
node CLI start --idle-timeout 30m       # tighter
node CLI start --idle-timeout never     # disable (unattended agents)
```

`node CLI status` reports the configured `idleTimeout`.

## Error responses

```json
{ "ok": false, "error": "credential_not_found", "credential": "github-pat" }
{ "ok": false, "error": "host_not_allowed", "credential": "github-pat", "host": "evil.example.com", "allowed": ["*.github.com"] }
{ "ok": false, "error": "vault_locked", "reason": "idle_timeout" }
{ "ok": false, "error": "bad_request", "message": "..." }
```

The `X-AgentVault-Proxy-Error` response header carries the same code.

## Status + stop

```bash
node CLI status
node CLI stop
```

## v1 limitations

- **HTTPS only at the upstream leg** in URL-rewrite mode. The agent-to-proxy leg is plain HTTP loopback by design.
- **No consent prompt.** Host allowlist is the only authorization gate in v1.
- **No in-process re-unlock.** Restart the proxy to re-unlock after idle lock.
