---
name: agent-id-proxy
description: Local stub-translating HTTP proxy. The agent sends requests with `AgentVault <name>` in headers or query params; the proxy substitutes the real credential from the vault before forwarding upstream. Enforces per-credential host allowlist (default-deny). Use whenever the agent calls an external service and the credential must never enter the agent's transcript or argv.
license: MIT
metadata:
  author: Alien Wallet
  version: "0.1.0"
allowed-tools: Bash(node *agent-id-proxy/bin/cli.mjs:*) Bash(curl:*) Bash(jq:*) Read
---

# Alien Agent ID — Proxy

The proxy intercepts HTTP requests, finds `AgentVault <credential-name>` stub markers in headers + URL query parameters, looks each one up in the unlocked vault, verifies the request host is on that credential's allowlist, and substitutes the materialized value before forwarding.

Requires that `agent-id-vault init` has produced a portable vault with at least one credential.

## Start the proxy

```bash
# Foreground (Ctrl-C to stop). Tries agent-key unlock first, falls back to /dev/tty prompt.
node CLI start --port 48771

# With explicit passphrase source:
node CLI start --passphrase-file ~/.agent-id-pass

# Print connection info as JSON (for piping into env setup):
node CLI start --print-config
```

CLI prints the suggested `HTTP_PROXY` env var. Set it in any shell or tool that should route through the proxy:

```bash
export HTTP_PROXY=http://127.0.0.1:48771
```

## Use a credential

The agent writes the stub wherever the credential would go. The proxy figures out the materialization from the credential type:

```bash
# bearer credential — proxy expands `AgentVault github-pat` → `Bearer ghp_xxx`
curl -H "Authorization: AgentVault github-pat" http://api.github.com/user

# header credential — proxy expands to just the raw value
curl -H "X-Api-Key: AgentVault openai-key" http://api.openai.com/v1/models

# query credential — URL-encoded by URLSearchParams
curl "http://example.com/api?api_key=AgentVault%20example-key"
```

## v1 limitations

- **HTTP only.** HTTPS upstream goes through CONNECT tunneling without MITM — stubs in HTTPS requests are NOT injected. The next milestone is the local-CA + per-host TLS interception spike described in `documentation/agent-id/vault-proxy-mvp-proposal.md`.
- **No consent prompt.** v1 uses the host allowlist as the only authorization gate. Consent dialogs (per-credential, per-agent, persisted) come in a follow-up.
- **No auto-lock.** The proxy holds the master key in memory until `stop`. Idle re-lock is a known follow-up.

## Status + stop

```bash
node CLI status   # JSON: { running, pid, host, port, uptimeMs, ... }
node CLI stop     # SIGTERM the running proxy
```

## Error responses

The proxy returns structured 4xx JSON when injection fails:

```json
{ "ok": false, "error": "credential_not_found", "credential": "github-pat" }
{ "ok": false, "error": "host_not_allowed", "credential": "github-pat", "host": "evil.example.com", "allowed": ["*.github.com"] }
{ "ok": false, "error": "https_not_supported_yet", "message": "..." }
```

The `X-AgentVault-Proxy-Error` response header carries the same code for clients that don't parse the body.
