---
name: agent-id-oauth
description: Self-hosted OAuth 2.0 token broker keyed off the agent's Alien Agent ID. Run the Authorization Code + PKCE flow with your own OAuth apps (Google, Slack, GitHub, Microsoft, Notion, and more), store access/refresh tokens in the encrypted vault, refresh them automatically, and gate on missing scopes. Use when a tool or API call needs a third-party OAuth bearer token and you want to broker it locally instead of relying on a hosted auth engine.
license: MIT
metadata:
  author: Alien Wallet
  version: "0.0.0"
allowed-tools: Bash(node *agent-id-oauth/bin/cli.mjs:*) Bash(curl:*) Bash(jq:*) Read
---

# Alien Agent ID — OAuth Broker

Self-hosted OAuth 2.0 token brokering. You bring your own OAuth app credentials; the
broker runs the Authorization Code (+ PKCE) flow, stores access/refresh tokens in the
**same encrypted vault** used by `agent-id-vault` (AES-256-GCM, key derived from the
agent's private key), refreshes them on demand, and detects when a requested scope was
never granted. This replaces the role of a hosted auth engine for third-party providers.

Requires that `agent-id-core bootstrap` has produced a keypair under
`${AGENT_ID_STATE_DIR:-$HOME/.agent-id}`. In the commands below, `CLI` is
`node /path/to/plugins/agent-id-oauth/bin/cli.mjs`.

## Built-in providers

`google`, `microsoft`, `github`, `slack`, `notion`, `linear`, `zoom`, `spotify`,
`discord`, `atlassian`, `x`, `dropbox`, `hubspot`, `asana`. Any other OAuth 2.0 provider
works via `--authorize-url` / `--token-url` (plus optional `--scope-separator`,
`--scope-param`, `--token-auth <body|basic>`, `--pkce`/`--no-pkce`).

## 1) Register your OAuth app (one-time per provider)

Create an OAuth app in the provider's console and add the redirect URI it prints
(default `http://localhost:8723/callback`).

```bash
CLI register --provider google \
  --client-id "<your-client-id>" --client-secret-env GOOGLE_CLIENT_SECRET
```

The client secret is read from the named environment variable (never placed on the
command line) and stored encrypted in the vault. Public/PKCE clients with no secret are
supported — just omit `--client-secret*`.

## 2) Log in (two phases — works locally and over SSH)

Phase 1 prints the authorize URL and returns immediately (so the URL is visible before
anything blocks). Show `authorize_url` to the user.

```bash
CLI login --provider google --scopes "https://www.googleapis.com/auth/gmail.readonly"
```

Phase 2 completes the flow. Pick one:

```bash
# local machine: run a loopback server that auto-captures the redirect
CLI complete --provider google --serve

# headless/remote: the user authorizes, copies the redirected localhost URL, you pass it
CLI complete --provider google --callback-url "http://localhost:8723/callback?code=...&state=..."
```

## 3) Get a token before each API call (auto-refreshes if expired)

```bash
AUTH=$(CLI token --provider google \
  --scopes "https://www.googleapis.com/auth/gmail.readonly" --raw)
curl -H "$AUTH" "https://gmail.googleapis.com/gmail/v1/users/me/messages"
```

If `token` returns `{"needs_consent": true, ...}`, a requested scope was never granted —
run the `login` command shown in its `action` field (it pre-merges the old and new
scopes), then `complete`, and retry.

## Other commands

```bash
CLI list                      # brokered providers (scopes/expiry, no secrets shown)
CLI logout --provider google  # remove the stored OAuth app + tokens for a provider
```

## Reusing existing tool ecosystems

Because `token` hands back a standard bearer token, it can feed any OSS tool library that
expects you to "supply your own access token". See `examples/arcade_bridge.py` for a
reference that runs Arcade's open-source toolkits (thousands of tools) with auth brokered
entirely by this plugin — no hosted engine.
