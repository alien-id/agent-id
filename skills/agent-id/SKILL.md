---
name: agent-id
description: Use the Alien Agent ID system on any agent harness — verifiable agent identity (Ed25519, L0/L1/L2 assurance), an encrypted credential vault (passkey/Touch ID, passphrase, or agent-key unlock), and a localhost proxy that injects secrets so the agent uses credentials BY NAME and never sees the value. Use whenever an agent must store or use an external-service credential, prove its identity, sign git commits, drive a logged-in browser, or send a blockchain transaction without the secret entering its context. Harness-neutral — plain Node CLIs plus an HTTP proxy; no Claude Code required.
license: MIT
metadata:
  version: "7.0.0"
  homepage: https://github.com/alien-id/agent-id
---

# Alien Agent ID — umbrella skill (any harness)

This is the **portable, harness-neutral** entry point. The Claude Code plugins are a
skin; underneath, every capability is a plain **Node CLI** plus a **localhost HTTP
proxy** that read/write state under `~/.agent-id`. Load this skill in any
Agent-Skills-aware harness, or read it as the integration contract for a custom one.

> Two other directions exist: [`docs/INTEGRATION.md`](../../docs/INTEGRATION.md) — how a
> **service** adds Alien auth; [`docs/VAULT-PROXY.md`](../../docs/VAULT-PROXY.md) — the
> vault/proxy internals + threat model. Per-capability detail lives in each
> `plugins/agent-id-<x>/skills/agent-id-<x>/SKILL.md`.

## Model in one paragraph

- **State** lives in one dir (`~/.agent-id`; override per command with `--state-dir`
  or `AGENT_ID_STATE_DIR`).
- **Capabilities are CLIs** at `plugins/<name>/bin/cli.mjs` (relative to the cloned
  repo root). They take flags, act on the state dir, and print **JSON to stdout**.
- **Runtime credential use goes through the proxy** — a localhost server that injects
  vaulted secrets into outbound requests so the agent uses a credential **by name**
  and never sees its value.

The agent never needs a secret — only (a) the ability to run a few `node …/cli.mjs`
commands and (b) the proxy URL.

## Setup (one time)

```bash
# Node 18+ (built-in fetch/WebCrypto). No Claude Code required.
git clone https://github.com/alien-id/agent-id.git && cd agent-id

# a) Agent identity — offline, usable immediately at L0 (self-asserted).
node plugins/agent-id-core/bin/cli.mjs init        # → {fingerprint, publicKeyPem}
node plugins/agent-id-core/bin/cli.mjs status      # → {level:0, assurance:"self-asserted"}
#   Human attestation (L1 anonymous / L2 linked) needs the Alien SSO:
#   …/agent-id-core/bin/cli.mjs bootstrap --provider-address <addr>

# b) Vault — choose how it unlocks.
node plugins/agent-id-vault/bin/cli.mjs init --unlock passkey   # Touch ID; agent can't self-unlock
#   or --unlock passphrase (secure form, dev mode) · plain init == --unlock agent-key (auto)

# c) Credentials — host-scoped (default-deny); value never hits argv/transcript.
node plugins/agent-id-vault/bin/cli.mjs add --name github-pat --type bearer \
  --domains '*.github.com,api.github.com' --value-file /tmp/tok
node plugins/agent-id-vault/bin/cli.mjs add --name openai-key --type header \
  --header-name X-Api-Key --domains api.openai.com --form    # human types it into a localhost form
```

`AGENT_ID_NO_BROWSER=1` makes any form/ceremony print its URL instead of opening a
browser (headless / SSH-tunnel use).

## Use credentials at runtime — the proxy

```bash
node plugins/agent-id-proxy/bin/cli.mjs start --port 48771   # agent-key unlock, else /dev/tty
# Hard boundary (agent can't self-unlock): a human unlocks once per session —
node plugins/agent-id-proxy/bin/cli.mjs start --unlock-form  # passphrase or passkey ceremony
```

**Mode 1 — URL-rewrite (recommended, universal, HTTPS upstreams).** The agent calls a
local URL naming the credential and the real upstream; the proxy validates the host
against that credential's allowlist, injects the secret, and forwards over HTTPS:

```
http://<proxy-host>:<port>/<credential-name>/<upstream-host>/<path>
```
```bash
curl http://localhost:48771/github-pat/api.github.com/user
curl -X POST http://localhost:48771/openai-key/api.openai.com/v1/chat/completions \
  -H 'content-type: application/json' -d '{"model":"...","messages":[...]}'
```

Wallet credentials (`solana-keypair`/`evm-keypair`) are signed *inside* the proxy:
the agent submits an *unsigned* JSON-RPC tx and the proxy fills the signature.
**Mode 2** (`HTTP_PROXY` + `Authorization: AgentVault <name>` stub) is the legacy
plain-HTTP fallback. Full per-type table → [`docs/VAULT-PROXY.md`](../../docs/VAULT-PROXY.md).

### System-prompt block to paste into your harness

> You have a credential proxy at `http://localhost:48771`. To call a service that
> needs a secret, request `http://localhost:48771/<credential-name>/<host>/<path>` —
> never ask for or handle the secret itself. Available credentials: `github-pat`
> (api.github.com), `openai-key` (api.openai.com), … Errors return JSON with an
> `error` field (`credential_not_found`, `host_not_allowed`, `vault_locked`).

## Other capabilities (no proxy)

```bash
# Inject into a child process's ENV, or a temp 0600 key FILE (env-var-auth tools):
node plugins/agent-id-vault/bin/cli.mjs exec --env OPENAI_API_KEY=openai-key.value -- python train.py
node plugins/agent-id-vault/bin/cli.mjs exec --file GIT_SSH_KEY=deploy-key.value -- \
  sh -c 'GIT_SSH_COMMAND="ssh -i $GIT_SSH_KEY -o IdentitiesOnly=yes" git fetch'

# Logged-in browser sealed in the vault; SSH-signed commits; DPoP service calls:
node plugins/agent-id-browser/bin/cli.mjs login --name x --url https://x.com   # headed, one-time
node plugins/agent-id-git/bin/cli.mjs commit --message "..." --push
node plugins/agent-id-auth/bin/cli.mjs call --url https://service/op --method POST --body '{...}'
```

## Replacing the Claude Code wrappers

| Claude Code piece | Did | Your harness equivalent |
|---|---|---|
| `SKILL.md` `description` | Auto-surfaced the capability | This file + per-plugin SKILL.md bodies, in your system prompt / skills dir |
| `allowed-tools` | Gated which commands ran | **Your harness must gate this** (see Security) |
| SessionStart hook | Popped the unlock form per session | Call `proxy start --unlock-form` at session start |
| Install hook | Auto-installed patchright | Run it once, or `cd plugins/agent-id-browser && npm install`; browser cmds also auto-install into `--plugin-data <dir>` |
| `${CLAUDE_PLUGIN_DATA}` | Browser's writable dir | Pass `--plugin-data <dir>` to browser commands (only that plugin needs it) |

## Security on a foreign harness — read this

- **The proxy boundary holds regardless of harness.** An agent making arbitrary proxy
  calls still cannot extract plaintext (injected, not returned) or reach a host off a
  credential's allowlist (default-deny). Safe to expose broadly.
- **`vault show` / `vault exec` / `vault add` are agent-invocable and DO surface or set
  secrets.** On Claude Code `allowed-tools` blocks them; **your harness must apply the
  same gate.** Treat `…/agent-id-vault/bin/cli.mjs` as privileged; treat proxy URL
  calls as unprivileged.
- **Hard vs. soft unlock.** `--unlock passkey|passphrase` (and `proxy --unlock-form`)
  need a human; `--unlock agent-key` lets the agent auto-unlock. Pick per stakes.
- **Idle lock** zeroes the master key after `--idle-timeout` (default 12h) →
  `401 {error:"vault_locked"}` until re-unlocked. An agent-key-unlocked proxy run with
  `--no-control` re-opens the vault itself (no human, no restart); a human-unlocked one
  needs the restart. With the control plane on, the request parks for an owner approval
  instead — or fails `401 no_unlock_method` when the vault has no approver slot to ask.
- **Residual:** vault/proxy run as the **same uid** as the agent (memory-scrape risk);
  closing that needs the proxy as a separate OS principal (roadmap).

## Command surface (JSON in → JSON out; `--help` on any CLI)

| Plugin | CLI | Key commands |
|---|---|---|
| core | `agent-id-core/bin/cli.mjs` | `init`, `bootstrap`, `status`, `refresh`, `sign`, `verify`, `export-proof` |
| vault | `agent-id-vault/bin/cli.mjs` | `init --unlock …`, `add`, `generate`, `show`, `list`, `remove`, `exec`, `rekey`, `export`, `import`, `migrate` |
| proxy | `agent-id-proxy/bin/cli.mjs` | `start`, `status`, `stop`, `pair`, `autounlock` |
| browser | `agent-id-browser/bin/cli.mjs` | `login`, `read`, `fetch`, `status`, `open`/`snapshot`/`click`/`type`/… |
| git | `agent-id-git/bin/cli.mjs` | `setup`, `commit`, `verify` |
| auth | `agent-id-auth/bin/cli.mjs` | `call`, `header`, `discover`, `capabilities`, `support` |
