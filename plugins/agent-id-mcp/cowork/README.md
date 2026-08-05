# agent-id — Cowork validation plugin

A **local (stdio) MCP server** packaged as a Claude Cowork plugin. Its job right
now is to settle one empirical question we can't answer from outside Cowork:

> When Cowork launches a plugin's stdio MCP server, does it run on the **real host
> machine** (where a real Chrome + localhost exist, so the vault-sealed browser
> can run locally) — or **inside the sandboxed Linux VM** (no Chrome, raw sockets
> blocked, so we must use a hosted transport instead)?

The server is **self-contained** (`server.bundle.mjs`, ~0.5 MB, deps bundled) so
it needs **no runtime `npm install`** — which matters because Cowork doesn't fire
the `SessionStart` hook the CLI plugins rely on.

## Install & run the probe

1. Install this directory as a Cowork plugin (Cowork plugin management → add local
   plugin, or package it into a `.plugin` bundle). It declares one stdio MCP
   server via `.mcp.json`:
   ```json
   { "mcpServers": { "agent-id": {
       "command": "node",
       "args": ["${CLAUDE_PLUGIN_ROOT}/server.bundle.mjs"] } } }
   ```
2. In a Cowork task, run the diagnostic tool **`agent_id_probe_env`** (no args).
3. Paste the JSON back. The fields that decide the architecture:

| Field | Meaning |
|---|---|
| `runtime` | `host` = real machine → **local browser viable**. `cowork-vm` = sandbox → **must go hosted**. |
| `platform` | `darwin`/`win32` = host; `linux` + hostname `claude` = the Cowork VM. |
| `chrome.found` | Is a real Chrome present to drive? |
| `localhostBindable` | Can the vault-sealed browser's control socket bind (a hardened sandbox blocks it)? |
| `agentIdCli.*` | Whether the `agent-id-*` CLIs resolve (they're not bundled here; tells us what the full plugin must also ship). |
| `env.CLAUDE_PLUGIN_ROOT` | Confirms Cowork substituted the plugin path. |

`verdict.canDriveLocalBrowser` summarizes `chrome.found && localhostBindable`.

## What each outcome means

- **`runtime: host`, chrome found, localhost bindable** → the **local** path works:
  ship the real `agent-id` MCP server (identity + vault + vault-sealed browser
  driving the user's own Chrome), no hosted service, vault stays on the machine,
  real residential IP. This is increment 1's server with the `agent-id-*` CLIs
  bundled alongside.
- **`runtime: cowork-vm`** (or chrome missing / localhost blocked) → the local
  browser can't run there; use the **hosted** transport (Streamable-HTTP connector
  backed by the hosted runtime service, browser server-side). Identity + vault may
  still work locally if the CLIs are bundled.

## Rebuilding the bundle

```bash
# from plugins/agent-id-mcp/
bun run build:bundle    # → cowork/server.bundle.mjs
```

The bundle is the increment-1 stdio server (`bin/server.mjs`) with
`@modelcontextprotocol/sdk` inlined. See [`../../../docs/COWORK-MCP.md`](../../../docs/COWORK-MCP.md).
