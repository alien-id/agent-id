# agent-id in Claude Cowork — the MCP connector path

## Why the CLI plugins don't work in Cowork

Cowork is **not** the Claude Code CLI. Verified from the runtime on disk + docs:

- Code runs in an **isolated Linux VM** (`claudevm.bundle`, Ubuntu 22.04, gVisor
  network sandbox). The agent loop is on the host; execution is in the guest.
- Cowork's extension model is **Skills + MCP Connectors**, installed from its own
  plugin marketplaces. It does not run bash-CLI plugins the way the CLI does.
- Concretely, every mechanism agent-id relies on is absent in the Cowork VM:
  1. **`SessionStart`/plugin hooks don't fire** → the `install-deps.sh` bootstrap
     never runs.
  2. **`CLAUDE_PLUGIN_ROOT` / `CLAUDE_PLUGIN_DATA` are not set** → both the hook
     and the skills' `node ${CLAUDE_PLUGIN_ROOT}/bin/cli.mjs --plugin-data …`
     invocations are unresolved, and bare `@alien-id/*` imports fail.
  3. **No persistent plugin-data dir** → nowhere for the shared libs to live.
  4. **No Chrome, no display, raw sockets blocked** → the vault-sealed browser
     (system Chrome + a localhost TCP daemon) and the `agent-id-proxy` localhost
     server cannot run in the VM. Cowork's own browsing is the *host* Chrome
     extension (claude-in-chrome MCP) — a different path.
  5. **Egress is proxy-only** (HTTPS via a MITM proxy) → in-VM `npm install` is
     unreliable.

This is an architecture mismatch, not a bug: CLI plugins assume "my Node CLIs run
on the user's machine with Chrome + localhost"; Cowork offers "MCP connectors in a
locked VM."

## The fix: expose agent-id as a hosted MCP connector

MCP connectors are exactly how Cowork wires in tools. Instead of shipping bash-CLI
plugins, ship an **MCP server** that Cowork adds as a **remote connector** over
HTTPS. The server is a **thin adapter over the existing `agent-id-*` CLIs** — the
same pattern Lethe already uses (shell out, return JSON) — so there is no
re-implementation of command logic.

```
Cowork VM ── HTTPS (Streamable-HTTP MCP, per-user bearer) ──▶  agent-id-mcp
                                                                  │ subprocess
                                                                  ▼
                                     agent-id-core / -vault / -browser CLIs
                                     (+ Google Chrome, in the container)
```

Running the server **hosted** (not in the VM) sidesteps every VM limitation — no
hooks, no plugin env vars, no npm-in-VM, no Chrome-in-VM. The VM just opens one
allowed HTTPS connection. The **vault-sealed browser runs server-side**, exactly
as `lethe-hosted` already does, so the "agent never sees the credential" seal is
preserved (a host-Chrome path would break it — secrets would flow through Cowork's
own browser). Vault + identity state persist on the service, not the ephemeral VM.

### Components

1. **`plugins/agent-id-mcp/`** (new, private) — an MCP server (`@modelcontextprotocol/sdk`).
   - Maps MCP tools → the existing CLIs via subprocess, returning their JSON.
   - Resolves each CLI by `AGENT_ID_{CORE,VAULT,BROWSER}_BIN` env or PATH (mirrors
     lethe's `find_bin`).
   - Two transports from one tool registry: **stdio** (local dev / in-VM option)
     and **Streamable HTTP** (hosted connector).
   - Tool surface = the current lethe surface: `agent_id_status/sign/bind`,
     `vault_list/add/remove/set_totp`, `browser_open/act/close/login/auto_login/fill_secret/fill_otp`.
2. **Hosting** — reuse the `lethe-hosted` runtime image (Chrome + CLIs baked, the
   `AGENT_ID_BROWSER_NO_SANDBOX`/`--shm-size` work already done). Expose the MCP
   server on an HTTPS route with per-user auth (lethe-hosted already issues
   per-user tokens). Per-user state dir → per-user vault/identity.
3. **Cowork plugin** — a thin bundle (a `.claude-plugin` + a connector manifest
   declaring the MCP server + optional `/`-skills that call it) so it appears in
   Cowork's plugin/connector setup flow. Auth via the connector's bearer/OAuth.

### Build increments

- [x] **0. Plan** (this doc).
- [ ] **1. MCP server foundation** — `agent-id-mcp` package; stdio transport; the
  identity + vault tools mapped to the CLIs; smoke-tested (`list_tools`, call
  `vault_list`/`agent_id_status`). ← *in progress this session*
- [ ] **2. Browser tools** — map `browser_*` to `agent-id-browser` (the daemon
  already runs server-side; the MCP server just relays `open/act/close/fill_*`).
- [ ] **3. HTTP transport + auth** — Streamable-HTTP with a per-user bearer; map
  the bearer → per-user `AGENT_ID_STATE_DIR`.
- [ ] **4. Hosting** — add the MCP route to lethe-hosted (or a sibling service);
  bake `agent-id-mcp` into the runtime image; nginx route + TLS.
- [ ] **5. Cowork plugin** — connector manifest + skills; validate install via the
  Cowork setup flow.

### Open decisions

- **Where hosted**: fold into the lethe-hosted control plane vs a standalone
  `agent-id-mcp` service. Leaning fold-in (reuses per-user containers + Chrome).
- **Auth**: reuse lethe-hosted per-user tokens vs a dedicated OAuth for the
  connector. Cowork connectors support both bearer and OAuth.
- **Multi-tenant browser**: one sealed-browser daemon per user (as today) keyed by
  the per-user state dir.
