# Self-Hosted OAuth Broker + Arcade Tool Reuse — Work Report

Date: 2026-06-17

## Goal

Reuse Arcade's open-source tool implementations (the `arcade-*` toolkit packages) while
replacing Arcade's hosted auth engine with self-hosted auth. The agent's encrypted vault
becomes the token store; OAuth flows, refresh, and scope handling run locally. No Arcade
Cloud and no `ARCADE_API_KEY` for the brokered providers.

## What was built

### 1. New plugin: `agent-id-oauth`

A self-hosted OAuth 2.0 token broker, added as a fifth plugin alongside `core`, `git`,
`vault`, and `auth`. Depends on `agent-id-core` (state) and `agent-id-vault` (crypto).

Files:

- `plugins/agent-id-oauth/.claude-plugin/plugin.json` — manifest (deps: core + vault)
- `plugins/agent-id-oauth/lib/oauth.mjs` — broker logic
- `plugins/agent-id-oauth/bin/cli.mjs` — CLI wiring via the shared `runCli` runtime
- `plugins/agent-id-oauth/skills/agent-id-oauth/SKILL.md` — usage doc

Subcommands: `register`, `login`, `complete`, `token`, `list`, `logout`.

Capabilities:

- Authorization Code flow with PKCE (per-provider).
- Tokens stored in the existing AES-256-GCM vault, keyed off the agent's Ed25519 key.
- Automatic refresh when the access token is expired.
- Incremental-consent detection: `token` returns `needs_consent` when a requested scope
  was never granted, with the exact `login` command to widen scopes.
- A 14-provider catalog plus a generic escape hatch (`--authorize-url`, `--token-url`,
  `--scope-separator`, `--scope-param`, `--token-auth`, `--pkce`).
- Two-phase login (`login` prints the URL and returns; `complete` captures the code) to
  avoid the "URL must be shown before blocking" deadlock. `complete --serve` runs a
  loopback server; `complete --callback-url` supports headless/remote.

### 2. Reference integration: `examples/arcade_bridge.py`

Runs Arcade's real OSS tools with auth supplied by the broker:

1. `ToolCatalog.add_module(toolkit)` loads the genuine tool implementations.
2. The tool's `requirements.authorization` yields `provider_id` + scopes.
3. The broker `token` command returns a valid access token from the vault.
4. A `ToolContext(authorization=ToolAuthorizationContext(token=...))` is injected.
5. Arcade's own `ToolExecutor.run` validates input, injects the context, and runs.

### 3. Repo housekeeping

- Registered `agent-id-oauth` in `.claude-plugin/marketplace.json` (now five plugins).
- Updated `README.md` (plugin table, directory tree, install list).

## Verification status

Honesty matters here: "exists" and "the auth works" are not the same as "an Arcade tool
runs end-to-end through the bridge." Status as actually tested:

| Item | Status | Evidence |
| --- | --- | --- |
| Broker `register`/`login`/`complete`/`token` | Proven | Ran against real state |
| Google user OAuth via broker | Proven | Real token, refresh, `gmail.readonly` |
| Gmail tools through the bridge | Proven | `arcade_gmail.ListEmails` returned real inbox |
| Discord user OAuth via broker | Proven | Real token, listed real servers |
| Discord through the bridge | Partial | No PyPI package; demoed a hand-written tool only |
| Other provider toolkits | Not tested | Exist on PyPI; load/auth unverified |
| API-key toolkits | Not usable yet | Bridge does not inject `secrets` yet |

### End-to-end proof (Gmail)

`arcade_gmail.ListEmails` was executed through `examples/arcade_bridge.py`, authenticated
solely by the vault-brokered Google token, and returned the real current inbox — with no
Arcade Cloud and no `ARCADE_API_KEY`.

## Provider and toolkit matrix

Provider auth feasibility and prebuilt-toolkit availability are independent axes. PyPI
availability below was checked directly against the PyPI JSON API on 2026-06-17.

### Auth: redirect friction

- Loopback (`http://localhost`, no tunnel): Google, GitHub, Microsoft, Discord (and
  Spotify/Dropbox via `127.0.0.1`).
- HTTPS required (needs a tunnel such as ngrok): Slack, Notion, Atlassian, Linear, Zoom,
  HubSpot, Asana.

### Prebuilt toolkits on PyPI

- Present: `arcade-gmail`, `arcade-google-calendar`, `arcade-google-docs`,
  `arcade-google-drive`, `arcade-slack`, `arcade-github`, `arcade-notion`,
  `arcade-linear`, `arcade-x`, `arcade-spotify`, `arcade-microsoft`, `arcade-zoom`,
  `arcade-jira`, `arcade-confluence`, `arcade-asana`, `arcade-dropbox`, `arcade-hubspot`.
- API-key tier (no OAuth): `arcade-web`, `arcade-search`, `arcade-google-search`,
  `arcade-code-sandbox`, `arcade-e2b`, `arcade-firecrawl`, `arcade-stripe`,
  `arcade-postgres`.
- Absent: `arcade-discord` (no package — tools must be hand-written).
- Stub: `arcade-google` v3 exists but ships zero tools (deprecated).

## Known limitations and gaps

- The bridge injects only OAuth `authorization`, not `secrets`. API-key toolkits and
  bot-token tools (for example Discord bot actions) do not work until a small
  secret-injection change is added (estimated ~10 lines).
- Only `arcade_gmail` is proven through the bridge. The other PyPI toolkits are listed as
  available but their load and auth behavior is untested.
- Public distribution of Google restricted scopes (Gmail, Calendar, Drive) to users
  outside the org requires Google's CASA security assessment (annual, paid). Personal,
  testing-mode, and Workspace-internal use do not.
- Slack and similarly strict providers reject `http://localhost` redirects and require an
  HTTPS redirect URL (tunnel or deployed catcher).

## Security notes

- Client secrets and access/refresh tokens are stored only inside the encrypted vault
  bundle; non-secret metadata (scopes, expiry) is kept in clear for fast checks.
- During testing, a Google client secret was echoed in plaintext in the session
  transcript. It is stored encrypted now, but rotating that secret is recommended if the
  transcript is retained or shared.

## Suggested next steps

1. Add `secrets` injection to `examples/arcade_bridge.py` to unlock the API-key toolkit
   tier (search, scraping, code sandboxes) and bot tokens.
2. Verify the high-value PyPI toolkits by installing, loading, and running one tool each
   through the bridge — starting with `arcade-github` — to the same bar as Gmail.
3. Decide the shared-app strategy for any provider meant for end users (own the OAuth app
   plus verification, keep bring-your-own-app, or use a hosted engine for that provider).
