---
name: agent-id-browser
description: Drive a real, logged-in browser whose profile is sealed in the agent vault — fine-grained control (click, type, fill forms, press keys, select, hover, navigate, screenshot, run JS) via an accessibility snapshot with element refs, plus one-shot read/fetch. One-time HEADED login establishes the session; afterwards the agent drives it HEADLESS (no window). Use for authenticated sites that block API/OAuth/cookie access (e.g. Gmail/Workspace) or any task needing a real logged-in browser — the agent never sees a credential, it drives the browser.
license: MIT
metadata:
  author: Alien Wallet
  version: "0.1.0"
allowed-tools: Bash(node *agent-id-browser/bin/cli.mjs:*) Read
---

# Alien Agent ID — Browser

Drives a real browser (patchright — a stealth-patched Playwright, **bundled with
this plugin, no install**) using a profile **sealed in the vault**. The human logs
in **once** in a visible window; the session is encrypted at rest, and the agent
reuses it **headless** to observe and act on any site. The agent never handles a
secret — it only drives the browser.

`CLI` below is `node /path/to/plugins/agent-id-browser/bin/cli.mjs`.

## Before anything — the vault must be unlocked

Every command needs the vault open. Unlock order (automatic):
1. **agent-key slot** — silent, unattended (if the vault has one).
2. **passphrase** — `--passphrase-file F` / `--passphrase-env V`.
3. **owner-approval** — if the vault has an owner-approval slot, the command sends
   an approval request to the owner's **Alien app** and waits; the owner taps
   approve and the command continues. This is the same app-unlock the proxy uses.
   Because it **blocks until approved**, run such a command in the **background**
   and tell the owner to approve. (`--no-owner-approval` skips it.)

If none is available, the command returns:

```json
{ "ok": false, "error": "VAULT_LOCKED", "action": "ask_owner_to_unlock", "message": "..." }
```

**On `VAULT_LOCKED`: STOP. Ask the owner to unlock the vault (provide a passphrase,
or approve in the Alien app). Do not retry until they confirm.** (patchright is
bundled — there is no install step; never run `npm install` or any setup command.)

## 1) One-time login (headed — the only human step)

Opens a real window; the owner signs in and **closes it**; the profile is sealed
into the vault as a `browser-profile` credential.

```bash
CLI login --name gmail --url https://mail.google.com/ --account me@company.com
```

It **blocks until the window is closed**, so run it in the **background** and tell
the owner to sign in. On success: `{ ok: true, name, headlessDefault: true }`.
Re-run `login --name gmail` to re-establish the session after a logout.

## 2) Interactive control (the main loop)

Start a persistent session, then observe → act → observe. **Run `open` in the
background** (it stays running) and wait for its `{"ready":true,...}` line:

```bash
CLI open --name gmail            # background; add --headed to watch
```

**Observe** — get an accessibility snapshot; every actionable element has a `ref`:

```bash
CLI snapshot --name gmail
# → { elements: [ { ref:"e5", role:"button", name:"Compose" }, … ] }
```

**Act** — reference elements by their `ref` from the latest snapshot:

```bash
CLI click  --name gmail --ref e5
CLI type   --name gmail --ref e8 --text "hello@there.com" [--submit]
CLI fill   --name gmail --fields '[{"ref":"e8","value":"a"},{"ref":"e9","value":"b"}]'
CLI select --name gmail --ref e3 --values Option1
CLI press  --name gmail --key Enter [--ref e8]
CLI hover  --name gmail --ref e4
CLI scroll --name gmail --dy 800
CLI navigate --name gmail --url https://mail.google.com/mail/u/0/
CLI back   --name gmail
CLI page-text --name gmail --max-chars 4000     # visible text of the page
CLI screenshot --name gmail --path /tmp/shot.png [--full]
CLI eval   --name gmail --js "document.title"
CLI wait   --name gmail --text "Inbox"          # or --ms 1500
```

**Re-snapshot after anything that changes the page** (click/navigate/submit) —
refs are only valid until the next snapshot/navigation. After an action that
navigates, `wait` for expected text, then `snapshot` again.

**Finish** — always close; this reseals the (refreshed) session and wipes the
plaintext working copy:

```bash
CLI close --name gmail
CLI sessions            # list open sessions
```

## 3) One-shot reads (no session needed)

For a quick read without opening an interactive session:

```bash
CLI read  --name gmail --url "https://mail.google.com/mail/u/0/"     # page text + final URL
CLI fetch --name gmail --url "https://mail.google.com/mail/u/0/feed/atom"  # authenticated GET
```

> Gmail tip: open `https://mail.google.com/mail/u/0/` (via `read` or `navigate`)
> once so `mail.google.com` issues its host cookies before `fetch`-ing the feed —
> a bare feed request can 401 right after login.

## 4) Status

```bash
CLI status [--name gmail]   # profiles: account, headlessDefault, sealed, lastSyncedAt
```

If the vault is locked, `status` returns `{ ok: true, unlocked: false }` (not an error).

## Handling logout

`read` / `fetch` (and a navigation in a session that lands on a sign-in page)
return `"sessionExpired": true` with `"action": "re_login"`. On that signal,
**re-run `login --name <profile>`** — do not keep retrying.

## Notes

- **Headless by default**; `--headed` shows the window. Login is always headed.
- The profile is unsealed to a temp working dir only while a session/read runs,
  re-sealed (capturing rotated cookies) when it ends, and the plaintext is wiped.
- Universal — point it at any site; not Gmail-specific.
