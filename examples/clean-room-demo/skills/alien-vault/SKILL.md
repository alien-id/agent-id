---
name: alien-vault
description: Access the owner's external services (Gmail, GitHub, APIs) that require a credential, by calling the local Alien Agent ID vault proxy — without ever seeing, requesting, or handling the secret. Use whenever you're asked to read the owner's email or call a service that needs an API key / token / login. Starts the proxy if it isn't running; the owner unlocks the vault once on their phone; you only ever name the credential.
allowed-tools: Bash(node *agent-id-proxy/bin/cli.mjs:*), Bash(curl:*), Bash(python3:*)
---

<!--
  TEMPLATE — before use, replace the two placeholders below with absolute paths:
    <AGENT_ID_REPO>  → your agent-id checkout, e.g. /Users/you/agent-id
    <VAULT_DIR>      → the vault's state-dir (where vault.enc lives), e.g. /Users/you/vault-demo
  And edit the "Available credentials" table to match the credentials you added.
  See this directory's README.md for the full setup.
-->

# Alien Vault — using the owner's credentials without seeing them

The owner keeps their API keys, tokens, and logins in an **encrypted vault**. A
local **proxy** holds the unlocked vault in memory and injects the real
credential into outbound requests for you. You never receive the secret value —
you only ever name the credential.

**The trust boundary, and your one rule:** you can *identify* a credential by
name; you can never *read* its value. So:

- ✅ Call the proxy URL naming the credential and the upstream host.
- ❌ Never ask the owner for the secret, never try to read the vault file, never
  run `agent-id-vault show`, never echo a token. There is nothing to copy — the
  proxy does the auth.

## Step 1 — Make sure the proxy is running

The proxy listens on `http://127.0.0.1:48771` (data) and `:48772` (control).
Check whether it's up:

```bash
curl -s -m 2 http://127.0.0.1:48772/status
```

- Returns JSON (`{"ok":true,...}`) → it's already running. Go to Step 2.
- Connection refused / empty → it isn't running. **Start it yourself**, as a
  long-running **background** process (it serves until stopped — do not wait for
  it to exit / don't block on it):

  ```bash
  node <AGENT_ID_REPO>/plugins/agent-id-proxy/bin/cli.mjs \
    start --state-dir <VAULT_DIR> \
    --await-mobile --approval-timeout 5m --idle-timeout 30m
  ```

  Wait ~2 s, then confirm:

  ```bash
  curl -s http://127.0.0.1:48772/status
  ```

  You should see `"locked": true` and a paired device. Always start it
  **locked** with `--await-mobile`, and point `--state-dir` at the directory
  holding `vault.enc` — the owner unlocks on their phone, never via a stored
  key. Don't start it any other way.

## Step 2 — Call the service

To reach an upstream service, call:

```
http://127.0.0.1:48771/<credential-name>/<upstream-host>/<path...>
```

The proxy looks up `<credential-name>`, checks `<upstream-host>` against that
credential's allowlist, injects the real credential, and forwards to
`https://<upstream-host>/<path>` over real TLS. You get the upstream's response
body back. You do **not** do TLS or auth yourself — just call the local URL.

### Available credentials

| Name | Upstream host | What it is |
|---|---|---|
| `gmail` | `gmail.googleapis.com` | The owner's Gmail (read-only) |

(If you need a credential that isn't listed, tell the owner its name and what
it's for — don't guess or ask for the raw secret.)

## Step 3 — The owner unlocks on their phone

The vault starts **locked** (and re-locks when idle). There is **no unlock
command for you to run** — you can't unlock it, and you shouldn't try. Instead:

1. Just make your request. If the vault is locked, the proxy **pauses your
   request** and sends an approval prompt to the owner's phone. Use a generous
   timeout so the request can wait:

   ```bash
   curl -s --max-time 180 'http://127.0.0.1:48771/gmail/gmail.googleapis.com/gmail/v1/users/me/profile'
   ```

2. The owner slides to unlock on their phone. Your paused request then completes
   and returns normally — often after a 10–60 s pause. That pause is expected;
   don't abort and retry in a tight loop.
3. Once unlocked, further requests return instantly (no prompt) until it
   idle-locks again.

If you instead get back `{"error":"vault_locked"}` with HTTP 401, the proxy is
running without a phone-approval channel — restart it with `--await-mobile` as
in Step 1.

## Reading Gmail (recipes)

All paths below are relative to `http://127.0.0.1:48771/gmail/gmail.googleapis.com`.

- **Confirm access / whoami:** `GET /gmail/v1/users/me/profile`
- **List recent inbox message IDs:** `GET /gmail/v1/users/me/messages?maxResults=10&q=in:inbox`
- **Search:** add a Gmail query, e.g. `?q=from:boss@example.com newer_than:7d`
- **Headers + snippet of one message:**
  `GET /gmail/v1/users/me/messages/<id>?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`
- **Full body of one message:** `GET /gmail/v1/users/me/messages/<id>?format=full`
  (the body is base64url in `payload.parts[].body.data` / `payload.body.data`).

`messages.list` returns only IDs — fetch each message separately for headers and
content. To list the latest inbox emails with sender + subject + snippet:

```bash
python3 - <<'PY'
import json
from urllib.request import urlopen
B = "http://127.0.0.1:48771/gmail/gmail.googleapis.com/gmail/v1/users/me"
def get(p):
    with urlopen(B + p) as r: return json.load(r)
ids = [m["id"] for m in get("/messages?maxResults=10&q=in:inbox").get("messages", [])]
for i, mid in enumerate(ids, 1):
    d = get("/messages/%s?format=metadata&metadataHeaders=From&metadataHeaders=Subject" % mid)
    h = {x["name"]: x["value"] for x in d["payload"]["headers"]}
    unread = "*" if "UNREAD" in d.get("labelIds", []) else " "
    print("%2d. %s %-40s | %s" % (i, unread, h.get("From","?")[:40], h.get("Subject","")[:60]))
    print("      " + d.get("snippet","")[:90])
PY
```

## Errors

| Response | Meaning | What to do |
|---|---|---|
| connection refused on :48771/:48772 | Proxy not running | Start it (Step 1) |
| HTTP 401 `vault_locked` | Running without phone channel | Restart with `--await-mobile` (Step 1) |
| HTTP 400 `credential_not_found` | No credential by that name | List what you tried; ask the owner for the right name |
| HTTP 403 `host_not_allowed` | Host isn't on the credential's allowlist | You used the wrong upstream host for that credential |
| HTTP 401/502 `oauth_refresh_*` | The stored token was revoked/expired | Tell the owner to re-mint that credential |

Report what you read in plain terms. The credential value never appears in your
output because you never had it — that's the design.
