---
name: agent-id-browser
description: Sign an agent into a website using a `login` credential from the vault, in a browser reached over its RPC port. The password goes from the vault straight into the page and is never seen by the agent; a 2FA step is answered from a stored TOTP seed or by a card raised to the owner at the moment the site sends the code. A recipe on the credential drives multi-step and identity-provider forms. Use when a task needs an account and the browser is signed out; driving the browser otherwise is not this plugin's job.
license: MIT
metadata:
  author: Alien Wallet
  version: "8.0.1"
allowed-tools: Bash(node *agent-id-browser/bin/cli.mjs:*) Read
---

# Alien Agent ID — Browser

One job: **get a browser signed in** without the password passing through the
agent.

The browser is a separate process — `agent-browser`, which serves a
CDP-shaped RPC port and holds its own profile. Whoever runs it drives it
directly over that port: opening pages, reading them, clicking. This plugin does
not do any of that, and there is no session to open here. It steps in for the one
thing a page-driver cannot do safely: reading a secret out of the vault and
typing it into a form.

```bash
agent-id-browser auto-login --cred CRED --rpc HOST:PORT
```

`--rpc` is the browser's RPC address (`AGENT_ID_BROWSER_RPC` is the default when
set). The command finds or starts a session on that browser, drives the sign-in,
and leaves the browser signed in — that is the whole result. It closes nothing:
the session and its profile belong to the browser.

## What it needs from the vault

A `login` credential, created by the owner through the secure form:

```bash
agent-id-vault add --type login --name github --login-url https://github.com/login \
  --domains github.com --form
```

- `--login-url` — where the sign-in starts. Required.
- `--domains` — the hosts this credential may be used on. **Load-bearing, not
  advisory**: every navigation and every step that types the password or a code
  is refused off this list, so a recipe cannot be talked into typing a secret
  into somebody else's page. A sign-in only reveals which hosts it redirects
  through once it has been driven — widen it afterwards with
  `agent-id-vault set-domains`.
- 2FA policy: `--otp totp` with a stored seed, `--otp interactive` to ask the
  owner for the code, `--otp none` when the site asks for none.
- Passwordless sites (an identifier, then a mailed or texted code) are
  `--passwordless --otp interactive`. There is no password to store, and none
  should be invented.

## How it finds the form

Two ways, in this order:

- **A recipe** — the reliable one for anything past a plain form. An ordered list
  of steps (`navigate`, `fill`, `type`, `click`, `press`, `wait`) with
  `{username}` / `{password}` / `{otp}` substituted at run time. Write it from a
  page you have actually read, and store it with
  `agent-id-vault set-recipe --name CRED --recipe '[…]'`.
- **A heuristic** — fills the identifier field and the password field and
  submits. Good for a single- or two-step form; not for an identity provider.

Microsoft ADFS and Entra are driven by their own well-known element ids, since
their real password field only appears after a "Next" step the heuristic cannot
see.

## What comes back

Success is `{"ok": true, "outcome": "logged-in", "finalUrl": …}`.

A failure carries an `action` saying who has to act — the field to branch on:

| `action` | Meaning |
| --- | --- |
| `owner_must_drive` | A bot wall, or an identity provider that refuses automation. No stored credential clears it. Hand the browser to the owner; do not retry. |
| `owner_must_confirm` | The sign-in is waiting on the owner approving a prompt on their own device. Not a failure — wait for it. |
| `fix_credential` | The stored credential is wrong or incomplete. Report it; retrying the same values changes nothing. |

`outcome` says what the page was doing (`blocked`, `otp-rejected`,
`magic-link`, `qr-sign-in`, `confirm-timeout`, `timeout`, …), `trace` says what
the engine saw round by round, and `pageError` carries the page's own rejection
copy when it printed one. None of them ever contains a secret.

## The secret path

The password is read by **this process**, which holds the vault key, and typed
into the page as real keystrokes. It is never in an argument, a result, a log
line, or an error message — a step that throws while entering a secret is
re-raised without the value.

A one-time code comes from the credential's TOTP seed, or from a card raised to
the owner **at the moment the site actually sends it** — not before, so nobody
sits in front of an empty box waiting for a mail. The card says where the code
was sent, because the page just said so. One run asks at most twice.

## What it will not do

- **Sign in with a read-only credential.** `access: ro` used to mean the session
  it minted was read-only, enforced inside the process that owned the browser.
  This command does not own the browser, and whoever drives it afterwards has no
  such limit — so it refuses rather than quietly handing out the access the
  credential was restricted from.
- **Clear a bot challenge.** Nothing stored can. It reports `owner_must_drive`.
- **Ask the owner for a password**, or invent one for a site that has none.
