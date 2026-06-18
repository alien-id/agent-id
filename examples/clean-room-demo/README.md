# Clean-room demo — an agent using vaulted credentials

A fresh AI agent, given **only** the [`alien-vault`](skills/alien-vault/SKILL.md)
skill, reads the owner's Gmail — unlocked once from the owner's phone — **without
ever seeing a credential**. If the proxy isn't running, the agent starts it
itself.

This is the consumer-facing counterpart to the operator docs in
[`docs/VAULT-PROXY.md`](../../docs/VAULT-PROXY.md): the vault + proxy give an
agent typed, domain-scoped credentials it can *name but never read*; this skill
is what teaches an agent to use them.

## What the skill teaches

1. **Start the proxy if it's down** (`--await-mobile`, locked) — pointing at the
   vault's state-dir.
2. **Call** `http://127.0.0.1:48771/<credential>/<host>/<path>` — the proxy
   injects the real credential and forwards over TLS.
3. **The owner unlocks once on their phone** — a locked request parks until the
   phone approves, then completes. The agent never runs an unlock command (it
   can't) and never handles a secret.

## Setup (one time)

1. **Build a vault** (see the [`agent-id-vault`](../../plugins/agent-id-vault/)
   skill):

   ```bash
   node <AGENT_ID_REPO>/plugins/agent-id-vault/bin/cli.mjs \
     init --state-dir <VAULT_DIR> --passphrase-file <passfile>
   ```

2. **Log in once and let the vault capture the credential.** Two ways:

   **Option A — capture your browser session (no Cloud Console).** The
   [`gmail-cookie-bootstrap.mjs`](../gmail-cookie-bootstrap.mjs) script captures
   your Gmail web session's cookies into a `cookie-jar` credential via a `0600`
   temp file that's removed on exit (including on Ctrl-C). Nothing from Google Cloud Console is
   needed; the agent reads the cookie-authed **Gmail Atom feed** through the
   proxy. Two modes (it auto-picks Firefox if a profile is found):

   ```bash
   # Firefox — reuses the session you ALREADY have open. Firefox stores cookies
   # unencrypted, so there's no browser launch and no re-login.
   node <AGENT_ID_REPO>/examples/gmail-cookie-bootstrap.mjs \
     --state-dir <VAULT_DIR> --passphrase-file <passfile> --name gmail \
     --browser firefox            # add --profile <name|dir> for a non-default profile

   # Chrome — launches Chrome; you sign into Gmail once (Chrome encrypts cookies
   # on disk, so they can't be read without a live session). Requires Node >= 22.
   node <AGENT_ID_REPO>/examples/gmail-cookie-bootstrap.mjs \
     --state-dir <VAULT_DIR> --passphrase-file <passfile> --name gmail \
     --browser chrome             # add --reuse-profile <dir> (Chrome must be closed)
   ```

   The agent then reads via
   `http://127.0.0.1:48771/gmail/mail.google.com/mail/u/0/feed/atom` (the bare
   `/mail/feed/atom` 302-redirects to this account-indexed path). **Tradeoff:**
   Google rotates session cookies, so a captured jar isn't durable — re-run the
   bootstrap when reads start redirecting to login. Smoothest for a demo; for
   something you rely on daily, prefer Option B.

   **Option B — OAuth refresh token (durable, needs a one-time OAuth client).**
   The [`gmail-login-bootstrap.mjs`](../gmail-login-bootstrap.mjs) script runs a
   loopback OAuth flow: it opens your browser to Google's consent screen
   (reusing your existing Google session — you just click **Allow**), captures
   the grant on `http://127.0.0.1:<port>`, exchanges it for a long-lived
   **refresh token**, and pipes that token straight into an `oauth2` credential
   via a `0600` temp file that's removed on exit (including on Ctrl-C).

   ```bash
   node <AGENT_ID_REPO>/examples/gmail-login-bootstrap.mjs \
     --client-id <CLIENT_ID> --client-secret-file <secretfile> \
     --state-dir <VAULT_DIR> --passphrase-file <passfile> \
     --name gmail --scope https://www.googleapis.com/auth/gmail.readonly
   ```

   The proxy then auto-refreshes short-lived access tokens from that stored
   refresh token on every request — the agent never sees any token. This is the
   only option with true read-only scoping, but it needs a **one-time Google
   setup:** create an OAuth client (Google Cloud Console → APIs & Services →
   Credentials → **OAuth client ID** → *Desktop app*), enable the **Gmail API**,
   and set the consent screen to **In production** so the refresh token doesn't
   expire after 7 days.

3. **Add an unlock method** so a locked vault can be re-opened on demand:

   - **Owner-approval (recommended).** The proxy drives the approval through the
     Alien SSO over TLS — your phone (on any network, even cellular) approves in
     the Alien app, and the master key never crosses a link. Needs an owner
     session (`agent-id-core auth`), then:
     ```bash
     agent-id-vault rekey add-owner-approval --state-dir <VAULT_DIR>
     ```
     (Today the SSO escrow contract is implemented only by `examples/dev-sso.mjs`;
     production use waits on the Alien SSO shipping it.)
   - **Mobile slot (same machine / trusted LAN only).** A phone unseals the
     master key and POSTs it to the control plane. That POST is plain HTTP, so a
     *separate* phone means binding the control plane to the LAN and sending the
     master key in cleartext — fine for a same-host approver or a trusted-LAN
     demo, not the open network. Pair with `agent-id-proxy pair` (shows a QR) or
     `agent-id-vault rekey add-mobile --device-pubkey <hex>`.

4. **Install the skill** into the demo project:

   ```bash
   mkdir -p <project>/.claude/skills/alien-vault
   cp skills/alien-vault/SKILL.md <project>/.claude/skills/alien-vault/SKILL.md
   # then replace <AGENT_ID_REPO> and <VAULT_DIR> in that file with absolute paths
   ```

## Run it

```
cd <project>
claude                      # a fresh agent — its only skill is alien-vault
```

Then tell the agent: **"Read my latest Gmail."**

1. The agent invokes the skill, finds the proxy down, and **starts it** (locked).
2. It calls the proxy; the request **parks** — the vault is locked.
3. You **approve in the Alien app** (owner-approval: the proxy drives the SSO and
   you tap Approve; or, for a mobile slot, your phone slides to unlock).
4. The request completes; the agent prints your inbox. No secret ever entered the
   agent's context, transcript, or prompt cache — it only ever typed `gmail`.

## Security notes

- **Never commit `vault.enc`.** It holds your (encrypted) credentials; keep it in
  the state-dir, out of version control. This example ships only the skill.
- Keep the vault's state-dir separate from where the agent key lives if you want
  to *force* the phone-unlock path (no agent-key fast-unlock available there).
- The proxy idle-locks (default 12 h; `--idle-timeout` to tune); a locked request
  re-prompts the phone.
