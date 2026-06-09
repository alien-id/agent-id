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

1. **Build a vault and add a credential** (see the
   [`agent-id-vault`](../../plugins/agent-id-vault/) skill). For the Gmail demo,
   an `oauth2` credential auto-refreshes access tokens from a stored refresh
   token:

   ```bash
   node <AGENT_ID_REPO>/plugins/agent-id-vault/bin/cli.mjs \
     init --state-dir <VAULT_DIR> --passphrase-file <passfile>
   node <AGENT_ID_REPO>/plugins/agent-id-vault/bin/cli.mjs \
     add --state-dir <VAULT_DIR> --name gmail --type oauth2 \
     --domains gmail.googleapis.com \
     --token-endpoint https://oauth2.googleapis.com/token \
     --client-id <CLIENT_ID> --client-secret-file <secretfile> \
     --refresh-token-file <refreshfile> \
     --scope https://www.googleapis.com/auth/gmail.readonly
   ```

   (Mint the Google refresh token with your **own** OAuth client via a loopback
   flow or the OAuth Playground with *offline access*; set the consent screen to
   **In production** so the refresh token doesn't expire after 7 days.)

2. **Pair a phone** — the Alien vault-approver app self-registers over the
   control plane while the proxy is unlocked (or use
   `agent-id-vault rekey add-mobile --device-pubkey <hex>`).

3. **Install the skill** into the demo project:

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
3. Your phone shows the approval → **slide to unlock**.
4. The request completes; the agent prints your inbox. No secret ever entered the
   agent's context, transcript, or prompt cache — it only ever typed `gmail`.

## Security notes

- **Never commit `vault.enc`.** It holds your (encrypted) credentials; keep it in
  the state-dir, out of version control. This example ships only the skill.
- Keep the vault's state-dir separate from where the agent key lives if you want
  to *force* the phone-unlock path (no agent-key fast-unlock available there).
- The proxy idle-locks (default 12 h; `--idle-timeout` to tune); a locked request
  re-prompts the phone.
