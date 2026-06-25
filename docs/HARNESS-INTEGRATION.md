# Integrating Alien Agent ID into any agent harness

*A manual / power-user guide for wiring agent-id into an agent framework other than
Claude Code (Hermes, a custom loop, a shell, CI, …).*

> **Different from [INTEGRATION.md](INTEGRATION.md)** — that one is the *other
> direction*: how a web **service** adds Alien Agent ID auth. This one is how an
> **agent operator** gives their agent the identity + vault + proxy.

The Claude Code plugins are a **skin**. Underneath, every capability is a plain
**Node CLI** plus a **localhost HTTP proxy** that read and write state under
`~/.agent-id`. Nothing in the runtime path depends on Claude Code — the skill
manifests, `allowed-tools`, and hooks are the only Claude-specific pieces, and you
replace them with your harness's own equivalents (system prompt, permissioning,
setup step). This guide is the contract.

---

## 1. Model in one paragraph

- **Identity + vault state** live in a single dir (`~/.agent-id`, overridable per
  command with `--state-dir` or the `AGENT_ID_STATE_DIR` env var).
- **Capabilities are CLIs** under `plugins/<name>/bin/cli.mjs`. They take flags,
  act on the state dir, and print **JSON to stdout** (human notes go to stderr).
- **Runtime credential use goes through the proxy** — a localhost HTTP server that
  injects vaulted secrets into outbound requests so the agent uses a credential
  **by name** and never sees its value.

The agent never needs a secret. It needs (a) the ability to run a few `node …/cli.mjs`
commands and (b) the proxy URL.

---

## 2. Prerequisites & install

```bash
# Node 18+ (uses built-in fetch, node:test, WebCrypto). No Claude Code required.
git clone https://github.com/alien-id/agent-id.git
cd agent-id
# CLIs are zero-dependency except the browser plugin (patchright, installed on demand).

# Convenience: alias the CLIs (adjust the absolute path).
ROOT=$(pwd)
core(){  node "$ROOT/plugins/agent-id-core/bin/cli.mjs"   "$@"; }
vault(){ node "$ROOT/plugins/agent-id-vault/bin/cli.mjs"  "$@"; }
proxy(){ node "$ROOT/plugins/agent-id-proxy/bin/cli.mjs"  "$@"; }
```

State dir resolution for **every** command: `--state-dir <path>` → `$AGENT_ID_STATE_DIR`
→ `~/.agent-id`.

---

## 3. One-time setup

```bash
# a) Create the agent identity (offline; usable immediately at assurance level L0).
core init                      # → {fingerprint, publicKeyPem}
core status                    # → {level:0, assurance:"self-asserted", ...}
#   Optional human attestation (L1 anonymous / L2 linked) needs the Alien SSO:
#   core bootstrap --provider-address <addr>   (init + auth + bind)

# b) Create the vault — choose how it unlocks (see the vault skill for the trade-offs).
vault init --unlock passkey    # Touch ID / Face ID / security key (agent can't self-unlock)
#   or: vault init --unlock passphrase     (typed into a secure form; dev mode)
#   or: vault init                          (== --unlock agent-key: unattended auto-unlock)

# c) Add credentials, host-scoped (default-deny). The value never hits argv/transcript:
vault add --name github-pat --type bearer --domains '*.github.com,api.github.com' \
  --value-file /tmp/tok
vault add --name openai-key --type header --header-name X-Api-Key \
  --domains api.openai.com --form        # opens a localhost form for a human to type it
```

`AGENT_ID_NO_BROWSER=1` makes any form/ceremony print its URL instead of opening a
browser — use it on headless boxes (open the URL through an SSH tunnel).

---

## 4. The integration centerpiece — the proxy

Start it once; it holds the unlocked master key in memory and injects credentials
into outbound requests.

```bash
proxy start --port 48771           # tries agent-key unlock, else prompts on /dev/tty
# Hard-boundary unlock (agent can't self-unlock): a human unlocks once per session:
proxy start --unlock-form          # passphrase form (dev vault) or a passkey ceremony
```

### Mode 1 — URL-rewrite (recommended, universal, HTTPS upstreams)

The agent calls a local URL that names the credential and the real upstream:

```
http://<proxy-host>:<port>/<credential-name>/<upstream-host>/<path>
```

```bash
# The agent only ever names the credential — the proxy injects the secret + forwards over HTTPS:
curl http://localhost:48771/github-pat/api.github.com/user
curl -X POST http://localhost:48771/openai-key/api.openai.com/v1/chat/completions \
  -H 'content-type: application/json' -d '{"model":"...","messages":[...]}'
```

The proxy validates the upstream host against that credential's allowlist
(default-deny), materializes the secret by type (`bearer`→`Authorization: Bearer`,
`header`→named header, `query`→query param, `cookie`/`cookie-jar`, `totp`→generated
code), and is itself the HTTPS client. **Wallet credentials** (`solana-keypair`,
`evm-keypair`) are signed *inside* the proxy: the agent submits an *unsigned*
JSON-RPC tx and the proxy fills the signature — the private key never leaves the
process. (Full per-type table + wallet flows: [VAULT-PROXY.md](VAULT-PROXY.md).)

### Mode 2 — `HTTP_PROXY` stub (legacy, plain HTTP only)

For agents that just set the standard proxy env and can't rewrite URLs:

```bash
export HTTP_PROXY=http://127.0.0.1:48771
curl -H 'Authorization: AgentVault github-pat' http://api.example.com/foo
```

HTTPS upstreams would need TLS interception (out of scope) — prefer Mode 1.

### What to put in your harness's system prompt

> You have a credential proxy at `http://localhost:48771`. To call a service that
> needs a secret, request `http://localhost:48771/<credential-name>/<host>/<path>`
> — never ask for or handle the secret itself. Available credentials: `github-pat`
> (api.github.com), `openai-key` (api.openai.com), … Errors come back as JSON with
> an `error` field (`credential_not_found`, `host_not_allowed`, `vault_locked`).

---

## 5. Other capabilities (no proxy)

```bash
# Inject a credential into a child process's ENV or a temp key FILE (env-var-auth tools):
vault exec --env OPENAI_API_KEY=openai-key.value -- python train.py
vault exec --file GIT_SSH_KEY=deploy-key.value -- \
  sh -c 'GIT_SSH_COMMAND="ssh -i $GIT_SSH_KEY -o IdentitiesOnly=yes" git fetch'

# Drive a real, logged-in browser whose session is sealed in the vault:
node plugins/agent-id-browser/bin/cli.mjs login --name x --url https://x.com   # headed, one-time
node plugins/agent-id-browser/bin/cli.mjs read  --name x --url https://x.com/home   # headless

# SSH-signed git commits with provenance:
node plugins/agent-id-git/bin/cli.mjs setup
node plugins/agent-id-git/bin/cli.mjs commit --message "..." --push

# DPoP-signed calls to Alien-aware services:
node plugins/agent-id-auth/bin/cli.mjs call --url https://service/op --method POST --body '{...}'
```

---

## 6. Replacing the Claude Code wrappers

| Claude Code piece | What it did | Your harness equivalent |
|---|---|---|
| `SKILL.md` `description` | Auto-surfaced the capability to the model | Put a capability/usage block in your system prompt or tool registry (distill from each `skills/*/SKILL.md`) |
| `allowed-tools` | Gated which commands the agent could run | **Your harness must gate this** — see §7 |
| SessionStart hook (`session-unlock.sh`) | Popped the unlock form once per session | Call `proxy start --unlock-form` yourself at session start |
| Install hook (`install-patchright.sh`) | Auto-installed patchright | Run it once, or `cd plugins/agent-id-browser && npm install`. Browser commands also auto-install into `--plugin-data <dir>` on first use |
| `${CLAUDE_PLUGIN_DATA}` | Per-plugin writable dir for the browser | Pass `--plugin-data <dir>` to browser commands (only the browser plugin needs it) |

Env vars you control: `AGENT_ID_STATE_DIR` (state location), `AGENT_ID_PROXY`
(convention for the proxy base URL), `AGENT_ID_NO_BROWSER=1` (headless: print form
URLs instead of opening a browser).

---

## 7. Security model on a foreign harness — read this

The **capability** ports for free; the **guardrails** need your harness to cooperate.

- **The proxy boundary holds regardless of harness.** An agent that can make
  arbitrary calls to the proxy still cannot extract plaintext (it gets injected, not
  returned) and cannot reach a host outside each credential's allowlist (default-deny).
  This is the safe surface to expose broadly.
- **`vault show` and `vault exec` are agent-invocable and *do* surface secrets** (by
  design, for export / env-var-auth tools). On Claude Code `allowed-tools` keeps the
  agent from calling them; **on your harness you must apply the same gate** — restrict
  or human-approve `vault show`, `vault exec`, and `vault add`. Treat
  `node …/agent-id-vault/bin/cli.mjs` as a privileged command; treat proxy URL calls
  as unprivileged.
- **Hard vs. soft unlock.** `vault init --unlock passkey|passphrase` (and
  `proxy start --unlock-form`) require a *human* to unlock — the agent cannot
  self-unlock. `--unlock agent-key` lets the agent auto-unlock (convenience). Pick per
  stakes.
- **Idle lock.** The proxy zeroes the master key after `--idle-timeout` (default 12h);
  requests then return `401 {error:"vault_locked"}` until re-unlocked.
- **Residual.** Vault/proxy run as the **same uid** as the agent, so a same-user process
  could scrape this process's memory. Closing that needs the proxy as a separate OS
  principal (roadmap). Don't run the agent and the proxy as the same user if you need
  that boundary today.

---

## 8. Command surface (JSON in → JSON out)

Every command prints a JSON object; `ok:false` carries an `error` code. Run any CLI
with `--help` for the full flag list.

| Plugin | CLI | Key commands |
|---|---|---|
| core | `agent-id-core/bin/cli.mjs` | `init`, `bootstrap`, `status`, `refresh`, `sign`, `verify`, `export-proof` |
| vault | `agent-id-vault/bin/cli.mjs` | `init --unlock …`, `add`, `generate`, `show`, `list`, `remove`, `exec`, `rekey`, `export`, `import`, `migrate` |
| proxy | `agent-id-proxy/bin/cli.mjs` | `start`, `status`, `stop`, `pair`, `autounlock` |
| browser | `agent-id-browser/bin/cli.mjs` | `login`, `read`, `fetch`, `status`, `open`/`snapshot`/`click`/`type`/… |
| git | `agent-id-git/bin/cli.mjs` | `setup`, `commit`, `verify` |
| auth | `agent-id-auth/bin/cli.mjs` | `call`, `header`, `discover`, `capabilities`, `support` |

For the detailed per-command flags and security rationale, read each plugin's
`skills/<name>/SKILL.md` — they double as the canonical usage docs (just ignore the
YAML frontmatter, which is Claude-Code metadata).
