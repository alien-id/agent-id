---
name: agent-id-vault
description: Portable encrypted credential vault with LUKS-style slots (passphrase + agent-key) and typed/domain-scoped credential records. Pairs with agent-id-proxy so the agent never sees credential values — the proxy injects them by substituting `AgentVault <name>` stubs. Use whenever the user asks to save, fetch, or remove a service credential, or whenever a downstream tool needs an external-service secret that must not appear in shell history, source files, or process arguments.
license: MIT
metadata:
  author: Alien Wallet
  version: "5.0.0"
allowed-tools: Bash(node *agent-id-vault/bin/cli.mjs:*) Bash(curl:*) Bash(jq:*) Read
---

# Alien Agent ID — Vault

Portable single-file encrypted vault at `${AGENT_ID_STATE_DIR:-$HOME/.agent-id}/vault.enc`.

The master key is held in slots, LUKS-style:
- **slot 0**: passphrase-wrapped (Argon2id-class KDF — scrypt in v1)
- **slot 1**: agent-key-wrapped (auto-unlock on the agent's own machine)

Copy the file to a second machine, type the passphrase, you're in.

Pairs with the agent-id-proxy plugin — the proxy unlocks the vault and injects values into outbound HTTP requests. The agent itself does not retrieve plaintext during normal operation; `show` exists only for manual export.

## Resolve the CLI

`bin/cli.mjs` lives in this plugin's directory. Substitute `CLI` with the absolute path (e.g. `node /abs/path/to/plugins/agent-id-vault/bin/cli.mjs`).

## Initialize the vault

```bash
# Interactive — passphrase typed on /dev/tty, never enters the agent transcript:
node CLI init

# Non-interactive (for automation):
node CLI init --passphrase-file /path/to/pass
```

If the agent has a main key (from `agent-id-core bootstrap`), an agent-key slot is added automatically for fast unattended unlock. Pass `--no-agent-key` to skip it.

## Add a credential

Every credential needs a **name**, **type**, and **domain allowlist** (default-deny — the proxy refuses to inject for any host not on the list).

```bash
# Bearer token (GitHub PATs, OpenAI keys, Slack bot tokens, …):
node CLI add --name github-pat --type bearer \
  --domains '*.github.com,api.github.com' --value-file /tmp/tok

# Custom header (X-Api-Key style):
node CLI add --name openai --type header --header-name X-Api-Key \
  --domains api.openai.com --value-file /tmp/key

# Basic auth:
node CLI add --name old-svc --type basic --domains svc.example.com \
  --username admin --password-file /tmp/pw

# Query param (?api_key=... style):
node CLI add --name geocoder --type query --param-name api_key \
  --domains api.example.com --value-env GEO_KEY

# Cookie:
node CLI add --name session --type cookie --cookie-name sid \
  --domains app.example.com --value-file /tmp/sid

# TOTP seed (proxy generates the code at request time):
node CLI add --name github-totp --type totp --domains '*.github.com' \
  --secret-file /tmp/seed.b32

# Full cookie jar for one origin (JSON object):
echo '{"sid":"abc","csrf":"xyz"}' | node CLI add --name gmail \
  --type cookie-jar --domains mail.google.com
```

Value-input channels — pick the one with the smallest attack surface:
- `--<field>-file <path>` — read from file (recommended)
- `--<field>-env <VAR>` — read from environment variable
- stdin (piped) — `echo "secret" | node CLI add ...`
- `--<field> <value>` — visible in process list; avoid

Never paste a secret into chat. The agent transcript persists.

## Generate a wallet keypair (the key never leaves the vault)

For blockchain wallets the vault can create the private key **itself** — the
key material is generated inside the vault process and sealed
(`exportable: false`): `show` redacts it, `add` refuses the type, and the only
way to exercise it is transaction signing inside the proxy. The command prints
**only the public address**.

```bash
# Solana wallet (ed25519). Domains = RPC hosts the proxy may sign for:
node CLI generate --name sol-hot --type solana-keypair \
  --domains api.mainnet-beta.solana.com

# EVM wallet (secp256k1) — Ethereum, Polygon, Base, any EIP-1559 chain:
node CLI generate --name polygon-hot --type evm-keypair \
  --domains polygon-bor-rpc.publicnode.com,ethereum-rpc.publicnode.com
```

Output (and `list`) carries the address (`publicKey` for Solana, `address` for
EVM) — that is all an agent ever needs: fund the address, build unsigned
transactions against it, and submit them through the proxy, which signs them
in-process (see the proxy skill, "Wallet credentials").

## List, show, remove

```bash
node CLI list                     # metadata only; never plaintext
node CLI show --name github-pat   # plaintext export; prefer the proxy for runtime use
                                  # (sealed/generated records stay redacted)
node CLI remove --name github-pat
```

## Rekey: add/remove slots

```bash
node CLI rekey add-passphrase --new-passphrase-file /tmp/newpass
node CLI rekey add-agent-key
node CLI rekey remove-slot --id 1
```

The CLI refuses to remove the last slot (vault would become unrecoverable).

## Portability

```bash
node CLI export --out vault.enc        # already-encrypted; copy anywhere
node CLI import --in vault.enc         # install on a new machine
```

After importing on machine B, run `rekey add-agent-key` to wire B's main key in for unattended unlock.

## Migration from v4 (single-key-derived) vault

```bash
node CLI migrate                                # interactive passphrase prompt
node CLI migrate --passphrase-file /tmp/pass    # automation
```

One-shot: the old `~/.agent-id/vault/` directory is renamed to `vault.bak/`. Migrated records get the placeholder allowlist `["UNCONFIGURED.invalid"]` — the proxy refuses to inject them until you attach real domains via `agent-id-vault add --name <N> --domains <H,…> --value-env <V>`.

## Common flag

`--state-dir <path>` — defaults to `$AGENT_ID_STATE_DIR` then `~/.agent-id`.
