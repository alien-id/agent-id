# Alien Agent ID — Vault: admin reference

Less-common vault administration: managing unlock slots, moving the vault between
machines, and migrating a legacy v4 vault. As in `SKILL.md`, `CLI` is
`${CLAUDE_PLUGIN_ROOT}/bin/cli.mjs`, and `--state-dir <path>` (default
`$AGENT_ID_STATE_DIR` then `~/.agent-id`) works on every subcommand below.

## Rekey: add/remove slots

```bash
node CLI rekey add-passkey [--device-label NAME]                  # Touch ID / Face ID / security key
node CLI rekey add-passphrase --new-passphrase-file /tmp/newpass   # DEV-mode vaults only
node CLI rekey add-agent-key
node CLI rekey add-mobile --device-pubkey HEX [--device-id NAME]   # phone (ECDH)
node CLI rekey add-owner-approval [--sso-url URL]                  # Alien app
node CLI rekey remove-slot --id 1
```

`rekey add-passphrase` only works on a **dev-mode** vault — on a user-mode vault it
is refused (`PASSPHRASE_NOT_ALLOWED`), and there is no command to convert modes.
The CLI also refuses to remove the last slot (vault would become unrecoverable).

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
