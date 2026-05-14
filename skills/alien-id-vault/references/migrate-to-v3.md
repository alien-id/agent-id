# Migrate to agent-id 3.0.0+

Pre-3.0 agents bound via the v2 owner-proof model carry cnf-less id_tokens and a `owner-binding.json` artifact that the v3 verifier rejects. Migrate before the next signed call.

## Detect

After `node CLI status`, check for the legacy artifact:

```bash
STATE_DIR="${AGENT_ID_STATE_DIR:-$HOME/.agent-id}"
test -f "$STATE_DIR/owner-binding.json" && echo "pre-v3 state — migrate"
```

If the file exists, stop and surface the migration to the user. Do not proceed with `call`, `sign`, `git-commit`, or any operation that asserts identity until the migration is done.

## Recommended — safe in-place migration

Keeps the agent keypair, vault, and audit log. Re-runs OAuth under DPoP so the new id_token carries `cnf.jkt`. Previously signed commits stay verifiable because the keypair is unchanged.

```bash
node CLI setup-owner-session --provider-address <PROVIDER_ADDRESS>
```

The command clears only `owner-binding.json`, `owner-session.json`, and `pending-auth.json`, then walks through the same QR-code flow as bootstrap step 3-4. The user scans, the new owner-session is written, the migration is done.

Resolve `<PROVIDER_ADDRESS>` exactly as in [bootstrap.md](bootstrap.md) step 1 — ask the user before reading `default-provider.txt`.

## Fallback — back up and re-bootstrap

Only if the safe path fails or the state directory is corrupt. Renames the existing directory aside instead of deleting it, so vault contents and the audit chain stay recoverable:

```bash
STATE_DIR="${AGENT_ID_STATE_DIR:-$HOME/.agent-id}"
mv "$STATE_DIR" "${STATE_DIR}.pre-v3-backup-$(date +%Y%m%d-%H%M%S)"
# then run the full bootstrap flow — see bootstrap.md
node CLI init
node CLI auth --provider-address <PROVIDER_ADDRESS>
node CLI bind
node CLI git-setup
```

What changes for the user:

- new agent keypair — every commit previously signed by this agent loses its provenance link (the SSH signature still verifies as bytes, but `git-verify` will fail because the new key has a different thumbprint),
- vault entries are not carried over — GitHub PATs, Slack tokens, AWS keys etc. live under `<backup-dir>/vault/` and must be re-stored via `vault-store` if needed,
- the audit log chain restarts from sequence 0; the old chain is preserved under the backup directory for forensics.

Surface every item above to the user before running the `mv`. The backup directory is the user's responsibility to remove once they confirm nothing was needed from it.

## After migration

Re-run `node CLI status` and confirm `bound: true` with a `jkt` value present. The next `node CLI call` will exercise the cnf.jkt-bound id_token; a 401 here usually means the SSO is still on a pre-v3 deploy, not that the migration failed.
