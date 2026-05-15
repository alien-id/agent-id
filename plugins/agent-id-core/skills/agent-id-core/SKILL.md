---
name: agent-id-core
description: Alien Agent ID — bootstrap and lifecycle. Establish an agent identity bound to a verified human owner via Alien Network SSO (OIDC + DPoP), check or refresh the identity's state, and sign or verify arbitrary attestation operations into the agent's local hash-chained audit trail. Use when the user asks to bootstrap an Alien Agent ID, set up the agent identity, check whether one already exists, refresh the SSO session, migrate a pre-v3 binding, or sign / verify / export-proof an arbitrary operation. Also triggers on "Alien ID", "Agent ID", "DPoP", "cnf.jkt", or "owner binding".
license: MIT
metadata:
  author: Alien Wallet
  version: "0.0.0"
allowed-tools: Bash(node *agent-id-core/bin/cli.mjs:*) Bash(curl:*) Bash(jq:*) Read
---

# Alien Agent ID — Core

The bootstrap and lifecycle surface. Every other agent-id-* plugin assumes the state directory produced here exists and that the owner session is current.

State directory layout (under `${AGENT_ID_STATE_DIR:-$HOME/.agent-id}`):

- `keys/main.json` — Ed25519 keypair for the main agent identity.
- `owner-session.json` — SSO-issued `id_token` / `access_token` / `refresh_token`, plus the bound owner's `sub`.
- `audit/operations.jsonl` — hash-chained record of every signed operation.
- `sequence.json`, `nonces.json` — counters that anchor the chain.

## Resolve the CLI

`bin/cli.mjs` lives in this plugin's directory. Substitute `CLI` with the absolute path (e.g. `node /abs/path/to/plugins/agent-id-core/bin/cli.mjs`) in the examples below.

## At the start of a session

Check whether an identity already exists:

```bash
node CLI status
```

Returns `{ initialized, bound, jkt, ownerSub, providerAddress, ... }`. If `bound: true`, skip to signing operations or to the per-plugin CLIs.

If `bound: false`, start bootstrap **immediately** — do not ask "want me to start?" first; invoking this skill is the opt-in. The first user-facing message is the provider question (Step 1 below), not a confirmation prompt.

## Bootstrap

The flow requires the user to scan a QR code in the Alien App. The single-call `bootstrap` blocks ≤5 minutes; for environments where you can surface the QR to the user before polling starts, run the steps individually instead.

```bash
# Single call (blocks during the polling window):
node CLI bootstrap --provider-address <addr>

# Or step-by-step:
node CLI init                              # generate keypair
node CLI auth --provider-address <addr>    # emits deep_link + qrCode
# show the qrCode / deepLink to the user, ask them to scan with Alien App
node CLI bind --timeout-sec 300            # poll for approval
```

The default provider address can be set via `--provider-address`, the `ALIEN_PROVIDER_ADDRESS` environment variable, or a `default-provider.txt` next to `bin/cli.mjs`.

After bootstrap completes, the agent has a bound identity but is not configured for git signing. To enable signed commits, run `agent-id-git setup` from the git plugin's CLI.

## Migrate a pre-v3 binding

If `status` shows `bound: true` but the verifier complains about missing `cnf.jkt`, the binding predates v3. Force a fresh OIDC flow that produces a DPoP-bound, cnf-carrying id_token without rotating the agent key (preserving the audit trail and any signed commits):

```bash
node CLI setup-owner-session --provider-address <addr>
```

## Refresh the SSO session

The access_token rotates on a tight cadence. Every per-plugin CLI calls `SignatureEngine.ensureValidSession()` internally, so most consumers do not need to refresh explicitly. To refresh manually:

```bash
node CLI refresh
```

Returns `{ ok, refreshedAt, ownerSessionSub, providerAddress }` or an `auth-revoked` error if the AS has rejected the refresh token.

## Sign an arbitrary operation

Every operation that needs to leave a tamper-evident record in the audit trail goes through `sign`. Git commits and vault writes call this internally; you only need it directly for custom attestations (e.g., signed tool calls, arbitrary witness events).

```bash
node CLI sign \
  --type CUSTOM_OPERATION \
  --action my.namespace.action \
  --payload '{"key":"value","more":42}' \
  --meta '{"hint":"optional context"}'
```

Output: `{ ok, operationId, seq, nonce, agentId, signatureShort, envelopeHashShort }`.

## Verify the local chain

```bash
node CLI verify
```

Walks the audit log, checks every prevHash, envelopeHash, signature, and delegation against the persisted keys. Returns `{ ok, errorCount, errors, operations, agents, ... }`. Exits non-zero when `ok: false` so CI can gate on the result.

For verifying a specific commit's provenance (not a local-state check), use `agent-id-git verify` — it calls the universal `verifyBundle` in this plugin's library and adds the SSH-signature check.

## Export a portable proof

```bash
node CLI export-proof
```

Emits the owner session + complete audit trail as JSON on stdout. Useful for offline auditing or for transferring proof to a verifier that does not have access to the agent's state directory.

## Common flag

`--state-dir <path>` — defaults to `$AGENT_ID_STATE_DIR` then `~/.agent-id`.
