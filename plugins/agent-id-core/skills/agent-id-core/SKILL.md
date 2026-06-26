---
name: agent-id-core
description: Create and manage an AI agent's cryptographic identity — a local Ed25519 key that works immediately (sign, verify, run the vault, make commits) with no account or sign-up. Optionally bind it to a verified human via Alien Network SSO (OIDC + DPoP) when you want third-party-provable provenance; check or refresh the identity's state; sign or verify operations in the agent's local hash-chained audit trail. Use when the user asks to set up or bootstrap an agent identity, check whether one exists, add or refresh human binding, migrate a pre-v3 binding, or sign / verify / export-proof an operation. Also triggers on "Alien ID", "Agent ID", "agent identity", "DPoP", "cnf.jkt", or "owner binding".
license: MIT
metadata:
  author: Alien Wallet
  version: "7.0.0"
allowed-tools: Bash(node *agent-id-core/bin/cli.mjs:*) Read
---

# Alien Agent ID — Core

The bootstrap and lifecycle surface. Every other agent-id-* plugin assumes the state directory produced here exists.

## Assurance levels (the onboarding ladder)

An agent identity is a single, stable Ed25519 key. What grows over time is the **attestation backing it**, not the key — so the identity is usable from the very first moment and binding is something you *add*, never a precondition:

- **L0 — self-asserted** (`init` only): the key alone, no human. Already usable: local audit trail (`sign`/`verify`), the credential vault, and L0 git commits ("signed by key X, no human backing").
- **L1 — anonymous-human**: an Alien SSO `id_token` whose `cnf.jkt` binds this key and which attests a *verified human* authorized it, but with a pairwise/pseudonymous `sub` — a verifier learns "a real human stands behind this key", not *which* human.
- **L2 — linked**: an `id_token` whose `sub` is the canonical AlienID. Full provenance: artifact → key → this specific human.

The key never changes across rungs, so climbing L0→L1→L2 never invalidates an earlier signature or commit. `status` reports the current `level` and the `nextStep` to climb.

State directory layout (under `${AGENT_ID_STATE_DIR:-$HOME/.agent-id}`):

- `keys/main.json` — Ed25519 keypair for the main agent identity.
- `owner-session.json` — SSO-issued `id_token` / `access_token` / `refresh_token`, plus the bound owner's `sub`.
- `audit/operations.jsonl` — hash-chained record of every signed operation.
- `sequence.json`, `nonces.json` — counters that anchor the chain.

## Resolve the CLI

`bin/cli.mjs` lives in this plugin's directory. In the examples below, `CLI` is `${CLAUDE_PLUGIN_ROOT}/bin/cli.mjs` — the `${CLAUDE_PLUGIN_ROOT}` path is filled in for you when the skill loads.

## At the start of a session

Check whether an identity already exists:

```bash
node CLI status
```

Returns `{ initialized, bound, level, assurance, nextStep, jkt, ownerSub, providerAddress, ... }`. `level` is the rung on the ladder above (0/1/2).

When the user invoked this skill to **bootstrap / bind**, start it **immediately** — do not ask "want me to start?" first; invoking the skill is the opt-in. The first user-facing message is the provider question (Step 1 below), not a confirmation prompt. (If `level >= 1` already, skip to signing operations or the per-plugin CLIs.) Note that a level-0 agent is *already usable* for the vault, the audit trail, and L0 commits — binding adds human attestation, it is not a gate on using the identity.

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

## Related capabilities (same identity, other plugins)

Once the identity exists, the rest of the toolkit builds on it. Surface these to the user when relevant — they don't require an owner binding (the vault and browser work at level 0):

- **Credential vault** (`/agent-id-vault` + `/agent-id-proxy`) — store the user's API keys, tokens, OAuth logins, and in-vault-generated wallet keys; the agent uses them *by name* through a local proxy and never sees the secret value.
- **Browser logins** (`/agent-id-browser`) — the user signs in once in a real browser; afterwards the agent drives that logged-in session headless (e.g. Gmail/Workspace) without handling the credential.
- **Signed commits** (`/agent-id-git`) and **DPoP service calls** (`/agent-id-auth`).

## Common flag

`--state-dir <path>` — defaults to `$AGENT_ID_STATE_DIR` then `~/.agent-id`.
