---
name: alien-agent-id
description: Umbrella entry point for the Alien Agent ID toolkit — verifiable cryptographic identity for AI agents, linked to a verified human owner via Alien Network SSO. Use when the user asks generally about "Alien Agent ID" / "Agent ID" without naming a specific operation, when you need an overview of the four sub-skills (setup, commit, sso, vault), or when picking which sub-skill to invoke. For concrete tasks, invoke the focused sub-skill directly. Also triggers on "Alien ID", "DPoP", "cnf.jkt", "owner binding" when the user has not yet specified an action.
license: MIT
metadata:
  author: Alien Wallet
  version: "3.1.1"
allowed-tools: Bash(node *alien-agent-id/cli.mjs:*) Read
---

# Alien Agent ID

A verifiable identity for AI agents. Provides:

1. A cryptographic identity bound to a verified human owner (Alien Network).
2. Signed authentication to Alien-aware services (RFC 9449 DPoP).
3. An encrypted credential vault for external services.
4. SSH-signed git commits with attestation trailers.

The toolkit is decomposed into four focused sub-skills. Invoke the one that matches the user's request directly — this skill is just a router.

## Pick a sub-skill

| User intent | Sub-skill | Slash |
|---|---|---|
| Bootstrap a fresh identity, re-auth, or migrate pre-v3 state | [[alien-id-setup]] | `/alien-id-setup` |
| Make an SSH-signed git commit with provenance, or verify one | [[alien-id-commit]] | `/alien-id-commit` |
| Call an Alien-aware service (discovery + DPoP-signed requests) | [[alien-id-sso]] | `/alien-id-sso` |
| Store / retrieve external-service credentials (GitHub, Slack, AWS, …) | [[alien-id-vault]] | `/alien-id-vault` |

If the user has not yet specified an action, run the cheap status probe to decide where to point them:

```bash
node CLI status
```

`CLI` is the absolute path to `cli.mjs` sitting next to this `SKILL.md`.

- `"bound": false` → start with [[alien-id-setup]].
- `"bound": true` → ask which task they want, then hand off.

## Shared assets (this directory)

The four sub-skills all call into the same CLI and read the same reference docs:

| Path | Purpose |
|---|---|
| `cli.mjs` | All agent operations. |
| `lib.mjs` | Portable library — crypto, OIDC, DPoP, signing, verification. |
| `qrcode.cjs` | Vendored QR generator (terminal output). |
| `default-provider.txt` | Default SSO provider address. |
| `reference/bootstrap.md` | First-time identity setup. |
| `reference/services.md` | Manifests, `auth-header`, DPoP details. |
| `reference/vault.md` | Secure credential storage. |
| `reference/git-commits.md` | Signed commit anatomy, GitHub *Verified* badge. |
| `reference/state-and-errors.md` | State-directory layout, error catalog, security guarantees. |
| `reference/migrate-to-v3.md` | Detect pre-3.0 state and migrate. |

## Command reference (full)

| Command | Sub-skill | Purpose |
|---|---|---|
| `status` | setup | Show whether an identity exists and is bound. |
| `init` | setup | Generate Ed25519 keypair. |
| `auth --provider-address <addr>` | setup | Start OIDC auth, get QR / deep link. |
| `bind` | setup | Poll for user approval, exchange tokens, persist `owner-session.json`. |
| `setup-owner-session` | setup | Re-run auth + bind (re-auth / pre-v3 migration). |
| `git-setup` | setup | Configure git SSH signing. |
| `bootstrap` | setup | init + auth + bind + git-setup (blocks ≤5 min). |
| `git-commit --message <M> [--push]` | commit | Signed commit + trailers + proof note. |
| `git-verify [--commit H]` | commit | Verify the provenance chain of a commit. |
| `sign --type T --action A --payload <JSON>` | commit | Sign an arbitrary operation into the audit trail. |
| `verify` | commit | Verify the state chain integrity. |
| `export-proof` | commit | Emit a proof bundle to stdout. |
| `discover-service --url <U>` | sso | Fetch + validate `/.well-known/alien-agent-id.json`. |
| `capabilities --url <U>` | sso | Render a manifest's `api.operations[]` as markdown. |
| `service-support --url <U>` | sso | Probe a page for the `<meta name="alien-agent-id">` support signal. |
| `call --url <U> [--method M] [--body-file F]` | sso | One-shot signed HTTP request. |
| `auth-header --url <U> [--method M] [--raw]` | sso | Emit `Authorization` + `DPoP` headers. |
| `refresh` | sso | Refresh SSO tokens. |
| `vault-get --service <S>` | vault | Retrieve a decrypted credential. |
| `vault-list` | vault | List vault entries (metadata only). |
| `vault-store --service <S>` | vault | Store a credential securely. |
| `vault-remove --service <S>` | vault | Remove a credential. |

Common flag: `--state-dir <path>` (defaults to `~/.agent-id`, or `AGENT_ID_STATE_DIR`).
