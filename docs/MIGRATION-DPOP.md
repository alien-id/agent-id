# Migration — agent-id 3.0.0 (DPoP cutover)

This is a **hard cutover** for agent-driven flows. Pre-3.0 commits stop verifying because their `id_tokens` lack the `cnf.jkt` confirmation claim that the new verifier requires. There is no `--allow-legacy` flag — every cnf-less `id_token` is a forgery primitive (see [forgery PoC](https://github.com/truehazker-eti/agent-id-forgery-poc)) and the verifier refuses to honor them.

Humans signing in via "Sign in with Alien" through standard OIDC RPs are unaffected. Only Agent-ID CLI users and verifier installations need to migrate.

## Who needs to do what

| Role | Action |
|---|---|
| Agent operator (developer using the CLI) | Upgrade CLI → run `alien-agent-id setup-owner-session` once → re-attach proof to HEAD |
| CI / verifier installation | Upgrade verifier package; no further config |
| Repository maintainer | Decide on history back-fill policy (see below) |
| OIDC RP using `/oauth/authorize` for human login | No action |
| Miniapp using `/sso/*` | No action |

## Per-developer steps

```bash
# 1. Upgrade the CLI
npm install -g @alien-id/agent-id@3

# 2. Re-bind the agent. This will:
#    - Generate a DPoP keypair on disk (Ed25519)
#    - Hit /oauth/authorize with dpop_jkt
#    - Exchange the auth code with a DPoP proof
#    - Receive an id_token with cnf.jkt matching the keypair
#    - Refuse to write the session if cnf is missing
alien-agent-id setup-owner-session

# 3. Re-attach a fresh proof note to the current HEAD (and back-fill if you choose)
alien-agent-id attach-proof HEAD
```

The CLI will fail with a specific error if the SSO does not return a `cnf`-bearing `id_token`. This is the bootstrap fuse; do not bypass it.

## History back-fill (optional)

Old commits with cnf-less `id_tokens` will fail verification. Two policies:

1. **Don't back-fill.** Old history shows as unverifiable; new commits verify cleanly going forward. Recommended for low-stakes repos.
2. **Back-fill.** Use `alien-agent-id attach-proof <commit-range>` to write fresh proof notes for historical commits the agent legitimately authored. The new proofs reference the new keypair and verify under 3.0. Recommended for repos under audit.

You cannot back-fill commits authored by another agent (the keypair to bind doesn't exist on your machine). That history is permanently legacy.

## Verifier behavior change

| Input | Pre-3.0 | 3.0 |
|---|---|---|
| `id_token` with `cnf.jkt` matching agent JWK | ok | ok |
| `id_token` with `cnf.jkt` mismatched | (no check) | rejected |
| `id_token` without `cnf.jkt` | ok | rejected |

The check is offline — the verifier reads the `id_token` from `refs/notes/agent-id`, validates the SSO's RS256 signature against the cached JWKS, and asserts `cnf.jkt == thumbprint(agent_jwk)`. No network is required after JWKS is fetched once.

## Rollback

There is no clean rollback. The new `id_tokens` carry claims old verifiers don't read but tolerate. The blocking issue is the verifier itself — pinning the verifier to <3.0 reopens the forgery vulnerability. If a compatibility shim is unavoidable, the only safe one is a `--allow-legacy` flag on the verifier explicitly scoped to a known-good commit range; this is out of scope for this release and would need its own design.

## Help / debugging

`alien-agent-id setup-owner-session --verbose` prints the DPoP proof, the `dpop_jkt` query param, the `cnf.jkt` claim observed in the returned `id_token`, and the agent's local thumbprint. A mismatch at this stage indicates the SSO is misdeployed; raise an issue with the printed values.
