# Deploy — DPoP / cnf.jkt cutover

Operations notes for deploying the SSO server (`alien-id/sso`) and rolling out agent-id 3.0.0.

## Order of operations

1. **SSO server first.** Deploy the DPoP-aware SSO. Existing pre-3.0 agents continue to work because DPoP at `/oauth/authorize` is opt-in — no `dpop_jkt` means no DPoP, same wire as before.
2. **Agent-ID CLI second.** Once SSO is live, ship the 3.0 CLI. It will pass `dpop_jkt` on every authorize, sign DPoP proofs at token, and verify the returned `cnf.jkt` matches.
3. **Verifier last.** Roll the 3.0 verifier across CI fleets. Once verifiers are upgraded, pre-3.0 commits stop verifying — coordinate this step with the org so the cutover is announced.

The SSO can be deployed independently and held for any length of time before CLI rollout. The verifier should be deployed only after enough developers have re-bound that "broken history" is the expected, communicated state.

## Configuration (SSO)

No new required env vars. The DPoP path activates automatically when clients send `dpop_jkt` and `DPoP` headers.

| Env var | Default | Purpose |
|---|---|---|
| `SSO_ACCESS_TOKEN_EXPIRATION_SEC` | 2592000 | Existing — DPoP-bound ATs use this same TTL. |
| `REFRESH_TOKEN_EXPIRATION_SEC` | 2592000 | Existing — DPoP-bound RTs are non-rotating; this is their full lifetime. |
| `SIGNATURE_MAX_AGE_SEC` | 60 | DPoP proof `iat` freshness window. |
| `CLOCK_SKEW_TOLERANCE_SEC` | 5 | Allowance for proof `iat` slightly in the future. |
| `OIDC_RSA_PRIVATE_KEY` | required | RS256 key that signs `id_tokens` carrying `cnf.jkt`. Already required pre-3.0; no change. |

## Database

Two tables are added by migration:

- `dpop_jti_seen` — replay protection for proof IDs. Primary key on `(jkt, jti)`. Populated on every accepted DPoP-bound token request and userinfo call. Row TTL is `SIGNATURE_MAX_AGE_SEC + CLOCK_SKEW_TOLERANCE_SEC` (so ~65s by default). The existing background session cleaner reaps expired rows.
- `oauth_dpop_refresh_tokens` — refresh-token-to-cnf binding for non-rotating refresh.

Migration files: `migrations/000010_dpop.up.sql`, `migrations/000011_dpop_refresh_tokens.up.sql`. Run on deploy. Both are idempotent; safe to re-run.

## Capacity

- `dpop_jti_seen` row count is bounded by `tokens_per_minute × 65s`. At 10k tokens/min, expect ~10k rows steady-state. Well within Postgres comfort zone.
- Existing background cleaner sweeps every minute; no additional cron.

## Observability

DPoP failure modes log structured errors with stable codes:

| Code | Meaning |
|---|---|
| `dpop_missing_header` | Bound session but no `DPoP` header |
| `dpop_duplicate_header` | More than one `DPoP` header on the request |
| `dpop_proof_invalid` | Signature, format, or alg failure |
| `dpop_thumbprint_mismatch` | Proof's JWK thumbprint ≠ session's `dpop_jkt` |
| `dpop_replay` | `(jkt, jti)` already in `dpop_jti_seen` |
| `dpop_clock_skew` | `iat` outside freshness window |
| `dpop_htu_mismatch` | Proof `htu` ≠ canonicalized request URI |
| `dpop_htm_mismatch` | Proof `htm` ≠ request method |
| `dpop_missing_ath` | Resource (userinfo) proof without `ath` claim |
| `dpop_ath_mismatch` | `ath` ≠ `base64url(SHA-256(access_token))` |
| `dpop_oversized_jti` | `jti` longer than 256 chars |
| `dpop_jwk_has_private_key` | Proof `jwk` carries RFC 7517 private-key member |

Recommend dashboards on rate-of `dpop_replay`, `dpop_proof_invalid`, `dpop_thumbprint_mismatch` — sustained spikes indicate either a misbehaving client or active probing.

## OIDC discovery

`/.well-known/openid-configuration` advertises:

- `dpop_signing_alg_values_supported: ["EdDSA"]`
- `cnf` in `claims_supported`

Update this in your service registry / API gateway docs if those are auto-generated from a separate source.

## Third-party DPoP servers (agent-id outbound)

When the agent-id CLI talks to a third-party DPoP server (not our SSO), it handles `400 use_dpop_nonce` challenges automatically: receives the `DPoP-Nonce` header, retries with the nonce embedded in a fresh proof, and caches the nonce per-URL for subsequent calls. No operator config — this is a property of the client library.

## Rollback

The SSO change is wire-compatible with pre-3.0 clients (no `dpop_jkt` → no DPoP path → same response as before). Rolling back the SSO is safe at any point if no agents have started using DPoP yet. After agents are using DPoP, rollback breaks them — they'll reject the cnf-less `id_tokens` from a downgraded SSO. Coordinate with CLI rollout state before rolling SSO back.
