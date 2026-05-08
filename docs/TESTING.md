# Testing

Three layers, each catching a different class of regression.

```
┌─────────────────────────────────────────────────────────────────────┐
│  L1  Unit / integration (mocked)                                    │
│      node --test tests/test-*.mjs                                   │
│      • 115 tests, ~1.3s                                             │
│      • In-process HTTP mocks for SSO / service                      │
│      • Pure-function tests for crypto, schema, hardening            │
├─────────────────────────────────────────────────────────────────────┤
│  L2  End-to-end (local servers)                                     │
│      bash tests/integration/full-stack.sh                           │
│      • Spawns examples/dev-sso.mjs + examples/demo-service.mjs      │
│      • Full bootstrap: init → auth → bind → discover → call         │
│      • DPoP token exchange, cnf.jkt verification, refresh stickiness│
│      • Manifest fetch, support-signal probe, token verification     │
├─────────────────────────────────────────────────────────────────────┤
│  L3  Real production SSO                                            │
│      Manual gate. Requires Alien App + DPoP-deployed SSO.           │
│      • See "L3 — production SSO" below                              │
└─────────────────────────────────────────────────────────────────────┘
```

## L1 — unit / integration (mocked)

```bash
node --test tests/test-*.mjs
```

**What it proves**
- Manifest schema validation, hardening (8 KiB cap, redirects refused, content-type required, same-authority enforcement).
- Pure-function correctness: DPoP proof generation, JWK thumbprints, PKCE, canonical JSON, htu canonicalization, Ed25519 SPKI parsing.
- CLI subprocess invocation against in-process HTTP mocks.

**What it does NOT prove**
- That a real HTTP server (with TCP, real `Content-Length`, redirect handling, etc.) accepts what we emit.
- That the production SSO behaves as the cutover spec says.
- That `@alien-id/sso-agent-id` (the npm verifier package) accepts our tokens.

## L2 — end-to-end against local dev-sso + demo-service

```bash
bash tests/integration/full-stack.sh
```

11 numbered steps, each asserting a concrete invariant. On failure, the script tails the last 20 lines of `/tmp/dev-sso.log` and `/tmp/demo.log`.

### What runs

| Process | Source | Port | Role |
|---|---|---|---|
| `dev-sso` | `examples/dev-sso.mjs` | 5050 | Local OIDC + DPoP; auto-approves every authorize call. RS256-signed id_tokens with `cnf.jkt` derived from the agent's `dpop_jkt`. |
| `demo-service` | `examples/demo-service.mjs` | 3141 | Publishes `/.well-known/alien-agent-id.json`, hosts `<meta name="alien-agent-id" content="v1">`, verifies `Authorization: AgentID <token>` headers. |

### Override knobs

```bash
SSO_PORT=15050 DEMO_PORT=13141 STATE_DIR=/tmp/integ-alt \
  bash tests/integration/full-stack.sh
```

### What L2 proves
- DPoP proof reaches `/oauth/token`, server verifies `htm`/`htu`/`jti`/`iat`/signature, and emits `token_type: "DPoP"` per RFC 9449 §5.
- Issued id_token carries `cnf.jkt` matching the agent's RFC 7638 thumbprint, and the agent's `verifyIdToken` passes.
- Refresh token is **sticky**: a refresh request with a different `dpop_jkt` is rejected. The original key still refreshes correctly.
- Manifest fetch obeys hardening (size cap, content-type, same-authority, no redirects).
- `auth-header --raw` produces a token the demo service accepts.
- Tampered token → 401 `malformed_token`/`bad_signature`. Missing scheme → 401 `invalid_scheme`.

### What L2 does NOT prove
- Anything specific to the **real Alien SSO** at `sso.alien-api.com`. Our dev-sso implements the documented cutover contract; the production SSO may behave differently in ways the spec doesn't pin down.
- TLS-specific failure modes (cert validation, HTTP/2 quirks, real CDN behavior).
- Behavior of `@alien-id/sso-agent-id` (the npm verifier). The demo service mirrors its surface checks (signature, fingerprint binding, freshness) but does not call the package.

## L3 — production SSO (manual)

> ⚠️ **Status check (recorded 2026-05-08).** The production SSO at `https://sso.alien-api.com` does **not** yet advertise the DPoP cutover:
>
> ```jsonc
> // /.well-known/openid-configuration
> { "id_token_signing_alg_values_supported": ["RS256"], // OK
>   "claims_supported": ["sub","iss","aud","exp","iat","nonce","auth_time"], // ⚠️ no "cnf"
>   // ⚠️ no "dpop_signing_alg_values_supported"
> }
> ```
>
> The JWKS already publishes both an RS256 key (active) and an EdDSA key (staged), so the material is in place — the discovery doc just hasn't been flipped. Until it is, the post-cutover CLI will reject id_tokens for missing `cnf.jkt` and L3 will fail by design (see `docs/RELEASE-NOTES.md`: *"Verifier rejects id_tokens without cnf.jkt"*).
>
> When Alien deploys the cutover server-side, this section becomes runnable.

### Once production SSO advertises DPoP

```bash
# Clean state.
STATE_DIR=/tmp/agent-id-l3
rm -rf "$STATE_DIR" && mkdir -p "$STATE_DIR"

# Bootstrap. Requires the Alien App on a phone to scan the QR.
node skills/alien-agent-id/cli.mjs init   --state-dir "$STATE_DIR"
node skills/alien-agent-id/cli.mjs auth   --state-dir "$STATE_DIR" \
  --provider-address "$(cat skills/alien-agent-id/default-provider.txt)"
# … scan QR with Alien App, approve …
node skills/alien-agent-id/cli.mjs bind   --state-dir "$STATE_DIR"

# Assertions (manual but mechanical).
node -e '
  import("fs").then(async ({default: fs}) => {
    const session = JSON.parse(fs.readFileSync(process.env.STATE_DIR + "/owner-session.json"));
    const idToken = session.idToken;
    const [_, payloadB] = idToken.split(".");
    const payload = JSON.parse(Buffer.from(payloadB, "base64url").toString("utf8"));
    if (!payload.cnf || !payload.cnf.jkt) {
      console.error("FAIL: id_token missing cnf.jkt — server has not deployed the cutover");
      process.exit(1);
    }
    console.log("OK: id_token carries cnf.jkt =", payload.cnf.jkt);
  });
'
```

### What L3 proves (and only L3)
- Production `https://sso.alien-api.com` actually emits cnf-bound id_tokens after the cutover deploy.
- DPoP nonce-challenge handling works against whatever rotation policy the production AS uses.
- The Alien App approval flow is intact.

## Adding tests

| Layer | Where to add |
|---|---|
| Schema/hardening regression | new test file under `tests/` matching `tests/test-*.mjs`; gets picked up by L1. |
| End-to-end behavior | extend `tests/integration/full-stack.sh` with a numbered step + `assert "label" bash -c '<cmd>'`. |
| Production-only behavior | document a manual procedure here in L3; do not commit production credentials. |

## Cleanup

The integration script kills its subprocesses on exit (success or failure). If something escapes:

```bash
pkill -f 'examples/dev-sso.mjs'
pkill -f 'examples/demo-service.mjs'
rm -rf /tmp/agent-id-integration /tmp/dev-sso.log /tmp/demo.log /tmp/integ.*.json
```
