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
│  L3  Real Alien SSO (develop / staging / prod)                      │
│      SSO_URL=https://sso.develop.alien-api.com \                    │
│      PROVIDER=<env-specific-address>                  \             │
│        bash tests/integration/full-stack.sh                         │
│      • Same script, points at a real DPoP-deployed SSO              │
│      • Requires the Alien App build for that environment            │
└─────────────────────────────────────────────────────────────────────┘
```

## L1 — unit / integration (mocked)

```bash
npm test               # node --test tests/test-*.mjs
```

**What it proves**
- Manifest schema validation, hardening (8 KiB cap, redirects refused, content-type required, same-authority enforcement).
- Pure-function correctness: DPoP proof generation, JWK thumbprints, PKCE, canonical JSON, htu canonicalization, Ed25519 SPKI parsing.
- CLI subprocess invocation against in-process HTTP mocks.

**What it does NOT prove**
- That a real HTTP server (with TCP, real `Content-Length`, redirect handling, etc.) accepts what we emit.
- That any real Alien SSO behaves identically to our spec-faithful local mock.
- That `@alien-id/sso-agent-id` (the npm verifier package) accepts our tokens.

## L2 — end-to-end against local dev-sso + demo-service

```bash
npm run test:integration   # bash tests/integration/full-stack.sh
```

11 numbered steps, each asserting a concrete invariant. On failure, the script tails the last 20 lines of `/tmp/dev-sso.log` and `/tmp/demo.log`.

### What runs (default — local servers)

| Process | Source | Port | Role |
|---|---|---|---|
| `dev-sso` | `examples/dev-sso.mjs` | 5050 | Local OIDC + DPoP; auto-approves every authorize call. RS256-signed id_tokens with `cnf.jkt` derived from the agent's `dpop_jkt`. |
| `demo-service` | `examples/demo-service.mjs` | 3141 | Publishes `/.well-known/alien-agent-id.json`, hosts `<meta name="alien-agent-id" content="v1">`, verifies RFC 9449 `Authorization: DPoP <access_token>` + `DPoP: <proof>` header pairs. |

### Override knobs

```bash
# Different ports / state dir
SSO_PORT=15050 DEMO_PORT=13141 STATE_DIR=/tmp/integ-alt \
  bash tests/integration/full-stack.sh

# Skip dev-sso, point at any external DPoP-aware SSO (see L3 below)
SSO_URL=https://sso.develop.alien-api.com \
PROVIDER=<develop-provider-address> \
  bash tests/integration/full-stack.sh
```

When `SSO_URL` is set, the script does **not** spawn `examples/dev-sso.mjs` and skips its auto-approval shortcut. Steps 1–2 still run (`init` and `auth`), but step 3 (`bind`) blocks until a human approves via the Alien App build that points at the same environment.

### What L2 (local mode) proves
- DPoP proof reaches `/oauth/token`, server verifies `htm`/`htu`/`jti`/`iat`/signature, and emits `token_type: "DPoP"` per RFC 9449 §5.
- Issued id_token carries `cnf.jkt` matching the agent's RFC 7638 thumbprint, and the agent's `verifyIdToken` passes.
- Refresh token is **sticky**: a refresh request with a different `dpop_jkt` is rejected. The original key still refreshes correctly.
- Manifest fetch obeys hardening (size cap, content-type, same-authority, no redirects).
- `auth-header --raw` produces a token the demo service accepts.
- Tampered token → 401 `malformed_token`/`bad_signature`. Missing scheme → 401 `invalid_scheme`.

### What L2 (local mode) does NOT prove
- Anything specific to a **real Alien SSO**. Our dev-sso implements the documented cutover contract; a real SSO may behave differently in corners the spec doesn't pin down.
- TLS-specific failure modes (cert validation, HTTP/2 quirks, real CDN behavior).
- Behavior of `@alien-id/sso-agent-id` (the npm verifier). The demo service mirrors its surface checks (signature, fingerprint binding, freshness) but does not call the package.

## L3 — real Alien SSO (manual gate)

### Where the SSO is actually deployed (recorded 2026-05-08)

There are **four** Alien SSO environments. Each is its own EC2 ASG behind its own ALB (`alien-alb-{env}`), backed by its own Postgres (`alien-shared-1-{env}` or `alien-sso-{env}`):

| Env | URL | DPoP cutover | Backend |
|---|---|---|---|
| **prod** | `sso.alien-api.com` | ❌ not yet | ✅ healthy (2 instances) |
| **staging** | `sso.staging.alien-api.com` | ✅ deployed | ✅ healthy (1 instance) |
| **develop** | `sso.develop.alien-api.com` | ✅ deployed | ✅ healthy (1 instance) |
| **testnt** | `sso.testnt.alien-api.com` | (unknown) | ⚠️ 502 — operator action needed |

The cutover landed on develop+staging via launch-template `lt-099a17b58fb7fd1e4` v11 on 2026-05-06. Production rolls behind develop+staging by design (see `docs/DEPLOY-DPOP.md` "Order of operations") and will follow once App-side and verifier rollouts are validated.

A clean way to confirm the discovery doc state for any environment:

```bash
curl -s https://sso.<env>.alien-api.com/.well-known/openid-configuration \
  | jq '{ cnf_supported: (.claims_supported | index("cnf") != null),
          dpop_algs: .dpop_signing_alg_values_supported }'
```

### Running L3 against develop

```bash
# 1. Register a develop-environment provider via the develop dev portal:
#    https://devportal.develop.alien-api.com
#    Note the provider-address it returns.

# 2. Run the integration script against develop SSO + a develop-built service.
SSO_URL=https://sso.develop.alien-api.com \
PROVIDER=<develop-provider-address> \
DEMO_HOST=<your-develop-service-host> \
  bash tests/integration/full-stack.sh

# 3. When step 3 (bind) blocks, scan the QR / open the deep link with the
#    develop build of the Alien App. The App approves; bind proceeds.
```

### What L3 proves (and only L3)
- A real Alien SSO emits cnf-bound id_tokens after the cutover deploy. (Already true on develop+staging; pending on prod.)
- DPoP nonce-challenge handling against whatever rotation policy the real AS uses.
- The Alien App approval flow is intact end-to-end.
- TLS, real CDN/ELB behavior, real cert validation.

### Production check (for when prod deploys the cutover)

Before flipping production traffic:

```bash
# Verify discovery advertises cutover.
curl -s https://sso.alien-api.com/.well-known/openid-configuration \
  | jq -e '.claims_supported | index("cnf") != null and
           .dpop_signing_alg_values_supported == ["EdDSA"]' \
  || echo "FAIL: prod SSO discovery does not advertise cutover"

# Run the integration script. Same caveats as develop.
SSO_URL=https://sso.alien-api.com \
PROVIDER="$(cat skills/alien-agent-id/default-provider.txt)" \
  bash tests/integration/full-stack.sh
```

### testnt (currently broken)

`sso.testnt.alien-api.com` returns 502 — the active EC2 target is failing health checks while a previous one is mid-deregistration. This looks like an in-progress deploy that didn't stabilize. Until the operator either rolls forward or rolls back, treat testnt as offline. Do not waste cycles debugging the agent against it.

## Adding tests

| Layer | Where to add |
|---|---|
| Schema/hardening regression | new test file under `tests/` matching `tests/test-*.mjs`; picked up by L1. |
| End-to-end behavior | extend `tests/integration/full-stack.sh` with a numbered step + `assert "label" bash -c '<cmd>'`. |
| Real-SSO behavior | run L2 with `SSO_URL=...`. If a corner doesn't reproduce locally, file the discrepancy against `examples/dev-sso.mjs` so the local mock catches it next time. |

## Cleanup

The integration script kills its subprocesses on exit (success or failure). If something escapes:

```bash
pkill -f 'examples/dev-sso.mjs'
pkill -f 'examples/demo-service.mjs'
rm -rf /tmp/agent-id-integration /tmp/dev-sso.log /tmp/demo.log /tmp/integ.*.json
```
