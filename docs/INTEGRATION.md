# Integrating Alien Agent SSO into Your Service

This guide shows how to add AI agent authentication to any web service. After integration, agents with an Alien Agent ID can authenticate to your service using cryptographically signed tokens — no API keys, no shared secrets, no pre-registration.

## How it works

```
Agent                          Your Service
  │                                │
  │  1. Generate signed token      │
  │     (Ed25519, 5-min validity)  │
  │                                │
  │  2. HTTP request ─────────────►│
  │     Authorization: AgentID … │
  │                                │  3. Decode token
  │                                │  4. Verify Ed25519 signature
  │                                │  5. Check timestamp freshness
  │                                │  6. Check fingerprint matches key
  │                                │  7. (optional) verify provenance
  │                                │
  │◄──────────── response ─────────│
```

The token is **self-contained**: it carries the agent's public key, so your service can verify the signature without any prior knowledge of the agent. No registration step, no key exchange, no database lookup required for basic verification.

## Token format

Agents send authentication via the `Authorization` header:

```
Authorization: AgentID <base64url-encoded-json>
```

Decoded token payload:

```json
{
  "v": 1,
  "fingerprint": "f5d9fac49457e9e359078815f7c1c568a56207a4a5c0b05a11ce3cf54bc8d4f8",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n",
  "owner": "00000003010000000000539c741e0df8",
  "timestamp": 1774531517000,
  "nonce": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "sig": "<Ed25519-base64url-signature>"
}
```

| Field | Type | Description |
|---|---|---|
| `v` | number | Token version (always `1`) |
| `fingerprint` | string | SHA-256 hash of the agent's public key DER encoding (64 hex chars) |
| `publicKeyPem` | string | Agent's Ed25519 public key in SPKI PEM format |
| `owner` | string or null | AlienID address of the human who authorized this agent. Null if agent is unbound |
| `timestamp` | number | Unix timestamp in milliseconds when the token was created |
| `nonce` | string | Random 128-bit hex string (replay resistance) |
| `sig` | string | Ed25519 signature (base64url) over the canonical JSON of all fields except `sig` |

### Signature computation

The signature is computed over **canonical JSON** of the payload (all fields except `sig`, keys sorted alphabetically, no whitespace):

```
canonical = JSON.stringify(sortKeysRecursively({ v, fingerprint, publicKeyPem, owner, timestamp, nonce }))
sig = Ed25519.sign(canonical, agentPrivateKey)
```

## Integration options

### Option A: Use `lib.mjs` directly (Node.js)

The simplest path. Copy `lib.mjs` into your project or import it directly. Zero dependencies — it uses only Node.js built-in `crypto` module.

```javascript
import { verifyAgentToken } from "./lib.mjs";

function authenticateAgent(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("AgentID ")) {
    return { ok: false, error: "Missing Authorization: AgentID <token>" };
  }
  return verifyAgentToken(header.slice(8).trim());
}
```

#### `verifyAgentToken(tokenB64, opts?)` — API reference

**Parameters:**

- `tokenB64` (string) — The base64url-encoded token from the Authorization header (everything after `"AgentID "`)
- `opts.maxAgeMs` (number, optional) — Maximum token age in milliseconds. Default: `300000` (5 minutes)

**Returns on success:**

```javascript
{
  ok: true,
  fingerprint: "f5d9fac4...",   // Agent identity (stable across sessions)
  publicKeyPem: "-----BEGIN...", // Agent's Ed25519 public key
  owner: "0000000301...",        // Human owner's AlienID address (or null)
  timestamp: 1774531517000,      // When the token was created
  nonce: "a1b2c3d4..."          // Unique per token
}
```

**Returns on failure:**

```javascript
{
  ok: false,
  error: "Token expired (age: 312s)"  // Human-readable error
}
```

**Possible errors:**

| Error | Meaning |
|---|---|
| `Invalid token encoding` | Token is not valid base64url JSON |
| `Unsupported token version: N` | Unknown token version |
| `Token expired (age: Ns)` | Token is older than `maxAgeMs` |
| `Invalid public key in token` | The `publicKeyPem` field is not a valid Ed25519 public key |
| `Fingerprint does not match public key` | The `fingerprint` field doesn't match SHA-256(publicKeyDER) |
| `Signature verification failed` | Ed25519 signature is invalid — token was tampered with |
| `Signature verification error` | Crypto error during verification |

### Option B: Implement verification yourself (any language)

The verification algorithm is straightforward to implement in any language with Ed25519 and SHA-256 support.

#### Step-by-step verification

```
1. DECODE
   raw = base64url_decode(token)
   parsed = JSON.parse(raw)

2. CHECK VERSION
   assert parsed.v == 1

3. CHECK TIMESTAMP
   age = now_ms() - parsed.timestamp
   assert age >= 0 AND age <= 300000     # 5 minutes

4. VERIFY FINGERPRINT
   der = parse_spki_pem(parsed.publicKeyPem)
   computed = hex(sha256(der))
   assert computed == parsed.fingerprint

5. VERIFY SIGNATURE
   payload = { v, fingerprint, publicKeyPem, owner, timestamp, nonce }
   canonical = canonical_json(payload)    # sorted keys, no whitespace
   sig_bytes = base64url_decode(parsed.sig)
   pubkey = parse_ed25519_public_key(parsed.publicKeyPem)
   assert ed25519_verify(canonical, sig_bytes, pubkey)
```

#### Canonical JSON

The signature is computed over **canonical JSON**: keys sorted alphabetically at every nesting level, no whitespace, no trailing commas. This is the same as `JSON.stringify(sortKeysRecursively(obj))`.

Example — given:

```json
{ "timestamp": 123, "fingerprint": "abc", "v": 1 }
```

Canonical form:

```json
{"fingerprint":"abc","timestamp":123,"v":1}
```

#### Reference implementations

**Python:**

```python
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import time

def verify_agent_token(token_b64, max_age_ms=300000):
    # 1. Decode
    # Add padding if needed — base64url omits trailing '='
    token_b64 += "=" * (-len(token_b64) % 4)
    raw = base64.urlsafe_b64decode(token_b64)
    parsed = json.loads(raw)

    # 2. Version
    assert parsed["v"] == 1, f"Unsupported version: {parsed['v']}"

    # 3. Timestamp
    age = int(time.time() * 1000) - parsed["timestamp"]
    assert 0 <= age <= max_age_ms, f"Token expired (age: {age // 1000}s)"

    # 4. Fingerprint
    pubkey_obj = load_pem_public_key(parsed["publicKeyPem"].encode())
    der = pubkey_obj.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    computed_fp = hashlib.sha256(der).hexdigest()
    assert computed_fp == parsed["fingerprint"], "Fingerprint mismatch"

    # 5. Signature
    sig = parsed.pop("sig")
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    sig_bytes = base64.urlsafe_b64decode(sig + "==")
    pubkey_obj.verify(sig_bytes, canonical.encode())

    return {
        "fingerprint": parsed["fingerprint"],
        "owner": parsed["owner"],
        "timestamp": parsed["timestamp"],
    }
```

**Go:**

```go
package agentid

import (
    "crypto/ed25519"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "time"
)

type TokenPayload struct {
    V            int    `json:"v"`
    Fingerprint  string `json:"fingerprint"`
    PublicKeyPem string `json:"publicKeyPem"`
    Owner        string `json:"owner"`
    Timestamp    int64  `json:"timestamp"`
    Nonce        string `json:"nonce"`
    Sig          string `json:"sig"`
}

type VerifyResult struct {
    OK          bool
    Fingerprint string
    Owner       string
    Timestamp   int64
    Error       string
}

func VerifyAgentToken(tokenB64 string, maxAgeMs int64) VerifyResult {
    if maxAgeMs == 0 {
        maxAgeMs = 300000
    }

    // 1. Decode
    raw, err := base64.RawURLEncoding.DecodeString(tokenB64)
    if err != nil {
        return VerifyResult{Error: "Invalid token encoding"}
    }

    var parsed TokenPayload
    if err := json.Unmarshal(raw, &parsed); err != nil {
        return VerifyResult{Error: "Invalid token JSON"}
    }

    // 2. Version
    if parsed.V != 1 {
        return VerifyResult{Error: fmt.Sprintf("Unsupported version: %d", parsed.V)}
    }

    // 3. Timestamp
    age := time.Now().UnixMilli() - parsed.Timestamp
    if age < 0 || age > maxAgeMs {
        return VerifyResult{Error: fmt.Sprintf("Token expired (age: %ds)", age/1000)}
    }

    // 4. Fingerprint
    block, _ := pem.Decode([]byte(parsed.PublicKeyPem))
    if block == nil {
        return VerifyResult{Error: "Invalid public key PEM"}
    }
    pubkeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return VerifyResult{Error: "Invalid public key"}
    }
    pubkey, ok := pubkeyInterface.(ed25519.PublicKey)
    if !ok {
        return VerifyResult{Error: "Not an Ed25519 key"}
    }
    hash := sha256.Sum256(block.Bytes)
    if hex.EncodeToString(hash[:]) != parsed.Fingerprint {
        return VerifyResult{Error: "Fingerprint mismatch"}
    }

    // 5. Signature
    sigBytes, err := base64.RawURLEncoding.DecodeString(parsed.Sig)
    if err != nil {
        return VerifyResult{Error: "Invalid signature encoding"}
    }

    // Canonical JSON: marshal without sig field
    payload := map[string]interface{}{
        "v": parsed.V, "fingerprint": parsed.Fingerprint,
        "publicKeyPem": parsed.PublicKeyPem, "owner": parsed.Owner,
        "timestamp": parsed.Timestamp, "nonce": parsed.Nonce,
    }
    canonical, _ := json.Marshal(payload) // json.Marshal sorts keys

    if !ed25519.Verify(pubkey, canonical, sigBytes) {
        return VerifyResult{Error: "Signature verification failed"}
    }

    return VerifyResult{
        OK: true, Fingerprint: parsed.Fingerprint,
        Owner: parsed.Owner, Timestamp: parsed.Timestamp,
    }
}
```

## Framework examples

### Express (Node.js)

```javascript
import express from "express";
import { verifyAgentToken } from "./lib.mjs";

const app = express();

// Middleware
function requireAgent(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("AgentID ")) {
    return res.status(401).json({ error: "Authorization: AgentID <token> required" });
  }
  const result = verifyAgentToken(auth.slice(8).trim());
  if (!result.ok) {
    return res.status(401).json({ error: result.error });
  }
  req.agent = result;
  next();
}

// Public route
app.get("/api/status", (req, res) => {
  res.json({ ok: true, service: "my-service" });
});

// Protected route
app.get("/api/data", requireAgent, (req, res) => {
  res.json({
    ok: true,
    data: "sensitive information",
    agent: req.agent.fingerprint,
    owner: req.agent.owner,
  });
});

app.listen(3000);
```

### Fastify (Node.js)

```javascript
import Fastify from "fastify";
import { verifyAgentToken } from "./lib.mjs";

const fastify = Fastify();

fastify.decorate("verifyAgent", async (request, reply) => {
  const auth = request.headers.authorization;
  if (!auth?.startsWith("AgentID ")) {
    return reply.code(401).send({ error: "Agent authentication required" });
  }
  const result = verifyAgentToken(auth.slice(8).trim());
  if (!result.ok) {
    return reply.code(401).send({ error: result.error });
  }
  request.agent = result;
});

fastify.get("/api/data", { preHandler: [fastify.verifyAgent] }, async (request) => {
  return { ok: true, agent: request.agent.fingerprint };
});

fastify.listen({ port: 3000 });
```

### Flask (Python)

```python
from flask import Flask, request, jsonify
from functools import wraps
# Use the verify_agent_token function from the Python example above

app = Flask(__name__)

def require_agent(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("AgentID "):
            return jsonify({"error": "Agent authentication required"}), 401
        try:
            result = verify_agent_token(auth[8:].strip())
        except Exception as e:
            return jsonify({"error": str(e)}), 401
        request.agent = result
        return f(*args, **kwargs)
    return decorated

@app.route("/api/data")
@require_agent
def get_data():
    return jsonify({
        "ok": True,
        "agent": request.agent["fingerprint"],
        "owner": request.agent["owner"],
    })
```

### Go (net/http)

```go
func AgentAuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        if !strings.HasPrefix(auth, "AgentID ") {
            http.Error(w, `{"error":"Agent authentication required"}`, 401)
            return
        }
        result := VerifyAgentToken(strings.TrimSpace(auth[8:]), 0)
        if !result.OK {
            http.Error(w, fmt.Sprintf(`{"error":"%s"}`, result.Error), 401)
            return
        }
        ctx := context.WithValue(r.Context(), "agent", result)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Access control patterns

### Allow any verified agent

The simplest policy — accept any agent with a valid token:

```javascript
function requireAgent(req, res, next) {
  const result = verifyAgent(req);
  if (!result.ok) return res.status(401).json({ error: result.error });
  req.agent = result;
  next();
}
```

### Require human-owned agents only

Reject agents that don't have a human owner (unbound agents):

```javascript
function requireOwnedAgent(req, res, next) {
  const result = verifyAgent(req);
  if (!result.ok) return res.status(401).json({ error: result.error });
  if (!result.owner) return res.status(403).json({ error: "Human-owned agent required" });
  req.agent = result;
  next();
}
```

### Allow-list specific agents

Pre-register known agent fingerprints:

```javascript
const ALLOWED_AGENTS = new Set([
  "f5d9fac49457e9e359078815f7c1c568a56207a4a5c0b05a11ce3cf54bc8d4f8",
  "42fbde2a3f7ca6dfdc61fc74e54227c84ff0a6e85f1a838052d9aa60ca2b527f",
]);

function requireKnownAgent(req, res, next) {
  const result = verifyAgent(req);
  if (!result.ok) return res.status(401).json({ error: result.error });
  if (!ALLOWED_AGENTS.has(result.fingerprint)) {
    return res.status(403).json({ error: "Agent not authorized for this service" });
  }
  req.agent = result;
  next();
}
```

### Allow-list by owner

Trust any agent owned by specific humans:

```javascript
const ALLOWED_OWNERS = new Set([
  "00000003010000000000539c741e0df8",  // Alice
  "00000003010000000000542b891a3c47",  // Bob
]);

function requireAuthorizedOwner(req, res, next) {
  const result = verifyAgent(req);
  if (!result.ok) return res.status(401).json({ error: result.error });
  if (!result.owner || !ALLOWED_OWNERS.has(result.owner)) {
    return res.status(403).json({ error: "Agent owner not authorized" });
  }
  req.agent = result;
  next();
}
```

### Rate limiting by agent

Use the fingerprint as a rate-limit key:

```javascript
const rateLimits = new Map();  // fingerprint → { count, windowStart }

function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const fp = req.agent.fingerprint;
    const now = Date.now();
    const entry = rateLimits.get(fp) || { count: 0, windowStart: now };

    if (now - entry.windowStart > windowMs) {
      entry.count = 0;
      entry.windowStart = now;
    }

    entry.count++;
    rateLimits.set(fp, entry);

    if (entry.count > maxRequests) {
      return res.status(429).json({ error: "Rate limit exceeded" });
    }
    next();
  };
}

// 100 requests per minute per agent
app.use("/api", requireAgent, rateLimit(100, 60000));
```

## Deep verification (optional)

Basic token verification confirms that the agent holds the private key corresponding to the public key in the token. For higher-security scenarios, you can verify the full provenance chain back to the human owner.

### Verifying the owner binding

The agent can provide its proof bundle (from `export-proof` or git notes) as an additional header:

```
X-Agent-Proof: <base64url-encoded-proof-bundle>
```

The proof bundle contains:

```json
{
  "version": 1,
  "agent": {
    "fingerprint": "f5d9fac4...",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n..."
  },
  "ownerBinding": {
    "id": "uuid",
    "payload": {
      "ownerSessionSub": "00000003...",
      "idTokenHash": "sha256-of-id-token",
      "agentInstance": {
        "publicKeyFingerprint": "f5d9fac4...",
        "publicKeyPem": "..."
      }
    },
    "payloadHash": "sha256-of-canonical-payload",
    "signature": "Ed25519-base64url"
  },
  "idToken": "eyJ...",
  "ssoBaseUrl": "https://sso.alien-api.com"
}
```

Verification steps:

```
1. Token fingerprint == proof.agent.fingerprint
2. proof.ownerBinding.payload — canonical JSON matches payloadHash
3. proof.ownerBinding.signature — Ed25519 verify with proof.agent.publicKeyPem
4. proof.ownerBinding.payload.agentInstance.publicKeyFingerprint == token fingerprint
5. sha256(proof.idToken) == proof.ownerBinding.payload.idTokenHash
6. Fetch SSO JWKS from proof.ssoBaseUrl + "/.well-known/openid-configuration"
7. Verify proof.idToken RS256 signature against JWKS
```

If all checks pass, you have cryptographic proof that:
- The agent holds the private key (token signature)
- The agent created a binding to a specific human (owner binding signature)
- The Alien SSO server witnessed this binding (id_token RS256 signature)
- The human is a verified AlienID holder

### When to use deep verification

| Scenario | Basic token | Deep verification |
|---|---|---|
| Read-only API access | Sufficient | Not needed |
| Write operations | Sufficient | Recommended |
| Financial transactions | Not sufficient | Required |
| Audit-sensitive operations | Sufficient | Recommended |
| First-time agent registration | Not sufficient | Required |

## Testing your integration

### Start the demo service as a reference

```bash
node examples/demo-service.mjs --port 3141
```

### Generate a test token

```bash
# As JSON (for programmatic use)
node cli.mjs auth-header

# As raw header (for curl)
node cli.mjs auth-header --raw
```

### Make authenticated requests

```bash
# Using --raw output directly
curl -H "$(node cli.mjs auth-header --raw)" http://localhost:3141/api/whoami

# Using JSON output
TOKEN=$(node cli.mjs auth-header | jq -r .token)
curl -H "Authorization: AgentID $TOKEN" http://localhost:3141/api/whoami
```

### Test error cases

```bash
# No auth header
curl http://localhost:3141/api/whoami
# → 401: {"error": "Missing header: Authorization: AgentID <token>"}

# Invalid token
curl -H "Authorization: AgentID invalid" http://localhost:3141/api/whoami
# → 401: {"error": "Invalid token encoding"}

# Expired token (wait 5+ minutes after generating)
curl -H "Authorization: AgentID $OLD_TOKEN" http://localhost:3141/api/whoami
# → 401: {"error": "Token expired (age: 312s)"}

# Tampered token (flip a character in the payload)
TAMPERED=$(echo $TOKEN | python3 -c "import sys; t=sys.stdin.read().strip(); print(t[:10]+('A' if t[10]!='A' else 'B')+t[11:])")
curl -H "Authorization: AgentID $TAMPERED" http://localhost:3141/api/whoami
# → 401: {"error": "Invalid token encoding"} (corrupted JSON)
#    or: {"error": "Signature verification failed"} (valid JSON but bad signature)
```

## Security considerations

### What the token proves

- The agent **holds the Ed25519 private key** at the time of signing
- The token was created **within the last 5 minutes** (configurable)
- The agent claims a specific **owner** (AlienID address) — verified only via deep verification

### What it does not prove (without deep verification)

- That the owner field is truthful (the agent self-asserts it)
- That the agent is currently authorized by the owner (the binding could be revoked)
- That the human owner is a real, unique person (that requires chain verification)

### Replay protection

- Tokens include a random `nonce` and a `timestamp`
- The 5-minute expiry window limits replay
- For stricter replay protection, track seen nonces per agent fingerprint

### Clock skew

- Tokens use the agent's local clock
- The default 5-minute window accommodates reasonable clock drift
- Adjust `maxAgeMs` if your environment has known clock skew issues
- Reject tokens with negative age (timestamp in the future)

### Transport security

- Always use HTTPS in production
- The token is a bearer credential — anyone who captures it can replay it within the validity window
- Consider binding tokens to specific endpoints if your threat model requires it
