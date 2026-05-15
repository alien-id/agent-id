#!/usr/bin/env node
//
// dev-sso — a minimal local SSO that implements the RFC 9449 DPoP cutover
// contract (id_token cnf.jkt + DPoP-bound token endpoint) so the agent-id CLI
// can run end to end against a real HTTP server without requiring the
// production Alien SSO (which is closed-source and, at time of writing, has
// not yet rolled out the cutover server-side).
//
// What this is:
//   - Auto-approves every authorize request. No QR, no Alien App.
//   - Issues RS256-signed id_tokens that carry `cnf.jkt` matching the
//     `dpop_jkt` query param from /oauth/authorize (RFC 9449 §10).
//   - Verifies the `DPoP` proof header on /oauth/token and /oauth/userinfo.
//   - Emits `token_type: "DPoP"` on token responses (RFC 9449 §5).
//
// What this is NOT:
//   - The real Alien SSO. There's no Alien App callback, no TON/Solana
//     attestation, no real human approval. The owner identity is a fixture
//     held entirely in this process.
//   - A reference implementation. It exists to drive integration tests.
//
// Usage:
//   node examples/dev-sso.mjs --port 5050
//   # then in another shell:
//   node plugins/agent-id-core/bin/cli.mjs auth \
//     --provider-address dev-fixture-provider \
//     --sso-url http://localhost:5050
//
// Endpoints:
//   GET  /.well-known/openid-configuration
//   GET  /oauth/jwks
//   GET  /oauth/authorize
//   POST /oauth/poll
//   POST /oauth/token
//   GET  /oauth/userinfo
//
// All state is in-memory; restart the process to reset.

import http from "node:http";
import {
  generateKeyPairSync,
  createPublicKey,
  createSign,
  randomBytes,
  createHash,
  verify as cryptoVerify,
} from "node:crypto";
import { parseArgs } from "node:util";

import {
  ed25519PublicKeyToJwk,
  fingerprintPublicKeyPem,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";

// ─── CLI args ──────────────────────────────────────────────────────────────

const { values: argv } = parseArgs({
  args: process.argv.slice(2),
  options: {
    port: { type: "string", default: "5050" },
    host: { type: "string", default: "127.0.0.1" },
    "auto-approve-delay-ms": { type: "string", default: "0" },
    verbose: { type: "boolean", default: false },
  },
  allowPositionals: false,
});

const PORT = Number(argv.port);
const HOST = argv.host;
const AUTO_APPROVE_DELAY_MS = Number(argv["auto-approve-delay-ms"]);
const VERBOSE = argv.verbose;

const log = (...args) => {
  // eslint-disable-next-line no-console
  console.error("[dev-sso]", ...args);
};
const trace = (...args) => {
  if (VERBOSE) log(...args);
};

// ─── Crypto material (ephemeral per process) ───────────────────────────────

// RS256 keypair that signs id_tokens. Published under its own kid in JWKS.
const rsa = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const rsaPubObj = createPublicKey(rsa.publicKey);
const rsaJwk = rsaPubObj.export({ format: "jwk" });
const rsaKid = b64url(createHash("sha256").update(JSON.stringify({
  e: rsaJwk.e, kty: rsaJwk.kty, n: rsaJwk.n,
})).digest()).slice(0, 16);

// Ed25519 fixture owner-session key. Every issued binding points back to this
// "owner" — every developer running dev-sso shares the same fixture identity.
const ownerKeys = generateEd25519PemPair();
const ownerFingerprint = fingerprintPublicKeyPem(ownerKeys.publicKeyPem);
// The session_address is opaque to the agent-id chain; production uses a
// TON-like address. Here we derive it from the fixture key fingerprint so it
// is stable across the process lifetime.
const OWNER_SESSION_ADDRESS = `dev-owner-${ownerFingerprint.slice(0, 24)}`;
const OWNER_PROVIDER_ADDRESS_DEFAULT = "dev-fixture-provider";

// In-memory session stores ─────────────────────────────────────────────────

// pollingCode → { clientId, codeChallenge, dpopJkt, scope, status,
//                 authorizationCode, deepLink, expiredAt }
const authzSessions = new Map();
// authorizationCode → { clientId, codeChallenge, dpopJkt, sub, consumed }
const authzCodes = new Map();
// refreshToken → { clientId, dpopJkt, sub }
const refreshTokens = new Map();
// accessToken → { clientId, dpopJkt, sub, exp }
const accessTokens = new Map();

// ─── Helpers ───────────────────────────────────────────────────────────────

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}
function fromB64url(s) {
  return Buffer.from(String(s), "base64url");
}
function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function send(res, status, body, extraHeaders = {}) {
  const isJson = body !== null && typeof body === "object";
  const payload = isJson ? JSON.stringify(body) : (body == null ? "" : String(body));
  const headers = {
    "Content-Type": isJson ? "application/json; charset=utf-8" : "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    ...extraHeaders,
  };
  res.writeHead(status, headers);
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let buf = "";
    req.setEncoding("utf8");
    req.on("data", (c) => { buf += c; });
    req.on("end", () => resolve(buf));
    req.on("error", reject);
  });
}

function parseJwsProof(token) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("Malformed JWS");
  const [headerB, payloadB, sigB] = parts;
  const header = JSON.parse(fromB64url(headerB).toString("utf8"));
  const payload = JSON.parse(fromB64url(payloadB).toString("utf8"));
  return { header, payload, signingInput: `${headerB}.${payloadB}`, sigB };
}

// Canonicalize htu the same way the agent does so equality compares hold.
function canonicalizeHtu(value) {
  let url;
  try { url = new URL(value); } catch { return value; }
  url.search = "";
  url.hash = "";
  let host = url.host.toLowerCase();
  if (
    (url.protocol === "https:" && url.port === "443") ||
    (url.protocol === "http:" && url.port === "80")
  ) {
    host = url.hostname.toLowerCase();
  }
  return `${url.protocol.toLowerCase()}//${host}${url.pathname}`;
}

// Verify a DPoP proof per RFC 9449 §4.3.
// Returns { ok, jkt, jwk } on success, throws otherwise.
function verifyDPoPProof({ proof, htm, htu, accessToken: at }) {
  const { header, payload, signingInput, sigB } = parseJwsProof(proof);
  if (header.typ !== "dpop+jwt") throw new Error("DPoP: typ must be dpop+jwt");
  if (header.alg !== "EdDSA") throw new Error("DPoP: alg must be EdDSA");
  if (!header.jwk || header.jwk.kty !== "OKP" || header.jwk.crv !== "Ed25519") {
    throw new Error("DPoP: header.jwk must be an Ed25519 OKP JWK");
  }
  // Refuse private-key members in jwk header (RFC 9449 §4.2 / RFC 7517).
  for (const k of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
    if (k in header.jwk) throw new Error(`DPoP: header.jwk must not carry private member '${k}'`);
  }
  if (typeof payload.jti !== "string" || !payload.jti) throw new Error("DPoP: jti required");
  if (payload.htm !== htm) throw new Error(`DPoP: htm mismatch (expected ${htm}, got ${payload.htm})`);
  const expectedHtu = canonicalizeHtu(htu);
  const proofHtu = canonicalizeHtu(payload.htu);
  if (proofHtu !== expectedHtu) {
    throw new Error(`DPoP: htu mismatch (expected ${expectedHtu}, got ${proofHtu})`);
  }
  if (typeof payload.iat !== "number") throw new Error("DPoP: iat required");
  const ageSec = Math.abs(nowSec() - payload.iat);
  if (ageSec > 300) throw new Error(`DPoP: iat too old (${ageSec}s)`);
  if (at) {
    const expectedAth = b64url(createHash("sha256").update(at).digest());
    if (payload.ath !== expectedAth) throw new Error("DPoP: ath mismatch");
  }
  // Verify EdDSA signature against the embedded JWK.
  const jwkPub = createPublicKey({ key: header.jwk, format: "jwk" });
  const ok = cryptoVerify(
    null,
    Buffer.from(signingInput, "utf8"),
    jwkPub,
    fromB64url(sigB),
  );
  if (!ok) throw new Error("DPoP: signature invalid");
  return { ok: true, jkt: jwkThumbprint(header.jwk), jwk: header.jwk };
}

// Sign an RS256 JWT with the dev RSA key. Used for id_token issuance.
//
// id_token verifier contract this dev-sso satisfies — forward-compat with the
// hardened verifier landing in agent-id Wave 1 PR-A11 (RFC 7515/7518/7519/8725
// + OIDC §3.1.3.7 + RFC 9449 §6.1):
//
//   header: { alg: "RS256" | "EdDSA", typ: "JWT", kid }
//     · alg in {RS256, EdDSA}            (RFC 7515 §10.7 allowlist)
//     · crit absent or empty             (RFC 7515 §4.1.11)
//     · typ === "JWT"                    (RFC 8725 §3.11 typ-confusion guard)
//
//   payload: { iss, sub, aud, iat, exp, cnf: { jkt }, [nbf], [nonce] }
//     · iss equals discovery.issuer      (RFC 7519 §4.1.1)
//     · aud equals providerAddress       (single-value; multi-aud requires azp)
//     · iat present, NumericDate         (RFC 7519 §4.1.6)
//     · exp present, in the future       (RFC 7519 §4.1.4)
//     · nbf OPTIONAL; if present must be in the past (RFC 7519 §4.1.5)
//     · cnf.jkt MUST equal jwkThumbprint(agent_jwk) when caller supplies key
//                                        (RFC 9449 §6.1 + RFC 7800)
//     · nonce checked only when caller passes expectedNonce (OIDC §3.1.3.7)
//
//   ssoBaseUrl scheme: https:// in production, http:// permitted only on
//                      loopback (localhost / 127.0.0.1) (RFC 6749 §10 carve-out).
//
// If a future verifier change adds a required claim, surface it here first
// before flipping behavior server-side.
function signRs256Jwt(payload) {
  const header = { alg: "RS256", typ: "JWT", kid: rsaKid };
  const headerB = b64url(JSON.stringify(header));
  const payloadB = b64url(JSON.stringify(payload));
  const signingInput = `${headerB}.${payloadB}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  const sig = signer.sign(rsa.privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

// ─── Routes ────────────────────────────────────────────────────────────────

const ISSUER = `http://${HOST}:${PORT}`;

function routeDiscovery(req, res) {
  send(res, 200, {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
    jwks_uri: `${ISSUER}/oauth/jwks`,
    response_types_supported: ["code"],
    response_modes_supported: ["query", "json"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid"],
    token_endpoint_auth_methods_supported: ["none"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "nonce", "auth_time", "cnf"],
    code_challenge_methods_supported: ["S256"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    dpop_signing_alg_values_supported: ["EdDSA"],
  });
}

function routeJwks(req, res) {
  send(res, 200, {
    keys: [
      {
        kty: "RSA",
        use: "sig",
        alg: "RS256",
        kid: rsaKid,
        n: rsaJwk.n,
        e: rsaJwk.e,
      },
    ],
  });
}

// GET /oauth/authorize?response_type=code&client_id=...&dpop_jkt=...&...
// Returns { deep_link, polling_code, expired_at } and immediately marks the
// session as authorized.
function routeAuthorize(req, res, url) {
  const q = url.searchParams;
  const clientId = q.get("client_id");
  const codeChallenge = q.get("code_challenge");
  const responseType = q.get("response_type");
  const dpopJkt = q.get("dpop_jkt");
  if (responseType !== "code") return send(res, 400, { error: "unsupported_response_type" });
  if (!clientId) return send(res, 400, { error: "invalid_request", error_description: "client_id required" });
  if (!codeChallenge) return send(res, 400, { error: "invalid_request", error_description: "code_challenge required" });

  const pollingCode = b64url(randomBytes(18));
  const authorizationCode = b64url(randomBytes(24));
  const expiredAt = nowSec() + 300;

  const session = {
    clientId,
    codeChallenge,
    dpopJkt,
    status: "pending",
    authorizationCode,
    expiredAt,
  };
  authzSessions.set(pollingCode, session);

  // Auto-approve. In a real SSO this would happen after the human approves
  // in the Alien App; we just flip the bit inline (or after a delay if the
  // operator wants to simulate human latency).
  const approve = () => {
    session.status = "authorized";
    authzCodes.set(authorizationCode, {
      clientId,
      codeChallenge,
      dpopJkt,
      sub: OWNER_SESSION_ADDRESS,
      consumed: false,
    });
    trace(`auto-approved polling_code=${pollingCode.slice(0, 8)}…`);
  };
  if (AUTO_APPROVE_DELAY_MS > 0) setTimeout(approve, AUTO_APPROVE_DELAY_MS);
  else approve();

  send(res, 200, {
    deep_link: `dev-sso://approve?polling_code=${pollingCode}`,
    polling_code: pollingCode,
    expired_at: expiredAt,
  });
}

// POST /oauth/poll {polling_code}
async function routePoll(req, res) {
  const body = await readBody(req);
  let parsed;
  try { parsed = JSON.parse(body); } catch { return send(res, 400, { error: "invalid_json" }); }
  const session = authzSessions.get(String(parsed.polling_code || ""));
  if (!session) return send(res, 200, { status: "expired" });
  if (session.status !== "authorized") return send(res, 200, { status: "pending" });
  send(res, 200, {
    status: "authorized",
    authorization_code: session.authorizationCode,
  });
}

// POST /oauth/token  (form-urlencoded; DPoP header required)
async function routeToken(req, res) {
  const body = await readBody(req);
  const params = new URLSearchParams(body);
  const grantType = params.get("grant_type");
  const dpopHeader = req.headers["dpop"];

  if (!dpopHeader) {
    return send(res, 400, { error: "invalid_dpop_proof", error_description: "DPoP header required" });
  }
  let proof;
  try {
    proof = verifyDPoPProof({
      proof: dpopHeader,
      htm: "POST",
      htu: `${ISSUER}/oauth/token`,
    });
  } catch (err) {
    return send(res, 400, { error: "invalid_dpop_proof", error_description: err.message });
  }

  if (grantType === "authorization_code") {
    const code = params.get("code");
    const verifier = params.get("code_verifier");
    const clientId = params.get("client_id");
    const codeRec = authzCodes.get(String(code || ""));
    if (!codeRec || codeRec.consumed) return send(res, 400, { error: "invalid_grant" });
    codeRec.consumed = true;
    if (codeRec.clientId !== clientId) return send(res, 400, { error: "invalid_grant", error_description: "client_id mismatch" });
    const expectedChallenge = b64url(createHash("sha256").update(String(verifier || "")).digest());
    if (expectedChallenge !== codeRec.codeChallenge) return send(res, 400, { error: "invalid_grant", error_description: "PKCE mismatch" });
    if (codeRec.dpopJkt && codeRec.dpopJkt !== proof.jkt) {
      return send(res, 400, { error: "invalid_dpop_proof", error_description: "dpop_jkt mismatch with /authorize" });
    }
    return mintTokens(res, { clientId, sub: codeRec.sub, jkt: proof.jkt });
  }

  if (grantType === "refresh_token") {
    const rt = params.get("refresh_token");
    const clientId = params.get("client_id");
    const rtRec = refreshTokens.get(String(rt || ""));
    if (!rtRec) return send(res, 400, { error: "invalid_grant" });
    if (rtRec.clientId !== clientId) return send(res, 400, { error: "invalid_grant" });
    if (rtRec.jkt !== proof.jkt) {
      trace(`refresh jkt mismatch: stored=${rtRec.jkt} proof=${proof.jkt}`);
      return send(res, 400, { error: "invalid_dpop_proof", error_description: "refresh-token jkt sticky" });
    }
    // RFC 9449: sticky binding, do NOT rotate refresh token.
    return mintTokens(res, { clientId, sub: rtRec.sub, jkt: proof.jkt, refreshToken: rt });
  }

  send(res, 400, { error: "unsupported_grant_type" });
}

function mintTokens(res, { clientId, sub, jkt, refreshToken: existingRt }) {
  const accessToken = b64url(randomBytes(32));
  const refreshToken = existingRt || b64url(randomBytes(32));
  const exp = nowSec() + 3600;

  accessTokens.set(accessToken, { clientId, jkt, sub, exp });
  refreshTokens.set(refreshToken, { clientId, jkt, sub });

  const idToken = signRs256Jwt({
    iss: ISSUER,
    sub,
    aud: clientId,
    iat: nowSec(),
    exp,
    cnf: { jkt },
  });

  send(res, 200, {
    access_token: accessToken,
    refresh_token: refreshToken,
    id_token: idToken,
    token_type: "DPoP",
    expires_in: 3600,
    scope: "openid",
  });
}

// GET /oauth/userinfo (requires Authorization: DPoP <at> + DPoP proof)
async function routeUserinfo(req, res) {
  const auth = req.headers.authorization || "";
  const m = /^DPoP\s+(.+)$/i.exec(auth);
  if (!m) {
    return send(res, 401, { error: "invalid_token" }, {
      "WWW-Authenticate": 'DPoP error="invalid_token", algs="EdDSA"',
    });
  }
  const at = m[1];
  const atRec = accessTokens.get(at);
  if (!atRec) {
    return send(res, 401, { error: "invalid_token" }, {
      "WWW-Authenticate": 'DPoP error="invalid_token", algs="EdDSA"',
    });
  }
  if (atRec.exp <= nowSec()) {
    return send(res, 401, { error: "invalid_token", error_description: "expired" });
  }
  const dpopHeader = req.headers["dpop"];
  if (!dpopHeader) {
    return send(res, 401, { error: "invalid_dpop_proof" }, {
      "WWW-Authenticate": 'DPoP error="invalid_dpop_proof", algs="EdDSA"',
    });
  }
  let proof;
  try {
    proof = verifyDPoPProof({
      proof: dpopHeader,
      htm: "GET",
      htu: `${ISSUER}/oauth/userinfo`,
      accessToken: at,
    });
  } catch (err) {
    return send(res, 401, { error: "invalid_dpop_proof", error_description: err.message }, {
      "WWW-Authenticate": 'DPoP error="invalid_dpop_proof", algs="EdDSA"',
    });
  }
  if (proof.jkt !== atRec.jkt) {
    return send(res, 401, { error: "invalid_token", error_description: "cnf.jkt mismatch" });
  }
  send(res, 200, {
    sub: atRec.sub,
    iss: ISSUER,
    aud: atRec.clientId,
  });
}

// ─── Server ────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, ISSUER);
  trace(`${req.method} ${req.url}`);
  try {
    if (url.pathname === "/.well-known/openid-configuration" && req.method === "GET") return routeDiscovery(req, res);
    if (url.pathname === "/oauth/jwks" && req.method === "GET") return routeJwks(req, res);
    if (url.pathname === "/oauth/authorize" && req.method === "GET") return routeAuthorize(req, res, url);
    if (url.pathname === "/oauth/poll" && req.method === "POST") return await routePoll(req, res);
    if (url.pathname === "/oauth/token" && req.method === "POST") return await routeToken(req, res);
    if (url.pathname === "/oauth/userinfo" && req.method === "GET") return await routeUserinfo(req, res);
    return send(res, 404, { error: "not_found", path: url.pathname });
  } catch (err) {
    log("ERROR:", err.stack || err);
    return send(res, 500, { error: "server_error", error_description: String(err.message || err) });
  }
});

server.listen(PORT, HOST, () => {
  log(`listening on http://${HOST}:${PORT}`);
  log(`issuer: ${ISSUER}`);
  log(`rs256 kid: ${rsaKid}`);
  log(`fixture owner sub: ${OWNER_SESSION_ADDRESS}`);
  log(`auto-approve: yes${AUTO_APPROVE_DELAY_MS > 0 ? ` (${AUTO_APPROVE_DELAY_MS}ms delay)` : ""}`);
  log(`recommended provider-address: ${OWNER_PROVIDER_ADDRESS_DEFAULT}`);
});

process.on("SIGINT", () => { server.close(() => process.exit(0)); });
process.on("SIGTERM", () => { server.close(() => process.exit(0)); });
