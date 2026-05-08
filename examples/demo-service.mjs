#!/usr/bin/env node
//
// demo-service — a tiny Alien-aware service for end-to-end integration tests.
// Publishes the well-known manifest, hosts a meta-tag support signal, and
// verifies inbound `Authorization: AgentID <token>` headers with the same
// primitives the production verifier package (@alien-id/sso-agent-id) uses.
//
// Layered with examples/dev-sso.mjs, it exercises the full agent flow:
//   agent — DPoP-bound OIDC ⇄ dev-sso
//   agent — AgentID self-signed token ⇄ demo-service
//
// Verification scope here is intentionally narrow (signature + freshness +
// fingerprint). Full chain verification is deferred to @alien-id/sso-agent-id.
// See README.md "Service Authentication" for the production pattern.
//
// Usage:
//   node examples/demo-service.mjs --port 3141
//   node examples/demo-service.mjs --port 3141 --strict-fingerprint <fp>

import http from "node:http";
import { parseArgs } from "node:util";

import {
  verifyEd25519Base64Url,
  fingerprintPublicKeyPem,
  canonicalJSONString,
  fromB64url,
} from "../skills/alien-agent-id/lib.mjs";

const { values: argv } = parseArgs({
  args: process.argv.slice(2),
  options: {
    port: { type: "string", default: "3141" },
    host: { type: "string", default: "127.0.0.1" },
    "service-name": { type: "string", default: "demo-service" },
    "spec-url": { type: "string" },
    "strict-fingerprint": { type: "string" },
    "token-max-age-sec": { type: "string", default: "300" },
    verbose: { type: "boolean", default: false },
  },
  allowPositionals: false,
});

const PORT = Number(argv.port);
const HOST = argv.host;
const TOKEN_MAX_AGE_SEC = Number(argv["token-max-age-sec"]);
const STRICT_FINGERPRINT = argv["strict-fingerprint"];
const SERVICE_NAME = argv["service-name"];
const SPEC_URL = argv["spec-url"];
const VERBOSE = argv.verbose;

const log = (...args) => console.error("[demo-service]", ...args);
const trace = (...args) => { if (VERBOSE) log(...args); };

const ORIGIN = `http://${HOST}:${PORT}`;

// ─── Manifest ──────────────────────────────────────────────────────────────

function manifest() {
  const m = {
    version: 1,
    service: { name: SERVICE_NAME, url: ORIGIN },
    auth: { header: "Authorization", scheme: "AgentID" },
    api: { base: `${ORIGIN}/api/v1` },
  };
  if (SPEC_URL) m.api.specUrl = SPEC_URL;
  return m;
}

// ─── Token verification (mirror of sso-agent-id's surface check) ──────────

// Returns { ok: true, agent, token } on success or
//         { ok: false, status, code, reason }.
//
// Token shape (produced by `auth-header`):
//   { v, fingerprint, publicKeyPem, owner, timestamp /* ms epoch */,
//     nonce, sig, ownerBinding, idToken }
//
// This mirrors the surface checks @alien-id/sso-agent-id performs at its
// shallow tier: signature, fingerprint binding, freshness. Full chain
// verification (owner binding → id_token RS256 sig → JWKS) is what the
// production verifier package does and is out of scope for this demo.
function verifyAgentToken(authHeader) {
  if (typeof authHeader !== "string" || !authHeader) {
    return { ok: false, status: 401, code: "missing_header", reason: "Missing Authorization header" };
  }
  const m = /^AgentID\s+(.+)$/.exec(authHeader);
  if (!m) {
    return { ok: false, status: 401, code: "invalid_scheme", reason: "Expected `Authorization: AgentID <token>`" };
  }
  const tokenB64 = m[1];
  let token;
  try {
    token = JSON.parse(fromB64url(tokenB64).toString("utf8"));
  } catch {
    return { ok: false, status: 401, code: "malformed_token", reason: "Token is not base64url(JSON)" };
  }
  if (!token || typeof token !== "object") {
    return { ok: false, status: 401, code: "malformed_token", reason: "Token payload is not an object" };
  }
  for (const k of ["fingerprint", "publicKeyPem", "timestamp", "sig"]) {
    if (token[k] === undefined || token[k] === null) {
      return { ok: false, status: 401, code: "missing_field", reason: `Token missing field '${k}'` };
    }
  }
  if (typeof token.fingerprint !== "string" || typeof token.publicKeyPem !== "string" || typeof token.sig !== "string") {
    return { ok: false, status: 401, code: "bad_field_type", reason: "fingerprint/publicKeyPem/sig must be strings" };
  }
  // Freshness: `timestamp` is ms-epoch.
  const ageMs = Date.now() - Number(token.timestamp);
  if (!Number.isFinite(ageMs) || ageMs < -5_000 || ageMs > TOKEN_MAX_AGE_SEC * 1000) {
    return { ok: false, status: 401, code: "stale_token", reason: `Token age ${ageMs}ms outside (-5000, ${TOKEN_MAX_AGE_SEC * 1000}]` };
  }
  // Fingerprint pin (if requested).
  if (STRICT_FINGERPRINT && token.fingerprint !== STRICT_FINGERPRINT) {
    return { ok: false, status: 403, code: "fingerprint_pin_miss", reason: "fingerprint not allow-listed" };
  }
  // Fingerprint must match the embedded publicKeyPem.
  let derivedFingerprint;
  try { derivedFingerprint = fingerprintPublicKeyPem(token.publicKeyPem); }
  catch (err) { return { ok: false, status: 401, code: "bad_pubkey", reason: String(err.message || err) }; }
  if (derivedFingerprint !== token.fingerprint) {
    return { ok: false, status: 401, code: "fingerprint_self_mismatch", reason: "fingerprint != SHA-256(publicKeyPem)" };
  }
  // Verify Ed25519 signature. The signed payload is exactly the fields
  // createAgentToken signs — `ownerBinding` and `idToken` are appended
  // post-signature and must NOT be included in the signing input.
  const signedPayload = {
    v: token.v,
    fingerprint: token.fingerprint,
    publicKeyPem: token.publicKeyPem,
    owner: token.owner,
    timestamp: token.timestamp,
    nonce: token.nonce,
  };
  let signatureValid;
  try {
    signatureValid = verifyEd25519Base64Url(canonicalJSONString(signedPayload), token.sig, token.publicKeyPem);
  } catch (err) {
    return { ok: false, status: 401, code: "bad_signature", reason: String(err.message || err) };
  }
  if (!signatureValid) {
    return { ok: false, status: 401, code: "bad_signature", reason: "Ed25519 signature verification failed" };
  }
  return { ok: true, agent: { fingerprint: token.fingerprint, owner: token.owner }, token };
}

// ─── Routes ────────────────────────────────────────────────────────────────

function send(res, status, body, headers = {}) {
  const isJson = body !== null && typeof body === "object";
  const payload = isJson ? JSON.stringify(body) : (body == null ? "" : String(body));
  res.writeHead(status, {
    "Content-Type": isJson
      ? "application/json; charset=utf-8"
      : "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(payload);
}

function indexHtml() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="alien-agent-id" content="v1">
    <title>${SERVICE_NAME}</title>
  </head>
  <body>
    <h1>${SERVICE_NAME}</h1>
    <p>This service is Alien Agent ID-aware. The well-known manifest is at
      <a href="/.well-known/alien-agent-id.json">/.well-known/alien-agent-id.json</a>.</p>
  </body>
</html>`;
}

const server = http.createServer((req, res) => {
  trace(`${req.method} ${req.url}`);

  if (req.url === "/" && req.method === "GET") {
    return send(res, 200, indexHtml());
  }
  if (req.url === "/.well-known/alien-agent-id.json" && req.method === "GET") {
    return send(res, 200, manifest());
  }
  if (req.url === "/api/v1/whoami" && req.method === "GET") {
    const auth = req.headers["authorization"] || "";
    const v = verifyAgentToken(auth);
    if (!v.ok) {
      trace(`auth FAIL: ${v.code} — ${v.reason}`);
      return send(res, v.status, { ok: false, error: v.code, reason: v.reason });
    }
    return send(res, 200, {
      ok: true,
      service: SERVICE_NAME,
      agent_fingerprint: v.agent.fingerprint,
      service_token: `svc-token-${Date.now().toString(36)}`,
    });
  }
  return send(res, 404, { error: "not_found", path: req.url });
});

server.listen(PORT, HOST, () => {
  log(`listening on ${ORIGIN}`);
  log(`manifest: ${ORIGIN}/.well-known/alien-agent-id.json`);
  log(`api.base: ${ORIGIN}/api/v1`);
  log(`token max-age: ${TOKEN_MAX_AGE_SEC}s`);
  if (STRICT_FINGERPRINT) log(`strict-fingerprint pinned: ${STRICT_FINGERPRINT}`);
});

process.on("SIGINT", () => server.close(() => process.exit(0)));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
