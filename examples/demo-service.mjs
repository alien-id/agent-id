#!/usr/bin/env node
//
// demo-service — a tiny Alien-aware service for end-to-end integration tests.
// Publishes the well-known manifest, hosts a meta-tag support signal, and
// verifies inbound requests per RFC 9449 (OAuth 2.0 DPoP):
//
//   Authorization: DPoP <access_token>       ← Alien at+jwt (RS256), signed by SSO
//   DPoP: <proof JWT>                        ← EdDSA, signed by the agent main key
//
// Layered with examples/dev-sso.mjs, it exercises the full agent flow:
//   agent — DPoP-bound OIDC ⇄ dev-sso
//   agent — DPoP-protected request ⇄ demo-service
//
// Verification scope is the RFC 9449 §4.3 checklist plus the cnf.jkt binding
// from RFC 7800 §3.1 / RFC 9449 §6.1. No custom envelope: every fact the
// demo trusts is signed either by the SSO (access_token) or by the agent
// (DPoP proof). Production services should call into
// `@alien-id/sso-agent-id`'s `verifyDPoPRequest` instead of re-implementing
// this — kept self-contained here so the demo has no SDK build dependency.
//
// Usage:
//   node examples/demo-service.mjs --port 3141 --sso-url https://sso.develop.alien-api.com
//   node examples/demo-service.mjs --port 3141 --strict-jkt <jkt>

import http from "node:http";
import { createHash } from "node:crypto";
import { parseArgs } from "node:util";

import {
  b64url,
  parseJwt,
  jwkThumbprint,
  verifyJwtRs256Signature,
  verifyJwtEdDsaSignature,
  fetchOidcDiscovery,
  fetchJwks,
} from "../bin/lib.mjs";

const { values: argv } = parseArgs({
  args: process.argv.slice(2),
  options: {
    port: { type: "string", default: "3141" },
    host: { type: "string", default: "127.0.0.1" },
    "service-name": { type: "string", default: "demo-service" },
    "spec-url": { type: "string" },
    "sso-url": { type: "string", default: "https://sso.develop.alien-api.com" },
    "expected-iss": { type: "string" },
    "expected-aud": { type: "string" },
    "strict-jkt": { type: "string" },
    "proof-max-age-sec": { type: "string", default: "30" },
    "jti-cache-max": { type: "string", default: "10000" },
    verbose: { type: "boolean", default: false },
  },
  allowPositionals: false,
});

const PORT = Number(argv.port);
const HOST = argv.host;
const SERVICE_NAME = argv["service-name"];
const SPEC_URL = argv["spec-url"];
const SSO_URL = argv["sso-url"];
const EXPECTED_ISS = argv["expected-iss"] || SSO_URL;
const EXPECTED_AUD = argv["expected-aud"];
const STRICT_JKT = argv["strict-jkt"];
const PROOF_MAX_AGE_SEC = Number(argv["proof-max-age-sec"]);
const JTI_CACHE_MAX = Number(argv["jti-cache-max"]);
const VERBOSE = argv.verbose;

const log = (...args) => console.error("[demo-service]", ...args);
const trace = (...args) => { if (VERBOSE) log(...args); };

const ORIGIN = `http://${HOST}:${PORT}`;

// ─── Manifest ──────────────────────────────────────────────────────────────

function manifest() {
  const m = {
    version: 1,
    service: { name: SERVICE_NAME, url: ORIGIN },
    // RFC 9449 §7.1: protected resources use the `DPoP` Authorization scheme.
    auth: { header: "Authorization", scheme: "DPoP" },
    api: { base: `${ORIGIN}/api/v1` },
  };
  if (SPEC_URL) m.api.specUrl = SPEC_URL;
  return m;
}

// ─── JWKS cache ────────────────────────────────────────────────────────────
//
// One-shot fetch on first request; cached for the lifetime of the process.
// A production service would refresh on kid-miss + on a TTL.

let cachedDiscovery = null;
let cachedJwks = null;

async function loadKeys() {
  if (!cachedDiscovery) {
    cachedDiscovery = await fetchOidcDiscovery(SSO_URL);
  }
  if (!cachedJwks) {
    cachedJwks = await fetchJwks(cachedDiscovery.jwks_uri);
  }
  return { discovery: cachedDiscovery, jwks: cachedJwks };
}

// ─── jti replay cache ──────────────────────────────────────────────────────
//
// RFC 9449 §11.1: resource server SHOULD remember `jti` for at least the
// freshness window and reject replays. Simple FIFO with a hard cap; entries
// past the freshness window are pruned lazily on insert.

const jtiSeen = new Map(); // jti → iat (unix sec)

function rememberJti(jti, iat) {
  if (jtiSeen.has(jti)) return false;
  if (jtiSeen.size >= JTI_CACHE_MAX) {
    const cutoff = Math.floor(Date.now() / 1000) - PROOF_MAX_AGE_SEC;
    for (const [k, v] of jtiSeen) {
      if (v < cutoff) jtiSeen.delete(k);
      if (jtiSeen.size < JTI_CACHE_MAX) break;
    }
    if (jtiSeen.size >= JTI_CACHE_MAX) {
      const oldestKey = jtiSeen.keys().next().value;
      jtiSeen.delete(oldestKey);
    }
  }
  jtiSeen.set(jti, iat);
  return true;
}

// ─── DPoP verification (RFC 9449 §4.3 + §6.1) ──────────────────────────────
//
// Returns { ok: true, sub, jkt, atClaims, proofClaims } or
//         { ok: false, status, code, reason }.

async function verifyDPoPRequest(req) {
  // §4.3 step 1: exactly one Authorization header with the DPoP scheme.
  const authHeader = req.headers["authorization"];
  if (Array.isArray(authHeader) || typeof authHeader !== "string" || !authHeader) {
    return { ok: false, status: 401, code: "missing_authorization", reason: "Missing or duplicate Authorization header" };
  }
  // RFC 7235 §2.1: Authorization scheme names are case-insensitive.
  const authMatch = /^DPoP\s+(\S+)$/i.exec(authHeader);
  if (!authMatch) {
    return { ok: false, status: 401, code: "invalid_scheme", reason: "Expected `Authorization: DPoP <access_token>`" };
  }
  const accessToken = authMatch[1];

  // §4.3 step 1: exactly one DPoP proof header.
  const dpopHeader = req.headers["dpop"];
  if (Array.isArray(dpopHeader) || typeof dpopHeader !== "string" || !dpopHeader) {
    return { ok: false, status: 401, code: "missing_dpop", reason: "Missing or duplicate DPoP header" };
  }

  // §4.3 step 2: proof is a well-formed JWS.
  let proof;
  try {
    proof = parseJwt(dpopHeader);
  } catch (err) {
    return { ok: false, status: 401, code: "malformed_proof", reason: `Proof not a valid JWS: ${String(err.message || err)}` };
  }

  // §4.3 step 4: typ MUST be "dpop+jwt".
  if (proof.header.typ !== "dpop+jwt") {
    return { ok: false, status: 401, code: "bad_proof_typ", reason: `Proof typ must be 'dpop+jwt', got ${String(proof.header.typ)}` };
  }
  // §4.3 step 5: alg is a registered asymmetric signing alg. Alien agent
  // keys are Ed25519, so we accept EdDSA only and reject MAC/none up front.
  if (proof.header.alg !== "EdDSA") {
    return { ok: false, status: 401, code: "bad_proof_alg", reason: `Proof alg must be 'EdDSA', got ${String(proof.header.alg)}` };
  }
  // §4.3 step 6: header carries a `jwk` representing the public key.
  const proofJwk = proof.header.jwk;
  if (!proofJwk || typeof proofJwk !== "object") {
    return { ok: false, status: 401, code: "missing_proof_jwk", reason: "Proof header missing `jwk`" };
  }
  if (proofJwk.kty !== "OKP" || proofJwk.crv !== "Ed25519" || typeof proofJwk.x !== "string") {
    return { ok: false, status: 401, code: "bad_proof_jwk", reason: "Proof jwk must be {kty:OKP, crv:Ed25519, x}" };
  }
  // §4.3 step 6 cont.: jwk MUST NOT carry a private key part. RFC 8037 §2:
  // the OKP private member is `d`.
  if ("d" in proofJwk) {
    return { ok: false, status: 401, code: "private_in_proof_jwk", reason: "Proof jwk leaks private member `d`" };
  }

  // §4.3 step 7: signature verifies against the embedded JWK.
  let proofSigOk;
  try {
    proofSigOk = verifyJwtEdDsaSignature({
      signingInput: proof.signingInput,
      signatureB64url: proof.signatureB64url,
      jwk: proofJwk,
    });
  } catch (err) {
    return { ok: false, status: 401, code: "proof_sig_error", reason: String(err.message || err) };
  }
  if (!proofSigOk) {
    return { ok: false, status: 401, code: "bad_proof_signature", reason: "Proof signature failed verification" };
  }

  // §4.3 step 8: htm matches request method (case-sensitive bytewise compare).
  if (proof.payload.htm !== req.method) {
    return { ok: false, status: 401, code: "bad_proof_htm", reason: `Proof htm ${String(proof.payload.htm)} != request method ${req.method}` };
  }

  // §4.3 step 9: htu matches the request URL with query+fragment stripped.
  // Demo binds directly to HOST:PORT — no reverse proxy to honor here.
  // Normalize both sides via URL parsing so percent-encoding, default-port
  // elision, and case-folding of scheme/host are symmetric with the agent's
  // `createDPoPProof` (which calls `new URL(htu).toString()`).
  let requestHtu;
  let claimedHtu;
  try {
    const ru = new URL(`${ORIGIN}${req.url || "/"}`);
    ru.search = "";
    ru.hash = "";
    requestHtu = ru.toString();
    const cu = new URL(String(proof.payload.htu));
    cu.search = "";
    cu.hash = "";
    claimedHtu = cu.toString();
  } catch {
    return { ok: false, status: 401, code: "bad_proof_htu", reason: "Proof htu is not a parseable URL" };
  }
  if (claimedHtu !== requestHtu) {
    return { ok: false, status: 401, code: "bad_proof_htu", reason: `Proof htu ${claimedHtu} != request URL ${requestHtu}` };
  }

  // §4.3 step 11: iat within an acceptable window. Allow small clock skew
  // either way; the cap is on age, not on future-iat.
  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof proof.payload.iat !== "number") {
    return { ok: false, status: 401, code: "bad_proof_iat", reason: "Proof iat is not a NumericDate" };
  }
  const proofAgeSec = nowSec - proof.payload.iat;
  if (proofAgeSec > PROOF_MAX_AGE_SEC) {
    return { ok: false, status: 401, code: "stale_proof", reason: `Proof age ${proofAgeSec}s > max ${PROOF_MAX_AGE_SEC}s` };
  }
  if (proofAgeSec < -PROOF_MAX_AGE_SEC) {
    return { ok: false, status: 401, code: "future_proof", reason: `Proof iat ${-proofAgeSec}s in the future` };
  }

  // §4.3 step 12: jti not previously seen (in this freshness window).
  if (typeof proof.payload.jti !== "string" || !proof.payload.jti) {
    return { ok: false, status: 401, code: "missing_proof_jti", reason: "Proof missing jti" };
  }
  if (!rememberJti(proof.payload.jti, proof.payload.iat)) {
    return { ok: false, status: 401, code: "replayed_proof_jti", reason: "Proof jti has already been seen" };
  }

  // §4.3 step 10 + §6.1: verify the access_token, then bind it to the proof.
  let at;
  try {
    at = parseJwt(accessToken);
  } catch (err) {
    return { ok: false, status: 401, code: "malformed_access_token", reason: `access_token not a JWS: ${String(err.message || err)}` };
  }
  // RFC 9068 §2.1 + §4: access tokens MUST carry `typ:"at+jwt"` (or
  // `application/at+jwt`). Resource servers MUST verify; missing/wrong typ
  // means the token is NOT a compliant access token and MUST be rejected
  // — this is the cross-JWT-confusion gate against id_tokens and DPoP
  // proofs presented as access tokens.
  const atTyp = typeof at.header.typ === "string" ? at.header.typ.toLowerCase() : "";
  if (atTyp !== "at+jwt" && atTyp !== "application/at+jwt") {
    return { ok: false, status: 401, code: "bad_access_token_typ", reason: `access_token typ must be 'at+jwt' (RFC 9068 §4), got ${String(at.header.typ)}` };
  }

  let keys;
  try {
    keys = await loadKeys();
  } catch (err) {
    return { ok: false, status: 503, code: "jwks_unreachable", reason: `Could not fetch SSO JWKS: ${String(err.message || err)}` };
  }
  const { discovery, jwks } = keys;

  const atKty = at.header.alg === "RS256" ? "RSA" : at.header.alg === "EdDSA" ? "OKP" : null;
  if (!atKty) {
    return { ok: false, status: 401, code: "bad_access_token_alg", reason: `access_token alg must be RS256 or EdDSA, got ${String(at.header.alg)}` };
  }
  const atKey = jwks.keys.find((k) => k.kid === at.header.kid && k.kty === atKty);
  if (!atKey) {
    return { ok: false, status: 401, code: "unknown_access_token_kid", reason: `No JWKS entry for kid=${String(at.header.kid)} kty=${atKty}` };
  }
  const atVerifier = at.header.alg === "RS256" ? verifyJwtRs256Signature : verifyJwtEdDsaSignature;
  let atSigOk;
  try {
    atSigOk = atVerifier({
      signingInput: at.signingInput,
      signatureB64url: at.signatureB64url,
      jwk: atKey,
    });
  } catch (err) {
    return { ok: false, status: 401, code: "access_token_sig_error", reason: String(err.message || err) };
  }
  if (!atSigOk) {
    return { ok: false, status: 401, code: "bad_access_token_signature", reason: "access_token signature failed verification" };
  }

  // RFC 9068 §4: standard claim checks.
  const expectedIss = EXPECTED_ISS || discovery.issuer;
  if (at.payload.iss !== expectedIss) {
    return { ok: false, status: 401, code: "bad_access_token_iss", reason: `access_token iss ${String(at.payload.iss)} != ${expectedIss}` };
  }
  if (EXPECTED_AUD) {
    const aud = at.payload.aud;
    const audOk = Array.isArray(aud) ? aud.includes(EXPECTED_AUD) : aud === EXPECTED_AUD;
    if (!audOk) {
      return { ok: false, status: 401, code: "bad_access_token_aud", reason: `access_token aud does not include ${EXPECTED_AUD}` };
    }
  }
  if (typeof at.payload.exp !== "number" || at.payload.exp <= nowSec) {
    return { ok: false, status: 401, code: "expired_access_token", reason: "access_token is expired" };
  }
  if (typeof at.payload.sub !== "string" || !at.payload.sub) {
    return { ok: false, status: 401, code: "missing_access_token_sub", reason: "access_token missing sub" };
  }

  // §6.1: cnf.jkt MUST equal the thumbprint of the proof's jwk.
  const atJkt = at.payload.cnf?.jkt;
  if (typeof atJkt !== "string" || !atJkt) {
    return { ok: false, status: 401, code: "missing_cnf_jkt", reason: "access_token missing cnf.jkt" };
  }
  const proofJkt = jwkThumbprint(proofJwk);
  if (atJkt !== proofJkt) {
    return { ok: false, status: 401, code: "jkt_mismatch", reason: `access_token cnf.jkt ${atJkt} != proof jwk thumbprint ${proofJkt}` };
  }

  // §4.3 step 10: ath MUST equal b64url(sha256(access_token)). Required at
  // protected resources whenever the proof is presented alongside a token.
  const expectedAth = b64url(createHash("sha256").update(accessToken).digest());
  if (proof.payload.ath !== expectedAth) {
    return { ok: false, status: 401, code: "bad_proof_ath", reason: "Proof ath does not match sha256(access_token)" };
  }

  // Optional admin pin: limit which agent key may call us.
  if (STRICT_JKT && proofJkt !== STRICT_JKT) {
    return { ok: false, status: 403, code: "jkt_pin_miss", reason: "Agent jkt not allow-listed" };
  }

  return {
    ok: true,
    sub: at.payload.sub,
    jkt: proofJkt,
    atClaims: at.payload,
    proofClaims: proof.payload,
  };
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

const server = http.createServer(async (req, res) => {
  trace(`${req.method} ${req.url}`);

  if (req.url === "/" && req.method === "GET") {
    return send(res, 200, indexHtml());
  }
  if (req.url === "/.well-known/alien-agent-id.json" && req.method === "GET") {
    return send(res, 200, manifest());
  }
  if (req.url === "/api/v1/whoami" && req.method === "GET") {
    let v;
    try {
      v = await verifyDPoPRequest(req);
    } catch (err) {
      log(`verifier crashed: ${err.stack || err}`);
      return send(res, 500, { ok: false, error: "verifier_crash", reason: String(err.message || err) });
    }
    if (!v.ok) {
      trace(`auth FAIL: ${v.code} — ${v.reason}`);
      // RFC 9449 §7.1: protected resources signal DPoP via WWW-Authenticate.
      return send(res, v.status, { ok: false, error: v.code, reason: v.reason }, {
        "WWW-Authenticate": `DPoP error="invalid_token", error_description="${v.code}"`,
      });
    }
    return send(res, 200, {
      ok: true,
      service: SERVICE_NAME,
      owner_sub: v.sub,
      agent_jkt: v.jkt,
      service_token: `svc-token-${Date.now().toString(36)}`,
    });
  }
  return send(res, 404, { error: "not_found", path: req.url });
});

server.listen(PORT, HOST, () => {
  log(`listening on ${ORIGIN}`);
  log(`manifest: ${ORIGIN}/.well-known/alien-agent-id.json`);
  log(`SSO: ${SSO_URL}`);
  log(`expected iss: ${EXPECTED_ISS}`);
  if (EXPECTED_AUD) log(`expected aud: ${EXPECTED_AUD}`);
  log(`proof max-age: ${PROOF_MAX_AGE_SEC}s`);
  if (STRICT_JKT) log(`strict-jkt pinned: ${STRICT_JKT}`);
});

process.on("SIGINT", () => server.close(() => process.exit(0)));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
