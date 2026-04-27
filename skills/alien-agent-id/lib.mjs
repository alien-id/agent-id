// Alien Agent ID — Portable library for agent identity management.
// Zero npm dependencies. Requires Node.js 18+ (built-in crypto, fetch, fs).
//
// Consolidated from openclaw-alienid-signature-demo/src/{canonical,crypto,state,oidc,signer,verify}.js

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
  verify,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
} from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

// ════════════════════════════════════════════════════════════════════════════════
// Canonical JSON
// ════════════════════════════════════════════════════════════════════════════════

function sortValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const out = {};
  const keys = Object.keys(value).sort();
  for (const key of keys) {
    out[key] = sortValue(value[key]);
  }
  return out;
}

export function canonicalJSONString(value) {
  return JSON.stringify(sortValue(value));
}

export function sha256HexCanonical(value) {
  const input = typeof value === "string" ? value : canonicalJSONString(value);
  return createHash("sha256").update(input).digest("hex");
}

// ════════════════════════════════════════════════════════════════════════════════
// Crypto
// ════════════════════════════════════════════════════════════════════════════════

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function fromB64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4;
  const padded = pad === 0 ? normalized : normalized + "=".repeat(4 - pad);
  return Buffer.from(padded, "base64");
}

export function sha256B64url(text) {
  return b64url(createHash("sha256").update(text).digest());
}

export function sha256Hex(text) {
  return createHash("sha256").update(text).digest("hex");
}

export function nowMs() {
  return Date.now();
}

export function newOperationId() {
  return randomUUID();
}

export function generateEd25519PemPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
}

export function fingerprintPublicKeyPem(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ format: "der", type: "spki" });
  return createHash("sha256").update(der).digest("hex");
}

export function signEd25519Base64Url(payload, privateKeyPem) {
  const sig = sign(null, Buffer.from(payload), createPrivateKey(privateKeyPem));
  return b64url(sig);
}

export function verifyEd25519Base64Url(payload, signatureB64url, publicKeyPem) {
  const signature = fromB64url(signatureB64url);
  return verify(null, Buffer.from(payload), createPublicKey(publicKeyPem), signature);
}

function normalizeHex(input, label, expectedBytes) {
  if (typeof input !== "string") {
    throw new Error(`${label} must be a string`);
  }
  const trimmed = input.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(trimmed) || trimmed.length % 2 !== 0) {
    throw new Error(`${label} must be valid hex`);
  }
  const out = Buffer.from(trimmed, "hex");
  if (expectedBytes != null && out.length !== expectedBytes) {
    throw new Error(`${label} must be ${expectedBytes} bytes`);
  }
  return out;
}

export function verifyEd25519HexMessage(message, signatureHex, publicKeyHex) {
  const signature = normalizeHex(signatureHex, "signatureHex", 64);
  const publicKeyRaw = normalizeHex(publicKeyHex, "publicKeyHex", 32);
  const publicKeyDer = Buffer.concat([ED25519_SPKI_PREFIX, publicKeyRaw]);
  const publicKey = createPublicKey({ key: publicKeyDer, format: "der", type: "spki" });
  return verify(null, Buffer.from(message), publicKey, signature);
}

export function verifyJwtRs256Signature(params) {
  const { signingInput, signatureB64url, jwk } = params;
  const publicKey = createPublicKey({ format: "jwk", key: jwk });
  return verify("RSA-SHA256", Buffer.from(signingInput), publicKey, fromB64url(signatureB64url));
}

// ════════════════════════════════════════════════════════════════════════════════
// SSH Key Conversion
// ════════════════════════════════════════════════════════════════════════════════

export function ed25519PemToSshPublicKey(publicKeyPem, comment) {
  const keyObj = createPublicKey(publicKeyPem);
  const der = keyObj.export({ format: "der", type: "spki" });
  // SPKI DER for Ed25519: 12-byte prefix (302a300506032b6570032100) + 32-byte raw key
  const rawKey = der.slice(12);

  // SSH wire format: uint32(len("ssh-ed25519")) + "ssh-ed25519" + uint32(len(key)) + key
  const typeStr = Buffer.from("ssh-ed25519");
  const typeLenBuf = Buffer.alloc(4);
  typeLenBuf.writeUInt32BE(typeStr.length);
  const keyLenBuf = Buffer.alloc(4);
  keyLenBuf.writeUInt32BE(rawKey.length);

  const wireFormat = Buffer.concat([typeLenBuf, typeStr, keyLenBuf, rawKey]);
  const b64 = wireFormat.toString("base64");

  return `ssh-ed25519 ${b64}${comment ? ` ${comment}` : ""}`;
}

export function ed25519PemToOpenSSHPrivateKey(privateKeyPem) {
  const pk = createPrivateKey(privateKeyPem);
  const pub = createPublicKey(pk);
  const privDer = pk.export({ format: "der", type: "pkcs8" });
  const pubDer = pub.export({ format: "der", type: "spki" });
  const privRaw = privDer.subarray(privDer.length - 32);
  const pubRaw = pubDer.subarray(pubDer.length - 32);

  function strBuf(s) {
    const b = Buffer.alloc(4 + s.length);
    b.writeUInt32BE(s.length, 0);
    b.write(s, 4);
    return b;
  }
  function binBuf(d) {
    const b = Buffer.alloc(4 + d.length);
    b.writeUInt32BE(d.length, 0);
    d.copy(b, 4);
    return b;
  }

  const keytype = "ssh-ed25519";
  const checkInt = randomBytes(4);
  const pubBlob = Buffer.concat([strBuf(keytype), binBuf(pubRaw)]);
  const privSection = Buffer.concat([
    checkInt, checkInt,
    strBuf(keytype),
    binBuf(pubRaw),
    binBuf(Buffer.concat([privRaw, pubRaw])),
    strBuf(""),
  ]);
  const padLen = (8 - (privSection.length % 8)) % 8;
  const padding = Buffer.alloc(padLen);
  for (let i = 0; i < padLen; i++) padding[i] = i + 1;

  const nkeysBuf = Buffer.alloc(4);
  nkeysBuf.writeUInt32BE(1, 0);
  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0"),
    strBuf("none"), strBuf("none"), binBuf(Buffer.alloc(0)),
    nkeysBuf, binBuf(pubBlob), binBuf(Buffer.concat([privSection, padding])),
  ]);
  const lines = body.toString("base64").match(/.{1,70}/g);
  return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + lines.join("\n") + "\n-----END OPENSSH PRIVATE KEY-----\n";
}

// ════════════════════════════════════════════════════════════════════════════════
// State Management
// ════════════════════════════════════════════════════════════════════════════════

async function ensureParent(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
}

export async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true, mode: 0o700 });
}

export async function readJsonFile(filePath, fallback = null) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err && typeof err === "object" && err.code === "ENOENT") {
      return fallback;
    }
    throw err;
  }
}

export async function writeJsonFile(filePath, value, mode = 0o600) {
  await ensureParent(filePath);
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  await fs.writeFile(filePath, payload, { encoding: "utf8", mode });
}

export async function appendJsonl(filePath, value) {
  await ensureParent(filePath);
  const line = `${JSON.stringify(value)}\n`;
  await fs.appendFile(filePath, line, { encoding: "utf8" });
}

export async function readJsonl(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (err) {
    if (err && typeof err === "object" && err.code === "ENOENT") {
      return [];
    }
    throw err;
  }
}

export function statePaths(baseDir) {
  return {
    baseDir,
    ownerBinding: path.join(baseDir, "owner-binding.json"),
    ownerSession: path.join(baseDir, "owner-session.json"),
    pendingAuth: path.join(baseDir, "pending-auth.json"),
    nonces: path.join(baseDir, "nonces.json"),
    seq: path.join(baseDir, "sequence.json"),
    mainKey: path.join(baseDir, "keys", "main.json"),
    subagentKeysDir: path.join(baseDir, "keys", "subagents"),
    delegationsDir: path.join(baseDir, "delegations"),
    auditJsonl: path.join(baseDir, "audit", "operations.jsonl"),
    vaultDir: path.join(baseDir, "vault"),
  };
}

export async function setPrivateFilePermissions(filePath) {
  try {
    await fs.chmod(filePath, 0o600);
  } catch {
    // Ignore on unsupported filesystems.
  }
}

// ════════════════════════════════════════════════════════════════════════════════
// OIDC
// ════════════════════════════════════════════════════════════════════════════════

function normalizeOptionalString(value) {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function parseOwnerProof(raw) {
  if (!raw || typeof raw !== "object") {
    return null;
  }

  const sessionAddress = normalizeOptionalString(raw.session_address);
  const sessionSignature = normalizeOptionalString(raw.session_signature);
  const sessionSignatureSeed = normalizeOptionalString(raw.session_signature_seed);
  const sessionPublicKey = normalizeOptionalString(raw.session_public_key);
  const providerAddress = normalizeOptionalString(raw.provider_address);

  const anyPresent =
    sessionAddress || sessionSignature || sessionSignatureSeed || sessionPublicKey || providerAddress;
  if (!anyPresent) {
    return null;
  }

  if (!sessionAddress || !sessionSignature || !sessionSignatureSeed || !sessionPublicKey) {
    throw new Error(
      "Poll response owner_proof is missing required session_address/session_signature/session_signature_seed/session_public_key",
    );
  }

  return {
    sessionAddress,
    sessionSignature,
    sessionSignatureSeed,
    sessionPublicKey,
    providerAddress,
    signatureVerifiedAt: Number(raw.signature_verified_at || 0) || 0,
  };
}

function withNoTrailingSlash(value) {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

async function readJsonResponse(res) {
  const text = await res.text();
  try {
    const json = text ? JSON.parse(text) : {};
    return { json, text };
  } catch {
    return { json: null, text };
  }
}

async function fetchJson(url, init) {
  const res = await fetch(url, init);
  const { json, text } = await readJsonResponse(res);
  if (!res.ok) {
    const details = json && typeof json === "object" ? JSON.stringify(json) : text;
    throw new Error(`HTTP ${res.status} from ${url}: ${details || "no body"}`);
  }
  if (!json || typeof json !== "object") {
    throw new Error(`Expected JSON response from ${url}`);
  }
  return json;
}

function parseJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }
  const [headerPart, payloadPart, sigPart] = parts;
  const header = JSON.parse(fromB64url(headerPart).toString("utf8"));
  if (header.alg === "none") {
    throw new Error("Unsigned JWTs (alg: none) are not accepted");
  }
  const payload = JSON.parse(fromB64url(payloadPart).toString("utf8"));
  return {
    token,
    parts,
    header,
    payload,
    signingInput: `${headerPart}.${payloadPart}`,
    signatureB64url: sigPart,
  };
}

export function generatePkcePair() {
  const codeVerifier = b64url(randomBytes(32));
  const codeChallenge = sha256B64url(codeVerifier);
  return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}

export async function beginOidcAuthorization(params) {
  const base = withNoTrailingSlash(params.ssoBaseUrl);
  const pkce = generatePkcePair();

  const url = new URL(`${base}/oauth/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("response_mode", "json");
  url.searchParams.set("client_id", params.providerAddress);
  url.searchParams.set("scope", "openid");
  url.searchParams.set("code_challenge", pkce.codeChallenge);
  url.searchParams.set("code_challenge_method", pkce.codeChallengeMethod);

  const headers = {};
  if (typeof params.oidcOrigin === "string" && params.oidcOrigin.trim()) {
    headers.Origin = params.oidcOrigin.trim();
  }
  const out = await fetchJson(url.toString(), {
    method: "GET",
    headers,
  });
  const deepLink = out.deep_link;
  const pollingCode = out.polling_code;
  const expiredAt = out.expired_at;

  if (!deepLink || !pollingCode || !expiredAt) {
    throw new Error("Authorize response missing deep_link/polling_code/expired_at");
  }

  return {
    deepLink,
    pollingCode,
    expiredAt,
    codeVerifier: pkce.codeVerifier,
  };
}

export async function pollForAuthorizationCode(params) {
  const base = withNoTrailingSlash(params.ssoBaseUrl);
  const started = Date.now();
  const timeoutMs = params.timeoutSec * 1000;

  while (Date.now() - started < timeoutMs) {
    const out = await fetchJson(`${base}/oauth/poll`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ polling_code: params.pollingCode }),
    });

    const status = out.status;
    if (status === "authorized") {
      if (!out.authorization_code) {
        throw new Error("Poll status authorized but authorization_code is missing");
      }
      return {
        authorizationCode: out.authorization_code,
        ownerProof: parseOwnerProof(out.owner_proof),
      };
    }
    if (status === "rejected") {
      throw new Error("User rejected Alien SSO authorization");
    }
    if (status === "expired") {
      throw new Error("Alien SSO authorization session expired");
    }

    await new Promise((resolve) => setTimeout(resolve, params.pollIntervalMs));
  }

  throw new Error("Timed out waiting for Alien SSO authorization");
}

export function verifyOwnerSessionProof(params) {
  const proof = params?.proof;
  if (!proof || typeof proof !== "object") {
    return { ok: false, reason: "owner proof is missing" };
  }

  const sessionAddress = normalizeOptionalString(proof.sessionAddress);
  const sessionSignature = normalizeOptionalString(proof.sessionSignature);
  const sessionSignatureSeed = normalizeOptionalString(proof.sessionSignatureSeed);
  const sessionPublicKey = normalizeOptionalString(proof.sessionPublicKey);
  const providerAddress = normalizeOptionalString(proof.providerAddress);

  if (!sessionAddress || !sessionSignature || !sessionSignatureSeed || !sessionPublicKey) {
    return { ok: false, reason: "owner proof fields are incomplete" };
  }

  const expectedSessionAddress = normalizeOptionalString(params.expectedSessionAddress);
  if (expectedSessionAddress && sessionAddress !== expectedSessionAddress) {
    return {
      ok: false,
      reason: `owner proof session mismatch: expected ${expectedSessionAddress}, got ${sessionAddress}`,
    };
  }

  const expectedProviderAddress = normalizeOptionalString(params.expectedProviderAddress);
  if (expectedProviderAddress && providerAddress && providerAddress !== expectedProviderAddress) {
    return {
      ok: false,
      reason: `owner proof provider mismatch: expected ${expectedProviderAddress}, got ${providerAddress}`,
    };
  }

  const message = `${sessionAddress}${sessionSignatureSeed}`;
  try {
    const sigOk = verifyEd25519HexMessage(message, sessionSignature, sessionPublicKey);
    if (!sigOk) {
      return { ok: false, reason: "owner proof signature verification failed" };
    }
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }

  return {
    ok: true,
    proof: {
      sessionAddress,
      sessionSignature,
      sessionSignatureSeed,
      sessionPublicKey,
      providerAddress: providerAddress || null,
      signatureVerifiedAt: Number(proof.signatureVerifiedAt || 0) || 0,
    },
  };
}

export async function exchangeAuthorizationCode(params) {
  const base = withNoTrailingSlash(params.ssoBaseUrl);
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", params.authorizationCode);
  body.set("client_id", params.providerAddress);
  body.set("code_verifier", params.codeVerifier);

  const out = await fetchJson(`${base}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!out.id_token || !out.access_token) {
    throw new Error("Token response missing id_token/access_token");
  }

  return out;
}

export async function refreshSession(params) {
  const base = withNoTrailingSlash(params.ssoBaseUrl);
  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("refresh_token", params.refreshToken);
  body.set("client_id", params.providerAddress);

  const out = await fetchJson(`${base}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!out.access_token) {
    throw new Error("Refresh response missing access_token");
  }

  return out;
}

export async function fetchOidcDiscovery(ssoBaseUrl) {
  const base = withNoTrailingSlash(ssoBaseUrl);
  return await fetchJson(`${base}/.well-known/openid-configuration`, { method: "GET" });
}

export async function fetchJwks(jwksUri) {
  const out = await fetchJson(jwksUri, { method: "GET" });
  if (!Array.isArray(out.keys)) {
    throw new Error("JWKS response missing keys[]");
  }
  return out;
}

export async function verifyIdToken(params) {
  const parsed = parseJwt(params.idToken);
  if (parsed.header.alg !== "RS256") {
    throw new Error(`Unsupported id_token alg: ${String(parsed.header.alg)}`);
  }

  const discovery = await fetchOidcDiscovery(params.ssoBaseUrl);
  const issuer = discovery.issuer;
  const jwksUri = discovery.jwks_uri;
  if (!issuer || !jwksUri) {
    throw new Error("Discovery response missing issuer or jwks_uri");
  }

  const jwks = await fetchJwks(jwksUri);
  const kid = parsed.header.kid;
  const key = jwks.keys.find((k) => k.kid === kid && k.kty === "RSA");
  if (!key) {
    throw new Error(`Unable to find RSA JWK for kid=${String(kid)}`);
  }

  const validSig = verifyJwtRs256Signature({
    signingInput: parsed.signingInput,
    signatureB64url: parsed.signatureB64url,
    jwk: key,
  });

  if (!validSig) {
    throw new Error("id_token signature verification failed");
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const payload = parsed.payload;
  if (payload.iss !== issuer) {
    throw new Error(`id_token issuer mismatch: expected ${issuer}, got ${String(payload.iss)}`);
  }
  const aud = payload.aud;
  const audOk = Array.isArray(aud) ? aud.includes(params.providerAddress) : aud === params.providerAddress;
  if (!audOk) {
    throw new Error("id_token audience mismatch");
  }
  if (typeof payload.exp !== "number" || payload.exp <= nowSec) {
    throw new Error("id_token is expired");
  }
  if (typeof payload.sub !== "string" || !payload.sub) {
    throw new Error("id_token sub is missing");
  }

  return {
    issuer,
    payload,
    header: parsed.header,
    keyId: kid,
  };
}

/**
 * Verify only the RSA signature of an id_token against the SSO's JWKS,
 * without checking expiration, audience, or issuer. This is used for
 * post-hoc provenance verification: the token has expired but the
 * signature remains valid proof that the SSO server attested the binding.
 */
export async function verifyIdTokenSignatureOnly(params) {
  const parsed = parseJwt(params.idToken);
  if (parsed.header.alg !== "RS256") {
    throw new Error(`Unsupported id_token alg: ${String(parsed.header.alg)}`);
  }

  const discovery = await fetchOidcDiscovery(params.ssoBaseUrl);
  const jwksUri = discovery.jwks_uri;
  if (!jwksUri) {
    throw new Error("Discovery response missing jwks_uri");
  }

  const jwks = await fetchJwks(jwksUri);
  const kid = parsed.header.kid;
  const key = jwks.keys.find((k) => k.kid === kid && k.kty === "RSA");
  if (!key) {
    throw new Error(`Unable to find RSA JWK for kid=${String(kid)}`);
  }

  const validSig = verifyJwtRs256Signature({
    signingInput: parsed.signingInput,
    signatureB64url: parsed.signatureB64url,
    jwk: key,
  });

  if (!validSig) {
    throw new Error("id_token signature verification failed");
  }

  return {
    signatureValid: true,
    issuer: discovery.issuer,
    payload: parsed.payload,
    header: parsed.header,
    keyId: kid,
  };
}

// ════════════════════════════════════════════════════════════════════════════════
// Signing Engine
// ════════════════════════════════════════════════════════════════════════════════

function summarizePayload(payload, max = 220) {
  const raw = typeof payload === "string" ? payload : canonicalJSONString(payload);
  if (raw.length <= max) {
    return raw;
  }
  return `${raw.slice(0, max)}...`;
}

function safeName(input) {
  return (input || "unknown").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function agentKeyFile(baseDir, agentId) {
  if (agentId === "main") {
    return path.join(baseDir, "keys", "main.json");
  }
  return path.join(baseDir, "keys", "subagents", `${safeName(agentId)}.json`);
}

function delegationFile(baseDir, childAgentId) {
  return path.join(baseDir, "delegations", `${safeName(childAgentId)}.json`);
}

function normalizeOwnerSessionProof(input) {
  if (!input || typeof input !== "object") {
    return null;
  }
  const asString = (value) => (typeof value === "string" && value.trim() ? value.trim() : null);
  const sessionAddress = asString(input.sessionAddress);
  const sessionSignature = asString(input.sessionSignature);
  const sessionSignatureSeed = asString(input.sessionSignatureSeed);
  const sessionPublicKey = asString(input.sessionPublicKey);
  const providerAddress = asString(input.providerAddress);
  if (!sessionAddress || !sessionSignature || !sessionSignatureSeed || !sessionPublicKey) {
    return null;
  }
  return {
    sessionAddress,
    sessionSignature,
    sessionSignatureSeed,
    sessionPublicKey,
    providerAddress,
    signatureVerifiedAt: Number(input.signatureVerifiedAt || 0) || 0,
  };
}

export function resolveAgentId(ctx = {}) {
  if (ctx.agentId && typeof ctx.agentId === "string") {
    return ctx.agentId;
  }
  return "main";
}

export class SignatureEngine {
  constructor(params) {
    this.baseDir = params.baseDir;
    this.ownerProfileUrl = params.ownerProfileUrl || null;
    this.paths = statePaths(this.baseDir);
    this.keys = new Map();
    this.delegations = new Map();
    this.nonces = null;
    this.sequence = null;
    this.ownerBinding = null;
    this.writeQueue = Promise.resolve();
  }

  async init() {
    await ensureDir(this.baseDir);
    await ensureDir(path.dirname(this.paths.auditJsonl));

    this.nonces = (await readJsonFile(this.paths.nonces, { byAgent: {} })) || { byAgent: {} };
    this.sequence =
      (await readJsonFile(this.paths.seq, {
        nextSeq: 1,
        lastHash: null,
      })) || { nextSeq: 1, lastHash: null };
    this.ownerBinding = await readJsonFile(this.paths.ownerBinding, null);

    await this.ensureMainKey();
  }

  isOwnerBound() {
    return Boolean(this.ownerBinding && this.ownerBinding.binding);
  }

  getOwnerBinding() {
    return this.ownerBinding;
  }

  async ensureMainKey() {
    return await this.ensureAgentKey("main");
  }

  async ensureAgentKey(agentId) {
    const normalized = agentId || "main";
    if (this.keys.has(normalized)) {
      return this.keys.get(normalized);
    }

    const keyPath = agentKeyFile(this.baseDir, normalized);
    let key = await readJsonFile(keyPath, null);

    if (!key) {
      const pair = generateEd25519PemPair();
      key = {
        version: 1,
        agentId: normalized,
        keyNonce: 0,
        createdAt: nowMs(),
        publicKeyPem: pair.publicKeyPem,
        privateKeyPem: pair.privateKeyPem,
        fingerprint: fingerprintPublicKeyPem(pair.publicKeyPem),
      };
      await writeJsonFile(keyPath, key);
      await setPrivateFilePermissions(keyPath);
    }

    this.keys.set(normalized, key);

    if (normalized !== "main") {
      await this.ensureDelegation(normalized);
    }

    return key;
  }

  async ensureDelegation(childAgentId) {
    if (childAgentId === "main") {
      return null;
    }
    if (this.delegations.has(childAgentId)) {
      return this.delegations.get(childAgentId);
    }

    const filePath = delegationFile(this.baseDir, childAgentId);
    let cert = await readJsonFile(filePath, null);
    if (!cert) {
      const main = await this.ensureMainKey();
      const child = await this.ensureAgentKey(childAgentId);
      const payload = {
        version: 1,
        parentAgentId: "main",
        childAgentId,
        childPublicKeyPem: child.publicKeyPem,
        issuedAt: nowMs(),
      };
      const payloadCanonical = canonicalJSONString(payload);
      cert = {
        version: 1,
        payload,
        payloadHash: sha256Hex(payloadCanonical),
        signature: signEd25519Base64Url(payloadCanonical, main.privateKeyPem),
      };
      await writeJsonFile(filePath, cert);
      await setPrivateFilePermissions(filePath);
    }

    this.delegations.set(childAgentId, cert);
    return cert;
  }

  async bindOwnerSession(params) {
    const main = await this.ensureMainKey();
    const hostname = os.hostname();
    const ownerSessionProof = normalizeOwnerSessionProof(params.ownerSessionProof);
    if (ownerSessionProof?.sessionAddress && ownerSessionProof.sessionAddress !== params.ownerSessionSub) {
      throw new Error(
        `owner session proof mismatch: expected ${params.ownerSessionSub}, got ${ownerSessionProof.sessionAddress}`,
      );
    }
    if (
      ownerSessionProof?.providerAddress &&
      ownerSessionProof.providerAddress !== params.providerAddress
    ) {
      throw new Error(
        `owner session proof provider mismatch: expected ${params.providerAddress}, got ${ownerSessionProof.providerAddress}`,
      );
    }

    const bindingPayload = {
      version: 1,
      issuedAt: nowMs(),
      issuer: params.issuer,
      providerAddress: params.providerAddress,
      ownerSessionSub: params.ownerSessionSub,
      ownerAudience: params.ownerAudience,
      ownerProfileUrl: params.ownerProfileUrl || this.ownerProfileUrl,
      idTokenHash: sha256Hex(params.idToken),
      ownerSessionProof: ownerSessionProof || null,
      ownerSessionProofHash: ownerSessionProof ? sha256HexCanonical(ownerSessionProof) : null,
      agentInstance: {
        hostname,
        publicKeyFingerprint: main.fingerprint,
        publicKeyPem: main.publicKeyPem,
      },
    };

    const canonical = canonicalJSONString(bindingPayload);
    const binding = {
      id: newOperationId(),
      payload: bindingPayload,
      payloadHash: sha256HexCanonical(canonical),
      signature: signEd25519Base64Url(canonical, main.privateKeyPem),
      createdAt: nowMs(),
    };

    const ownerRecord = {
      version: 1,
      binding,
    };

    await writeJsonFile(this.paths.ownerBinding, ownerRecord);
    this.ownerBinding = ownerRecord;

    const ownerSessionRecord = {
      version: 1,
      issuer: params.issuer,
      ssoBaseUrl: params.ssoBaseUrl || params.issuer,
      providerAddress: params.providerAddress,
      ownerSessionSub: params.ownerSessionSub,
      idToken: params.idToken,
      accessToken: params.accessToken,
      refreshToken: params.refreshToken,
      ownerSessionProof: ownerSessionProof || null,
      savedAt: nowMs(),
    };
    await writeJsonFile(this.paths.ownerSession, ownerSessionRecord);
    await setPrivateFilePermissions(this.paths.ownerSession);

    return ownerRecord;
  }

  async ensureValidSession(opts = {}) {
    const session = await readJsonFile(this.paths.ownerSession, null);
    if (!session?.accessToken) return null;

    const bufferSec = opts.bufferSec ?? 60;

    // Decode the access_token JWT to check expiry (no signature verification —
    // we just need to know if it's still fresh).
    let expired = false;
    try {
      const payload = parseJwt(session.accessToken).payload;
      const nowSec = Math.floor(Date.now() / 1000);
      expired = typeof payload.exp === "number" && payload.exp - bufferSec <= nowSec;
    } catch {
      // If the access_token isn't a JWT (opaque token), treat it as expired
      // so we attempt a refresh.
      expired = true;
    }

    if (!expired) return session;

    // No refresh_token — can't renew.
    if (!session.refreshToken) return null;

    // Resolve SSO base URL: explicit field, fall back to issuer.
    const ssoBaseUrl = session.ssoBaseUrl || session.issuer;
    if (!ssoBaseUrl) return null;

    const fresh = await refreshSession({
      ssoBaseUrl,
      refreshToken: session.refreshToken,
      providerAddress: session.providerAddress,
    });

    // Verify the refreshed token still belongs to the same owner.
    if (session.ownerSessionSub) {
      try {
        const freshPayload = parseJwt(fresh.access_token).payload;
        if (freshPayload.sub && freshPayload.sub !== session.ownerSessionSub) {
          throw new Error(
            `Refreshed token subject mismatch: expected ${session.ownerSessionSub}, got ${freshPayload.sub}`,
          );
        }
      } catch (err) {
        if (err instanceof Error && err.message.includes("subject mismatch")) throw err;
        // Non-JWT or unparseable — skip subject check (opaque tokens have no sub).
      }
    }

    session.accessToken = fresh.access_token;
    if (fresh.refresh_token) session.refreshToken = fresh.refresh_token;
    if (fresh.id_token) session.idToken = fresh.id_token;
    session.refreshedAt = nowMs();

    await writeJsonFile(this.paths.ownerSession, session);
    await setPrivateFilePermissions(this.paths.ownerSession);

    return session;
  }

  async nextNonce(agentId) {
    const key = agentId || "main";
    const current = Number(this.nonces.byAgent[key] || 0);
    const next = current + 1;
    this.nonces.byAgent[key] = next;
    await writeJsonFile(this.paths.nonces, this.nonces);
    return next;
  }

  async nextSequence() {
    const seq = Number(this.sequence.nextSeq || 1);
    this.sequence.nextSeq = seq + 1;
    await writeJsonFile(this.paths.seq, this.sequence);
    return seq;
  }

  async appendOperation(params) {
    this.writeQueue = this.writeQueue.then(async () => {
      if (!this.ownerBinding?.binding?.id) {
        throw new Error("Owner binding missing. Run `auth` and `bind` first.");
      }

      const agentId = resolveAgentId(params.ctx);
      const key = await this.ensureAgentKey(agentId);
      const delegation = agentId === "main" ? null : await this.ensureDelegation(agentId);

      const nonce = await this.nextNonce(agentId);
      const seq = await this.nextSequence();
      const payloadSummary = summarizePayload(params.payload);
      const payloadHash = sha256HexCanonical(params.payload);

      const unsignedEnvelope = {
        version: 1,
        operationId: newOperationId(),
        seq,
        hook: params.hook || null,
        operationType: params.operationType,
        action: params.action,
        timestamp: nowMs(),
        agentId,
        keyNonce: Number(key.keyNonce || 0),
        nonce,
        sessionKey: params.ctx?.sessionKey || null,
        ownerBindingId: this.ownerBinding.binding.id,
        ownerSessionSub: this.ownerBinding.binding.payload.ownerSessionSub,
        agentPublicKeyPem: key.publicKeyPem,
        parentAgentId: delegation ? delegation.payload.parentAgentId : null,
        delegationPayloadHash: delegation ? delegation.payloadHash : null,
        delegationSignature: delegation ? delegation.signature : null,
        payloadHash,
        payloadSummary,
        meta: params.meta || null,
      };

      const canonicalUnsigned = canonicalJSONString(unsignedEnvelope);
      const envelope = {
        ...unsignedEnvelope,
        signature: signEd25519Base64Url(canonicalUnsigned, key.privateKeyPem),
      };

      const envelopeHash = sha256HexCanonical(canonicalJSONString(envelope));
      const auditEntry = {
        version: 1,
        prevHash: this.sequence.lastHash || null,
        envelopeHash,
        envelope,
        persistedAt: nowMs(),
      };

      this.sequence.lastHash = envelopeHash;
      await writeJsonFile(this.paths.seq, this.sequence);
      await appendJsonl(this.paths.auditJsonl, auditEntry);

      return {
        auditEntry,
        signatureShort: envelope.signature.slice(0, 18),
        envelopeHashShort: envelopeHash.slice(0, 16),
        agentId,
        nonce,
        seq,
      };
    });

    return await this.writeQueue;
  }
}

// ════════════════════════════════════════════════════════════════════════════════
// Verification
// ════════════════════════════════════════════════════════════════════════════════

async function readAllKeyRecords(paths) {
  const map = new Map();

  const main = await readJsonFile(paths.mainKey, null);
  if (main?.agentId && main?.publicKeyPem) {
    map.set(main.agentId, main);
  }

  try {
    const files = await fs.readdir(paths.subagentKeysDir);
    for (const file of files) {
      if (!file.endsWith(".json")) {
        continue;
      }
      const rec = await readJsonFile(path.join(paths.subagentKeysDir, file), null);
      if (rec?.agentId && rec?.publicKeyPem) {
        map.set(rec.agentId, rec);
      }
    }
  } catch {
    // No subagent dir yet.
  }

  return map;
}

async function readAllDelegations(paths) {
  const map = new Map();
  try {
    const files = await fs.readdir(paths.delegationsDir);
    for (const file of files) {
      if (!file.endsWith(".json")) {
        continue;
      }
      const rec = await readJsonFile(path.join(paths.delegationsDir, file), null);
      if (rec?.payload?.childAgentId) {
        map.set(rec.payload.childAgentId, rec);
      }
    }
  } catch {
    // No delegations yet.
  }
  return map;
}

function verifyOwnerBindingRecord(ownerBinding, keyByAgent, errors) {
  if (!ownerBinding?.binding) {
    errors.push("owner-binding.json is missing");
    return;
  }
  const binding = ownerBinding.binding;
  const main = keyByAgent.get("main");
  if (!main?.publicKeyPem) {
    errors.push("main key missing while verifying owner binding");
    return;
  }

  const payloadCanonical = canonicalJSONString(binding.payload);
  const payloadHash = sha256HexCanonical(payloadCanonical);
  if (payloadHash !== binding.payloadHash) {
    errors.push("owner binding payload hash mismatch");
  }

  const ok = verifyEd25519Base64Url(payloadCanonical, binding.signature, main.publicKeyPem);
  if (!ok) {
    errors.push("owner binding signature invalid");
  }

  verifyOwnerSessionProofInBinding(binding.payload, errors);
}

function verifyOwnerSessionProofInBinding(payload, errors) {
  const proof = payload?.ownerSessionProof;
  if (!proof || typeof proof !== "object") {
    // ownerSessionProof is optional — some Alien App versions don't return it.
    // The binding is still valid via the id_token server signature.
    return;
  }

  const required = [
    "sessionAddress",
    "sessionSignature",
    "sessionSignatureSeed",
    "sessionPublicKey",
  ];
  for (const field of required) {
    if (typeof proof[field] !== "string" || !proof[field]) {
      errors.push(`owner session proof missing ${field}`);
      return;
    }
  }

  const message = `${proof.sessionAddress}${proof.sessionSignatureSeed}`;
  let sigOk = false;
  try {
    sigOk = verifyEd25519HexMessage(message, proof.sessionSignature, proof.sessionPublicKey);
  } catch (err) {
    errors.push(`owner session proof parse error: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  if (!sigOk) {
    errors.push("owner session proof signature invalid");
  }

  if (payload.ownerSessionSub && payload.ownerSessionSub !== proof.sessionAddress) {
    errors.push(
      `owner session proof subject mismatch: binding=${payload.ownerSessionSub} proof=${proof.sessionAddress}`,
    );
  }

  if (payload.providerAddress && proof.providerAddress && payload.providerAddress !== proof.providerAddress) {
    errors.push(
      `owner session proof provider mismatch: binding=${payload.providerAddress} proof=${proof.providerAddress}`,
    );
  }

  if (payload.ownerSessionProofHash) {
    const proofHash = sha256HexCanonical(canonicalJSONString(proof));
    if (proofHash !== payload.ownerSessionProofHash) {
      errors.push("owner session proof hash mismatch");
    }
  }
}

function verifyDelegation(childAgentId, delegation, keyByAgent, errors) {
  if (!delegation) {
    errors.push(`missing delegation certificate for subagent ${childAgentId}`);
    return;
  }

  const main = keyByAgent.get("main");
  if (!main?.publicKeyPem) {
    errors.push("main key missing while verifying delegation");
    return;
  }

  const payloadCanonical = canonicalJSONString(delegation.payload);
  const payloadHash = sha256HexCanonical(payloadCanonical);
  if (payloadHash !== delegation.payloadHash) {
    errors.push(`delegation payload hash mismatch for ${childAgentId}`);
  }

  const sigOk = verifyEd25519Base64Url(payloadCanonical, delegation.signature, main.publicKeyPem);
  if (!sigOk) {
    errors.push(`delegation signature invalid for ${childAgentId}`);
  }
}

function verifyAuditRecord(record, prevHash, keyByAgent, delegationsByChild, ownerBindingId, errors) {
  if ((record.prevHash || null) !== (prevHash || null)) {
    errors.push(`prevHash mismatch at seq=${record?.envelope?.seq ?? "?"}`);
  }

  if (!record?.envelope) {
    errors.push("audit record missing envelope");
    return prevHash;
  }

  const envelopeCanonical = canonicalJSONString(record.envelope);
  const expectedEnvelopeHash = sha256HexCanonical(envelopeCanonical);
  if (expectedEnvelopeHash !== record.envelopeHash) {
    errors.push(`envelopeHash mismatch at seq=${record.envelope.seq}`);
  }

  const { signature, ...unsignedEnvelope } = record.envelope;
  const unsignedCanonical = canonicalJSONString(unsignedEnvelope);

  const keyRecord = keyByAgent.get(record.envelope.agentId);
  if (!keyRecord?.publicKeyPem) {
    errors.push(`unknown agent key for ${record.envelope.agentId}`);
  } else {
    const ok = verifyEd25519Base64Url(unsignedCanonical, signature, keyRecord.publicKeyPem);
    if (!ok) {
      errors.push(`operation signature invalid at seq=${record.envelope.seq}`);
    }
  }

  if (record.envelope.ownerBindingId !== ownerBindingId) {
    errors.push(`ownerBindingId mismatch at seq=${record.envelope.seq}`);
  }

  if (record.envelope.agentId !== "main") {
    const child = record.envelope.agentId;
    const cert = delegationsByChild.get(child);
    verifyDelegation(child, cert, keyByAgent, errors);

    if (cert && record.envelope.delegationPayloadHash !== cert.payloadHash) {
      errors.push(`delegationPayloadHash mismatch at seq=${record.envelope.seq}`);
    }
    if (cert && record.envelope.delegationSignature !== cert.signature) {
      errors.push(`delegationSignature mismatch at seq=${record.envelope.seq}`);
    }
  }

  return expectedEnvelopeHash;
}

export async function verifyState(baseDir) {
  const paths = statePaths(baseDir);
  const errors = [];

  const ownerBinding = await readJsonFile(paths.ownerBinding, null);
  const keyByAgent = await readAllKeyRecords(paths);
  const delegationsByChild = await readAllDelegations(paths);
  const auditRecords = await readJsonl(paths.auditJsonl);

  verifyOwnerBindingRecord(ownerBinding, keyByAgent, errors);

  let prevHash = null;
  for (const record of auditRecords) {
    prevHash = verifyAuditRecord(
      record,
      prevHash,
      keyByAgent,
      delegationsByChild,
      ownerBinding?.binding?.id,
      errors,
    );
  }

  return {
    ok: errors.length === 0,
    errorCount: errors.length,
    errors,
    ownerSessionSub: ownerBinding?.binding?.payload?.ownerSessionSub || null,
    ownerProfileUrl: ownerBinding?.binding?.payload?.ownerProfileUrl || null,
    operations: auditRecords.length,
    agents: Array.from(keyByAgent.keys()).sort(),
    subagentDelegations: Array.from(delegationsByChild.keys()).sort(),
  };
}

// ════════════════════════════════════════════════════════════════════════════════
// Vault — Encrypted credential storage linked to agent identity
// ════════════════════════════════════════════════════════════════════════════════

export function deriveVaultKey(privateKeyPem) {
  const privKey = createPrivateKey(privateKeyPem);
  const rawKey = privKey.export({ type: "pkcs8", format: "der" });
  return Buffer.from(
    hkdfSync("sha256", rawKey, "agent-id-vault-v1", "vault-encryption", 32),
  );
}

export function vaultEncrypt(key, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    data: encrypted.toString("hex"),
    tag: tag.toString("hex"),
  };
}

export function vaultDecrypt(key, entry) {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(entry.iv, "hex"),
  );
  decipher.setAuthTag(Buffer.from(entry.tag, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(entry.data, "hex")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

// ════════════════════════════════════════════════════════════════════════════════
// Agent Auth Token — Self-contained signed assertions for service authentication
// ════════════════════════════════════════════════════════════════════════════════

export function createAgentToken(params) {
  const payload = {
    v: 1,
    fingerprint: params.fingerprint,
    publicKeyPem: params.publicKeyPem,
    owner: params.ownerSessionSub || null,
    aud: params.aud || null,
    timestamp: nowMs(),
    nonce: randomBytes(16).toString("hex"),
  };
  const canonical = canonicalJSONString(payload);
  const signature = signEd25519Base64Url(canonical, params.privateKeyPem);
  const token = { ...payload, sig: signature };
  if (params.ownerBinding) {
    token.ownerBinding = params.ownerBinding;
  }
  if (params.idToken) {
    token.idToken = params.idToken;
  }
  return b64url(JSON.stringify(token));
}
