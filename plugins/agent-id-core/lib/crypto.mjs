// Alien Agent ID — Pure crypto primitives.
// Zero npm dependencies. Requires Node.js 18+ (built-in crypto).
//
// No I/O, no global state, no session/identity awareness. Every function
// here is callable by any plugin (including agent-id-verify auditors with
// no bound identity).

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
  verify,
  randomBytes,
} from "node:crypto";

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

// RFC 9110 §5.6.2 token = 1*tchar; tchar = "!" / "#" / "$" / "%" / "&" / "'"
// / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA.
const HTTP_TOKEN_REGEX = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// RFC 4648 §5 / RFC 7515 §2: base64url has the alphabet [A-Za-z0-9_-]; JOSE
// strips trailing '=' padding. Reject any character outside the canonical
// alphabet (in particular whitespace, '+', '/', '=') so RFC 7519 §7.2 holds.
const BASE64URL_REGEX = /^[A-Za-z0-9_-]*$/;

export function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function fromB64url(value) {
  if (typeof value !== "string") {
    throw new Error("fromB64url: input must be a string");
  }
  // RFC 7515 §2 / RFC 7519 §7.2: the JOSE encoding is strict base64url with
  // no padding. Whitespace, '+'/'/' (standard base64), and '=' (padding) are
  // not part of the canonical alphabet and must cause the JWS to be
  // considered invalid — Node's Buffer.from(*, "base64") would silently
  // tolerate them.
  if (!BASE64URL_REGEX.test(value)) {
    throw new Error("fromB64url: input contains characters outside RFC 4648 §5 base64url alphabet");
  }
  const pad = value.length % 4;
  // RFC 4648 §5: a 4-char group decodes to 3 bytes; a residue of length 1
  // is never produced by canonical encoding and indicates corruption.
  if (pad === 1) {
    throw new Error("fromB64url: invalid base64url length");
  }
  const padded = pad === 0 ? value : value + "=".repeat(4 - pad);
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

// ─── JWK helpers (RFC 8037, RFC 7638) ───────────────────────────────────────────
//
// Pure functions: no I/O, no global state, no time calls. Used by the DPoP
// signer (RFC 9449) and by the agent CLI to derive `dpop_jkt` for the
// authorize-URL hint and the `cnf.jkt` claim that the SSO emits in id_tokens.

/**
 * Convert an Ed25519 public key (PEM-encoded SPKI) to its canonical
 * RFC 8037 JWK representation: {kty:"OKP", crv:"Ed25519", x:<base64url(raw)>}.
 *
 * Throws if the PEM is not an Ed25519 public key.
 */
export function ed25519PublicKeyToJwk(publicKeyPem) {
  const keyObject = createPublicKey(publicKeyPem);
  const der = keyObject.export({ format: "der", type: "spki" });
  if (der.length !== 44) {
    throw new Error(
      `ed25519PublicKeyToJwk: expected 44-byte Ed25519 SPKI, got ${der.length} bytes (likely non-Ed25519 key type)`,
    );
  }
  if (!der.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) {
    throw new Error(
      "ed25519PublicKeyToJwk: SPKI AlgorithmIdentifier does not match Ed25519 (OID 1.3.101.112)",
    );
  }
  const rawKey = der.subarray(12);
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: b64url(rawKey),
  };
}

/**
 * RFC 7638 JWK Thumbprint. For an OKP/Ed25519 key the canonical JSON is
 * exactly: `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` — members in lexical
 * order, no whitespace, no extra fields. SHA-256 the bytes, then base64url
 * (no padding).
 *
 * Pure: no I/O, no time calls. Extra members on the input JWK are ignored.
 */
export function jwkThumbprint(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new Error("jwkThumbprint: jwk must be an object");
  }
  if (jwk.kty !== "OKP") {
    throw new Error(`jwkThumbprint: unsupported kty=${String(jwk.kty)} (only OKP/Ed25519 supported)`);
  }
  if (jwk.crv !== "Ed25519") {
    throw new Error(`jwkThumbprint: unsupported crv=${String(jwk.crv)} (only Ed25519 supported)`);
  }
  if (typeof jwk.x !== "string" || jwk.x.length === 0) {
    throw new Error("jwkThumbprint: jwk.x is required");
  }
  // RFC 7638 §3.2 canonical members for OKP keys, lexically sorted.
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`;
  return b64url(createHash("sha256").update(canonical).digest());
}

// ─── DPoP proof signer (RFC 9449) ───────────────────────────────────────────────

/**
 * Build a compact JWS DPoP proof per RFC 9449 §4.
 *
 *   header  = {"typ":"dpop+jwt","alg":"EdDSA","jwk":<full Ed25519 OKP JWK>}
 *   payload = {"jti":<unique>,"htm":<method>,"htu":<target-no-query>,"iat":<unix-sec>}
 *   signature = Ed25519 over `b64url(header) + "." + b64url(payload)`
 *
 * Pure: `iat` and `jti` may be injected for determinism (tests, replay-safe
 * batched issuance). When omitted, defaults are derived from `Date.now()` and
 * `randomUUID()` respectively.
 */
export function createDPoPProof(params) {
  if (!params || typeof params !== "object") {
    throw new Error("createDPoPProof: params required");
  }
  const { privateKeyPem, htm, htu } = params;
  if (typeof privateKeyPem !== "string" || !privateKeyPem) {
    throw new Error("createDPoPProof: privateKeyPem is required");
  }
  if (typeof htm !== "string" || !htm) {
    throw new Error("createDPoPProof: htm is required");
  }
  // RFC 9110 §5.6.2 / §9.1: an HTTP method is a `token` (1*tchar). RFC 9449
  // §4.2 carries the literal method text in `htm`, and §4.3 verifies it
  // against the request method by exact (case-sensitive) string compare —
  // standard methods are uppercase, but registered extension methods (e.g.
  // WebDAV `PROPFIND`) and arbitrary tokens are case-sensitive. Validate
  // shape and preserve case so the proof matches the wire request.
  if (!HTTP_TOKEN_REGEX.test(htm)) {
    throw new Error(`createDPoPProof: htm must be an RFC 9110 token, got ${JSON.stringify(htm)}`);
  }
  if (typeof htu !== "string" || !htu) {
    throw new Error("createDPoPProof: htu is required");
  }

  // Strip query and fragment per RFC 9449 §4.2 ("htu" claim).
  const cleanHtu = stripUrlQueryAndFragment(htu);

  // Derive the public JWK from the private key for the embedded `jwk` header.
  const publicKey = createPublicKey(createPrivateKey(privateKeyPem));
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const jwk = ed25519PublicKeyToJwk(publicKeyPem);

  const header = { typ: "dpop+jwt", alg: "EdDSA", jwk };
  const payload = {
    jti: typeof params.jti === "string" && params.jti ? params.jti : randomUUID(),
    // RFC 9449 §4.2 / §4.3: htm is the literal method, compared bytewise
    // against the request method. Preserve the caller's case so extension
    // method tokens round-trip exactly as sent on the wire.
    htm,
    htu: cleanHtu,
    iat: typeof params.iat === "number" ? params.iat : Math.floor(Date.now() / 1000),
  };
  // RFC 9449 §4.2: at protected resources, bind the proof to the AT.
  if (typeof params.accessToken === "string" && params.accessToken) {
    payload.ath = b64url(createHash("sha256").update(params.accessToken).digest());
  }
  // RFC 9449 §8/§9: when a server challenges via use_dpop_nonce, the client
  // retries with the supplied nonce echoed in the proof payload.
  if (typeof params.nonce === "string" && params.nonce) {
    payload.nonce = params.nonce;
  }

  const headerB64 = b64url(JSON.stringify(header));
  const payloadB64 = b64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = sign(null, Buffer.from(signingInput), createPrivateKey(privateKeyPem));
  return `${signingInput}.${b64url(signature)}`;
}

function stripUrlQueryAndFragment(url) {
  // Tolerant: try URL parsing first; fall back to manual strip.
  try {
    const u = new URL(url);
    u.search = "";
    u.hash = "";
    // Trim trailing slash only if it was not present in input — keep "/path"
    // and "/path/" distinguishable. URL toString preserves the trailing slash
    // already present in the path, so just return as-is.
    return u.toString();
  } catch {
    const noFrag = url.split("#", 1)[0];
    const noQuery = noFrag.split("?", 1)[0];
    return noQuery;
  }
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

// RFC 7518 §3.3 / RFC 8725 §3.5: RS256 keys MUST be ≥ 2048 bits. The JWK
// `n` parameter is the unsigned modulus encoded base64url with no leading
// zero byte (RFC 7518 §6.3.1), so 256 bytes corresponds to exactly 2048
// bits.
const MIN_RSA_MODULUS_BYTES = 256;

export function verifyJwtRs256Signature(params) {
  const { signingInput, signatureB64url, jwk } = params;
  if (typeof jwk?.n !== "string" || fromB64url(jwk.n).length < MIN_RSA_MODULUS_BYTES) {
    throw new Error("RS256 JWK modulus is shorter than RFC 7518 §3.3 minimum (2048 bits)");
  }
  const publicKey = createPublicKey({ format: "jwk", key: jwk });
  return verify("RSA-SHA256", Buffer.from(signingInput), publicKey, fromB64url(signatureB64url));
}

// RFC 8037 §2 + RFC 7515 §10.7: verify an EdDSA (Ed25519) JWS signature
// against an OKP JWK. Mirrors verifyJwtRs256Signature so the verifier can
// dispatch by `alg` against a JWKS that publishes both keys.
export function verifyJwtEdDsaSignature(params) {
  const { signingInput, signatureB64url, jwk } = params;
  const publicKey = createPublicKey({ format: "jwk", key: jwk });
  return verify(null, Buffer.from(signingInput), publicKey, fromB64url(signatureB64url));
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
