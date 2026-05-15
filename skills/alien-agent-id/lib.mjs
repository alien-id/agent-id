// Alien Agent ID — Portable library for agent identity management.
// Zero npm dependencies. Requires Node.js 18+ (built-in crypto, fetch, fs).
//
// Consolidated from openclaw-alienid-signature-demo/src/{canonical,crypto,state,oidc,signer,verify}.js

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

// Re-export crypto primitives from agent-id-core. During the split refactor
// the canonical home is plugins/agent-id-core/lib/crypto.mjs; this re-export
// keeps existing imports from skills/alien-agent-id/lib.mjs working.
export * from "../../plugins/agent-id-core/lib/crypto.mjs";

// Re-export the v3 bundle module from agent-id-core. Bundles are the
// universal provenance unit — git commits today, signed tool calls
// tomorrow — so the constructor + parser + universal verifier live in
// core, not in the git plugin.
export * from "../../plugins/agent-id-core/lib/bundle.mjs";

import {
  b64url,
  canonicalJSONString,
  createDPoPProof,
  ed25519PublicKeyToJwk,
  fingerprintPublicKeyPem,
  fromB64url,
  generateEd25519PemPair,
  jwkThumbprint,
  newOperationId,
  nowMs,
  sha256B64url,
  sha256Hex,
  sha256HexCanonical,
  signEd25519Base64Url,
  verifyEd25519Base64Url,
  verifyJwtEdDsaSignature,
  verifyJwtRs256Signature,
} from "../../plugins/agent-id-core/lib/crypto.mjs";


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

// All current callers pass an SSO base URL — chokepoint for the RFC 6749 §10
// TLS guard so every flow (authorize, token, refresh, userinfo, discovery,
// id_token verification) inherits it.
function withNoTrailingSlash(value) {
  assertSsoBaseUrlSafe(value);
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

// RFC 6749 §10: bearer credentials and refresh tokens MUST be transmitted
// over TLS. Allow plain http:// only for loopback hosts (development).
function assertSsoBaseUrlSafe(ssoBaseUrl) {
  if (typeof ssoBaseUrl !== "string" || !ssoBaseUrl) {
    throw new Error("ssoBaseUrl is required");
  }
  let url;
  try {
    url = new URL(ssoBaseUrl);
  } catch {
    throw new Error(`ssoBaseUrl is not a valid URL: ${ssoBaseUrl}`);
  }
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")) {
    return;
  }
  throw new Error(`ssoBaseUrl must use https:// (got ${url.protocol}//${url.host})`);
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

export function parseJwt(token) {
  if (typeof token !== "string" || !token) {
    throw new Error("Invalid JWT format");
  }
  // RFC 7519 §7.2 step 1: the JWS Compact Serialization is exactly three
  // base64url segments separated by '.'. fromB64url enforces the strict
  // alphabet on each segment, which catches embedded whitespace, padding,
  // and standard-base64 alphabet leakage. The split-length check + each
  // segment non-empty is the structural complement.
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new Error("Invalid JWT format");
  }
  const [headerPart, payloadPart, sigPart] = parts;
  const header = JSON.parse(fromB64url(headerPart).toString("utf8"));
  if (header.alg === "none") {
    throw new Error("Unsigned JWTs (alg: none) are not accepted");
  }
  const payload = JSON.parse(fromB64url(payloadPart).toString("utf8"));
  // Pre-decode the signature segment to surface RFC 7515 §2 violations at
  // parse time rather than at signature-verify time.
  fromB64url(sigPart);
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
  // RFC 9207 §2.4 requires comparing any AS-supplied `iss` on the
  // authorization response against the AS's discovered issuer to defeat
  // mix-up attacks. Discover once here and propagate to the poll step.
  const discovery = await fetchOidcDiscovery(base);
  const expectedIssuer = discovery.issuer;
  if (typeof expectedIssuer !== "string" || !expectedIssuer) {
    throw new Error("Discovery response missing issuer");
  }
  const pkce = generatePkcePair();

  // RFC 6749 §4.1.1 / §10.12: `state` is an opaque value that lets the
  // client correlate the authorization response with the request and
  // mitigate cross-site request forgery. OIDC Core §3.1.3.7: `nonce` is
  // bound into the id_token and verified on receipt to mitigate replay.
  // 256 bits of CSPRNG entropy is the standard choice for both.
  const state = b64url(randomBytes(32));
  const nonce = b64url(randomBytes(32));

  const url = new URL(`${base}/oauth/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("response_mode", "json");
  url.searchParams.set("client_id", params.providerAddress);
  url.searchParams.set("scope", "openid");
  url.searchParams.set("code_challenge", pkce.codeChallenge);
  url.searchParams.set("code_challenge_method", pkce.codeChallengeMethod);
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);

  // RFC 9449 §10: dpop_jkt advertises the public key the client will use to
  // bind tokens via DPoP. Equal to the RFC 7638 thumbprint of the agent JWK.
  if (typeof params.agentPublicKeyPem === "string" && params.agentPublicKeyPem) {
    const jwk = ed25519PublicKeyToJwk(params.agentPublicKeyPem);
    url.searchParams.set("dpop_jkt", jwkThumbprint(jwk));
  }

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

  // RFC 6749 §10.12: when the AS echoes `state` (e.g., on the authorize
  // response itself), require it to round-trip. Servers that don't yet
  // surface the value here are tolerated (state is also re-checked on the
  // poll response).
  if (typeof out.state === "string" && out.state !== state) {
    throw new Error("Authorize response state mismatch (RFC 6749 §10.12)");
  }
  // RFC 9207 §2.4: when the AS surfaces `iss` here, it MUST equal the
  // discovered issuer. Tolerated when absent (legacy AS surfaces the
  // value only on the poll response).
  if (typeof out.iss === "string" && out.iss !== expectedIssuer) {
    throw new Error(
      `Authorize response issuer mismatch (RFC 9207 §2.4): expected ${expectedIssuer}, got ${out.iss}`,
    );
  }

  return {
    deepLink,
    pollingCode,
    expiredAt,
    codeVerifier: pkce.codeVerifier,
    state,
    nonce,
    issuer: expectedIssuer,
  };
}

export async function pollForAuthorizationCode(params) {
  const base = withNoTrailingSlash(params.ssoBaseUrl);
  const started = Date.now();
  const timeoutMs = params.timeoutSec * 1000;
  const expectedState = typeof params.expectedState === "string" && params.expectedState
    ? params.expectedState
    : null;
  const expectedIssuer = typeof params.expectedIssuer === "string" && params.expectedIssuer
    ? params.expectedIssuer
    : null;

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
      // RFC 6749 §10.12: when the AS echoes `state` on the authorization
      // response, the client MUST verify it equals the value sent. If the
      // server does not echo `state` (legacy), skip — the polling design
      // already binds the response to the polling_code we created.
      if (expectedState && typeof out.state === "string" && out.state !== expectedState) {
        throw new Error("Authorization response state mismatch (RFC 6749 §10.12)");
      }
      // RFC 9207 §2.4: when the AS surfaces `iss` on the authorization
      // response, it MUST equal the AS's discovered issuer. Tolerated when
      // absent for legacy AS that have not yet adopted RFC 9207.
      if (expectedIssuer && typeof out.iss === "string" && out.iss !== expectedIssuer) {
        throw new Error(
          `Authorization response issuer mismatch (RFC 9207 §2.4): expected ${expectedIssuer}, got ${out.iss}`,
        );
      }
      return {
        authorizationCode: out.authorization_code,
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

export async function exchangeAuthorizationCode(params) {
  const base = withNoTrailingSlash(params.ssoBaseUrl);
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", params.authorizationCode);
  body.set("client_id", params.providerAddress);
  body.set("code_verifier", params.codeVerifier);

  const tokenUrl = `${base}/oauth/token`;
  const out = await tokenEndpointPost(
    tokenUrl,
    body,
    params.agentPrivateKeyPem,
  );

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

  const tokenUrl = `${base}/oauth/token`;
  const out = await tokenEndpointPost(
    tokenUrl,
    body,
    params.agentPrivateKeyPem,
  );

  if (!out.access_token) {
    throw new Error("Refresh response missing access_token");
  }

  return out;
}

// tokenEndpointPost POSTs a form-encoded body to /oauth/token, optionally
// attaching a DPoP proof when an Ed25519 key is provided. On a server-issued
// nonce challenge (RFC 9449 §8) the request is retried once with the
// supplied nonce echoed in a freshly built proof.
async function tokenEndpointPost(tokenUrl, body, agentPrivateKeyPem) {
  const baseHeaders = { "Content-Type": "application/x-www-form-urlencoded" };
  const useDPoP = typeof agentPrivateKeyPem === "string" && agentPrivateKeyPem;

  const buildHeaders = (nonce) => {
    if (!useDPoP) return baseHeaders;
    return {
      ...baseHeaders,
      DPoP: createDPoPProof({
        privateKeyPem: agentPrivateKeyPem,
        htm: "POST",
        htu: tokenUrl,
        ...(nonce ? { nonce } : {}),
      }),
    };
  };

  const res = await fetchWithDPoPNonce(
    tokenUrl,
    { method: "POST", body },
    buildHeaders,
  );
  const { json, text } = await readJsonResponse(res);
  if (!res.ok) {
    const details = json && typeof json === "object" ? JSON.stringify(json) : text;
    const errorCode = json && typeof json === "object" && typeof json.error === "string"
      ? json.error
      : null;
    // RFC 6749 §5.2: invalid_grant signals revoked/expired/already-used
    // credentials. 401/403 are the bearer-level rejection codes. Surface
    // these distinctly so callers can prompt re-auth without substring
    // matching on error.message.
    if (res.status === 401 || res.status === 403 || errorCode === "invalid_grant") {
      throw new AuthRevokedError(
        `HTTP ${res.status} from ${tokenUrl}: ${details || "no body"}`,
        { status: res.status, errorCode },
      );
    }
    throw new Error(`HTTP ${res.status} from ${tokenUrl}: ${details || "no body"}`);
  }
  if (!json || typeof json !== "object") {
    throw new Error(`Expected JSON response from ${tokenUrl}`);
  }
  // RFC 9449 §5: when the client presents a DPoP proof, it MUST discard the
  // response unless `token_type` is "DPoP" (case-insensitive per RFC 6749
  // §5.1). Catches a downgrade or misbehaving AS that returns Bearer for a
  // DPoP-bound request.
  if (useDPoP) {
    const tokenType = typeof json.token_type === "string" ? json.token_type : "";
    if (tokenType.toLowerCase() !== "dpop") {
      throw new Error(
        `RFC 9449 §5: expected token_type="DPoP", got ${JSON.stringify(json.token_type)}`,
      );
    }
  }
  return json;
}

/**
 * Fetch the OIDC `/oauth/userinfo` claims for a DPoP-bound access token.
 *
 * RFC 9449 §7.1: requests carrying a DPoP-bound AT MUST use
 * `Authorization: DPoP <token>` and a fresh DPoP proof whose `ath` claim
 * equals base64url(SHA-256(accessToken)). On 400 + use_dpop_nonce challenge
 * (RFC 9449 §8/§9), the request is retried once with the supplied nonce
 * echoed in the proof.
 */
export async function getUserInfo(params) {
  if (!params || typeof params !== "object") {
    throw new Error("getUserInfo: params required");
  }
  const { ssoBaseUrl, accessToken, agentPrivateKeyPem } = params;
  if (typeof ssoBaseUrl !== "string" || !ssoBaseUrl) {
    throw new Error("getUserInfo: ssoBaseUrl is required");
  }
  if (typeof accessToken !== "string" || !accessToken) {
    throw new Error("getUserInfo: accessToken is required");
  }
  if (typeof agentPrivateKeyPem !== "string" || !agentPrivateKeyPem) {
    throw new Error("getUserInfo: agentPrivateKeyPem is required");
  }

  const userinfoUrl = `${withNoTrailingSlash(ssoBaseUrl)}/oauth/userinfo`;

  const buildHeaders = (nonce) => ({
    Authorization: `DPoP ${accessToken}`,
    DPoP: createDPoPProof({
      privateKeyPem: agentPrivateKeyPem,
      htm: "GET",
      htu: userinfoUrl,
      accessToken,
      ...(nonce ? { nonce } : {}),
    }),
  });

  const res = await fetchWithDPoPNonce(userinfoUrl, { method: "GET" }, buildHeaders);
  const { json, text } = await readJsonResponse(res);
  if (!res.ok) {
    const details = json && typeof json === "object" ? JSON.stringify(json) : text;
    throw new Error(`HTTP ${res.status} from userinfo: ${details || "no body"}`);
  }
  if (!json || typeof json !== "object") {
    throw new Error("getUserInfo: expected JSON response");
  }
  return json;
}

// dpopNonceCache stores the most-recent server-issued DPoP-Nonce per URL,
// per RFC 9449 §8.2-1: "the client MUST use the new nonce value for the
// next request and all subsequent requests until the server supplies a new
// nonce." Process-local in-memory; agent-id is a short-lived CLI so this
// is a per-invocation cache that batches multi-call flows (e.g., token
// then userinfo then refresh) without paying a 400/retry on each step.
const dpopNonceCache = new Map();

// fetchWithDPoPNonce executes a request, pre-attaching any cached nonce
// for `url`. Two challenge shapes are recognized per RFC 9449:
//
//   §8 (authorization server, e.g. /oauth/token):
//     400 + JSON body `{"error":"use_dpop_nonce"}` + `DPoP-Nonce` header.
//
//   §9 (resource server, e.g. /oauth/userinfo):
//     401 + `WWW-Authenticate: DPoP error="use_dpop_nonce"` + `DPoP-Nonce`.
//
// In either case the helper retries ONCE with the supplied nonce echoed in
// a freshly built proof and updates the cache. Subsequent responses
// bearing a DPoP-Nonce header (success or failure) refresh the cache so
// the server's rotation policy stays sticky.
async function fetchWithDPoPNonce(url, init, buildHeaders) {
  const cached = dpopNonceCache.get(url);
  let res = await fetch(url, { ...init, headers: buildHeaders(cached) });
  rememberNonce(url, res.headers.get("dpop-nonce"));

  if (res.status !== 400 && res.status !== 401) {
    return res;
  }
  const issuedNonce = res.headers.get("dpop-nonce");
  if (!issuedNonce) {
    return res;
  }

  // Detect the challenge in the right place per status code: §8 puts it in
  // the JSON body, §9 puts it in WWW-Authenticate.
  let challenged = false;
  if (res.status === 400) {
    try {
      const body = await res.clone().json();
      challenged = body && body.error === "use_dpop_nonce";
    } catch {
      challenged = false;
    }
  } else {
    const wwwAuth = res.headers.get("www-authenticate") || "";
    // RFC 6749 §3 / RFC 7235 §2.2: WWW-Authenticate parameter values are
    // either token or quoted-string. Match the `error` parameter
    // structurally so that the literal string "use_dpop_nonce" appearing
    // inside some other parameter's value (e.g. realm) does not
    // false-positive into a spurious retry.
    const m = wwwAuth.match(/\berror\s*=\s*(?:"([^"]*)"|([^,\s]+))/i);
    if (m) {
      const value = m[1] !== undefined ? m[1] : m[2];
      challenged = value.toLowerCase() === "use_dpop_nonce";
    }
  }

  if (challenged) {
    res = await fetch(url, { ...init, headers: buildHeaders(issuedNonce) });
    rememberNonce(url, res.headers.get("dpop-nonce"));
  }
  return res;
}

function rememberNonce(url, nonce) {
  if (typeof nonce === "string" && nonce) {
    dpopNonceCache.set(url, nonce);
  }
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

// RFC 7515 §10.7: applications anchor on a curated alg allowlist. SSO
// publishes RS256 today and may rotate to EdDSA (RFC 8037); accept either.
const ID_TOKEN_ALG_KTY = { RS256: "RSA", EdDSA: "OKP" };

// RFC 8725 §3.11 / OIDC Core §2: id_tokens are typed JWTs. Cross-JWT confusion
// (an `at+jwt` access token or `dpop+jwt` proof reused as an id_token) is
// blocked here. Missing/non-string `typ` is tolerated for legacy tokens that
// preceded the §3.11 guidance. RFC 6838 §4.2 — media types compare
// case-insensitively, so the comparison lowercases first.
function assertIdTokenTyp(rawTyp) {
  if (typeof rawTyp !== "string" || rawTyp.length === 0) return;
  const typ = rawTyp.toLowerCase();
  if (typ === "jwt" || typ === "application/jwt") return;
  throw new Error(`Unsupported id_token typ: ${rawTyp}`);
}

export async function verifyIdToken(params) {
  assertSsoBaseUrlSafe(params.ssoBaseUrl);
  const parsed = parseJwt(params.idToken);
  // RFC 7515 §4.1.11 / RFC 7519 §7.2: any non-empty `crit` array names
  // extensions the verifier MUST understand. We support none.
  if (Array.isArray(parsed.header.crit) && parsed.header.crit.length > 0) {
    throw new Error(`id_token contains unsupported crit extensions: ${parsed.header.crit.join(",")}`);
  }
  assertIdTokenTyp(parsed.header.typ);
  const alg = parsed.header.alg;
  const expectedKty = ID_TOKEN_ALG_KTY[alg];
  if (!expectedKty) {
    throw new Error(`Unsupported id_token alg: ${String(alg)}`);
  }

  const discovery = await fetchOidcDiscovery(params.ssoBaseUrl);
  const issuer = discovery.issuer;
  const jwksUri = discovery.jwks_uri;
  if (!issuer || !jwksUri) {
    throw new Error("Discovery response missing issuer or jwks_uri");
  }

  const jwks = await fetchJwks(jwksUri);
  const kid = parsed.header.kid;
  const key = jwks.keys.find((k) => k.kid === kid && k.kty === expectedKty);
  if (!key) {
    throw new Error(`Unable to find ${expectedKty} JWK for kid=${String(kid)}`);
  }

  const verifier = alg === "RS256" ? verifyJwtRs256Signature : verifyJwtEdDsaSignature;
  const validSig = verifier({
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
  // OIDC Core §3.1.3.7.6/.7: multi-aud id_token MUST carry azp == client_id;
  // when azp is present at all, it MUST equal client_id.
  const audIsMulti = Array.isArray(aud) && aud.length > 1;
  if (audIsMulti && payload.azp === undefined) {
    throw new Error("id_token has multiple audiences but no azp claim");
  }
  if (payload.azp !== undefined && payload.azp !== params.providerAddress) {
    throw new Error(`id_token azp mismatch: expected ${params.providerAddress}, got ${String(payload.azp)}`);
  }
  // RFC 7519 §4.1.6: `iat` is OPTIONAL but, when present, MUST be a number
  // (NumericDate). A non-numeric `iat` (string, object, …) is a malformed
  // claim and the token MUST be rejected.
  if ("iat" in payload && typeof payload.iat !== "number") {
    throw new Error("id_token iat is not a NumericDate");
  }
  // RFC 7519 §4.1.5: when present, current time MUST be ≥ nbf. The claim
  // itself MUST be a NumericDate when present.
  if ("nbf" in payload && typeof payload.nbf !== "number") {
    throw new Error("id_token nbf is not a NumericDate");
  }
  if (typeof payload.nbf === "number" && payload.nbf > nowSec) {
    throw new Error("id_token not yet valid");
  }
  if (typeof payload.exp !== "number" || payload.exp <= nowSec) {
    throw new Error("id_token is expired");
  }
  if (typeof payload.sub !== "string" || !payload.sub) {
    throw new Error("id_token sub is missing");
  }
  // OIDC Core §3.1.3.7 step 11: if the caller sent a `nonce` in the
  // authorization request, the id_token MUST carry the same value. The
  // comparison is exact-string. Refresh-token flows do not send a nonce,
  // so callers omit `expectedNonce` there; in that case any nonce the AS
  // chose to carry forward is accepted as opaque.
  if (typeof params.expectedNonce === "string" && params.expectedNonce) {
    if (typeof payload.nonce !== "string" || payload.nonce !== params.expectedNonce) {
      throw new Error("id_token nonce mismatch");
    }
  }
  // RFC 9449 §6.1 + RFC 7800 §3.1: when caller supplies the agent's public
  // key, surface a cnf.jkt mismatch immediately rather than deferring to
  // later proof-chain verification.
  if (typeof params.agentPublicKeyPem === "string" && params.agentPublicKeyPem) {
    const expectedJkt = jwkThumbprint(ed25519PublicKeyToJwk(params.agentPublicKeyPem));
    const actualJkt = payload.cnf?.jkt;
    if (typeof actualJkt !== "string" || !actualJkt) {
      throw new Error("id_token missing cnf.jkt");
    }
    if (actualJkt !== expectedJkt) {
      throw new Error(`id_token cnf.jkt mismatch: expected ${expectedJkt}, got ${actualJkt}`);
    }
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
  assertSsoBaseUrlSafe(params.ssoBaseUrl);
  const parsed = parseJwt(params.idToken);
  assertIdTokenTyp(parsed.header.typ);
  const alg = parsed.header.alg;
  const expectedKty = ID_TOKEN_ALG_KTY[alg];
  if (!expectedKty) {
    throw new Error(`Unsupported id_token alg: ${String(alg)}`);
  }

  const discovery = await fetchOidcDiscovery(params.ssoBaseUrl);
  const jwksUri = discovery.jwks_uri;
  if (!jwksUri) {
    throw new Error("Discovery response missing jwks_uri");
  }
  // OIDC Core §3.1.3.7 step 2: id_token MUST carry `iss` matching the
  // discovered issuer. Without this gate, an attacker-controlled discovery
  // endpoint can mint a self-consistent token whose `iss` claim points
  // anywhere — defeating the trust this function exposes to chain consumers.
  if (parsed.payload?.iss !== discovery.issuer) {
    throw new Error(
      `id_token issuer mismatch: expected ${discovery.issuer}, got ${String(parsed.payload?.iss)}`,
    );
  }

  const jwks = await fetchJwks(jwksUri);
  const kid = parsed.header.kid;
  const key = jwks.keys.find((k) => k.kid === kid && k.kty === expectedKty);
  if (!key) {
    throw new Error(`Unable to find ${expectedKty} JWK for kid=${String(kid)}`);
  }

  const verifier = alg === "RS256" ? verifyJwtRs256Signature : verifyJwtEdDsaSignature;
  const validSig = verifier({
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

/**
 * SubjectMismatchError marks a refresh-time security failure: the refreshed
 * token claims a different `sub` than the bound owner session. Callers use
 * `instanceof` to distinguish a security-relevant mismatch from incidental
 * parse errors on opaque tokens.
 */
export class SubjectMismatchError extends Error {
  constructor(message) {
    super(message);
    this.name = "SubjectMismatchError";
  }
}

/**
 * AuthRevokedError marks a token-endpoint failure where the AS has rejected
 * the supplied credential — HTTP 401, HTTP 403, or RFC 6749 §5.2
 * `invalid_grant`. Callers can catch this distinctly from network/parse
 * errors and prompt the user to re-authenticate.
 */
export class AuthRevokedError extends Error {
  constructor(message, { status, errorCode } = {}) {
    super(message);
    this.name = "AuthRevokedError";
    this.status = status ?? null;
    this.errorCode = errorCode ?? null;
  }
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

// ════════════════════════════════════════════════════════════════════════════════
// Service manifest discovery — /.well-known/alien-agent-id.json
//
// Trust model: the manifest is third-party data. It is parsed, schema-validated,
// and reduced to a fixed set of fields before any value is returned. The only
// URLs the agent will subsequently touch are those that share the same authority
// as the user-provided service URL (exact host or a subdomain).
// ════════════════════════════════════════════════════════════════════════════════

export const SERVICE_MANIFEST_PATH = "/.well-known/alien-agent-id.json";
export const SERVICE_MANIFEST_MAX_BYTES = 8192;
export const SERVICE_MANIFEST_VERSION = 1;
export const SERVICE_MANIFEST_VERSIONS = new Set([1, 2]);
export const SUPPORT_SIGNAL_MAX_BYTES = 65536;
export const SUPPORT_SIGNAL_VERSIONS = new Set(["v1"]);

const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
const ALLOWED_AUTH_SCHEMES = new Set(["DPoP", "Bearer", "none"]);
const ALLOWED_TOP_KEYS = new Set(["version", "service", "auth", "api"]);
const ALLOWED_SERVICE_KEYS = new Set(["name", "url"]);
const ALLOWED_AUTH_KEYS = new Set(["header", "scheme"]);
const ALLOWED_API_KEYS = new Set(["base", "specUrl", "operations"]);

// v2 operations[] — closed-key, capped, prompt-injection-bounded.
const OPERATIONS_MAX = 50;
const OP_DESC_MAX = 1024;
const OP_TITLE_MAX = 80;
const OP_PATH_MAX = 200;
const OP_PROP_DESC_MAX = 200;
const OP_PROPERTIES_MAX = 20;
const OP_ENUM_MAX = 32;
const OP_MAXLENGTH_MAX = 100000;
const OP_NAME_RE = /^[a-zA-Z][a-zA-Z0-9_]{0,63}$/;
const OP_PATH_RE = /^\/[^\s?#]*$/;
const OP_PATH_PARAM_RE = /\{([a-zA-Z][a-zA-Z0-9_]*)\}/g;
const OP_CONTROL_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;
const ALLOWED_OPERATION_KEYS = new Set(["name", "title", "description", "method", "path", "auth", "inputSchema", "outputSchema", "annotations"]);
const ALLOWED_ANNOTATION_KEYS = new Set(["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]);
const ALLOWED_OP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const ALLOWED_OP_AUTH = new Set(["required", "optional", "none"]);
const ALLOWED_OP_SCHEMA_KEYS = new Set(["type", "properties", "required", "additionalProperties", "description"]);
const ALLOWED_OP_PROPERTY_KEYS = new Set(["type", "description", "enum", "maxLength", "items"]);
const ALLOWED_OP_PROPERTY_TYPES = new Set(["string", "number", "integer", "boolean", "array"]);
const ALLOWED_OP_ARRAY_ITEM_TYPES = new Set(["string", "number", "integer", "boolean"]);

function rejectUnknownKeys(obj, allowed, where) {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new Error(`Manifest ${where}: unknown key "${key}"`);
    }
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isSameAuthority(host, allowedHost) {
  if (typeof host !== "string" || !host) return false;
  return host === allowedHost || host.endsWith(`.${allowedHost}`);
}

function validateManifestUrl(value, allowedHost, where, { allowInsecure = false } = {}) {
  if (typeof value !== "string" || !value) {
    throw new Error(`Manifest ${where}: must be a string URL`);
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Manifest ${where}: invalid URL`);
  }
  const protoOk = url.protocol === "https:" || (allowInsecure && url.protocol === "http:");
  if (!protoOk) {
    throw new Error(`Manifest ${where}: must be https://`);
  }
  if (!isSameAuthority(url.host, allowedHost)) {
    throw new Error(`Manifest ${where}: host "${url.host}" is not within "${allowedHost}"`);
  }
  return url.toString();
}

function parseOperationProperty(raw, where) {
  if (!isPlainObject(raw)) throw new Error(`Manifest ${where}: must be an object`);
  rejectUnknownKeys(raw, ALLOWED_OP_PROPERTY_KEYS, where);
  if (typeof raw.type !== "string" || !ALLOWED_OP_PROPERTY_TYPES.has(raw.type)) {
    throw new Error(`Manifest ${where}.type: must be one of ${[...ALLOWED_OP_PROPERTY_TYPES].join(", ")}`);
  }
  const out = { type: raw.type };
  if (raw.description !== undefined) {
    if (typeof raw.description !== "string" || raw.description.length > OP_PROP_DESC_MAX) {
      throw new Error(`Manifest ${where}.description: must be a string ≤${OP_PROP_DESC_MAX} chars`);
    }
    if (OP_CONTROL_CHARS.test(raw.description)) {
      throw new Error(`Manifest ${where}.description: control characters forbidden`);
    }
    out.description = raw.description;
  }
  if (raw.enum !== undefined) {
    if (!Array.isArray(raw.enum) || raw.enum.length === 0 || raw.enum.length > OP_ENUM_MAX) {
      throw new Error(`Manifest ${where}.enum: must be a 1-${OP_ENUM_MAX} item array`);
    }
    out.enum = [...raw.enum];
  }
  if (raw.maxLength !== undefined) {
    if (!Number.isInteger(raw.maxLength) || raw.maxLength < 0 || raw.maxLength > OP_MAXLENGTH_MAX) {
      throw new Error(`Manifest ${where}.maxLength: must be an integer 0-${OP_MAXLENGTH_MAX}`);
    }
    out.maxLength = raw.maxLength;
  }
  if (raw.items !== undefined) {
    if (raw.type !== "array") {
      throw new Error(`Manifest ${where}.items: only valid when type is "array"`);
    }
    if (typeof raw.items !== "string" || !ALLOWED_OP_ARRAY_ITEM_TYPES.has(raw.items)) {
      throw new Error(`Manifest ${where}.items: must be one of ${[...ALLOWED_OP_ARRAY_ITEM_TYPES].join(", ")}`);
    }
    out.items = raw.items;
  }
  return out;
}

function parseOperationSchema(raw, where) {
  if (!isPlainObject(raw)) throw new Error(`Manifest ${where}: must be an object`);
  rejectUnknownKeys(raw, ALLOWED_OP_SCHEMA_KEYS, where);
  if (raw.type !== "object") {
    throw new Error(`Manifest ${where}.type: must be "object"`);
  }
  const out = { type: "object" };
  if (raw.description !== undefined) {
    if (typeof raw.description !== "string" || raw.description.length > OP_PROP_DESC_MAX) {
      throw new Error(`Manifest ${where}.description: must be a string ≤${OP_PROP_DESC_MAX} chars`);
    }
    out.description = raw.description;
  }
  if (raw.additionalProperties !== undefined) {
    if (typeof raw.additionalProperties !== "boolean") {
      throw new Error(`Manifest ${where}.additionalProperties: must be boolean`);
    }
    out.additionalProperties = raw.additionalProperties;
  }
  if (raw.required !== undefined) {
    if (!Array.isArray(raw.required) || raw.required.length > OP_PROPERTIES_MAX) {
      throw new Error(`Manifest ${where}.required: must be a string array ≤${OP_PROPERTIES_MAX}`);
    }
    for (const k of raw.required) {
      if (typeof k !== "string") throw new Error(`Manifest ${where}.required: items must be strings`);
    }
    out.required = [...raw.required];
  }
  if (raw.properties !== undefined) {
    if (!isPlainObject(raw.properties)) throw new Error(`Manifest ${where}.properties: must be an object`);
    const keys = Object.keys(raw.properties);
    if (keys.length > OP_PROPERTIES_MAX) {
      throw new Error(`Manifest ${where}.properties: max ${OP_PROPERTIES_MAX} entries`);
    }
    out.properties = {};
    for (const k of keys) {
      out.properties[k] = parseOperationProperty(raw.properties[k], `${where}.properties[${JSON.stringify(k)}]`);
    }
  }
  if (out.required && out.properties) {
    for (const r of out.required) {
      if (!Object.prototype.hasOwnProperty.call(out.properties, r)) {
        throw new Error(`Manifest ${where}.required: "${r}" not in properties`);
      }
    }
  }
  return out;
}

function parseOperation(raw, where) {
  if (!isPlainObject(raw)) throw new Error(`Manifest ${where}: must be an object`);
  rejectUnknownKeys(raw, ALLOWED_OPERATION_KEYS, where);
  if (typeof raw.name !== "string" || !OP_NAME_RE.test(raw.name)) {
    throw new Error(`Manifest ${where}.name: must match ^[a-zA-Z][a-zA-Z0-9_]{0,63}$`);
  }
  if (typeof raw.description !== "string" || raw.description.length === 0 || raw.description.length > OP_DESC_MAX) {
    throw new Error(`Manifest ${where}.description: must be a 1-${OP_DESC_MAX} char string`);
  }
  if (OP_CONTROL_CHARS.test(raw.description)) {
    throw new Error(`Manifest ${where}.description: control characters forbidden`);
  }
  if (typeof raw.method !== "string" || !ALLOWED_OP_METHODS.has(raw.method)) {
    throw new Error(`Manifest ${where}.method: must be one of ${[...ALLOWED_OP_METHODS].join(", ")}`);
  }
  if (typeof raw.path !== "string" || raw.path.length === 0 || raw.path.length > OP_PATH_MAX || !OP_PATH_RE.test(raw.path)) {
    throw new Error(`Manifest ${where}.path: must match ^/[^\\s?#]* (≤${OP_PATH_MAX} chars)`);
  }
  const out = {
    name: raw.name,
    description: raw.description,
    method: raw.method,
    path: raw.path,
    auth: "required",
  };
  if (raw.title !== undefined) {
    if (typeof raw.title !== "string" || raw.title.length === 0 || raw.title.length > OP_TITLE_MAX) {
      throw new Error(`Manifest ${where}.title: must be a 1-${OP_TITLE_MAX} char string`);
    }
    out.title = raw.title;
  }
  if (raw.auth !== undefined) {
    if (typeof raw.auth !== "string" || !ALLOWED_OP_AUTH.has(raw.auth)) {
      throw new Error(`Manifest ${where}.auth: must be one of ${[...ALLOWED_OP_AUTH].join(", ")}`);
    }
    out.auth = raw.auth;
  }
  if (raw.inputSchema !== undefined) {
    out.inputSchema = parseOperationSchema(raw.inputSchema, `${where}.inputSchema`);
  }
  if (raw.outputSchema !== undefined) {
    out.outputSchema = parseOperationSchema(raw.outputSchema, `${where}.outputSchema`);
  }
  if (raw.annotations !== undefined) {
    if (!isPlainObject(raw.annotations)) throw new Error(`Manifest ${where}.annotations: must be an object`);
    rejectUnknownKeys(raw.annotations, ALLOWED_ANNOTATION_KEYS, `${where}.annotations`);
    const ann = {};
    for (const k of Object.keys(raw.annotations)) {
      if (typeof raw.annotations[k] !== "boolean") {
        throw new Error(`Manifest ${where}.annotations.${k}: must be boolean`);
      }
      ann[k] = raw.annotations[k];
    }
    out.annotations = ann;
  }
  const placeholders = [...out.path.matchAll(OP_PATH_PARAM_RE)].map(m => m[1]);
  if (placeholders.length > 0) {
    const props = out.inputSchema?.properties ?? {};
    for (const p of placeholders) {
      if (!Object.prototype.hasOwnProperty.call(props, p)) {
        throw new Error(`Manifest ${where}.path: placeholder {${p}} has no matching inputSchema.properties.${p}`);
      }
    }
  }
  return out;
}

export function parseServiceManifest(raw, allowedHost, options = {}) {
  if (!isPlainObject(raw)) {
    throw new Error("Manifest: root must be a JSON object");
  }
  rejectUnknownKeys(raw, ALLOWED_TOP_KEYS, "root");

  if (!SERVICE_MANIFEST_VERSIONS.has(raw.version)) {
    throw new Error(`Manifest: unsupported version ${JSON.stringify(raw.version)} (expected one of ${[...SERVICE_MANIFEST_VERSIONS].join(", ")})`);
  }

  if (!isPlainObject(raw.auth)) {
    throw new Error("Manifest: missing required \"auth\" object");
  }
  if (!isPlainObject(raw.api)) {
    throw new Error("Manifest: missing required \"api\" object");
  }

  rejectUnknownKeys(raw.auth, ALLOWED_AUTH_KEYS, "auth");
  rejectUnknownKeys(raw.api, ALLOWED_API_KEYS, "api");

  if (raw.api.operations !== undefined && raw.version !== 2) {
    throw new Error("Manifest api.operations: requires version 2");
  }

  const out = { version: raw.version };

  if (raw.service !== undefined) {
    if (!isPlainObject(raw.service)) {
      throw new Error("Manifest: \"service\" must be an object");
    }
    rejectUnknownKeys(raw.service, ALLOWED_SERVICE_KEYS, "service");
    const service = {};
    if (raw.service.name !== undefined) {
      if (typeof raw.service.name !== "string" || raw.service.name.length === 0 || raw.service.name.length > 80) {
        throw new Error("Manifest service.name: must be a 1-80 char string");
      }
      service.name = raw.service.name;
    }
    if (raw.service.url !== undefined) {
      service.url = validateManifestUrl(raw.service.url, allowedHost, "service.url", options);
    }
    out.service = service;
  }

  out.auth = {
    header: (() => {
      if (typeof raw.auth.header !== "string" || !HEADER_NAME_RE.test(raw.auth.header)) {
        throw new Error("Manifest auth.header: must match [A-Za-z0-9-]{1,64}");
      }
      return raw.auth.header;
    })(),
    scheme: (() => {
      if (raw.auth.scheme === undefined) return "DPoP";
      if (typeof raw.auth.scheme !== "string" || !ALLOWED_AUTH_SCHEMES.has(raw.auth.scheme)) {
        throw new Error(`Manifest auth.scheme: must be one of ${[...ALLOWED_AUTH_SCHEMES].join(", ")}`);
      }
      return raw.auth.scheme;
    })(),
  };

  out.api = {
    base: validateManifestUrl(raw.api.base, allowedHost, "api.base", options),
  };
  if (raw.api.specUrl !== undefined) {
    out.api.specUrl = validateManifestUrl(raw.api.specUrl, allowedHost, "api.specUrl", options);
  }
  if (raw.api.operations !== undefined) {
    if (!Array.isArray(raw.api.operations)) {
      throw new Error("Manifest api.operations: must be an array");
    }
    if (raw.api.operations.length > OPERATIONS_MAX) {
      throw new Error(`Manifest api.operations: max ${OPERATIONS_MAX} entries`);
    }
    const seen = new Set();
    out.api.operations = raw.api.operations.map((op, i) => {
      const parsed = parseOperation(op, `api.operations[${i}]`);
      if (seen.has(parsed.name)) {
        throw new Error(`Manifest api.operations: duplicate name "${parsed.name}"`);
      }
      seen.add(parsed.name);
      return parsed;
    });
  }

  return out;
}

// renderCapabilities: turn a validated manifest into LLM-friendly markdown.
// Per-operation `Call:` lines name the CLI explicitly so an agent reading
// the rendered output reaches for `node CLI call` (which signs DPoP per
// request) instead of raw curl/fetch (which gets 401).
export function renderCapabilities(manifest) {
  if (!isPlainObject(manifest)) {
    throw new Error("renderCapabilities: manifest must be an object");
  }
  const base = manifest.api?.base ?? "";
  const ops = manifest.api?.operations ?? [];
  const name = manifest.service?.name ?? "Service";
  const scheme = manifest.auth?.scheme ?? "DPoP";

  if (ops.length === 0) {
    if (manifest.api?.specUrl) {
      return `# ${name}\n\nNo inline operations. See OpenAPI at ${manifest.api.specUrl}.`;
    }
    return `# ${name}\n\nNo operations declared. Ask the user.`;
  }

  const lines = [
    `# ${name} — operations`,
    "",
    `Base: \`${base}\` · Auth: \`${scheme}\``,
    "",
    "Invoke each operation with `node CLI call --url <base+path> --method <verb> [--body-file ./body.json]`. The CLI signs each request with DPoP; raw curl/fetch will get 401.",
    "",
  ];

  for (const op of ops) {
    lines.push(`## ${op.name}`);
    lines.push("");
    lines.push(op.description);
    lines.push("");
    const bodyHint = op.inputSchema && op.method !== "GET" && op.method !== "DELETE"
      ? " --body-file ./body.json"
      : "";
    lines.push(`Call: \`node CLI call --url ${base}${op.path} --method ${op.method}${bodyHint}\``);
    if (op.auth && op.auth !== "required") {
      lines.push(`Auth: ${op.auth}`);
    }

    const props = op.inputSchema?.properties ?? {};
    const required = new Set(op.inputSchema?.required ?? []);
    const keys = Object.keys(props);
    if (keys.length) {
      lines.push("", "Input:");
      for (const k of keys) {
        const p = props[k];
        const typeStr = p.type === "array" && p.items ? `array of ${p.items}` : p.type;
        const req = required.has(k) ? ", required" : "";
        const max = p.maxLength ? `, max ${p.maxLength}` : "";
        const enumStr = p.enum ? `, one of [${p.enum.map(v => JSON.stringify(v)).join(", ")}]` : "";
        const hint = p.description ? `: ${p.description}` : "";
        lines.push(`- \`${k}\` (${typeStr}${req}${max}${enumStr})${hint}`);
      }
    }

    const ann = op.annotations ?? {};
    const warns = [];
    if (ann.destructiveHint && !ann.readOnlyHint) warns.push("destructive — confirm before calling");
    if (ann.openWorldHint) warns.push("open-world — may affect external state");
    if (warns.length) {
      lines.push("", `⚠ ${warns.join("; ")}.`);
    }
    lines.push("");
  }
  return lines.join("\n").replace(/\n+$/, "\n");
}

async function readBoundedBody(res, maxBytes) {
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      throw new Error(`Manifest exceeds ${maxBytes} bytes`);
    }
    return text;
  }
  let received = 0;
  const chunks = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    received += value.length;
    if (received > maxBytes) {
      try { await reader.cancel(); } catch {}
      throw new Error(`Manifest exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
}

export async function fetchServiceManifest(serviceUrl, options = {}) {
  if (typeof serviceUrl !== "string" || !serviceUrl) {
    throw new Error("fetchServiceManifest: serviceUrl required");
  }
  let parsed;
  try {
    parsed = new URL(serviceUrl);
  } catch {
    throw new Error("fetchServiceManifest: invalid serviceUrl");
  }
  const allowInsecure = options.allowInsecure === true;
  if (parsed.protocol !== "https:" && !(allowInsecure && parsed.protocol === "http:")) {
    throw new Error("fetchServiceManifest: serviceUrl must be https://");
  }
  const allowedHost = parsed.host;
  const manifestUrl = `${parsed.protocol}//${parsed.host}${SERVICE_MANIFEST_PATH}`;

  const controller = new AbortController();
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    res = await fetch(manifestUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "error",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    throw new Error(`Manifest fetch failed: HTTP ${res.status} from ${manifestUrl}`);
  }
  const contentType = res.headers.get("content-type") || "";
  if (!/^application\/json\b/i.test(contentType)) {
    throw new Error(`Manifest fetch failed: expected application/json, got "${contentType}"`);
  }

  const body = await readBoundedBody(res, SERVICE_MANIFEST_MAX_BYTES);
  let json;
  try {
    json = JSON.parse(body);
  } catch {
    throw new Error("Manifest fetch failed: response is not valid JSON");
  }

  const manifest = parseServiceManifest(json, allowedHost, { allowInsecure });
  return { manifest, manifestUrl, allowedHost };
}

// Build the HTTP header pair for an API call to a service whose manifest
// has been validated. Pure: no network, no I/O.
export function buildServiceAuthHeader(manifest, agentToken) {
  if (!isPlainObject(manifest) || !isPlainObject(manifest.auth)) {
    throw new Error("buildServiceAuthHeader: invalid manifest");
  }
  if (typeof agentToken !== "string" || !agentToken) {
    throw new Error("buildServiceAuthHeader: agentToken required");
  }
  const value = manifest.auth.scheme === "none"
    ? agentToken
    : `${manifest.auth.scheme} ${agentToken}`;
  return { name: manifest.auth.header, value };
}

// Probe a page URL for the closed-enum support-signal meta tag:
//   <meta name="alien-agent-id" content="v1">
//
// This is purely a hint that the service advertises Alien Agent ID support.
// It NEVER carries the manifest path — the manifest always lives at
// SERVICE_MANIFEST_PATH on the same host. Anything other than a known version
// in the closed-enum content is rejected (no prose, no URLs).
//
// Any network/HTTP/parse failure resolves to { supported: false, version: null }
// so callers can use this as a yes/no signal without needing error handling.
export async function probeServiceSupportSignal(pageUrl, options = {}) {
  if (typeof pageUrl !== "string" || !pageUrl) {
    throw new Error("probeServiceSupportSignal: pageUrl required");
  }
  let parsed;
  try { parsed = new URL(pageUrl); } catch { throw new Error("probeServiceSupportSignal: invalid pageUrl"); }
  const allowInsecure = options.allowInsecure === true;
  if (parsed.protocol !== "https:" && !(allowInsecure && parsed.protocol === "http:")) {
    throw new Error("probeServiceSupportSignal: pageUrl must be https://");
  }

  const controller = new AbortController();
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    res = await fetch(pageUrl, {
      method: "GET",
      headers: { Accept: "text/html" },
      redirect: "error",
      signal: controller.signal,
    });
  } catch {
    clearTimeout(timer);
    return { supported: false, version: null };
  }
  clearTimeout(timer);

  if (!res.ok) return { supported: false, version: null };
  const contentType = res.headers.get("content-type") || "";
  if (!/^text\/html\b/i.test(contentType)) return { supported: false, version: null };

  let html;
  try {
    html = await readBoundedBody(res, SUPPORT_SIGNAL_MAX_BYTES);
  } catch {
    return { supported: false, version: null };
  }

  const tagRe = /<meta\b[^>]*>/gi;
  const nameRe = /\bname\s*=\s*["']alien-agent-id["']/i;
  const contentRe = /\bcontent\s*=\s*["']([^"']*)["']/i;
  for (const m of html.matchAll(tagRe)) {
    const tag = m[0];
    if (!nameRe.test(tag)) continue;
    const cm = contentRe.exec(tag);
    if (!cm) return { supported: false, version: null };
    const value = cm[1];
    if (SUPPORT_SIGNAL_VERSIONS.has(value)) {
      return { supported: true, version: value };
    }
    return { supported: false, version: null };
  }
  return { supported: false, version: null };
}

// Resolve a request path against the manifest's api.base, refusing any path
// that escapes the base authority (e.g. "//evil.com/x" or a full https URL).
export function resolveServiceApiUrl(manifest, requestPath) {
  if (!isPlainObject(manifest) || !isPlainObject(manifest.api)) {
    throw new Error("resolveServiceApiUrl: invalid manifest");
  }
  if (typeof requestPath !== "string" || !requestPath) {
    throw new Error("resolveServiceApiUrl: requestPath required");
  }
  const base = new URL(manifest.api.base.endsWith("/") ? manifest.api.base : manifest.api.base + "/");
  const resolved = new URL(requestPath, base);
  if (resolved.host !== base.host || resolved.protocol !== base.protocol) {
    throw new Error(`resolveServiceApiUrl: path "${requestPath}" escapes api.base`);
  }
  return resolved.toString();
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
    this.idTokenJti = null;
    this.idTokenSub = null;
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

    // Parse the cached id_token (if any) for the audit-log anchor. The jti
    // (RFC 7519 §4.1.7) replaces the legacy ownerBindingId; sub is captured
    // for envelope fields that previously read it off the binding.
    const session = await readJsonFile(this.paths.ownerSession, null);
    if (session?.idToken) {
      try {
        const payload = parseJwt(session.idToken).payload;
        if (typeof payload?.jti === "string" && payload.jti) {
          this.idTokenJti = payload.jti;
        }
        if (typeof payload?.sub === "string" && payload.sub) {
          this.idTokenSub = payload.sub;
        }
      } catch {
        // Unparseable id_token — engine still functions for non-audit ops.
      }
    }

    await this.ensureMainKey();
  }

  isOwnerBound() {
    return Boolean(this.idTokenJti);
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
    await this.ensureMainKey();

    // v3 model: the SSO-signed id_token IS the binding (no agent-self-signed
    // ownerBinding envelope). Persist only the session; future operations
    // read the id_token directly and parse claims (sub, jti, cnf.jkt) at use.
    const ownerSessionRecord = {
      version: 1,
      issuer: params.issuer,
      ssoBaseUrl: params.ssoBaseUrl || params.issuer,
      providerAddress: params.providerAddress,
      ownerSessionSub: params.ownerSessionSub,
      idToken: params.idToken,
      accessToken: params.accessToken,
      refreshToken: params.refreshToken,
      savedAt: nowMs(),
    };
    await writeJsonFile(this.paths.ownerSession, ownerSessionRecord);
    await setPrivateFilePermissions(this.paths.ownerSession);

    // Refresh cached anchors so subsequent appendOperation calls work.
    try {
      const payload = parseJwt(params.idToken).payload;
      this.idTokenJti = typeof payload?.jti === "string" ? payload.jti : null;
      this.idTokenSub = typeof payload?.sub === "string" ? payload.sub : null;
    } catch {
      this.idTokenJti = null;
      this.idTokenSub = null;
    }

    return {
      ownerSessionSub: params.ownerSessionSub,
      issuer: params.issuer,
      providerAddress: params.providerAddress,
      idTokenJti: this.idTokenJti,
    };
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

    // Forward the agent's main keypair so the refresh request carries a DPoP
    // proof bound to the same key the SSO advertises in `cnf.jkt`.
    const main = await this.ensureMainKey();

    const fresh = await refreshSession({
      ssoBaseUrl,
      refreshToken: session.refreshToken,
      providerAddress: session.providerAddress,
      agentPrivateKeyPem: main.privateKeyPem,
    });

    // Verify the refreshed token still belongs to the same owner.
    if (session.ownerSessionSub) {
      try {
        const freshPayload = parseJwt(fresh.access_token).payload;
        if (freshPayload.sub && freshPayload.sub !== session.ownerSessionSub) {
          throw new SubjectMismatchError(
            `Refreshed token subject mismatch: expected ${session.ownerSessionSub}, got ${freshPayload.sub}`,
          );
        }
      } catch (err) {
        if (err instanceof SubjectMismatchError) throw err;
        // Non-JWT or unparseable — skip subject check (opaque tokens have no sub).
      }
    }

    // RFC 9449 §6.1 + RFC 6749 §6: when the AS rotates the id_token, re-run
    // the full claim+signature+cnf.jkt check before persistence. A
    // compromised or buggy AS that rotates `sub` or `cnf.jkt` is caught
    // here rather than at the next chain verification.
    if (fresh.id_token) {
      const verified = await verifyIdToken({
        ssoBaseUrl,
        providerAddress: session.providerAddress,
        idToken: fresh.id_token,
        agentPublicKeyPem: main.publicKeyPem,
      });
      if (session.ownerSessionSub && verified.payload.sub !== session.ownerSessionSub) {
        throw new SubjectMismatchError(
          `Refreshed id_token sub mismatch: expected ${session.ownerSessionSub}, got ${verified.payload.sub}`,
        );
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
      if (!this.idTokenJti) {
        throw new Error("Owner session missing or id_token has no jti. Run `auth` and `bind` first.");
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
        idTokenJti: this.idTokenJti,
        ownerSessionSub: this.idTokenSub,
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

function verifyAuditRecord(record, prevHash, keyByAgent, delegationsByChild, idTokenJti, errors) {
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

  // idTokenJti is the v3 audit-log anchor (RFC 7519 §4.1.7) — the audit chain
  // is consistent with whichever id_token was current at append time. Older
  // entries with a different jti just mean the session refreshed; that's not
  // a tamper signal, so only assert equality when both sides have a value.
  if (idTokenJti && record.envelope.idTokenJti && record.envelope.idTokenJti !== idTokenJti) {
    // Entries from a previous session — accept; verifyState only enforces
    // the chain-integrity (prevHash + envelopeHash + signature) invariants.
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

  const session = await readJsonFile(paths.ownerSession, null);
  const keyByAgent = await readAllKeyRecords(paths);
  const delegationsByChild = await readAllDelegations(paths);
  const auditRecords = await readJsonl(paths.auditJsonl);

  let currentJti = null;
  let ownerSub = null;
  if (session?.idToken) {
    try {
      const payload = parseJwt(session.idToken).payload;
      currentJti = typeof payload?.jti === "string" ? payload.jti : null;
      ownerSub = typeof payload?.sub === "string" ? payload.sub : null;
    } catch {
      errors.push("owner-session.json id_token is unparseable");
    }
  } else {
    errors.push("owner-session.json is missing");
  }

  let prevHash = null;
  for (const record of auditRecords) {
    prevHash = verifyAuditRecord(
      record,
      prevHash,
      keyByAgent,
      delegationsByChild,
      currentJti,
      errors,
    );
  }

  return {
    ok: errors.length === 0,
    errorCount: errors.length,
    errors,
    ownerSessionSub: ownerSub,
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

