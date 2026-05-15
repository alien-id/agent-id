// Alien Agent ID — OIDC flows: discovery, authorize/poll/exchange,
// refresh, userinfo, JWKS, id_token verification.
//
// All HTTP traffic is required to be TLS except for loopback (development);
// see assertSsoBaseUrlSafe. Every entry-point validates its inputs;
// callers should not need to pre-massage URLs.
//
// Dependencies: crypto primitives + DPoP proof builder (./crypto.mjs);
// AuthRevokedError for typed surface on token-endpoint rejections
// (./errors.mjs).

import { randomBytes } from "node:crypto";

import {
  b64url,
  createDPoPProof,
  ed25519PublicKeyToJwk,
  fromB64url,
  jwkThumbprint,
  sha256B64url,
  verifyJwtEdDsaSignature,
  verifyJwtRs256Signature,
} from "./crypto.mjs";

import { AuthRevokedError, errorMessage } from "./errors.mjs";

// Validate and normalize an SSO base URL in one pass. Every public function
// that accepts ssoBaseUrl calls this once; the returned value is safe and
// has no trailing slash.
function normalizeSsoBaseUrl(ssoBaseUrl) {
  if (typeof ssoBaseUrl !== "string" || !ssoBaseUrl) {
    throw new Error("ssoBaseUrl is required");
  }
  let url;
  try {
    url = new URL(ssoBaseUrl);
  } catch {
    throw new Error(`ssoBaseUrl is not a valid URL: ${ssoBaseUrl}`);
  }
  // RFC 6749 §10: bearer credentials and refresh tokens MUST be transmitted
  // over TLS. Allow plain http:// only for loopback hosts (development).
  if (url.protocol !== "https:") {
    const loopback = url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]");
    if (!loopback) {
      throw new Error(`ssoBaseUrl must use https:// (got ${url.protocol}//${url.host})`);
    }
  }
  return ssoBaseUrl.endsWith("/") ? ssoBaseUrl.slice(0, -1) : ssoBaseUrl;
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
  const base = normalizeSsoBaseUrl(params.ssoBaseUrl);
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
  const base = normalizeSsoBaseUrl(params.ssoBaseUrl);
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
  const base = normalizeSsoBaseUrl(params.ssoBaseUrl);
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
  const base = normalizeSsoBaseUrl(params.ssoBaseUrl);
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

  const userinfoUrl = `${normalizeSsoBaseUrl(ssoBaseUrl)}/oauth/userinfo`;

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
  const base = normalizeSsoBaseUrl(ssoBaseUrl);
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

// Shared core of verifyIdToken and verifyIdTokenSignatureOnly: parse the
// JWT, validate typ/alg, fetch discovery+JWKS, and verify the cryptographic
// signature. Returns { parsed, discovery, kid } on success.
async function verifyIdTokenSignatureCore(ssoBaseUrl, idToken) {
  const parsed = parseJwt(idToken);
  if (Array.isArray(parsed.header.crit) && parsed.header.crit.length > 0) {
    throw new Error(`id_token contains unsupported crit extensions: ${parsed.header.crit.join(",")}`);
  }
  assertIdTokenTyp(parsed.header.typ);
  const alg = parsed.header.alg;
  const expectedKty = ID_TOKEN_ALG_KTY[alg];
  if (!expectedKty) {
    throw new Error(`Unsupported id_token alg: ${String(alg)}`);
  }

  const discovery = await fetchOidcDiscovery(ssoBaseUrl);
  const jwksUri = discovery.jwks_uri;
  if (!jwksUri) {
    throw new Error("Discovery response missing jwks_uri");
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

  return { parsed, discovery, kid };
}

export async function verifyIdToken(params) {
  const base = normalizeSsoBaseUrl(params.ssoBaseUrl);
  const { parsed, discovery, kid } = await verifyIdTokenSignatureCore(base, params.idToken);

  const issuer = discovery.issuer;
  if (!issuer) {
    throw new Error("Discovery response missing issuer");
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
  const audIsMulti = Array.isArray(aud) && aud.length > 1;
  if (audIsMulti && payload.azp === undefined) {
    throw new Error("id_token has multiple audiences but no azp claim");
  }
  if (payload.azp !== undefined && payload.azp !== params.providerAddress) {
    throw new Error(`id_token azp mismatch: expected ${params.providerAddress}, got ${String(payload.azp)}`);
  }
  if ("iat" in payload && typeof payload.iat !== "number") {
    throw new Error("id_token iat is not a NumericDate");
  }
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
  if (typeof params.expectedNonce === "string" && params.expectedNonce) {
    if (typeof payload.nonce !== "string" || payload.nonce !== params.expectedNonce) {
      throw new Error("id_token nonce mismatch");
    }
  }
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

export async function verifyIdTokenSignatureOnly(params) {
  const base = normalizeSsoBaseUrl(params.ssoBaseUrl);
  const { parsed, discovery, kid } = await verifyIdTokenSignatureCore(base, params.idToken);

  if (parsed.payload?.iss !== discovery.issuer) {
    throw new Error(
      `id_token issuer mismatch: expected ${discovery.issuer}, got ${String(parsed.payload?.iss)}`,
    );
  }

  return {
    signatureValid: true,
    issuer: discovery.issuer,
    payload: parsed.payload,
    header: parsed.header,
    keyId: kid,
  };
}
