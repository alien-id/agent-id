// Alien Agent ID — Shared HTTP helpers.
//
// One home for the transport-safety, JSON-reading, and RFC 9449 DPoP-nonce
// retry logic that the OIDC stack (./oidc.mjs) and the vault's owner-approval
// client (../../agent-id-vault/lib/owner-approval.mjs) both need. Before this
// module each maintained its own near-identical copy, including the §8/§9
// `use_dpop_nonce` challenge parser and a separate loopback-host set that had
// drifted out of sync.

// RFC 6749 §10: bearer credentials and refresh tokens MUST be transmitted over
// TLS. The only carve-out is loopback (local dev / tests), where there is no
// network to eavesdrop. One canonical host set so every caller agrees on it.
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

export function isLoopbackHost(hostname) {
  return LOOPBACK_HOSTS.has(hostname);
}

// Validate that a URL rides https:// (or loopback http for dev). Returns the
// parsed URL on success; throws with a `label`-prefixed message otherwise.
export function assertHttpsOrLoopback(rawUrl, label = "url") {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`${label} is not a valid URL: ${rawUrl}`);
  }
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && isLoopbackHost(url.hostname)) return url;
  throw new Error(`${label} must use https:// (got ${url.protocol}//${url.host})`);
}

// Validate + strip a trailing slash from a base URL in one pass.
export function normalizeBaseUrl(rawUrl, label = "ssoBaseUrl") {
  if (typeof rawUrl !== "string" || !rawUrl) {
    throw new Error(`${label} is required`);
  }
  assertHttpsOrLoopback(rawUrl, label);
  return rawUrl.endsWith("/") ? rawUrl.slice(0, -1) : rawUrl;
}

// Read a Response body as JSON, tolerating an empty or non-JSON body (returns
// json:null in that case so callers can fall back to the raw text).
export async function readJsonResponse(res) {
  const text = await res.text();
  try {
    const json = text ? JSON.parse(text) : {};
    return { json, text };
  } catch {
    return { json: null, text };
  }
}

// Detect an RFC 9449 `use_dpop_nonce` challenge in the right place per status:
//   §8 (authorization server): 400 + JSON body `{"error":"use_dpop_nonce"}`.
//   §9 (resource server):       401 + `WWW-Authenticate: DPoP error="use_dpop_nonce"`.
// The WWW-Authenticate match is structural (RFC 7235 §2.2) so the literal token
// appearing inside some other parameter's value can't false-positive a retry.
async function isDpopNonceChallenge(res) {
  if (res.status === 400) {
    try {
      const body = await res.clone().json();
      return Boolean(body && body.error === "use_dpop_nonce");
    } catch {
      return false;
    }
  }
  if (res.status === 401) {
    const wwwAuth = res.headers.get("www-authenticate") || "";
    const m = wwwAuth.match(/\berror\s*=\s*(?:"([^"]*)"|([^,\s]+))/i);
    if (!m) return false;
    const value = m[1] !== undefined ? m[1] : m[2];
    return value.toLowerCase() === "use_dpop_nonce";
  }
  return false;
}

function rememberNonce(cache, url, nonce) {
  if (cache && typeof nonce === "string" && nonce) cache.set(url, nonce);
}

/**
 * Execute a fetch, retrying ONCE on an RFC 9449 §8/§9 `use_dpop_nonce`
 * challenge with the server-issued nonce echoed into a freshly built proof.
 *
 *   url          — request URL
 *   init         — fetch init (method, body, …); headers are supplied per-try
 *   buildHeaders — (nonce|null) => headers; called for the initial try and the
 *                  retry so the proof's `nonce` claim matches what the server
 *                  expects each time
 *   nonceCache   — optional Map keyed by url. When given, the most-recent
 *                  server nonce is pre-attached and refreshed per RFC 9449
 *                  §8.2 (sticky across calls). Omit for one-shot callers.
 */
export async function fetchWithDPoPNonce(url, init, buildHeaders, { nonceCache = null } = {}) {
  const cached = nonceCache ? nonceCache.get(url) : null;
  let res = await fetch(url, { ...init, headers: buildHeaders(cached) });
  rememberNonce(nonceCache, url, res.headers.get("dpop-nonce"));

  if (res.status !== 400 && res.status !== 401) return res;
  const issuedNonce = res.headers.get("dpop-nonce");
  if (!issuedNonce) return res;

  if (await isDpopNonceChallenge(res)) {
    res = await fetch(url, { ...init, headers: buildHeaders(issuedNonce) });
    rememberNonce(nonceCache, url, res.headers.get("dpop-nonce"));
  }
  return res;
}
