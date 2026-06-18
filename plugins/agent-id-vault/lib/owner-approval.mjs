// Alien Agent ID — Owner-approval unlock client (SSO side).
//
// Drives the per-unlock owner-approval flow against the Alien SSO. The vault's
// owner-approval slot is wrapped by a random KEK that lives only on the SSO
// (bound to the owner + this agent's key). To open the slot the agent must:
//
//   1. enroll  — at slot-creation time, hand the KEK to the SSO and get back
//                an opaque `keyRef`. The KEK is then discarded locally.
//   2. unlock  — POST /vault/unlock/start → SSO pushes an approval prompt to
//                the owner's Alien app (deep link / QR) → owner approves →
//                poll /vault/unlock/poll until the SSO releases the one-time
//                KEK, which unwraps the slot. The KEK is single-use.
//
// Every call is bound to the agent's Ed25519 key with a DPoP proof (RFC 9449)
// and carries the owner-session access token, so the SSO can confirm both the
// owner identity and that the same agent key that enrolled is asking to unlock.
//
// This is the CLIENT half. The matching SSO endpoints are documented in
// docs/VAULT-PROXY.md and simulated by examples/dev-sso.mjs for tests.

import { b64url, createDPoPProof, fromB64url } from "../../agent-id-core/lib/crypto.mjs";

// RFC 6749 §10: bearer/secret material MUST ride TLS; allow plain http only
// for loopback (development / the dev-sso fixture).
function assertTransportSafe(base) {
  let url;
  try {
    url = new URL(base);
  } catch {
    throw new Error(`ssoBaseUrl is not a valid URL: ${base}`);
  }
  if (url.protocol === "https:") return;
  const loopback =
    url.protocol === "http:" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]");
  if (!loopback) {
    throw new Error(`ssoBaseUrl must use https:// (got ${url.protocol}//${url.host})`);
  }
}

function normalizeBase(base) {
  if (typeof base !== "string" || !base) throw new Error("ssoBaseUrl is required");
  assertTransportSafe(base);
  return base.endsWith("/") ? base.slice(0, -1) : base;
}

async function readJson(res) {
  const text = await res.text();
  try {
    return { json: text ? JSON.parse(text) : {}, text };
  } catch {
    return { json: null, text };
  }
}

// POST JSON to an SSO endpoint with an access-token-bound DPoP proof. Retries
// once on an RFC 9449 §8/§9 `use_dpop_nonce` challenge with the issued nonce
// echoed into a fresh proof.
async function dpopPost({ url, accessToken, agentPrivateKeyPem, body }) {
  const buildHeaders = (nonce) => ({
    "Content-Type": "application/json",
    Authorization: `DPoP ${accessToken}`,
    DPoP: createDPoPProof({
      privateKeyPem: agentPrivateKeyPem,
      htm: "POST",
      htu: url,
      accessToken,
      ...(nonce ? { nonce } : {}),
    }),
  });

  const payload = JSON.stringify(body || {});
  let res = await fetch(url, { method: "POST", headers: buildHeaders(null), body: payload });

  if (res.status === 400 || res.status === 401) {
    const issuedNonce = res.headers.get("dpop-nonce");
    if (issuedNonce) {
      // §8 (400) puts the challenge in the JSON body; §9 (401) in WWW-Authenticate.
      let challenged = false;
      if (res.status === 400) {
        try {
          const b = await res.clone().json();
          challenged = b && b.error === "use_dpop_nonce";
        } catch {
          challenged = false;
        }
      } else {
        const wa = res.headers.get("www-authenticate") || "";
        const m = wa.match(/\berror\s*=\s*(?:"([^"]*)"|([^,\s]+))/i);
        if (m) challenged = (m[1] !== undefined ? m[1] : m[2]).toLowerCase() === "use_dpop_nonce";
      }
      if (challenged) {
        res = await fetch(url, { method: "POST", headers: buildHeaders(issuedNonce), body: payload });
      }
    }
  }

  const { json, text } = await readJson(res);
  if (!res.ok) {
    const details = json && typeof json === "object" ? JSON.stringify(json) : text;
    const err = new Error(`HTTP ${res.status} from ${url}: ${details || "no body"}`);
    err.status = res.status;
    err.errorCode = json && typeof json === "object" ? json.error : null;
    throw err;
  }
  if (!json || typeof json !== "object") {
    throw new Error(`Expected JSON response from ${url}`);
  }
  return json;
}

/**
 * Enroll an owner-approval KEK with the SSO. Returns `{ keyRef }` — an opaque
 * handle to store in the vault slot. The SSO binds the KEK to the owner
 * (from the access token) and this agent's key (from the DPoP proof).
 *
 * `secret` is the raw KEK Buffer (32 bytes). It is sent once and then discarded
 * by the caller; the SSO releases it only after an approved unlock.
 */
export async function enrollOwnerApproval({ ssoBaseUrl, accessToken, agentPrivateKeyPem, secret }) {
  const base = normalizeBase(ssoBaseUrl);
  if (typeof accessToken !== "string" || !accessToken) throw new Error("accessToken is required");
  if (typeof agentPrivateKeyPem !== "string" || !agentPrivateKeyPem) {
    throw new Error("agentPrivateKeyPem is required");
  }
  if (!Buffer.isBuffer(secret) || secret.length === 0) throw new Error("secret (KEK) is required");

  const out = await dpopPost({
    url: `${base}/vault/enroll`,
    accessToken,
    agentPrivateKeyPem,
    body: { secret: b64url(secret) },
  });
  const keyRef = out.key_ref || out.keyRef;
  if (typeof keyRef !== "string" || !keyRef) {
    throw new Error("Enroll response missing key_ref");
  }
  return { keyRef };
}

/**
 * Request a one-time unlock of an owner-approval slot. Starts an approval
 * session (the SSO pushes a prompt to the owner's Alien app), invokes
 * `onPrompt({ deepLink, expiredAt })` so the caller can surface the deep
 * link / QR, then polls until the owner approves. Resolves with
 * `{ secret: Buffer }` — the KEK that unwraps the slot.
 *
 * Throws on rejection, expiry, or timeout.
 */
export async function requestUnlockSecret({
  ssoBaseUrl,
  accessToken,
  agentPrivateKeyPem,
  keyRef,
  onPrompt = null,
  pollIntervalMs = 2000,
  timeoutSec = 300,
}) {
  const base = normalizeBase(ssoBaseUrl);
  if (typeof accessToken !== "string" || !accessToken) throw new Error("accessToken is required");
  if (typeof agentPrivateKeyPem !== "string" || !agentPrivateKeyPem) {
    throw new Error("agentPrivateKeyPem is required");
  }
  if (typeof keyRef !== "string" || !keyRef) throw new Error("keyRef is required");

  const start = await dpopPost({
    url: `${base}/vault/unlock/start`,
    accessToken,
    agentPrivateKeyPem,
    body: { key_ref: keyRef },
  });
  const pollingCode = start.polling_code || start.pollingCode;
  if (typeof pollingCode !== "string" || !pollingCode) {
    throw new Error("Unlock-start response missing polling_code");
  }
  if (typeof onPrompt === "function") {
    onPrompt({
      deepLink: start.deep_link || start.deepLink || null,
      expiredAt: start.expired_at || start.expiredAt || null,
      requestId: start.request_id || start.requestId || null,
    });
  }

  const startedAt = Date.now();
  const pollUrl = `${base}/vault/unlock/poll`;
  while (Date.now() - startedAt < timeoutSec * 1000) {
    const out = await dpopPost({
      url: pollUrl,
      accessToken,
      agentPrivateKeyPem,
      body: { polling_code: pollingCode },
    });
    const status = out.status;
    if (status === "authorized") {
      const secretB64 = out.secret;
      if (typeof secretB64 !== "string" || !secretB64) {
        throw new Error("Unlock poll authorized but secret is missing");
      }
      return { secret: fromB64url(secretB64) };
    }
    if (status === "rejected") throw new Error("Owner rejected the vault unlock");
    if (status === "expired") throw new Error("Vault unlock approval expired");
    await new Promise((r) => setTimeout(r, pollIntervalMs));
  }
  throw new Error("Timed out waiting for owner to approve vault unlock");
}
