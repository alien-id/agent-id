// Alien Agent ID — OAuth2 refresh-token exchange.
//
// The vault can hold an `oauth2` credential: a long-lived refresh token plus the
// client credentials and token endpoint needed to mint short-lived access
// tokens. The proxy calls `refreshAccessToken` at injection time, caches the
// result in memory, and materializes it as `Authorization: Bearer <access>`.
//
// The agent never sees the refresh token, the client secret, or the access
// token — only the credential name in its request URL. This module does the one
// network call (RFC 6749 §6) and parses the response; the proxy owns caching,
// expiry, and persistence of a rotated refresh token.

import http from "node:http";
import https from "node:https";

export class OAuthError extends Error {
  constructor(message, { oauthError = null, status = null } = {}) {
    super(message);
    this.name = "OAuthError";
    this.oauthError = oauthError; // RFC 6749 §5.2 error code, e.g. "invalid_grant"
    this.status = status; // HTTP status from the token endpoint, if any
  }
}

// POST an application/x-www-form-urlencoded body and read the whole response.
// Follows no redirects; the token endpoint is a fixed URL. http is only reached
// for loopback endpoints (local dev / tests) — see store.mjs validation.
function postForm(urlString, formBody) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (err) {
      reject(new OAuthError(`Bad token endpoint URL: ${err.message}`));
      return;
    }
    const client = url.protocol === "https:" ? https : http;
    const payload = Buffer.from(formBody, "utf8");
    const req = client.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        method: "POST",
        path: `${url.pathname}${url.search}`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
          "Content-Length": payload.length,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }),
        );
      },
    );
    req.on("error", (err) => reject(new OAuthError(`Token endpoint unreachable: ${err.message}`)));
    req.end(payload);
  });
}

/**
 * Exchange a refresh token for a fresh access token (RFC 6749 §6).
 *
 * Returns { accessToken, expiresInSec, refreshToken|null }. `refreshToken` is
 * only set when the server rotated it (the caller should then persist it).
 * Throws OAuthError on transport failure, a non-2xx response, or a body that
 * carries an `error` field — with `.oauthError` set so the caller can single
 * out `invalid_grant` (refresh token revoked/expired → re-mint needed).
 */
export async function refreshAccessToken({
  tokenEndpoint,
  clientId,
  clientSecret = null,
  refreshToken,
  scope = null,
}) {
  const form = new URLSearchParams();
  form.set("grant_type", "refresh_token");
  form.set("refresh_token", refreshToken);
  form.set("client_id", clientId);
  if (clientSecret) form.set("client_secret", clientSecret);
  if (scope) form.set("scope", scope);

  const { status, body } = await postForm(tokenEndpoint, form.toString());

  let parsed = null;
  if (body) {
    try {
      parsed = JSON.parse(body);
    } catch {
      // Non-JSON body — fall through to the status-based error below.
    }
  }

  if (status < 200 || status >= 300 || (parsed && parsed.error)) {
    const oauthError = parsed?.error || null;
    const detail = parsed?.error_description || parsed?.error || `HTTP ${status}`;
    throw new OAuthError(`Token refresh failed: ${detail}`, { oauthError, status });
  }

  if (!parsed || typeof parsed.access_token !== "string") {
    throw new OAuthError("Token refresh response missing access_token", { status });
  }

  // `expires_in` is seconds (RFC 6749 §5.1). Absent → assume a conservative
  // short life so the proxy re-refreshes soon rather than injecting a stale one.
  const expiresInSec = Number.isFinite(parsed.expires_in) ? Number(parsed.expires_in) : 300;

  return {
    accessToken: parsed.access_token,
    expiresInSec,
    refreshToken: typeof parsed.refresh_token === "string" ? parsed.refresh_token : null,
  };
}
